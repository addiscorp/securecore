//! The space each running microVM start keeps for its disks, shared by every launcher on the host
//! (addiscorp/securecore#100 re-review). A start's disks are sparse and fill as its guest writes,
//! so free space now is not free space later: at boot, N sites' starts all see the same free
//! space and, checked one by one, would together keep N times what is there. Each start
//! therefore checks and records what it keeps in one file, under one lock (`flock`), and a check
//! counts what the others on the same filesystem keep as taken.
//!
//! An entry is a start's state folder, its filesystem (`st_dev`), the bytes it keeps, and the
//! process that keeps them (pid and start time, so a reused pid is never mistaken for it). An
//! entry whose process is gone counts for nothing and is dropped at the next write. A start that
//! fails or stops drops its own ([`Reservation`]'s `Drop`).
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

/// `--space-ledger`'s default.
pub const DEFAULT_SPACE_LEDGER: &str = "/var/lib/securecore/space.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub state: PathBuf,
    pub dev: u64,
    pub bytes: u64,
    /// The guest's memory (MiB): every running guest's counts against the host's budget
    /// (#100 second re-review), whatever filesystem its disks are on.
    #[serde(default)]
    pub mem_mib: u64,
    pub pid: u32,
    /// The process's start time (`/proc/<pid>/stat` field 22).
    pub started: u64,
    /// The boot it was made in (`/proc/sys/kernel/random/boot_id`): an entry from an earlier boot
    /// counts for nothing, even when its pid and start time repeat.
    #[serde(default)]
    pub boot: String,
}

/// This boot's id.
pub fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id").map(|s| s.trim().to_owned()).unwrap_or_default()
}

/// What the other living starts keep: bytes on this start's filesystem, and guest memory on the
/// whole host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Others {
    pub bytes: u64,
    pub mem_mib: u64,
}

/// A process's start time, `None` when it is gone.
pub fn started(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // After the command's ")" (it may hold spaces): field 3 onward; field 22 is the 20th.
    stat.rsplit_once(')')?.1.split_whitespace().nth(19)?.parse().ok()
}

fn alive(e: &Entry, boot: &str) -> bool {
    e.boot == boot && started(e.pid) == Some(e.started)
}

/// The ledger, open and locked until dropped.
struct Locked(fs::File);

impl Locked {
    fn open(path: &Path) -> Result<Locked, String> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let f = OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        // SAFETY: flock(2) on the fd just opened, held by `f`.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(format!("{}: flock: {}", path.display(), std::io::Error::last_os_error()));
        }
        Ok(Locked(f))
    }

    fn read(&mut self) -> Vec<Entry> {
        let mut s = String::new();
        let _ = self.0.seek(SeekFrom::Start(0));
        let _ = self.0.read_to_string(&mut s);
        serde_json::from_str(&s).unwrap_or_default()
    }

    fn write(&mut self, entries: &[Entry]) -> Result<(), String> {
        let text = serde_json::to_string_pretty(entries).map_err(|e| e.to_string())?;
        self.0.set_len(0).map_err(|e| e.to_string())?;
        self.0.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        self.0.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        self.0.sync_data().map_err(|e| e.to_string())
    }
}

/// What a start keeps in the ledger, while it is held: dropped (a failed start, a stop) it
/// takes its entry out.
#[derive(Debug)]
pub struct Reservation {
    ledger: PathBuf,
    state: PathBuf,
    pid: u32,
}

/// Checks and keeps `bytes` (and a guest of `mem_mib`) for the start whose state folder is
/// `state` on filesystem `dev`: `check(others)` gets what the other living starts keep (bytes
/// on `dev`, guest memory on the host), and measures its free space there, all under the ledger's
/// lock, so two starts never both pass on the same free space or memory. `Ok`: the entry is
/// recorded (this state folder's earlier one replaced).
pub fn reserve(ledger: &Path, state: &Path, dev: u64, bytes: u64, mem_mib: u64, check: impl FnOnce(Others) -> Result<(), String>) -> Result<Reservation, String> {
    let pid = std::process::id();
    let me = started(pid).ok_or("this process's own start time (/proc/self/stat)")?;
    let boot = boot_id();
    let mut l = Locked::open(ledger)?;
    let mut entries: Vec<Entry> = l.read().into_iter().filter(|e| e.state != state && alive(e, &boot)).collect();
    let others = Others {
        bytes: entries.iter().filter(|e| e.dev == dev).map(|e| e.bytes).sum(),
        mem_mib: entries.iter().map(|e| e.mem_mib).sum(),
    };
    check(others)?;
    entries.push(Entry { state: state.to_owned(), dev, bytes, mem_mib, pid, started: me, boot });
    l.write(&entries)?;
    Ok(Reservation { ledger: ledger.to_owned(), state: state.to_owned(), pid })
}

impl Reservation {
    /// Keeps `bytes` from now on: what is still to come once the disks are built (with the
    /// snapshot's until it is written). The guest's memory stays kept while it runs. (A running
    /// guest's growth isn't shrunk as its disks fill: counted twice over time, which errs on the
    /// side of gelada for the next site's start.)
    pub fn keep(&self, bytes: u64) -> Result<(), String> {
        let mut l = Locked::open(&self.ledger)?;
        let mut entries = l.read();
        for e in entries.iter_mut().filter(|e| e.state == self.state && e.pid == self.pid) {
            e.bytes = bytes;
        }
        l.write(&entries)
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut l) = Locked::open(&self.ledger) {
            let entries: Vec<Entry> = l.read().into_iter().filter(|e| !(e.state == self.state && e.pid == self.pid)).collect();
            let _ = l.write(&entries);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sc-space-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("scratch");
        d
    }

    #[test]
    fn what_other_starts_keep_counts_as_taken() {
        let d = scratch("ledger");
        let ledger = d.join("space.json");
        let want = |n: u64| move |o: Others| if o.bytes == n { Ok(()) } else { Err(format!("{o:?}")) };
        let a = reserve(&ledger, Path::new("/s/a"), 7, 100, 0, want(0)).expect("a");
        let seen = std::cell::Cell::new(Others::default());
        let b = reserve(&ledger, Path::new("/s/b"), 7, 50, 0, |o| {
            seen.set(o);
            Ok(())
        })
        .expect("b");
        assert_eq!(seen.get().bytes, 100, "b sees what a keeps");
        // Another filesystem: nothing kept there.
        reserve(&ledger, Path::new("/s/c"), 8, 10, 0, want(0)).expect("another dev");
        a.keep(30).expect("keep");
        reserve(&ledger, Path::new("/s/d"), 7, 1, 0, want(80)).expect("a now keeps 30, b 50");
        drop(b);
        // b dropped its entry, and so did d (its reservation was never held): a's 30 only.
        reserve(&ledger, Path::new("/s/e"), 7, 1, 0, want(30)).expect("a 30 only");
        // A process that is gone keeps nothing; nor does one of an earlier boot whose pid and
        // start time are this process's own (#100 second re-review: a deterministic boot order).
        let me = started(std::process::id()).expect("start time");
        let mut l = Locked::open(&ledger).expect("open");
        let mut entries = l.read();
        let old = |state: &str, pid, started, boot: &str| Entry { state: state.into(), dev: 7, bytes: 1 << 40, mem_mib: 1 << 20, pid, started, boot: boot.into() };
        entries.push(old("/s/gone", u32::MAX - 1, 1, &boot_id()));
        entries.push(old("/s/lastboot", std::process::id(), me, "an-earlier-boot"));
        l.write(&entries).expect("write");
        drop(l);
        reserve(&ledger, Path::new("/s/f"), 7, 1, 0, |o| if o.bytes == 30 && o.mem_mib == 0 { Ok(()) } else { Err(format!("{o:?}")) }).expect("neither counts");
        drop(a);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn guests_together_stay_within_the_hosts_memory() {
        let d = scratch("mem");
        let ledger = d.join("space.json");
        // Two sites that each fit alone (6 GiB of an 8 GiB budget) and not together; on two
        // filesystems, since memory is the host's.
        let budget = 8 << 10;
        let fits = |mine: u64| move |o: Others| if o.mem_mib + mine <= budget { Ok(()) } else { Err(format!("{} MiB already", o.mem_mib)) };
        let a = reserve(&ledger, Path::new("/s/a"), 7, 1, 6 << 10, fits(6 << 10)).expect("the first fits");
        let e = reserve(&ledger, Path::new("/s/b"), 8, 1, 6 << 10, fits(6 << 10)).expect_err("the second doesn't");
        assert!(e.contains("6144 MiB already"), "{e}");
        drop(a);
        reserve(&ledger, Path::new("/s/b"), 8, 1, 6 << 10, fits(6 << 10)).expect("once the first stops, it does");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn two_starts_at_once_never_both_pass_on_the_same_space() {
        let d = scratch("race");
        let ledger = d.join("space.json");
        // 1000 free, each needs 600: one of the two may keep it. The check takes its time, as a
        // real start's statvfs and sums do, so without the lock both would pass.
        let free = 1000u64;
        let go = Arc::new(Barrier::new(2));
        let runs: Vec<_> = ["/s/one", "/s/two"]
            .into_iter()
            .map(|s| {
                let (ledger, go) = (ledger.clone(), go.clone());
                std::thread::spawn(move || {
                    go.wait();
                    reserve(&ledger, Path::new(s), 7, 600, 0, |others| {
                        std::thread::sleep(Duration::from_millis(200));
                        if 600 + others.bytes <= free { Ok(()) } else { Err("no room".to_owned()) }
                    })
                })
            })
            .collect();
        let results: Vec<_> = runs.into_iter().map(|r| r.join().expect("thread")).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1, "{results:?}");
        drop(results);
        let _ = fs::remove_dir_all(&d);
    }
}
