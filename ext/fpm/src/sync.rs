//! The guest's writable folders, synced back to the host (addiscorp/securecore#72). Linux only.
//!
//! A `layer1.write` folder inside the app root (uploads) is its own ext4 disk in the guest, and
//! the host can't safely read an ext4 image the guest has mounted read-write. So the guest tells
//! the host what changes, and an unprivileged writer on the host applies it to the real folder,
//! the one nginx serves and backups copy:
//!
//! ```text
//!   guest  securecore-init: inotify on each writable disk ──► vsock 516 (host-initiated)
//!   host   securecore-fpm: connects to guest port 516, hands the connection to
//!          `securecore-fpm --sync-writer`: the site's pool user (never root), no network, one
//!          O_PATH handle per folder, every path opened beneath it (openat2 RESOLVE_BENEATH, no
//!          symlink, no `..`)
//! ```
//!
//! **The guest's disk is the authority, the host folder its mirror.** On every connection the
//! guest first lists its whole tree ([`Op::Entry`] … [`Op::ListEnd`]); the host removes what the
//! guest doesn't have, makes the folders it lacks, and asks for each file whose size or mtime
//! differs ([`Reply::Need`]). Then the guest streams its changes as they happen: a file when it
//! is closed after writing, folders, deletes, renames and modes.
//!
//! **No committed upload is lost to a crash.** The guest fsyncs a file before it sends it, so
//! what reaches the host is already durable on the guest's disk. The host writes into a nameless
//! file (O_TMPFILE), fsyncs it and renames it into place, so a crash in the middle leaves the old
//! file or the new one, never a part. A connection that ends (a crash on either side) starts the
//! next one with the full listing, which sends whatever didn't arrive.
//!
//! **What the guest can do to the host** is what it can do to its own disk: create, replace and
//! remove entries inside the folders, within caps. Paths are relative and plain (no `.`, `..`,
//! empty or over-long names; [`check_path`]); a symlink or anything but a file or folder on the
//! host is never followed or written through (it is replaced, as the guest's tree says);
//! a folder's files never total more than its cap (its disk's size); bytes and operations are
//! rate-limited ([`Limits`]). The port is below 1024, so only the guest's root can listen on it,
//! and the host connects to it: no guest process can open a connection to the writer.

use std::collections::{BTreeMap, HashMap};
use std::ffi::{CStr, CString};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::jail::{BENEATH, openat2_raw};

/// The guest port the sync listens on. Below 1024: only the guest's root may bind it.
pub const SYNC_PORT: u32 = 516;
/// The longest relative path, the longest name in it, and the deepest nesting.
pub const MAX_PATH: usize = 4096;
pub const MAX_NAME: usize = 255;
pub const MAX_DEPTH: usize = 64;
/// The most entries one listing may hold.
pub const MAX_ENTRIES: usize = 1 << 20;
/// The longest error message in a reply.
const MAX_MESSAGE: usize = 1024;
/// The guest disk's own folder, never synced.
const LOST_FOUND: &str = "lost+found";

/// A file's modification time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Time {
    pub secs: i64,
    pub nanos: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
}

/// One message from the guest. `disk` is the writable folder's index, in the order of the start
/// message's mounts; every path is relative to that folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// A file's whole content follows: `size` bytes, then one byte, 1 to commit it or 0 to drop
    /// it (it changed while it was read; a later event sends it again).
    Put { disk: u8, path: String, mode: u32, mtime: Time, size: u64 },
    Mkdir { disk: u8, path: String, mode: u32 },
    Remove { disk: u8, path: String },
    Rename { disk: u8, from: String, to: String },
    Chmod { disk: u8, path: String, mode: u32 },
    /// One entry of the guest's tree. No reply; [`Op::ListEnd`] ends the listing.
    Entry { disk: u8, path: String, kind: Kind, size: u64, mode: u32, mtime: Time },
    /// The host replies with a [`Reply::Need`] for each file it wants, then [`Reply::Ok`].
    ListEnd,
}

/// The host's answer to an op (none to an [`Op::Entry`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Ok,
    /// Send this path whole (a listed file the host lacks, or a rename whose source it lacks).
    Need { disk: u8, path: String },
    Err(String),
}

/// A plain relative path: non-empty, `/`-separated names that are neither empty, `.` nor `..`,
/// no NUL, each at most [`MAX_NAME`] bytes, at most [`MAX_DEPTH`] deep and [`MAX_PATH`] long.
pub fn check_path(p: &str) -> Result<(), String> {
    if p.is_empty() || p.len() > MAX_PATH {
        return Err(format!("a path of {} bytes (1 to {MAX_PATH})", p.len()));
    }
    let mut depth = 0;
    for name in p.split('/') {
        depth += 1;
        if name.is_empty() || name == "." || name == ".." || name.len() > MAX_NAME || name.contains('\0') {
            return Err(format!("{p:?} is not a plain relative path"));
        }
    }
    if depth > MAX_DEPTH {
        return Err(format!("{p:?} is more than {MAX_DEPTH} folders deep"));
    }
    Ok(())
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn put_time(out: &mut Vec<u8>, t: Time) {
    out.extend_from_slice(&t.secs.to_be_bytes());
    out.extend_from_slice(&t.nanos.to_be_bytes());
}

fn read_n<const N: usize>(r: &mut impl Read) -> io::Result<[u8; N]> {
    let mut b = [0u8; N];
    r.read_exact(&mut b)?;
    Ok(b)
}

fn read_u8(r: &mut impl Read) -> io::Result<u8> {
    Ok(read_n::<1>(r)?[0])
}

fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    Ok(u32::from_be_bytes(read_n(r)?))
}

fn read_u64(r: &mut impl Read) -> io::Result<u64> {
    Ok(u64::from_be_bytes(read_n(r)?))
}

fn read_time(r: &mut impl Read) -> io::Result<Time> {
    let secs = i64::from_be_bytes(read_n(r)?);
    let nanos = read_u32(r)?;
    if nanos >= 1_000_000_000 {
        return Err(bad(format!("{nanos} nanoseconds")));
    }
    Ok(Time { secs, nanos })
}

fn read_string(r: &mut impl Read, max: usize) -> io::Result<String> {
    let len = usize::from(u16::from_be_bytes(read_n(r)?));
    if len > max {
        return Err(bad(format!("a string of {len} bytes (at most {max})")));
    }
    let mut b = vec![0u8; len];
    r.read_exact(&mut b)?;
    String::from_utf8(b).map_err(|_| bad("a string that isn't UTF-8"))
}

fn read_path(r: &mut impl Read) -> io::Result<String> {
    let p = read_string(r, MAX_PATH)?;
    check_path(&p).map_err(bad)?;
    Ok(p)
}

impl Op {
    /// The op's bytes (a [`Op::Put`]'s content and commit byte follow them).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        match self {
            Op::Put { disk, path, mode, mtime, size } => {
                out.extend([1, *disk]);
                put_str(&mut out, path);
                out.extend_from_slice(&mode.to_be_bytes());
                put_time(&mut out, *mtime);
                out.extend_from_slice(&size.to_be_bytes());
            }
            Op::Mkdir { disk, path, mode } => {
                out.extend([2, *disk]);
                put_str(&mut out, path);
                out.extend_from_slice(&mode.to_be_bytes());
            }
            Op::Remove { disk, path } => {
                out.extend([3, *disk]);
                put_str(&mut out, path);
            }
            Op::Rename { disk, from, to } => {
                out.extend([4, *disk]);
                put_str(&mut out, from);
                put_str(&mut out, to);
            }
            Op::Chmod { disk, path, mode } => {
                out.extend([5, *disk]);
                put_str(&mut out, path);
                out.extend_from_slice(&mode.to_be_bytes());
            }
            Op::Entry { disk, path, kind, size, mode, mtime } => {
                out.extend([6, *disk]);
                put_str(&mut out, path);
                out.push(match kind {
                    Kind::File => 0,
                    Kind::Dir => 1,
                });
                out.extend_from_slice(&size.to_be_bytes());
                out.extend_from_slice(&mode.to_be_bytes());
                put_time(&mut out, *mtime);
            }
            Op::ListEnd => out.push(7),
        }
        out
    }

    /// The next op, `None` at a clean end of the stream. Anything malformed (an unknown tag, a
    /// path that isn't plain) is `InvalidData`.
    pub fn read(r: &mut impl Read) -> io::Result<Option<Op>> {
        let mut tag = [0u8; 1];
        if r.read(&mut tag)? == 0 {
            return Ok(None);
        }
        if tag[0] == 7 {
            return Ok(Some(Op::ListEnd));
        }
        let disk = read_u8(r)?;
        Ok(Some(match tag[0] {
            1 => Op::Put { disk, path: read_path(r)?, mode: read_u32(r)?, mtime: read_time(r)?, size: read_u64(r)? },
            2 => Op::Mkdir { disk, path: read_path(r)?, mode: read_u32(r)? },
            3 => Op::Remove { disk, path: read_path(r)? },
            4 => Op::Rename { disk, from: read_path(r)?, to: read_path(r)? },
            5 => Op::Chmod { disk, path: read_path(r)?, mode: read_u32(r)? },
            6 => {
                let path = read_path(r)?;
                let kind = match read_u8(r)? {
                    0 => Kind::File,
                    1 => Kind::Dir,
                    k => return Err(bad(format!("entry kind {k}"))),
                };
                Op::Entry { disk, path, kind, size: read_u64(r)?, mode: read_u32(r)?, mtime: read_time(r)? }
            }
            t => return Err(bad(format!("unknown op {t}"))),
        }))
    }
}

impl Reply {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Reply::Ok => out.push(0),
            Reply::Need { disk, path } => {
                out.extend([1, *disk]);
                put_str(&mut out, path);
            }
            Reply::Err(msg) => {
                out.push(2);
                let mut end = msg.len().min(MAX_MESSAGE);
                while !msg.is_char_boundary(end) {
                    end -= 1;
                }
                put_str(&mut out, &msg[..end]);
            }
        }
        out
    }

    pub fn read(r: &mut impl Read) -> io::Result<Reply> {
        Ok(match read_u8(r)? {
            0 => Reply::Ok,
            1 => Reply::Need { disk: read_u8(r)?, path: read_path(r)? },
            2 => Reply::Err(read_string(r, MAX_MESSAGE)?),
            t => return Err(bad(format!("unknown reply {t}"))),
        })
    }
}

// --- files beneath a folder handle, shared by both sides --------------------------------------

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| bad("a NUL in a path"))
}

/// `rel` (a plain path, or "" for the folder itself) opened beneath `dir` with `flags`: no
/// symlink anywhere, no `..`, never out of `dir`.
fn open_beneath(dir: RawFd, rel: &str, flags: libc::c_int) -> io::Result<OwnedFd> {
    let p = if rel.is_empty() { c".".to_owned() } else { cstr(rel)? };
    let fd = openat2_raw(dir, &p, flags | libc::O_NOFOLLOW, BENEATH);
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat2(2) just returned this fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

const DIR_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY;

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: fstat(2) fills the zeroed struct passed.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        cvt(libc::fstat(fd, &mut st))?;
        Ok(st)
    }
}

/// The entry `name` in `dir`, not followed.
fn stat_at(dir: RawFd, name: &CStr) -> io::Result<libc::stat> {
    // SAFETY: fstatat(2) fills the zeroed struct passed; AT_SYMLINK_NOFOLLOW never follows.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        cvt(libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW))?;
        Ok(st)
    }
}

fn kind_of(st: &libc::stat) -> Option<Kind> {
    match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => Some(Kind::File),
        libc::S_IFDIR => Some(Kind::Dir),
        _ => None,
    }
}

fn mtime_of(st: &libc::stat) -> Time {
    Time { secs: st.st_mtime, nanos: st.st_mtime_nsec as u32 }
}

/// The names in the folder `dir` (without `.` and `..`).
fn list_dir(dir: RawFd) -> io::Result<Vec<CString>> {
    // SAFETY: a dup of `dir` handed to fdopendir(3), which owns it until closedir(3); readdir's
    // entries are copied out before the next call.
    unsafe {
        let fd = cvt(libc::fcntl(dir, libc::F_DUPFD_CLOEXEC, 0))?;
        libc::lseek(fd, 0, libc::SEEK_SET);
        let d = libc::fdopendir(fd);
        if d.is_null() {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        let mut out = Vec::new();
        loop {
            *libc::__errno_location() = 0;
            let e = libc::readdir(d);
            if e.is_null() {
                let errno = *libc::__errno_location();
                libc::closedir(d);
                if errno != 0 {
                    return Err(io::Error::from_raw_os_error(errno));
                }
                return Ok(out);
            }
            let name = CStr::from_ptr((*e).d_name.as_ptr());
            if name != c"." && name != c".." {
                out.push(name.to_owned());
            }
        }
    }
}

fn split(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() { name.to_owned() } else { format!("{dir}/{name}") }
}

/// Removes `name` from `dir`, a folder with everything in it; the bytes of the files removed.
/// Nothing is followed: a link is removed as itself. Missing: 0.
fn remove_entry(dir: RawFd, name: &CStr, depth: usize) -> io::Result<u64> {
    let st = match stat_at(dir, name) {
        Ok(st) => st,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(0),
        Err(e) => return Err(e),
    };
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        // SAFETY: unlinkat(2) of a name in a folder we hold.
        cvt(unsafe { libc::unlinkat(dir, name.as_ptr(), 0) })?;
        return Ok(if st.st_mode & libc::S_IFMT == libc::S_IFREG { st.st_size as u64 } else { 0 });
    }
    if depth > 4 * MAX_DEPTH {
        return Err(bad("a folder nested too deep to remove"));
    }
    let name_s = name.to_str().map_err(|_| bad("a name that isn't UTF-8"))?;
    let sub = open_beneath(dir, name_s, DIR_FLAGS)?;
    let mut freed = 0;
    for n in list_dir(sub.as_raw_fd())? {
        freed += remove_entry(sub.as_raw_fd(), &n, depth + 1)?;
    }
    drop(sub);
    // SAFETY: as above, for the now empty folder.
    cvt(unsafe { libc::unlinkat(dir, name.as_ptr(), libc::AT_REMOVEDIR) })?;
    Ok(freed)
}

/// [`remove_entry`] for a name that isn't UTF-8 (found on the host, never sent by the guest).
fn remove_raw(dir: RawFd, name: &CStr) -> io::Result<u64> {
    let st = stat_at(dir, name)?;
    if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
        // Its own folder can't be opened by a UTF-8 name: rename it to one first.
        let tmp = cstr(&format!(".sc-sync-rm-{}", std::process::id()))?;
        // SAFETY: renameat(2) within one folder we hold.
        cvt(unsafe { libc::renameat(dir, name.as_ptr(), dir, tmp.as_ptr()) })?;
        return remove_entry(dir, &tmp, 0);
    }
    remove_entry(dir, name, 0)
}

fn fsync(fd: RawFd) -> io::Result<()> {
    // SAFETY: fsync(2) on an fd we hold.
    cvt(unsafe { libc::fsync(fd) }).map(|_| ())
}

fn fchmod(fd: RawFd, mode: u32) -> io::Result<()> {
    // SAFETY: fchmod(2) on an fd we hold. Only the permission bits: never setuid, setgid or sticky.
    cvt(unsafe { libc::fchmod(fd, mode & 0o777) }).map(|_| ())
}

// --- the host's writer --------------------------------------------------------------------------

/// Rate caps for one writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub bytes_per_sec: u64,
    pub ops_per_sec: u64,
}

impl Limits {
    /// 256 MiB/s of file content and 2000 operations a second, each with one second of burst.
    pub const DEFAULT: Limits = Limits { bytes_per_sec: 256 << 20, ops_per_sec: 2000 };
}

/// A token bucket: `take` sleeps once the second's burst is spent.
struct Bucket {
    rate: f64,
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn new(rate: u64) -> Bucket {
        let rate = rate.max(1) as f64;
        Bucket { rate, tokens: rate, at: Instant::now() }
    }

    fn take(&mut self, n: u64) {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * self.rate).min(self.rate);
        self.at = now;
        self.tokens -= n as f64;
        if self.tokens < 0.0 {
            thread::sleep(Duration::from_secs_f64(-self.tokens / self.rate));
        }
    }
}

/// One host folder the writer mirrors into: a handle on it and the most its files may total.
pub struct Folder {
    pub dir: OwnedFd,
    pub cap: u64,
}

struct Mirror {
    dir: OwnedFd,
    cap: u64,
    used: u64,
}

/// A guest entry, as listed.
#[derive(Debug, Clone, Copy)]
struct Listed {
    kind: Kind,
    size: u64,
    mode: u32,
    mtime: Time,
}

/// Applies a guest's ops to the host folders. Runs as the site's pool user ([`writer_main`]).
pub struct Writer {
    folders: Vec<Mirror>,
    bytes: Bucket,
    ops: Bucket,
    listing: HashMap<(u8, String), Listed>,
    seq: u64,
    /// Log lines left before the writer goes quiet (the paths come from the guest).
    log_left: u32,
}

/// Why a connection ends: the guest broke the protocol or a cap (refused, then closed).
fn refuse(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

impl Writer {
    pub fn new(folders: Vec<Folder>, limits: Limits) -> io::Result<Writer> {
        let mut w = Writer {
            folders: Vec::new(),
            bytes: Bucket::new(limits.bytes_per_sec),
            ops: Bucket::new(limits.ops_per_sec),
            listing: HashMap::new(),
            seq: 0,
            log_left: 200,
        };
        for f in folders {
            let st = fstat(f.dir.as_raw_fd())?;
            if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
                return Err(bad("a sync folder that isn't a folder"));
            }
            w.folders.push(Mirror { dir: f.dir, cap: f.cap, used: 0 });
        }
        for i in 0..w.folders.len() {
            w.folders[i].used = w.measure(i)?;
        }
        Ok(w)
    }

    fn log(&mut self, msg: &str) {
        if self.log_left > 0 {
            self.log_left -= 1;
            eprintln!("securecore-fpm: sync: {msg}{}", if self.log_left == 0 { " (further sync errors are not logged)" } else { "" });
        }
    }

    /// The bytes of the files in folder `i` now.
    fn measure(&mut self, i: usize) -> io::Result<u64> {
        let mut used = 0;
        self.walk(i, &mut |_, k, st| {
            if k == Some(Kind::File) {
                used += st.st_size as u64;
            }
        })?;
        Ok(used)
    }

    fn mirror(&self, disk: u8) -> io::Result<usize> {
        let i = usize::from(disk);
        if i >= self.folders.len() {
            return Err(refuse(format!("disk {disk}: there are {} sync folders", self.folders.len())));
        }
        Ok(i)
    }

    /// The folder `rel` in folder `i`, made (as the guest's tree says it is) when `create`: a
    /// missing folder is made, and a file or link where a folder belongs is replaced by one.
    fn open_dir(&mut self, i: usize, rel: &str, create: bool) -> io::Result<OwnedFd> {
        let mut cur = open_beneath(self.folders[i].dir.as_raw_fd(), "", DIR_FLAGS)?;
        if !create {
            return if rel.is_empty() { Ok(cur) } else { open_beneath(cur.as_raw_fd(), rel, DIR_FLAGS) };
        }
        for name in rel.split('/').filter(|n| !n.is_empty()) {
            let c = cstr(name)?;
            let next = match open_beneath(cur.as_raw_fd(), name, DIR_FLAGS) {
                Ok(fd) => fd,
                Err(e) => {
                    match e.raw_os_error() {
                        Some(libc::ENOENT) => {}
                        Some(libc::ENOTDIR | libc::ELOOP) => {
                            let freed = remove_entry(cur.as_raw_fd(), &c, 0)?;
                            self.folders[i].used = self.folders[i].used.saturating_sub(freed);
                        }
                        _ => return Err(e),
                    }
                    // SAFETY: mkdirat(2) of a plain name in a folder we hold.
                    if unsafe { libc::mkdirat(cur.as_raw_fd(), c.as_ptr(), 0o755) } < 0 {
                        let e = io::Error::last_os_error();
                        if e.raw_os_error() != Some(libc::EEXIST) {
                            return Err(e);
                        }
                    }
                    open_beneath(cur.as_raw_fd(), name, DIR_FLAGS)?
                }
            };
            cur = next;
        }
        Ok(cur)
    }

    /// Every entry of folder `i`, parents first: its path ("" never), its kind (`None`: neither
    /// file nor folder) and its stat. Names that aren't UTF-8 are passed with a lossy path and
    /// can't be in the guest's listing.
    fn walk(&mut self, i: usize, f: &mut dyn FnMut(&str, Option<Kind>, &libc::stat)) -> io::Result<()> {
        let root = open_beneath(self.folders[i].dir.as_raw_fd(), "", DIR_FLAGS)?;
        let mut stack = vec![(root, String::new(), 0usize)];
        while let Some((dir, rel, depth)) = stack.pop() {
            let mut names = list_dir(dir.as_raw_fd())?;
            names.sort();
            for n in names {
                let Ok(st) = stat_at(dir.as_raw_fd(), &n) else { continue };
                let name = n.to_string_lossy();
                let path = join(&rel, &name);
                let kind = kind_of(&st);
                f(&path, kind, &st);
                if kind == Some(Kind::Dir) && depth < MAX_DEPTH && n.to_str().is_ok() {
                    match open_beneath(dir.as_raw_fd(), &name, DIR_FLAGS) {
                        Ok(sub) => stack.push((sub, path, depth + 1)),
                        Err(e) => self.log(&format!("listing {path:?}: {e}")),
                    }
                }
            }
        }
        Ok(())
    }

    /// Serves one guest connection until it ends. `Ok` at a clean end; `Err` when the guest broke
    /// the protocol or a cap (it is told why first) or the connection failed.
    pub fn serve(&mut self, r: &mut impl Read, w: &mut impl Write) -> io::Result<()> {
        loop {
            let op = match Op::read(r) {
                Ok(Some(op)) => op,
                Ok(None) => return Ok(()),
                Err(e) => {
                    if e.kind() == io::ErrorKind::InvalidData {
                        let _ = w.write_all(&Reply::Err(e.to_string()).encode());
                        let _ = w.flush();
                    }
                    return Err(e);
                }
            };
            self.ops.take(1);
            let reply = match self.apply(op, r, w) {
                Ok(Some(reply)) => reply,
                Ok(None) => continue,
                Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                    let _ = w.write_all(&Reply::Err(e.to_string()).encode());
                    let _ = w.flush();
                    return Err(e);
                }
                Err(e) => return Err(e),
            };
            w.write_all(&reply.encode())?;
            w.flush()?;
        }
    }

    /// One op. `Ok(None)`: no reply (a listing entry). A filesystem error on one path is that
    /// op's `Reply::Err`; `InvalidData` ends the connection.
    fn apply(&mut self, op: Op, r: &mut impl Read, w: &mut impl Write) -> io::Result<Option<Reply>> {
        let fs_err = |what: &str, path: &str, e: io::Error| -> io::Result<Option<Reply>> {
            if e.kind() == io::ErrorKind::InvalidData || e.kind() == io::ErrorKind::UnexpectedEof {
                return Err(e);
            }
            Ok(Some(Reply::Err(format!("{what} {path:?}: {e}"))))
        };
        match op {
            Op::Put { disk, path, mode, mtime, size } => {
                let i = self.mirror(disk)?;
                match self.put(i, &path, mode, mtime, size, r) {
                    Ok(()) => Ok(Some(Reply::Ok)),
                    Err(e) => {
                        let reply = fs_err("put", &path, e)?;
                        if let Some(Reply::Err(m)) = &reply {
                            self.log(m);
                        }
                        Ok(reply)
                    }
                }
            }
            Op::Mkdir { disk, path, mode } => {
                let i = self.mirror(disk)?;
                match self.open_dir(i, &path, true).and_then(|d| fchmod(d.as_raw_fd(), mode)) {
                    Ok(()) => Ok(Some(Reply::Ok)),
                    Err(e) => fs_err("mkdir", &path, e),
                }
            }
            Op::Remove { disk, path } => {
                let i = self.mirror(disk)?;
                match self.remove(i, &path) {
                    Ok(()) => Ok(Some(Reply::Ok)),
                    Err(e) => fs_err("remove", &path, e),
                }
            }
            Op::Rename { disk, from, to } => {
                let i = self.mirror(disk)?;
                match self.rename(i, &from, &to) {
                    Ok(true) => Ok(Some(Reply::Ok)),
                    Ok(false) => Ok(Some(Reply::Need { disk, path: to })),
                    Err(e) => fs_err("rename", &from, e),
                }
            }
            Op::Chmod { disk, path, mode } => {
                let i = self.mirror(disk)?;
                match self.chmod(i, &path, mode) {
                    Ok(()) => Ok(Some(Reply::Ok)),
                    Err(e) => fs_err("chmod", &path, e),
                }
            }
            Op::Entry { disk, path, kind, size, mode, mtime } => {
                self.mirror(disk)?;
                if self.listing.len() >= MAX_ENTRIES {
                    return Err(refuse(format!("a listing of more than {MAX_ENTRIES} entries")));
                }
                self.listing.insert((disk, path), Listed { kind, size, mode, mtime });
                Ok(None)
            }
            Op::ListEnd => {
                let listing = std::mem::take(&mut self.listing);
                let t = Instant::now();
                let mut needs = Vec::new();
                for i in 0..self.folders.len() {
                    let (n, removed) = self.reconcile(i, &listing)?;
                    eprintln!(
                        "securecore-fpm: sync: folder {i} reconciled in {:.0} ms: {} listed, {} to send, {removed} removed",
                        t.elapsed().as_secs_f64() * 1000.0,
                        listing.keys().filter(|(d, _)| usize::from(*d) == i).count(),
                        n.len()
                    );
                    needs.extend(n.into_iter().map(|p| (i as u8, p)));
                }
                for (disk, path) in needs {
                    w.write_all(&Reply::Need { disk, path }.encode())?;
                }
                Ok(Some(Reply::Ok))
            }
        }
    }

    /// A nameless file in `dir` (O_TMPFILE), or a named one where the filesystem has none.
    fn tmpfile(&mut self, dir: RawFd) -> io::Result<(OwnedFd, Option<CString>)> {
        // SAFETY: openat(2) with a constant path and the mode for O_TMPFILE.
        let fd = unsafe { libc::openat(dir, c".".as_ptr(), libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC, 0o600) };
        if fd >= 0 {
            // SAFETY: openat(2) just returned it.
            return Ok((unsafe { OwnedFd::from_raw_fd(fd) }, None));
        }
        let e = io::Error::last_os_error();
        if !matches!(e.raw_os_error(), Some(libc::EOPNOTSUPP | libc::EISDIR | libc::EINVAL)) {
            return Err(e);
        }
        self.seq += 1;
        let name = cstr(&format!(".sc-sync-{}-{}", std::process::id(), self.seq))?;
        let flags = libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: as above, a new plain name in a folder we hold.
        let fd = cvt(unsafe { libc::openat(dir, name.as_ptr(), flags, 0o600) })?;
        // SAFETY: as above.
        Ok((unsafe { OwnedFd::from_raw_fd(fd) }, Some(name)))
    }

    fn put(&mut self, i: usize, path: &str, mode: u32, mtime: Time, size: u64, r: &mut impl Read) -> io::Result<()> {
        let cap = self.folders[i].cap;
        if size > cap {
            return Err(refuse(format!("{path:?} is {size} bytes, more than its folder's cap of {cap}")));
        }
        let (parent, name) = split(path);
        let c = cstr(name)?;
        let dir = match self.open_dir(i, parent, true) {
            Ok(d) => d,
            Err(e) => {
                skip(r, size + 1)?;
                return Err(e);
            }
        };
        let old = stat_at(dir.as_raw_fd(), &c).ok().filter(|st| kind_of(st) == Some(Kind::File)).map_or(0, |st| st.st_size as u64);
        let used = self.folders[i].used.saturating_sub(old);
        if used + size > cap {
            return Err(refuse(format!("{path:?} ({size} bytes) would take its folder past its cap of {cap} bytes ({used} used)")));
        }
        let (tmp, named) = match self.tmpfile(dir.as_raw_fd()) {
            Ok(t) => t,
            Err(e) => {
                skip(r, size + 1)?;
                return Err(e);
            }
        };
        let unlink_named = |named: &Option<CString>| {
            if let Some(n) = named {
                // SAFETY: unlinkat(2) of the temporary name we made.
                unsafe { libc::unlinkat(dir.as_raw_fd(), n.as_ptr(), 0) };
            }
        };
        let mut out = std::fs::File::from(tmp);
        let mut left = size;
        let mut buf = vec![0u8; 256 << 10];
        let mut write_err = None;
        while left > 0 {
            let want = (buf.len() as u64).min(left) as usize;
            let n = match r.read(&mut buf[..want]) {
                Ok(0) => {
                    unlink_named(&named);
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the connection ended in a file"));
                }
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    unlink_named(&named);
                    return Err(e);
                }
            };
            self.bytes.take(n as u64);
            if write_err.is_none()
                && let Err(e) = out.write_all(&buf[..n])
            {
                write_err = Some(e);
            }
            left -= n as u64;
        }
        let commit = read_u8(r)? == 1;
        if let Some(e) = write_err {
            unlink_named(&named);
            return Err(e);
        }
        if !commit {
            unlink_named(&named);
            return Ok(());
        }
        let fd = out.as_raw_fd();
        fchmod(fd, mode)?;
        let times = [
            libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT },
            libc::timespec { tv_sec: mtime.secs as libc::time_t, tv_nsec: mtime.nanos as libc::c_long },
        ];
        // SAFETY: futimens(2) reads the two timespecs.
        cvt(unsafe { libc::futimens(fd, times.as_ptr()) })?;
        fsync(fd)?;
        let tmp_name = match named {
            Some(n) => n,
            None => {
                self.seq += 1;
                let n = cstr(&format!(".sc-sync-{}-{}", std::process::id(), self.seq))?;
                let via = cstr(&format!("/proc/self/fd/{fd}"))?;
                // SAFETY: linkat(2) of our nameless file (through its /proc link) to a new name.
                cvt(unsafe { libc::linkat(libc::AT_FDCWD, via.as_ptr(), dir.as_raw_fd(), n.as_ptr(), libc::AT_SYMLINK_FOLLOW) })?;
                n
            }
        };
        let rename = || {
            // SAFETY: renameat(2) within one folder we hold, onto a plain name.
            cvt(unsafe { libc::renameat(dir.as_raw_fd(), tmp_name.as_ptr(), dir.as_raw_fd(), c.as_ptr()) })
        };
        if let Err(e) = rename() {
            // A folder (or anything else) where the guest now has a file: replaced.
            if !matches!(e.raw_os_error(), Some(libc::EISDIR | libc::ENOTEMPTY | libc::EEXIST)) {
                unlink_named(&Some(tmp_name.clone()));
                return Err(e);
            }
            let freed = remove_entry(dir.as_raw_fd(), &c, 0)?;
            self.folders[i].used = self.folders[i].used.saturating_sub(freed);
            if let Err(e) = rename() {
                unlink_named(&Some(tmp_name.clone()));
                return Err(e);
            }
        }
        fsync(dir.as_raw_fd())?;
        self.folders[i].used = used + size;
        Ok(())
    }

    fn remove(&mut self, i: usize, path: &str) -> io::Result<()> {
        let (parent, name) = split(path);
        let dir = match self.open_dir(i, parent, false) {
            Ok(d) => d,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)) => return Ok(()),
            Err(e) => return Err(e),
        };
        let freed = remove_entry(dir.as_raw_fd(), &cstr(name)?, 0)?;
        self.folders[i].used = self.folders[i].used.saturating_sub(freed);
        fsync(dir.as_raw_fd())
    }

    /// `false`: the host has no `from` (the guest then sends `to` whole).
    fn rename(&mut self, i: usize, from: &str, to: &str) -> io::Result<bool> {
        let ((fp, fname), (tp, tname)) = (split(from), split(to));
        let src = match self.open_dir(i, fp, false) {
            Ok(d) => d,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)) => return Ok(false),
            Err(e) => return Err(e),
        };
        let (fc, tc) = (cstr(fname)?, cstr(tname)?);
        let Ok(st) = stat_at(src.as_raw_fd(), &fc) else { return Ok(false) };
        if kind_of(&st).is_none() {
            return Ok(false);
        }
        let dst = self.open_dir(i, tp, true)?;
        let rename = || {
            // SAFETY: renameat(2) between two folders we hold, plain names.
            cvt(unsafe { libc::renameat(src.as_raw_fd(), fc.as_ptr(), dst.as_raw_fd(), tc.as_ptr()) })
        };
        let replaced = stat_at(dst.as_raw_fd(), &tc).ok().filter(|s| kind_of(s) == Some(Kind::File)).map_or(0, |s| s.st_size as u64);
        if let Err(e) = rename() {
            if !matches!(e.raw_os_error(), Some(libc::EISDIR | libc::ENOTEMPTY | libc::EEXIST | libc::ENOTDIR)) {
                return Err(e);
            }
            let freed = remove_entry(dst.as_raw_fd(), &tc, 0)?;
            self.folders[i].used = self.folders[i].used.saturating_sub(freed);
            rename()?;
        } else {
            self.folders[i].used = self.folders[i].used.saturating_sub(replaced);
        }
        fsync(dst.as_raw_fd())?;
        fsync(src.as_raw_fd())?;
        Ok(true)
    }

    fn chmod(&mut self, i: usize, path: &str, mode: u32) -> io::Result<()> {
        let fd = match open_beneath(self.folders[i].dir.as_raw_fd(), path, libc::O_RDONLY | libc::O_NONBLOCK) {
            Ok(fd) => fd,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)) => return Ok(()),
            Err(e) => return Err(e),
        };
        if kind_of(&fstat(fd.as_raw_fd())?).is_none() {
            return Ok(());
        }
        fchmod(fd.as_raw_fd(), mode)
    }

    /// Folder `i` against the guest's listing: what the guest doesn't have (or has as another
    /// kind) is removed, its folders are made, and its files that differ in size or mtime are
    /// returned to be sent. The removed count is returned too.
    fn reconcile(&mut self, i: usize, listing: &HashMap<(u8, String), Listed>) -> io::Result<(Vec<String>, usize)> {
        let guest: BTreeMap<&str, &Listed> = listing.iter().filter(|((d, _), _)| usize::from(*d) == i).map(|((_, p), l)| (p.as_str(), l)).collect();
        let mut host: BTreeMap<String, Listed> = BTreeMap::new();
        let mut odd: Vec<String> = Vec::new();
        self.walk(i, &mut |path, kind, st| match kind {
            Some(kind) if !path.contains('\u{fffd}') => {
                host.insert(path.to_owned(), Listed { kind, size: st.st_size as u64, mode: st.st_mode & 0o777, mtime: mtime_of(st) });
            }
            _ => odd.push(path.to_owned()),
        })?;
        let mut removed = 0;
        // Links, devices, sockets and names that aren't UTF-8: never in the guest's tree.
        for path in odd {
            let (parent, name) = split(&path);
            if let Ok(dir) = self.open_dir(i, parent, false) {
                let raw = list_dir(dir.as_raw_fd())?.into_iter().find(|n| n.to_string_lossy() == name);
                if let Some(raw) = raw
                    && remove_raw(dir.as_raw_fd(), &raw).is_ok()
                {
                    removed += 1;
                }
            }
        }
        let mut gone: Vec<String> = Vec::new();
        for (path, h) in &host {
            if gone.iter().any(|g| path.starts_with(g.as_str())) {
                continue;
            }
            if guest.get(path.as_str()).is_some_and(|g| g.kind == h.kind) {
                continue;
            }
            match self.remove(i, path) {
                Ok(()) => removed += 1,
                Err(e) => self.log(&format!("removing {path:?}: {e}")),
            }
            if h.kind == Kind::Dir {
                gone.push(format!("{path}/"));
            }
        }
        let mut needs = Vec::new();
        for (path, g) in guest {
            let h = host.get(path).filter(|h| h.kind == g.kind && !gone.iter().any(|x| path.starts_with(x.as_str())));
            match g.kind {
                Kind::Dir => {
                    if h.is_none_or(|h| h.mode != g.mode & 0o777)
                        && let Err(e) = self.open_dir(i, path, true).and_then(|d| fchmod(d.as_raw_fd(), g.mode))
                    {
                        self.log(&format!("mkdir {path:?}: {e}"));
                    }
                }
                Kind::File => match h {
                    Some(h) if h.size == g.size && h.mtime == g.mtime => {
                        if h.mode != g.mode & 0o777
                            && let Err(e) = self.chmod(i, path, g.mode)
                        {
                            self.log(&format!("chmod {path:?}: {e}"));
                        }
                    }
                    _ => needs.push(path.to_owned()),
                },
            }
        }
        self.folders[i].used = self.measure(i)?;
        Ok((needs, removed))
    }
}

fn skip(r: &mut impl Read, n: u64) -> io::Result<()> {
    let copied = io::copy(&mut r.take(n), &mut io::sink())?;
    if copied < n {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the connection ended in a file"));
    }
    Ok(())
}

/// The first fd of the folders `securecore-fpm --sync-writer` gets (3, 4, …).
pub const WRITER_FIRST_FD: RawFd = 3;

/// `securecore-fpm --sync-writer <cap>[,<cap>…]`: the connection on fd 0, one folder handle per
/// cap from fd 3 on. Refuses to run as root. Returns the exit code.
pub fn writer_main(caps: &str) -> u8 {
    // SAFETY: geteuid(2) can't fail.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("securecore-fpm: sync: the writer never runs as root; refusing");
        return 125;
    }
    let caps: Vec<u64> = match caps.split(',').map(str::parse).collect() {
        Ok(c) => c,
        Err(_) => {
            eprintln!("securecore-fpm: sync: --sync-writer {caps:?}: want <bytes>[,<bytes>…]");
            return 2;
        }
    };
    let folders = caps
        .iter()
        .enumerate()
        // SAFETY: the launcher put one folder handle at each of these fds before exec.
        .map(|(n, &cap)| Folder { dir: unsafe { OwnedFd::from_raw_fd(WRITER_FIRST_FD + n as RawFd) }, cap })
        .collect();
    let mut writer = match Writer::new(folders, Limits::DEFAULT) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("securecore-fpm: sync: the folders: {e}");
            return 1;
        }
    };
    // SAFETY: fd 0 is the connection the launcher handed over.
    let conn = unsafe { std::os::unix::net::UnixStream::from_raw_fd(0) };
    let Ok(r) = conn.try_clone() else { return 1 };
    let mut r = BufReader::with_capacity(256 << 10, r);
    let mut w = BufWriter::new(conn);
    match writer.serve(&mut r, &mut w) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("securecore-fpm: sync: the connection ended: {e}");
            1
        }
    }
}

// --- the guest's side -----------------------------------------------------------------------------

/// The guest's sync, waited on by a `sync` control line: whether a host connection is up, and
/// how far the queue has been drained.
pub struct Drain {
    state: Mutex<(bool, u64, u64)>,
    cv: Condvar,
    wake: (OwnedFd, OwnedFd),
}

impl Drain {
    pub fn new() -> io::Result<Drain> {
        let mut fds = [0; 2];
        // SAFETY: pipe2(2) fills the array.
        cvt(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) })?;
        // SAFETY: both were just returned.
        let wake = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        Ok(Drain { state: Mutex::new((false, 0, 0)), cv: Condvar::new(), wake })
    }

    /// Waits until every change made before this call has reached the host and been written
    /// there, or `timeout`.
    pub fn wait(&self, timeout: Duration) -> Result<(), String> {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if !s.0 {
            return Err("no sync connection to the host".into());
        }
        s.1 += 1;
        let want = s.1;
        // SAFETY: one byte to the wake pipe (non-blocking: a full pipe already wakes it).
        unsafe { libc::write(self.wake.1.as_raw_fd(), c"w".as_ptr().cast(), 1) };
        let t = Instant::now();
        while s.2 < want {
            if !s.0 {
                return Err("the sync connection to the host ended".into());
            }
            let left = timeout.checked_sub(t.elapsed()).ok_or("the changes did not all reach the host in time")?;
            s = self.cv.wait_timeout(s, left).unwrap_or_else(|p| p.into_inner()).0;
        }
        Ok(())
    }

    fn set_connected(&self, up: bool) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        s.0 = up;
        self.cv.notify_all();
    }

    fn asked(&self) -> u64 {
        let mut b = [0u8; 64];
        // SAFETY: read(2) into our buffer, non-blocking.
        while unsafe { libc::read(self.wake.0.as_raw_fd(), b.as_mut_ptr().cast(), b.len()) } > 0 {}
        self.state.lock().unwrap_or_else(|p| p.into_inner()).1
    }

    fn done(&self, upto: u64) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        s.2 = s.2.max(upto);
        self.cv.notify_all();
    }
}

const WATCH_MASK: u32 = libc::IN_CLOSE_WRITE
    | libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_MOVED_FROM
    | libc::IN_MOVED_TO
    | libc::IN_ATTRIB
    | libc::IN_ONLYDIR
    | libc::IN_DONT_FOLLOW
    | libc::IN_EXCL_UNLINK;

struct Event {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: Option<String>,
}

/// One connection's worth of the guest's side: the disks' mount points, a handle on each, the
/// inotify watches, and the connection.
struct Guest<'a, R: Read, W: Write> {
    mounts: &'a [String],
    roots: Vec<OwnedFd>,
    ino: OwnedFd,
    wds: HashMap<i32, (u8, String)>,
    /// MOVED_FROM events still waiting for their MOVED_TO.
    moved: Vec<(u32, u8, String, bool)>,
    r: R,
    w: BufWriter<W>,
    log: &'a dyn Fn(&str),
}

/// Serves one host connection from the guest: watches every disk, sends the whole listing, then
/// every change, until the connection ends. `conn` is read from `r` and written to `w` (two
/// handles on it); `hangup` is its fd, watched for the host's close.
pub fn serve_guest<R: Read, W: Write>(mounts: &[String], r: R, w: W, hangup: RawFd, drain: &Drain, log: &dyn Fn(&str)) -> io::Result<()> {
    struct Up<'d>(&'d Drain);
    impl Drop for Up<'_> {
        fn drop(&mut self) {
            self.0.set_connected(false);
        }
    }
    // SAFETY: inotify_init1(2) with constant flags.
    let ino = cvt(unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) })?;
    // SAFETY: just returned.
    let ino = unsafe { OwnedFd::from_raw_fd(ino) };
    let mut roots = Vec::new();
    for m in mounts {
        let c = cstr(m)?;
        let fd = openat2_raw(libc::AT_FDCWD, &c, libc::O_PATH | libc::O_DIRECTORY, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: just returned.
        roots.push(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    let mut g = Guest { mounts, roots, ino, wds: HashMap::new(), moved: Vec::new(), r, w: BufWriter::with_capacity(256 << 10, w), log };
    for d in 0..mounts.len() {
        g.watch_tree(d as u8, "")?;
    }
    g.listing()?;
    drain.set_connected(true);
    let _up = Up(drain);
    let mut fds = [
        libc::pollfd { fd: g.ino.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: drain.wake.0.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: hangup, events: libc::POLLIN, revents: 0 },
    ];
    loop {
        // SAFETY: poll(2) on the three fds above.
        if unsafe { libc::poll(fds.as_mut_ptr(), 3, -1) } < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if fds[2].revents != 0 {
            return Ok(());
        }
        let asked = drain.asked();
        g.pump()?;
        drain.done(asked);
    }
}

impl<R: Read, W: Write> Guest<'_, R, W> {
    fn send(&mut self, op: &Op) -> io::Result<()> {
        self.w.write_all(&op.encode())
    }

    /// The reply to the op just sent.
    fn reply(&mut self) -> io::Result<Reply> {
        self.w.flush()?;
        Reply::read(&mut self.r)
    }

    fn ok_or_log(&mut self, what: &str) -> io::Result<Reply> {
        let reply = self.reply()?;
        if let Reply::Err(e) = &reply {
            (self.log)(&format!("the host refused {what}: {e}"));
        }
        Ok(reply)
    }

    fn mount_path(&self, disk: u8, rel: &str) -> String {
        let m = &self.mounts[usize::from(disk)];
        if rel.is_empty() { m.clone() } else { format!("{m}/{rel}") }
    }

    /// Watches the folder `rel` of `disk` and every folder in it.
    fn watch_tree(&mut self, disk: u8, rel: &str) -> io::Result<()> {
        let mut stack = vec![(rel.to_owned(), 0usize)];
        while let Some((rel, depth)) = stack.pop() {
            let c = cstr(&self.mount_path(disk, &rel))?;
            // SAFETY: inotify_add_watch(2) on a path; IN_DONT_FOLLOW|IN_ONLYDIR: a link isn't watched.
            let wd = unsafe { libc::inotify_add_watch(self.ino.as_raw_fd(), c.as_ptr(), WATCH_MASK) };
            if wd < 0 {
                let e = io::Error::last_os_error();
                if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) {
                    continue;
                }
                return Err(e);
            }
            self.wds.insert(wd, (disk, rel.clone()));
            if depth >= MAX_DEPTH {
                continue;
            }
            let Ok(dir) = open_beneath(self.roots[usize::from(disk)].as_raw_fd(), &rel, DIR_FLAGS) else { continue };
            for n in list_dir(dir.as_raw_fd())? {
                let Ok(name) = n.to_str() else { continue };
                if rel.is_empty() && name == LOST_FOUND {
                    continue;
                }
                if stat_at(dir.as_raw_fd(), &n).ok().and_then(|s| kind_of(&s)) == Some(Kind::Dir) {
                    stack.push((join(&rel, name), depth + 1));
                }
            }
        }
        Ok(())
    }

    /// Each file and folder under `rel` of `disk` (parents first), with its stat.
    fn each(&self, disk: u8, rel: &str, f: &mut dyn FnMut(&str, Kind, &libc::stat) -> io::Result<()>) -> io::Result<()> {
        let mut stack = vec![(rel.to_owned(), 0usize)];
        while let Some((rel, depth)) = stack.pop() {
            let Ok(dir) = open_beneath(self.roots[usize::from(disk)].as_raw_fd(), &rel, DIR_FLAGS) else { continue };
            let mut names = list_dir(dir.as_raw_fd())?;
            names.sort();
            for n in names {
                let Ok(name) = n.to_str() else {
                    (self.log)(&format!("not synced: a name that isn't UTF-8 in {:?}", self.mount_path(disk, &rel)));
                    continue;
                };
                if rel.is_empty() && name == LOST_FOUND {
                    continue;
                }
                let path = join(&rel, name);
                if check_path(&path).is_err() {
                    continue;
                }
                let Ok(st) = stat_at(dir.as_raw_fd(), &n) else { continue };
                let Some(kind) = kind_of(&st) else { continue };
                f(&path, kind, &st)?;
                if kind == Kind::Dir && depth < MAX_DEPTH {
                    stack.push((path, depth + 1));
                }
            }
        }
        Ok(())
    }

    /// The whole tree, then the files the host asks for.
    fn listing(&mut self) -> io::Result<()> {
        let mut ops = Vec::new();
        for d in 0..self.mounts.len() as u8 {
            self.each(d, "", &mut |path, kind, st| {
                let size = if kind == Kind::File { st.st_size as u64 } else { 0 };
                ops.push(Op::Entry { disk: d, path: path.to_owned(), kind, size, mode: st.st_mode & 0o777, mtime: mtime_of(st) });
                Ok(())
            })?;
        }
        for op in &ops {
            self.send(op)?;
        }
        self.send(&Op::ListEnd)?;
        let mut needs = Vec::new();
        loop {
            match self.reply()? {
                Reply::Ok => break,
                Reply::Need { disk, path } => needs.push((disk, path)),
                Reply::Err(e) => {
                    (self.log)(&format!("the host refused the listing: {e}"));
                    return Err(io::Error::other(e));
                }
            }
        }
        for (disk, path) in needs {
            if usize::from(disk) < self.mounts.len() {
                self.put(disk, &path)?;
            }
        }
        Ok(())
    }

    /// Sends the file `rel` of `disk` whole, after making it durable on the guest's disk.
    fn put(&mut self, disk: u8, rel: &str) -> io::Result<()> {
        let root = self.roots[usize::from(disk)].as_raw_fd();
        let fd = match open_beneath(root, rel, libc::O_RDONLY | libc::O_NONBLOCK) {
            Ok(fd) => fd,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)) => return Ok(()),
            Err(e) => return Err(e),
        };
        let st = fstat(fd.as_raw_fd())?;
        if kind_of(&st) != Some(Kind::File) {
            return Ok(());
        }
        // Durable here before the host has it: a crash after this loses nothing (the next
        // listing sends it again).
        fsync(fd.as_raw_fd())?;
        if let Ok(parent) = open_beneath(root, split(rel).0, DIR_FLAGS) {
            let _ = fsync(parent.as_raw_fd());
        }
        let size = st.st_size as u64;
        self.send(&Op::Put { disk, path: rel.to_owned(), mode: st.st_mode & 0o777, mtime: mtime_of(&st), size })?;
        let mut f = std::fs::File::from(fd);
        let mut left = size;
        let mut buf = vec![0u8; 256 << 10];
        let mut whole = true;
        while left > 0 {
            let want = (buf.len() as u64).min(left) as usize;
            let n = if whole { f.read(&mut buf[..want]).unwrap_or(0) } else { 0 };
            if n == 0 {
                // Shorter than it was: padded, and dropped by the commit byte.
                whole = false;
                buf[..want].fill(0);
                self.w.write_all(&buf[..want])?;
                left -= want as u64;
                continue;
            }
            self.w.write_all(&buf[..n])?;
            left -= n as u64;
        }
        let now = fstat(f.as_raw_fd())?;
        let same = now.st_size == st.st_size && mtime_of(&now) == mtime_of(&st);
        self.w.write_all(&[u8::from(whole && same)])?;
        self.ok_or_log(&format!("{rel:?}"))?;
        Ok(())
    }

    /// `rel` of `disk` whole: a file, or a folder with everything in it.
    fn put_tree(&mut self, disk: u8, rel: &str) -> io::Result<()> {
        let root = self.roots[usize::from(disk)].as_raw_fd();
        let Ok(fd) = open_beneath(root, rel, libc::O_PATH) else { return Ok(()) };
        let st = fstat(fd.as_raw_fd())?;
        match kind_of(&st) {
            Some(Kind::File) => self.put(disk, rel),
            Some(Kind::Dir) => {
                let mut items = Vec::new();
                items.push((rel.to_owned(), Kind::Dir, st.st_mode & 0o777));
                self.each(disk, rel, &mut |p, k, s| {
                    items.push((p.to_owned(), k, s.st_mode & 0o777));
                    Ok(())
                })?;
                for (p, k, mode) in items {
                    match k {
                        Kind::Dir => {
                            self.send(&Op::Mkdir { disk, path: p.clone(), mode })?;
                            self.ok_or_log(&format!("{p:?}"))?;
                        }
                        Kind::File => self.put(disk, &p)?,
                    }
                }
                Ok(())
            }
            None => Ok(()),
        }
    }

    fn simple(&mut self, op: Op, what: &str) -> io::Result<()> {
        self.send(&op)?;
        self.ok_or_log(what).map(|_| ())
    }

    /// Reads every queued event and applies it, until none is left; then the unpaired moves.
    fn pump(&mut self) -> io::Result<()> {
        loop {
            let events = self.read_events()?;
            if events.is_empty() {
                break;
            }
            for ev in events {
                self.event(ev)?;
            }
        }
        for (_, disk, rel, is_dir) in std::mem::take(&mut self.moved) {
            // Moved out of the watched tree (or its MOVED_TO was lost): gone from here.
            self.unwatch(disk, &rel, is_dir);
            self.simple(Op::Remove { disk, path: rel.clone() }, &format!("{rel:?}"))?;
        }
        Ok(())
    }

    fn read_events(&mut self) -> io::Result<Vec<Event>> {
        let mut buf = vec![0u8; 64 << 10];
        // SAFETY: read(2) into our buffer.
        let n = unsafe { libc::read(self.ino.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::WouldBlock { Ok(Vec::new()) } else { Err(e) };
        }
        let mut out = Vec::new();
        let head = std::mem::size_of::<libc::inotify_event>();
        let mut at = 0usize;
        while at + head <= n as usize {
            // SAFETY: the kernel wrote whole inotify_event records; read_unaligned copes with the
            // buffer's alignment.
            let ev: libc::inotify_event = unsafe { std::ptr::read_unaligned(buf[at..].as_ptr().cast()) };
            let len = ev.len as usize;
            let raw = &buf[at + head..(at + head + len).min(n as usize)];
            let name = raw.split(|b| *b == 0).next().filter(|s| !s.is_empty()).map(|s| String::from_utf8(s.to_vec()));
            let name = match name {
                Some(Ok(s)) => Some(s),
                Some(Err(_)) => {
                    (self.log)("not synced: a name that isn't UTF-8");
                    None
                }
                None => None,
            };
            out.push(Event { wd: ev.wd, mask: ev.mask, cookie: ev.cookie, name });
            at += head + len;
        }
        Ok(out)
    }

    fn unwatch(&mut self, disk: u8, rel: &str, is_dir: bool) {
        if !is_dir {
            return;
        }
        let prefix = format!("{rel}/");
        let gone: Vec<i32> = self.wds.iter().filter(|(_, (d, p))| *d == disk && (p == rel || p.starts_with(&prefix))).map(|(w, _)| *w).collect();
        for wd in gone {
            // SAFETY: inotify_rm_watch(2) of a watch we added.
            unsafe { libc::inotify_rm_watch(self.ino.as_raw_fd(), wd) };
            self.wds.remove(&wd);
        }
    }

    fn event(&mut self, ev: Event) -> io::Result<()> {
        if ev.mask & libc::IN_Q_OVERFLOW != 0 {
            // Events were lost: watch everything again and send the whole listing.
            (self.log)("the change queue overflowed; resending the whole listing");
            self.moved.clear();
            for d in 0..self.mounts.len() as u8 {
                self.watch_tree(d, "")?;
            }
            return self.listing();
        }
        if ev.mask & libc::IN_IGNORED != 0 {
            self.wds.remove(&ev.wd);
            return Ok(());
        }
        let (Some((disk, dir)), Some(name)) = (self.wds.get(&ev.wd).cloned(), ev.name) else { return Ok(()) };
        if dir.is_empty() && name == LOST_FOUND {
            return Ok(());
        }
        let rel = join(&dir, &name);
        if check_path(&rel).is_err() {
            return Ok(());
        }
        let is_dir = ev.mask & libc::IN_ISDIR != 0;
        let what = format!("{rel:?}");
        if ev.mask & libc::IN_MOVED_FROM != 0 {
            self.moved.push((ev.cookie, disk, rel, is_dir));
        } else if ev.mask & libc::IN_MOVED_TO != 0 {
            match self.moved.iter().position(|m| m.0 == ev.cookie && m.1 == disk) {
                Some(at) => {
                    let (_, _, from, _) = self.moved.remove(at);
                    self.send(&Op::Rename { disk, from: from.clone(), to: rel.clone() })?;
                    match self.ok_or_log(&what)? {
                        Reply::Need { .. } => self.put_tree(disk, &rel)?,
                        Reply::Ok if is_dir => {
                            let prefix = format!("{from}/");
                            for (_, (d, p)) in self.wds.iter_mut() {
                                if *d == disk && (*p == from || p.starts_with(&prefix)) {
                                    let moved = format!("{rel}{}", &p[from.len()..]);
                                    *p = moved;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                None => {
                    if is_dir {
                        self.watch_tree(disk, &rel)?;
                    }
                    self.put_tree(disk, &rel)?;
                }
            }
        } else if ev.mask & libc::IN_CREATE != 0 {
            if is_dir {
                self.watch_tree(disk, &rel)?;
                self.put_tree(disk, &rel)?;
            } else {
                // A hard link has no close: sent here. A new file is sent when it is closed.
                let root = self.roots[usize::from(disk)].as_raw_fd();
                let linked = open_beneath(root, &rel, libc::O_PATH).and_then(|f| fstat(f.as_raw_fd())).is_ok_and(|s| s.st_nlink > 1 && kind_of(&s) == Some(Kind::File));
                if linked {
                    self.put(disk, &rel)?;
                }
            }
        } else if ev.mask & libc::IN_CLOSE_WRITE != 0 {
            self.put(disk, &rel)?;
        } else if ev.mask & libc::IN_DELETE != 0 {
            self.simple(Op::Remove { disk, path: rel }, &what)?;
        } else if ev.mask & libc::IN_ATTRIB != 0 {
            let root = self.roots[usize::from(disk)].as_raw_fd();
            if let Ok(st) = open_beneath(root, &rel, libc::O_PATH).and_then(|f| fstat(f.as_raw_fd()))
                && kind_of(&st).is_some()
            {
                self.simple(Op::Chmod { disk, path: rel, mode: st.st_mode & 0o777 }, &what)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("securecore-sync-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch");
        fs::canonicalize(&dir).expect("canonical")
    }

    fn handle(p: &Path) -> OwnedFd {
        crate::jail::open_dir_beneath(p, Path::new("")).expect("handle")
    }

    fn writer(p: &Path, cap: u64) -> Writer {
        Writer::new(vec![Folder { dir: handle(p), cap }], Limits::DEFAULT).expect("writer")
    }

    /// Runs `ops` (with raw bytes after a Put) through a writer and returns its replies.
    fn run(w: &mut Writer, bytes: Vec<u8>) -> (io::Result<()>, Vec<Reply>) {
        let mut r = &bytes[..];
        let mut out = Vec::new();
        let res = w.serve(&mut r, &mut out);
        let mut replies = Vec::new();
        let mut o = &out[..];
        while !o.is_empty() {
            replies.push(Reply::read(&mut o).expect("reply"));
        }
        (res, replies)
    }

    fn put(path: &str, body: &[u8], commit: bool) -> Vec<u8> {
        let mut b = Op::Put { disk: 0, path: path.into(), mode: 0o640, mtime: Time { secs: 1_700_000_000, nanos: 5 }, size: body.len() as u64 }.encode();
        b.extend_from_slice(body);
        b.push(u8::from(commit));
        b
    }

    #[test]
    fn ops_and_replies_round_trip() {
        let t = Time { secs: -3, nanos: 999_999_999 };
        for op in [
            Op::Put { disk: 1, path: "2026/11/a.jpg".into(), mode: 0o644, mtime: t, size: 42 },
            Op::Mkdir { disk: 0, path: "2026".into(), mode: 0o755 },
            Op::Remove { disk: 0, path: "x".into() },
            Op::Rename { disk: 2, from: "a".into(), to: "b/c".into() },
            Op::Chmod { disk: 0, path: "a".into(), mode: 0o600 },
            Op::Entry { disk: 0, path: "a".into(), kind: Kind::Dir, size: 0, mode: 0o755, mtime: t },
            Op::ListEnd,
        ] {
            assert_eq!(Op::read(&mut &op.encode()[..]).expect("read"), Some(op.clone()), "{op:?}");
        }
        for r in [Reply::Ok, Reply::Need { disk: 3, path: "a/b".into() }, Reply::Err("no".into())] {
            assert_eq!(Reply::read(&mut &r.encode()[..]).expect("read"), r);
        }
        assert_eq!(Op::read(&mut &[][..]).expect("eof"), None, "a clean end");
        let long = Reply::Err("é".repeat(MAX_MESSAGE));
        assert!(matches!(Reply::read(&mut &long.encode()[..]), Ok(Reply::Err(m)) if m.len() <= MAX_MESSAGE));
    }

    #[test]
    fn only_plain_relative_paths_decode() {
        for p in ["../x", "/etc/passwd", "a/../../b", "a//b", ".", "a/./b", "", "a/", "a\0b"] {
            assert!(check_path(p).is_err(), "{p:?}");
            let op = Op::Remove { disk: 0, path: p.into() };
            let e = Op::read(&mut &op.encode()[..]).expect_err(p);
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{p:?}");
        }
        assert!(check_path(&"a/".repeat(MAX_DEPTH)[..MAX_DEPTH * 2 - 1]).is_ok());
        assert!(check_path(&"a/".repeat(MAX_DEPTH + 1)[..(MAX_DEPTH + 1) * 2 - 1]).is_err(), "too deep");
        assert!(check_path(&"n".repeat(MAX_NAME + 1)).is_err(), "too long a name");
        check_path("2026/11/photo-1.jpg").expect("an upload");
    }

    #[test]
    fn the_writer_mirrors_puts_folders_renames_removes_and_modes() {
        let host = scratch("mirror");
        let mut w = writer(&host, 1 << 20);
        let mut b = put("2026/11/a.txt", b"hello", true);
        b.extend(Op::Mkdir { disk: 0, path: "2026/12".into(), mode: 0o750 }.encode());
        b.extend(put("2026/11/b.txt", b"bee", true));
        b.extend(Op::Rename { disk: 0, from: "2026/11/b.txt".into(), to: "2026/12/b.txt".into() }.encode());
        b.extend(Op::Chmod { disk: 0, path: "2026/11/a.txt".into(), mode: 0o4755 }.encode());
        b.extend(put("2026/11/gone.txt", b"x", true));
        b.extend(Op::Remove { disk: 0, path: "2026/11/gone.txt".into() }.encode());
        b.extend(Op::Rename { disk: 0, from: "never-sent".into(), to: "2026/x".into() }.encode());
        b.extend(put("2026/11/dropped.txt", b"half", false));
        let (res, replies) = run(&mut w, b);
        res.expect("a clean end");
        assert_eq!(replies.len(), 9);
        assert!(replies[..7].iter().all(|r| *r == Reply::Ok), "{replies:?}");
        assert_eq!(replies[7], Reply::Need { disk: 0, path: "2026/x".into() }, "a rename whose source the host lacks");
        assert_eq!(replies[8], Reply::Ok);
        assert_eq!(fs::read(host.join("2026/11/a.txt")).expect("a"), b"hello");
        let m = fs::metadata(host.join("2026/11/a.txt")).expect("meta");
        assert_eq!(m.permissions().mode() & 0o7777, 0o755, "the mode, without setuid");
        assert_eq!((m.mtime(), m.mtime_nsec()), (1_700_000_000, 5), "the guest's mtime");
        assert_eq!(fs::read(host.join("2026/12/b.txt")).expect("b"), b"bee", "renamed");
        assert!(!host.join("2026/11/b.txt").exists());
        assert_eq!(fs::metadata(host.join("2026/12")).expect("dir").permissions().mode() & 0o777, 0o750);
        assert!(!host.join("2026/11/gone.txt").exists(), "removed");
        assert!(!host.join("2026/11/dropped.txt").exists(), "a put the guest dropped leaves nothing");
        let names: Vec<_> = fs::read_dir(host.join("2026/11")).expect("ls").flatten().map(|e| e.file_name()).collect();
        assert_eq!(names, ["a.txt"], "no temporary file left behind");
        // A folder removed with everything in it; a file put where a folder was.
        let mut b = put("t/deep/x", b"1", true);
        b.extend(Op::Remove { disk: 0, path: "t".into() }.encode());
        b.extend(put("2026/12", b"now a file", true));
        let (res, replies) = run(&mut w, b);
        res.expect("ok");
        assert!(replies.iter().all(|r| *r == Reply::Ok), "{replies:?}");
        assert!(!host.join("t").exists());
        assert_eq!(fs::read(host.join("2026/12")).expect("file"), b"now a file");
        let _ = fs::remove_dir_all(&host);
    }

    /// A link the site owner put in the host folder is never followed: the writer replaces it
    /// with the folder the guest has, and the place it pointed to is untouched.
    #[test]
    fn a_link_in_the_host_folder_is_replaced_never_followed() {
        let host = scratch("link");
        let outside = scratch("link-outside");
        std::os::unix::fs::symlink(&outside, host.join("evil")).expect("link");
        std::os::unix::fs::symlink(outside.join("target.txt"), host.join("file-link")).expect("link");
        fs::write(outside.join("target.txt"), "keep").expect("target");
        let mut w = writer(&host, 1 << 20);
        let mut b = put("evil/x.php", b"<?php", true);
        b.extend(put("file-link", b"replaced", true));
        b.extend(Op::Chmod { disk: 0, path: "file-link".into(), mode: 0o600 }.encode());
        b.extend(Op::Remove { disk: 0, path: "evil".into() }.encode());
        let (res, replies) = run(&mut w, b);
        res.expect("ok");
        assert!(replies.iter().all(|r| *r == Reply::Ok), "{replies:?}");
        assert_eq!(fs::read_dir(&outside).expect("ls").count(), 1, "nothing written outside");
        assert_eq!(fs::read_to_string(outside.join("target.txt")).expect("t"), "keep");
        assert_eq!(fs::metadata(outside.join("target.txt")).expect("m").permissions().mode() & 0o777, 0o644, "never chmod through a link");
        assert!(!fs::symlink_metadata(host.join("file-link")).expect("m").file_type().is_symlink(), "the link itself was replaced");
        assert!(!host.join("evil").exists());
        // A path that leaves the folder is refused, and the connection closed.
        let mut b = Op::Remove { disk: 0, path: "../link-outside".into() }.encode();
        b.extend(put("never.txt", b"x", true));
        let (res, replies) = run(&mut w, b);
        assert_eq!(res.expect_err("refused").kind(), io::ErrorKind::InvalidData);
        assert!(matches!(&replies[..], [Reply::Err(m)] if m.contains("not a plain relative path")), "{replies:?}");
        assert!(outside.exists() && !host.join("never.txt").exists());
        let (res, _) = run(&mut w, Op::Remove { disk: 7, path: "x".into() }.encode());
        assert!(res.expect_err("no disk 7").to_string().contains("1 sync folders"));
        let _ = fs::remove_dir_all(&host);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_folder_never_holds_more_than_its_cap() {
        let host = scratch("cap");
        fs::write(host.join("old.bin"), vec![0u8; 600]).expect("old");
        let mut w = writer(&host, 1000);
        let (res, replies) = run(&mut w, put("big.bin", &[1u8; 1001], true));
        assert!(res.is_err() && matches!(&replies[..], [Reply::Err(m)] if m.contains("more than its folder's cap")), "{replies:?}");
        let (res, replies) = run(&mut w, put("more.bin", &[1u8; 500], true));
        assert!(res.is_err() && matches!(&replies[..], [Reply::Err(m)] if m.contains("past its cap")), "600 + 500 > 1000: {replies:?}");
        assert!(!host.join("more.bin").exists() && !host.join("big.bin").exists());
        // Replacing a file counts only the difference.
        let (res, _) = run(&mut w, put("old.bin", &[2u8; 900], true));
        res.expect("900 in place of 600");
        let _ = fs::remove_dir_all(&host);
    }

    #[test]
    fn bytes_and_ops_are_rate_limited() {
        let mut b = Bucket::new(1000);
        let t = Instant::now();
        b.take(1000);
        assert!(t.elapsed() < Duration::from_millis(100), "one second of burst");
        b.take(500);
        assert!(t.elapsed() >= Duration::from_millis(450), "then the rate: {:?}", t.elapsed());
        assert_eq!(Limits::DEFAULT, Limits { bytes_per_sec: 256 << 20, ops_per_sec: 2000 });
    }

    #[test]
    fn a_listing_removes_extras_makes_folders_and_asks_for_what_differs() {
        let host = scratch("listing");
        fs::create_dir_all(host.join("same")).expect("dirs");
        fs::write(host.join("same/a.txt"), "aaa").expect("a");
        let a = fs::metadata(host.join("same/a.txt")).expect("m");
        let at = Time { secs: a.mtime(), nanos: a.mtime_nsec() as u32 };
        fs::write(host.join("stale.txt"), "x").expect("stale");
        fs::create_dir_all(host.join("old/sub")).expect("old");
        fs::write(host.join("changed.txt"), "v1").expect("changed");
        std::os::unix::fs::symlink("/etc", host.join("link")).expect("link");
        let mut w = writer(&host, 1 << 20);
        let e = |path: &str, kind, size, mtime| {
            let mode = if kind == Kind::Dir { 0o755 } else { 0o644 };
            Op::Entry { disk: 0, path: path.into(), kind, size, mode, mtime }.encode()
        };
        let mut b = Vec::new();
        b.extend(e("same", Kind::Dir, 0, at));
        b.extend(e("same/a.txt", Kind::File, 3, at));
        b.extend(e("changed.txt", Kind::File, 2, Time { secs: 1, nanos: 0 }));
        b.extend(e("new/deep", Kind::Dir, 0, at));
        b.extend(e("new/deep/n.txt", Kind::File, 1, at));
        b.extend(Op::ListEnd.encode());
        let (res, replies) = run(&mut w, b);
        res.expect("ok");
        assert_eq!(
            replies,
            [Reply::Need { disk: 0, path: "changed.txt".into() }, Reply::Need { disk: 0, path: "new/deep/n.txt".into() }, Reply::Ok],
            "only what differs is asked for"
        );
        assert!(!host.join("stale.txt").exists() && !host.join("old").exists(), "what the guest doesn't have is removed");
        assert!(fs::symlink_metadata(host.join("link")).is_err(), "a link is never part of the mirror");
        assert!(host.join("new/deep").is_dir(), "folders are made");
        assert_eq!(fs::read_to_string(host.join("same/a.txt")).expect("a"), "aaa", "the same file is kept");
        let _ = fs::remove_dir_all(&host);
    }

    /// The guest's side against the host's, over a socket pair, no VM: every kind of change in
    /// the guest's folder reaches the host's, and a drain waits for it.
    #[test]
    fn changes_in_the_guest_folder_reach_the_host_folder() {
        let guest = scratch("e2e-guest");
        let host = scratch("e2e-host");
        fs::create_dir_all(guest.join("2025/01")).expect("dirs");
        fs::write(guest.join("2025/01/before.txt"), "made before the connection").expect("before");
        fs::write(host.join("orphan.txt"), "only on the host").expect("orphan");
        let (g, h) = UnixStream::pair().expect("pair");
        let hostdir = host.clone();
        let writer_thread = thread::spawn(move || {
            let mut w = writer(&hostdir, 1 << 30);
            let mut r = BufReader::new(h.try_clone().expect("clone"));
            let mut out = h;
            w.serve(&mut r, &mut out)
        });
        let drain: &'static Drain = Box::leak(Box::new(Drain::new().expect("drain")));
        let mounts = vec![guest.display().to_string()];
        let (gr, gw) = (g.try_clone().expect("clone"), g.try_clone().expect("clone"));
        let hang = g.as_raw_fd();
        let guest_thread = thread::spawn(move || serve_guest(&mounts, BufReader::new(gr), gw, hang, drain, &|m| eprintln!("guest: {m}")));
        let t = Instant::now();
        while drain.wait(Duration::from_secs(1)).is_err() {
            assert!(t.elapsed() < Duration::from_secs(10), "the guest side never connected");
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(fs::read_to_string(host.join("2025/01/before.txt")).expect("before"), "made before the connection", "the listing");
        assert!(!host.join("orphan.txt").exists(), "the host mirrors the guest");
        fs::write(guest.join("2025/01/up.jpg"), vec![9u8; 3 << 20]).expect("upload");
        fs::create_dir_all(guest.join("2026/02/x")).expect("mkdir -p");
        fs::write(guest.join("2026/02/x/in-new-dir.txt"), "deep").expect("deep");
        fs::rename(guest.join("2025/01/before.txt"), guest.join("2025/renamed.txt")).expect("rename");
        fs::rename(guest.join("2026/02"), guest.join("2026/03")).expect("rename a folder");
        fs::write(guest.join("2026/03/x/after-dir-rename.txt"), "watched at its new path").expect("after");
        fs::write(guest.join("del.txt"), "x").expect("del");
        fs::set_permissions(guest.join("2025/01/up.jpg"), fs::Permissions::from_mode(0o600)).expect("chmod");
        fs::remove_file(guest.join("del.txt")).expect("rm");
        drain.wait(Duration::from_secs(10)).expect("drained");
        assert_eq!(fs::read(host.join("2025/01/up.jpg")).expect("up").len(), 3 << 20);
        assert_eq!(fs::metadata(host.join("2025/01/up.jpg")).expect("m").permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(host.join("2025/renamed.txt")).expect("renamed"), "made before the connection");
        assert!(!host.join("2025/01/before.txt").exists());
        assert_eq!(fs::read_to_string(host.join("2026/03/x/in-new-dir.txt")).expect("moved"), "deep");
        assert_eq!(fs::read_to_string(host.join("2026/03/x/after-dir-rename.txt")).expect("after"), "watched at its new path");
        assert!(!host.join("2026/02").exists() && !host.join("del.txt").exists());
        g.shutdown(std::net::Shutdown::Both).expect("close");
        guest_thread.join().expect("guest").expect("guest ended cleanly");
        let _ = writer_thread.join().expect("writer");
        assert!(drain.wait(Duration::from_secs(1)).is_err(), "no connection: a drain says so");
        let _ = fs::remove_dir_all(&guest);
        let _ = fs::remove_dir_all(&host);
    }
}
