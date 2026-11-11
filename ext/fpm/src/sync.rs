//! The guest's writable folders, synced with the host's (addiscorp/securecore#72). Linux only.
//!
//! A `layer1.write` folder inside the app root (uploads) is its own ext4 disk in the guest, and
//! the host can't safely read an ext4 image the guest has mounted read-write. So the guest tells
//! the host what changes, and an unprivileged writer on the host applies it to the real folder,
//! the one nginx serves and backups copy:
//!
//! ```text
//!   guest  securecore-init: inotify on each writable disk ──► vsock 516 (host-initiated)
//!   host   securecore-fpm: connects to guest port 516, hands the connection to
//!          `securecore-fpm --sync-writer`: the site's pool user (never root), no network, no
//!          new privileges, Landlock to its folders, a seccomp allowlist, a memory limit; one
//!          handle per folder, every path opened beneath it (openat2 RESOLVE_BENEATH |
//!          NO_SYMLINKS | NO_MAGICLINKS | NO_XDEV)
//! ```
//!
//! **Who wins: the record.** The host keeps, per folder, a record of what the writer last wrote
//! there or found in step with the guest: path → (size, mtime, inode) ([`Record`], in the
//! root-only state folder, which neither the guest nor the writer can write; the writer reports
//! each change to the launcher, which appends it). The writer replaces, renames or removes a host
//! entry **only while it still matches its record**; anything else on the host (an entry the
//! record doesn't have, or one that changed since) is the site owner's and wins:
//! - it is never overwritten or removed by the guest's changes (the op is refused, the guest
//!   told why, and the connection kept);
//! - at the next connection (every start, and every reconnect) it is pushed into the guest's
//!   disk ([`Reply::Push`]), so the two agree again.
//!
//! Removals never unlink: they move the file into `<state>/trash/<date>/<disk>/…` (kept 7 days,
//! outside the web root). Symlinks, devices, other mounts and names that aren't UTF-8 found on
//! the host are never followed, removed or pushed: they are skipped and logged once. (A name
//! that isn't UTF-8 travels as raw bytes, so one the guest made syncs like any other.)
//!
//! **The listing.** Each connection starts with the guest's whole tree ([`Op::Entry`] …
//! [`Op::ListEnd`]). Against it, the host:
//! - records what already agrees (size and mtime; `mke2fs -d` keeps both);
//! - asks for each file the guest changed or made ([`Reply::Need`]);
//! - moves to the trash what the guest removed (only recorded entries);
//! - pushes what the host changed or made (host wins).
//!
//! Then the guest streams its changes as they happen: a file when it is closed after writing,
//! folders, deletes, renames, modes and hard links.
//!
//! **No committed upload is lost to a crash.** The guest fsyncs a file before it sends it. The
//! host writes into a nameless file (O_TMPFILE), fsyncs it and renames it into place, so a crash
//! leaves the old file or the new one, never a part. A connection that ends starts the next one
//! with the full listing, which sends whatever didn't arrive.
//!
//! **Caps.** A file's content travels as its data extents (holes are skipped), and a folder's
//! files never take more blocks than its cap (its disk's size; a hard link counts once). A cap
//! breach refuses that one file before its body and keeps the connection. At most
//! [`MAX_ENTRIES`] files and folders per folder; a listing holds at most [`MAX_ENTRIES`] entries
//! and [`MAX_LISTING_BYTES`] of paths. Bytes and operations are rate-limited ([`Limits`]). The
//! port is below 1024, so only the guest's root can listen on it, and the host connects to it.

use std::collections::{BTreeMap, HashMap, HashSet};
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
/// The most files and folders a host folder may hold through the sync, and the most entries one
/// listing may hold.
pub const MAX_ENTRIES: usize = 1 << 20;
/// The most path bytes one listing may hold.
pub const MAX_LISTING_BYTES: usize = 64 << 20;
/// The longest error message in a reply.
const MAX_MESSAGE: usize = 1024;
/// The guest disk's own folder, never synced.
const LOST_FOUND: &[u8] = b"lost+found";
/// The sync's own temporary names, on both sides: never synced.
pub const TEMP_PREFIX: &[u8] = b".sc-sync-";
/// The most bytes one data chunk carries.
const CHUNK: usize = 256 << 10;
/// Every path beneath a folder handle: no symlink, no magic link, no `..` above it, and never
/// across a mount (a mount inside the folder is never written to or removed from).
pub const SYNC_BENEATH: u64 = BENEATH | libc::RESOLVE_NO_XDEV;
/// How long removed files stay in `<state>/trash/<date>/`.
pub const TRASH_DAYS: i64 = 7;

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

/// What the guest says about one of its entries. `blocks` is what it takes on disk (bytes, from
/// `st_blocks`), `ino` and `nlink` let the host keep hard links as links.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Meta {
    pub mode: u32,
    pub mtime: Time,
    pub size: u64,
    pub blocks: u64,
    pub ino: u64,
    pub nlink: u32,
}

/// One message from the guest. `disk` is the writable folder's index, in the order of the start
/// message's mounts; every path is relative to that folder, and is raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// A file, header only: the host answers [`Reply::Go`] (then its data extents follow,
    /// [`write_chunks`], and one byte, 1 to commit or 0 to drop: it changed while it was read),
    /// [`Reply::Linked`] (a hard link to a copy the host has: nothing follows) or
    /// [`Reply::Err`] (refused: nothing follows).
    Put { disk: u8, path: Vec<u8>, meta: Meta },
    Mkdir { disk: u8, path: Vec<u8>, mode: u32 },
    Remove { disk: u8, path: Vec<u8> },
    Rename { disk: u8, from: Vec<u8>, to: Vec<u8> },
    Chmod { disk: u8, path: Vec<u8>, mode: u32 },
    /// One entry of the guest's tree. No reply; [`Op::ListEnd`] ends the listing.
    Entry { disk: u8, path: Vec<u8>, kind: Kind, meta: Meta },
    /// The host replies with [`Reply::Push`]/[`Reply::PushDir`] (each answered by an
    /// [`Op::Pushed`]), then a [`Reply::Need`] for each file it wants, then [`Reply::Ok`].
    ListEnd,
    /// Whether the guest applied the push just sent.
    Pushed { disk: u8, path: Vec<u8>, ok: bool },
}

/// The host's answer to an op (none to an [`Op::Entry`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Ok,
    /// Send this path whole (a listed file the host lacks, or a rename whose source it lacks).
    Need { disk: u8, path: Vec<u8> },
    Err(String),
    /// Send the [`Op::Put`]'s data.
    Go,
    /// The [`Op::Put`] was made as a hard link on the host: send nothing.
    Linked,
    /// A host file the guest must take (the host's copy wins): its data extents and a commit
    /// byte follow.
    Push { disk: u8, path: Vec<u8>, mode: u32, mtime: Time, size: u64 },
    PushDir { disk: u8, path: Vec<u8>, mode: u32 },
}

/// A plain relative path: non-empty, `/`-separated names that are neither empty, `.` nor `..`,
/// no NUL, each at most [`MAX_NAME`] bytes, at most [`MAX_DEPTH`] deep and [`MAX_PATH`] long.
pub fn check_path(p: &[u8]) -> Result<(), String> {
    if p.is_empty() || p.len() > MAX_PATH {
        return Err(format!("a path of {} bytes (1 to {MAX_PATH})", p.len()));
    }
    let mut depth = 0;
    for name in p.split(|b| *b == b'/') {
        depth += 1;
        if name.is_empty() || name == b"." || name == b".." || name.len() > MAX_NAME || name.contains(&0) {
            return Err(format!("{} is not a plain relative path", show(p)));
        }
    }
    if depth > MAX_DEPTH {
        return Err(format!("{} is more than {MAX_DEPTH} folders deep", show(p)));
    }
    Ok(())
}

/// A path for a log line: quoted, with anything that isn't printable ASCII escaped.
pub fn show(p: &[u8]) -> String {
    format!("\"{}\"", p.escape_ascii())
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn put_bytes(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s);
}

fn put_time(out: &mut Vec<u8>, t: Time) {
    out.extend_from_slice(&t.secs.to_be_bytes());
    out.extend_from_slice(&t.nanos.to_be_bytes());
}

fn put_meta(out: &mut Vec<u8>, m: &Meta) {
    out.extend_from_slice(&m.mode.to_be_bytes());
    put_time(out, m.mtime);
    for v in [m.size, m.blocks, m.ino] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(&m.nlink.to_be_bytes());
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

fn read_meta(r: &mut impl Read) -> io::Result<Meta> {
    Ok(Meta { mode: read_u32(r)?, mtime: read_time(r)?, size: read_u64(r)?, blocks: read_u64(r)?, ino: read_u64(r)?, nlink: read_u32(r)? })
}

fn read_bytes(r: &mut impl Read, max: usize) -> io::Result<Vec<u8>> {
    let len = usize::from(u16::from_be_bytes(read_n(r)?));
    if len > max {
        return Err(bad(format!("a string of {len} bytes (at most {max})")));
    }
    let mut b = vec![0u8; len];
    r.read_exact(&mut b)?;
    Ok(b)
}

fn read_path(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let p = read_bytes(r, MAX_PATH)?;
    check_path(&p).map_err(bad)?;
    Ok(p)
}

impl Op {
    /// The op's bytes (a [`Op::Put`]'s data follows only after the host's [`Reply::Go`]).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        match self {
            Op::Put { disk, path, meta } => {
                out.extend([1, *disk]);
                put_bytes(&mut out, path);
                put_meta(&mut out, meta);
            }
            Op::Mkdir { disk, path, mode } => {
                out.extend([2, *disk]);
                put_bytes(&mut out, path);
                out.extend_from_slice(&mode.to_be_bytes());
            }
            Op::Remove { disk, path } => {
                out.extend([3, *disk]);
                put_bytes(&mut out, path);
            }
            Op::Rename { disk, from, to } => {
                out.extend([4, *disk]);
                put_bytes(&mut out, from);
                put_bytes(&mut out, to);
            }
            Op::Chmod { disk, path, mode } => {
                out.extend([5, *disk]);
                put_bytes(&mut out, path);
                out.extend_from_slice(&mode.to_be_bytes());
            }
            Op::Entry { disk, path, kind, meta } => {
                out.extend([6, *disk]);
                put_bytes(&mut out, path);
                out.push(match kind {
                    Kind::File => 0,
                    Kind::Dir => 1,
                });
                put_meta(&mut out, meta);
            }
            Op::ListEnd => out.push(7),
            Op::Pushed { disk, path, ok } => {
                out.extend([8, *disk]);
                put_bytes(&mut out, path);
                out.push(u8::from(*ok));
            }
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
            1 => Op::Put { disk, path: read_path(r)?, meta: read_meta(r)? },
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
                Op::Entry { disk, path, kind, meta: read_meta(r)? }
            }
            8 => Op::Pushed { disk, path: read_path(r)?, ok: read_u8(r)? == 1 },
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
                put_bytes(&mut out, path);
            }
            Reply::Err(msg) => {
                out.push(2);
                let mut end = msg.len().min(MAX_MESSAGE);
                while !msg.is_char_boundary(end) {
                    end -= 1;
                }
                put_bytes(&mut out, &msg.as_bytes()[..end]);
            }
            Reply::Go => out.push(3),
            Reply::Linked => out.push(4),
            Reply::Push { disk, path, mode, mtime, size } => {
                out.extend([5, *disk]);
                put_bytes(&mut out, path);
                out.extend_from_slice(&mode.to_be_bytes());
                put_time(&mut out, *mtime);
                out.extend_from_slice(&size.to_be_bytes());
            }
            Reply::PushDir { disk, path, mode } => {
                out.extend([6, *disk]);
                put_bytes(&mut out, path);
                out.extend_from_slice(&mode.to_be_bytes());
            }
        }
        out
    }

    pub fn read(r: &mut impl Read) -> io::Result<Reply> {
        Ok(match read_u8(r)? {
            0 => Reply::Ok,
            1 => Reply::Need { disk: read_u8(r)?, path: read_path(r)? },
            2 => Reply::Err(String::from_utf8_lossy(&read_bytes(r, MAX_MESSAGE)?).into_owned()),
            3 => Reply::Go,
            4 => Reply::Linked,
            5 => Reply::Push { disk: read_u8(r)?, path: read_path(r)?, mode: read_u32(r)?, mtime: read_time(r)?, size: read_u64(r)? },
            6 => Reply::PushDir { disk: read_u8(r)?, path: read_path(r)?, mode: read_u32(r)? },
            t => return Err(bad(format!("unknown reply {t}"))),
        })
    }
}

// --- files beneath a folder handle, shared by both sides --------------------------------------

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
}

fn cbytes(s: &[u8]) -> io::Result<CString> {
    CString::new(s).map_err(|_| bad("a NUL in a path"))
}

/// `rel` (a plain path, or empty for the folder itself) opened beneath `dir` with `flags`
/// ([`SYNC_BENEATH`]: no link anywhere, no `..`, never out of `dir`, never across a mount).
fn open_beneath(dir: RawFd, rel: &[u8], flags: libc::c_int) -> io::Result<OwnedFd> {
    let p = if rel.is_empty() { c".".to_owned() } else { cbytes(rel)? };
    let fd = openat2_raw(dir, &p, flags | libc::O_NOFOLLOW, SYNC_BENEATH);
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

/// `stat_at`, with a missing entry as `None`.
fn stat_opt(dir: RawFd, name: &CStr) -> io::Result<Option<libc::stat>> {
    match stat_at(dir, name) {
        Ok(st) => Ok(Some(st)),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(e) => Err(e),
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

fn meta_of(st: &libc::stat) -> Meta {
    Meta {
        mode: st.st_mode & 0o777,
        mtime: mtime_of(st),
        size: if kind_of(st) == Some(Kind::File) { st.st_size as u64 } else { 0 },
        blocks: st.st_blocks as u64 * 512,
        ino: st.st_ino,
        nlink: st.st_nlink as u32,
    }
}

/// The names in the folder `dir` (without `.` and `..`).
fn list_dir(dir: RawFd) -> io::Result<Vec<CString>> {
    // SAFETY: a fresh fd for `dir`'s folder handed to fdopendir(3), which owns it until
    // closedir(3); readdir's entries are copied out before the next call.
    unsafe {
        let fd = cvt(libc::openat(dir, c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC))?;
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

fn split(path: &[u8]) -> (&[u8], &[u8]) {
    match path.iter().rposition(|b| *b == b'/') {
        Some(at) => (&path[..at], &path[at + 1..]),
        None => (&[], path),
    }
}

fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
    if dir.is_empty() {
        return name.to_vec();
    }
    let mut p = Vec::with_capacity(dir.len() + 1 + name.len());
    p.extend_from_slice(dir);
    p.push(b'/');
    p.extend_from_slice(name);
    p
}

fn is_temp(name: &[u8]) -> bool {
    name.starts_with(TEMP_PREFIX)
}

fn fsync(fd: RawFd) -> io::Result<()> {
    // SAFETY: fsync(2) on an fd we hold.
    cvt(unsafe { libc::fsync(fd) }).map(|_| ())
}

fn fchmod(fd: RawFd, mode: u32) -> io::Result<()> {
    // SAFETY: fchmod(2) on an fd we hold. Only the permission bits: never setuid, setgid or sticky.
    cvt(unsafe { libc::fchmod(fd, mode & 0o777) }).map(|_| ())
}

fn set_mtime(fd: RawFd, t: Time) -> io::Result<()> {
    let times = [
        libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT },
        libc::timespec { tv_sec: t.secs as libc::time_t, tv_nsec: t.nanos as libc::c_long },
    ];
    // SAFETY: futimens(2) reads the two timespecs.
    cvt(unsafe { libc::futimens(fd, times.as_ptr()) }).map(|_| ())
}

fn renameat(from_dir: RawFd, from: &CStr, to_dir: RawFd, to: &CStr, noreplace: bool) -> io::Result<()> {
    let flags = if noreplace { libc::RENAME_NOREPLACE } else { 0 };
    // SAFETY: renameat2(2) of plain names in folders we hold.
    cvt(unsafe { libc::renameat2(from_dir, from.as_ptr(), to_dir, to.as_ptr(), flags) }).map(|_| ())
}

/// A nameless file in `dir` (O_TMPFILE), or a named one (`.sc-sync-…`) where the filesystem has
/// none.
fn tmpfile(dir: RawFd, seq: &mut u64) -> io::Result<(OwnedFd, Option<CString>)> {
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
    let name = temp_name(seq)?;
    let flags = libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: as above, a new plain name in a folder we hold.
    let fd = cvt(unsafe { libc::openat(dir, name.as_ptr(), flags, 0o600) })?;
    // SAFETY: as above.
    Ok((unsafe { OwnedFd::from_raw_fd(fd) }, Some(name)))
}

fn temp_name(seq: &mut u64) -> io::Result<CString> {
    *seq += 1;
    cbytes(format!(".sc-sync-{}-{seq}", std::process::id()).as_bytes())
}

/// Gives the file `fd` (from [`tmpfile`]) a temporary name in `dir`, if it has none yet.
fn name_tmp(dir: RawFd, fd: RawFd, named: Option<CString>, seq: &mut u64) -> io::Result<CString> {
    if let Some(n) = named {
        return Ok(n);
    }
    let n = temp_name(seq)?;
    let via = cbytes(format!("/proc/self/fd/{fd}").as_bytes())?;
    // SAFETY: linkat(2) of our nameless file (through its /proc link) to a new plain name.
    cvt(unsafe { libc::linkat(libc::AT_FDCWD, via.as_ptr(), dir, n.as_ptr(), libc::AT_SYMLINK_FOLLOW) })?;
    Ok(n)
}

fn unlink(dir: RawFd, name: &CStr) {
    // SAFETY: unlinkat(2) of a plain name we made.
    unsafe { libc::unlinkat(dir, name.as_ptr(), 0) };
}

/// Writes the data of `fd` (`size` bytes long) as extents: for each run of data, `[u32 len][u64
/// offset]` and its bytes, then `[u32 0]`. Holes are skipped. `false`: the file got shorter while
/// it was read (what was sent is incomplete; the commit byte then drops it).
pub fn write_chunks(w: &mut impl Write, fd: RawFd, size: u64) -> io::Result<bool> {
    let mut buf = vec![0u8; CHUNK];
    let mut at: i64 = 0;
    let end = size as i64;
    let mut whole = true;
    'extents: while at < end {
        // SAFETY: lseek(2) on an fd we hold.
        let data = unsafe { libc::lseek(fd, at, libc::SEEK_DATA) };
        if data < 0 {
            // ENXIO: only a hole is left. Anything else: no SEEK_DATA here, send it all.
            if io::Error::last_os_error().raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            at = at.max(0);
        } else {
            at = data;
        }
        if at >= end {
            break;
        }
        // SAFETY: as above.
        let hole = unsafe { libc::lseek(fd, at, libc::SEEK_HOLE) };
        let stop = if hole < 0 { end } else { hole.min(end) };
        while at < stop {
            let want = ((stop - at) as usize).min(CHUNK);
            // SAFETY: pread(2) into our buffer.
            let n = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), want, at) };
            if n <= 0 {
                whole = false;
                break 'extents;
            }
            let n = n as usize;
            w.write_all(&(n as u32).to_be_bytes())?;
            w.write_all(&(at as u64).to_be_bytes())?;
            w.write_all(&buf[..n])?;
            at += n as i64;
        }
    }
    w.write_all(&0u32.to_be_bytes())?;
    Ok(whole)
}

/// What [`read_chunks`] took in.
struct Received {
    /// Data bytes (holes excluded).
    data: u64,
    /// The first error writing them (the rest of the stream is still read).
    err: Option<io::Error>,
}

/// Reads extents ([`write_chunks`]) into `out` (none: discarded). Each lies inside `size`, in
/// order and not overlapping, or the stream is `InvalidData`. Writing stops at the first error,
/// or once more than `budget` data bytes came, but the stream is always read to its end.
fn read_chunks(r: &mut impl Read, out: Option<RawFd>, size: u64, budget: u64, bytes: &mut Option<&mut Bucket>) -> io::Result<Received> {
    let mut buf = vec![0u8; CHUNK];
    let mut next = 0u64;
    let mut got = Received { data: 0, err: None };
    loop {
        let len = read_u32(r)? as usize;
        if len == 0 {
            return Ok(got);
        }
        let off = read_u64(r)?;
        if len > CHUNK || off < next || off.checked_add(len as u64).is_none_or(|e| e > size) {
            return Err(bad(format!("a data chunk of {len} bytes at {off} (file of {size} bytes, next at {next})")));
        }
        r.read_exact(&mut buf[..len])?;
        if let Some(b) = bytes.as_deref_mut() {
            b.take(len as u64);
        }
        next = off + len as u64;
        got.data += len as u64;
        if got.err.is_none() && got.data > budget {
            got.err = Some(io::Error::other(format!("more data than the {budget} bytes left under the folder's cap")));
        }
        if got.err.is_none()
            && let Some(fd) = out
        {
            let mut done = 0;
            while done < len {
                // SAFETY: pwrite(2) from our buffer.
                let n = unsafe { libc::pwrite(fd, buf[done..len].as_ptr().cast(), len - done, (off + done as u64) as i64) };
                if n < 0 {
                    got.err = Some(io::Error::last_os_error());
                    break;
                }
                done += n as usize;
            }
        }
    }
}

// --- the record --------------------------------------------------------------------------------

/// What the record holds for a path: the host entry as the writer last left it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rec {
    pub kind: Kind,
    pub size: u64,
    pub mtime: Time,
    pub ino: u64,
}

impl Rec {
    fn of(st: &libc::stat) -> Option<Rec> {
        let kind = kind_of(st)?;
        Some(match kind {
            Kind::File => Rec { kind, size: st.st_size as u64, mtime: mtime_of(st), ino: st.st_ino },
            // A folder's size and mtime change with what is in it: it is known by its inode.
            Kind::Dir => Rec { kind, size: 0, mtime: Time::default(), ino: st.st_ino },
        })
    }
}

/// Per host folder: what the writer last wrote there, or found in step with the guest
/// (path → (size, mtime, inode)). Kept by the launcher (root) in the state folder as lines:
/// `+ <hex path> f|d <size> <secs> <nanos> <ino>`, `- <hex path>` (it and everything beneath it)
/// and `> <hex from> <hex to>` (it and everything beneath it, moved). The writer gets a
/// read-only copy at its start and reports each change on stdout as `<disk> <line>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record {
    map: BTreeMap<Vec<u8>, Rec>,
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()).collect()
}

/// `path` and everything beneath it, as a range of record keys.
fn under(map: &BTreeMap<Vec<u8>, Rec>, path: &[u8]) -> Vec<Vec<u8>> {
    let mut prefix = path.to_vec();
    prefix.push(b'/');
    let mut keys: Vec<Vec<u8>> = map.range(prefix.clone()..).take_while(|(k, _)| k.starts_with(&prefix)).map(|(k, _)| k.clone()).collect();
    if map.contains_key(path) {
        keys.push(path.to_vec());
    }
    keys
}

impl Record {
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, path: &[u8]) -> Option<&Rec> {
        self.map.get(path)
    }

    /// Whether the host entry `st` at `path` is still what the record says.
    pub fn matches(&self, path: &[u8], st: &libc::stat) -> bool {
        self.map.get(path).is_some_and(|r| Rec::of(st).as_ref() == Some(r))
    }

    /// Applies one line; `false` for a line that isn't one (it changes nothing).
    pub fn apply(&mut self, line: &str) -> bool {
        let w: Vec<&str> = line.split(' ').collect();
        match w[..] {
            ["+", p, k, size, secs, nanos, ino] => {
                let (Some(p), Ok(size), Ok(secs), Ok(nanos), Ok(ino)) = (unhex(p), size.parse(), secs.parse(), nanos.parse(), ino.parse()) else { return false };
                let kind = match k {
                    "f" => Kind::File,
                    "d" => Kind::Dir,
                    _ => return false,
                };
                if check_path(&p).is_err() || (self.map.len() >= MAX_ENTRIES && !self.map.contains_key(&p)) {
                    return false;
                }
                self.map.insert(p, Rec { kind, size, mtime: Time { secs, nanos }, ino });
                true
            }
            ["-", p] => {
                let Some(p) = unhex(p) else { return false };
                for k in under(&self.map, &p) {
                    self.map.remove(&k);
                }
                true
            }
            [">", from, to] => {
                let (Some(from), Some(to)) = (unhex(from), unhex(to)) else { return false };
                if check_path(&to).is_err() {
                    return false;
                }
                for k in under(&self.map, &to) {
                    self.map.remove(&k);
                }
                for k in under(&self.map, &from) {
                    if let Some(v) = self.map.remove(&k) {
                        let mut n = to.clone();
                        n.extend_from_slice(&k[from.len()..]);
                        self.map.insert(n, v);
                    }
                }
                true
            }
            _ => false,
        }
    }

    /// The record from its file's text (lines that don't parse are skipped).
    pub fn parse(text: &str) -> Record {
        let mut r = Record::default();
        for line in text.lines() {
            r.apply(line);
        }
        r
    }

    /// Its compacted text: one `+` line per entry.
    pub fn text(&self) -> String {
        self.map.iter().map(|(p, r)| set_line(p, r)).collect()
    }
}

fn set_line(p: &[u8], r: &Rec) -> String {
    let k = if r.kind == Kind::File { "f" } else { "d" };
    format!("+ {} {k} {} {} {} {}\n", hex(p), r.size, r.mtime.secs, r.mtime.nanos, r.ino)
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
pub struct Bucket {
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

/// One host folder the writer keeps in step: a handle on it, the most its files may take, a
/// handle on its trash folder, and its record.
pub struct Folder {
    pub dir: OwnedFd,
    pub cap: u64,
    pub trash: OwnedFd,
    pub record: Record,
}

struct Mirror {
    dir: OwnedFd,
    dev: u64,
    cap: u64,
    trash: OwnedFd,
    record: Record,
    /// Bytes on disk of the files (each inode once), and the files and folders.
    used: u64,
    entries: usize,
}

/// A host entry, as walked.
struct HostEntry {
    st: libc::stat,
    /// `None`: never synced (a symlink, a device, another mount).
    kind: Option<Kind>,
}

/// Applies a guest's ops to the host folders. Runs as the site's pool user ([`writer_main`]).
pub struct Writer {
    folders: Vec<Mirror>,
    bytes: Bucket,
    ops: Bucket,
    listing: Vec<(u8, Vec<u8>, Kind, Meta)>,
    listing_bytes: usize,
    /// (disk, guest inode) → a host path holding that file, for hard links.
    links: HashMap<(u8, u64), Vec<u8>>,
    seq: u64,
    /// Where each change to a record is reported (the launcher appends it to the record file).
    report: Box<dyn Write>,
    /// Log lines left before the writer goes quiet (the paths come from the guest).
    log_left: u32,
    /// Kinds of skipped host entries already logged once.
    skipped: HashSet<&'static str>,
    pub pushed: (u64, u64),
}

/// Why a connection ends: the guest broke the protocol (refused, then closed).
fn refuse(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// A refusal of one op that keeps the connection: the host's copy wins, or a cap.
struct Kept(String);

impl Writer {
    pub fn new(folders: Vec<Folder>, limits: Limits, report: Box<dyn Write>) -> io::Result<Writer> {
        let mut w = Writer {
            folders: Vec::new(),
            bytes: Bucket::new(limits.bytes_per_sec),
            ops: Bucket::new(limits.ops_per_sec),
            listing: Vec::new(),
            listing_bytes: 0,
            links: HashMap::new(),
            seq: 0,
            report,
            log_left: 200,
            skipped: HashSet::new(),
            pushed: (0, 0),
        };
        for f in folders {
            let st = fstat(f.dir.as_raw_fd())?;
            if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
                return Err(bad("a sync folder that isn't a folder"));
            }
            w.folders.push(Mirror { dir: f.dir, dev: st.st_dev, cap: f.cap, trash: f.trash, record: f.record, used: 0, entries: 0 });
        }
        for i in 0..w.folders.len() {
            w.measure(i)?;
        }
        Ok(w)
    }

    fn log(&mut self, msg: &str) {
        if self.log_left > 0 {
            self.log_left -= 1;
            eprintln!("securecore-fpm: sync: {msg}{}", if self.log_left == 0 { " (further sync errors are not logged)" } else { "" });
        }
    }

    /// A host entry the sync never touches: logged once per kind.
    fn skip(&mut self, what: &'static str, path: &[u8]) {
        if self.skipped.insert(what) {
            eprintln!("securecore-fpm: sync: not synced, never removed: {what} on the host ({}; others like it are not logged)", show(path));
        }
    }

    fn note(&mut self, i: usize, line: String) {
        self.folders[i].record.apply(line.trim_end());
        let _ = self.report.write_all(format!("{i} {line}").as_bytes());
        let _ = self.report.flush();
    }

    fn note_set(&mut self, i: usize, path: &[u8], st: &libc::stat) {
        if let Some(r) = Rec::of(st)
            && self.folders[i].record.get(path) != Some(&r)
        {
            self.note(i, set_line(path, &r));
        }
    }

    fn note_del(&mut self, i: usize, path: &[u8]) {
        if !under(&self.folders[i].record.map, path).is_empty() {
            self.note(i, format!("- {}\n", hex(path)));
        }
    }

    /// The bytes on disk and the entry count of folder `i` now.
    fn measure(&mut self, i: usize) -> io::Result<()> {
        let all = self.walk(i)?;
        let mut seen = HashSet::new();
        let (mut used, mut entries) = (0u64, 0usize);
        for (_, e) in &all {
            match e.kind {
                Some(Kind::File) => {
                    entries += 1;
                    if e.st.st_nlink <= 1 || seen.insert(e.st.st_ino) {
                        used += e.st.st_blocks as u64 * 512;
                    }
                }
                Some(Kind::Dir) => entries += 1,
                None => {}
            }
        }
        self.folders[i].used = used;
        self.folders[i].entries = entries;
        Ok(())
    }

    fn mirror(&self, disk: u8) -> io::Result<usize> {
        let i = usize::from(disk);
        if i >= self.folders.len() {
            return Err(refuse(format!("disk {disk}: there are {} sync folders", self.folders.len())));
        }
        Ok(i)
    }

    /// Every entry of folder `i` (never "" itself), parents before children: what is beneath a
    /// symlink, another mount or a name that isn't UTF-8 (and isn't in the record) isn't walked.
    fn walk(&mut self, i: usize) -> io::Result<Vec<(Vec<u8>, HostEntry)>> {
        let root = open_beneath(self.folders[i].dir.as_raw_fd(), b"", DIR_FLAGS)?;
        let dev = self.folders[i].dev;
        let mut out = Vec::new();
        let mut stack = vec![(root, Vec::new(), 0usize)];
        while let Some((dir, rel, depth)) = stack.pop() {
            let mut names = list_dir(dir.as_raw_fd())?;
            names.sort();
            for n in names {
                if is_temp(n.to_bytes()) {
                    continue;
                }
                let Ok(st) = stat_at(dir.as_raw_fd(), &n) else { continue };
                let path = join(&rel, n.to_bytes());
                let kind = if st.st_dev != dev { None } else { kind_of(&st) };
                let descend = kind == Some(Kind::Dir) && depth < MAX_DEPTH && (std::str::from_utf8(&path).is_ok() || self.folders[i].record.get(&path).is_some());
                if descend {
                    match open_beneath(dir.as_raw_fd(), n.to_bytes(), DIR_FLAGS) {
                        Ok(sub) => stack.push((sub, path.clone(), depth + 1)),
                        Err(e) => self.log(&format!("listing {}: {e}", show(&path))),
                    }
                }
                out.push((path, HostEntry { st, kind }));
                if out.len() > MAX_ENTRIES + 1 {
                    return Err(io::Error::other(format!("more than {MAX_ENTRIES} entries in a sync folder")));
                }
            }
        }
        Ok(out)
    }

    /// Serves one guest connection until it ends. `Ok` at a clean end; `Err` when the guest broke
    /// the protocol (it is told why first) or the connection failed.
    pub fn serve(&mut self, r: &mut impl Read, w: &mut impl Write) -> io::Result<()> {
        loop {
            let res = match Op::read(r) {
                Ok(Some(op)) => {
                    self.ops.take(1);
                    self.apply(op, r, w)
                }
                Ok(None) => return Ok(()),
                Err(e) => Err(e),
            };
            match res {
                Ok(()) => w.flush()?,
                Err(e) => {
                    if e.kind() == io::ErrorKind::InvalidData {
                        let _ = w.write_all(&Reply::Err(e.to_string()).encode());
                        let _ = w.flush();
                    }
                    return Err(e);
                }
            }
        }
    }

    fn reply(w: &mut impl Write, reply: &Reply) -> io::Result<()> {
        w.write_all(&reply.encode())
    }

    /// One op, its replies written. A filesystem error or a refusal on one path is that op's
    /// `Reply::Err` and the connection goes on; `InvalidData` ends it.
    fn apply(&mut self, op: Op, r: &mut impl Read, w: &mut impl Write) -> io::Result<()> {
        let done = |me: &mut Writer, w: &mut dyn Write, what: &str, path: &[u8], res: io::Result<Result<(), Kept>>| -> io::Result<()> {
            match res {
                Ok(Ok(())) => w.write_all(&Reply::Ok.encode()),
                Ok(Err(Kept(why))) => {
                    me.log(&format!("{what} {}: {why}", show(path)));
                    w.write_all(&Reply::Err(why).encode())
                }
                Err(e) if matches!(e.kind(), io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof) => Err(e),
                Err(e) => {
                    let m = format!("{what} {}: {e}", show(path));
                    me.log(&m);
                    w.write_all(&Reply::Err(m).encode())
                }
            }
        };
        match op {
            Op::Put { disk, path, meta } => {
                let i = self.mirror(disk)?;
                self.put(i, &path, &meta, r, w)
            }
            Op::Mkdir { disk, path, mode } => {
                let i = self.mirror(disk)?;
                let res = self.mkdir(i, &path, mode);
                done(self, w, "mkdir", &path, res)
            }
            Op::Remove { disk, path } => {
                let i = self.mirror(disk)?;
                let res = self.remove(i, &path);
                done(self, w, "remove", &path, res)
            }
            Op::Rename { disk, from, to } => {
                let i = self.mirror(disk)?;
                match self.rename(i, &from, &to) {
                    Ok(Ok(true)) => Self::reply(w, &Reply::Ok),
                    Ok(Ok(false)) => Self::reply(w, &Reply::Need { disk, path: to }),
                    Ok(Err(k)) => done(self, w, "rename", &from, Ok(Err(k))),
                    Err(e) => done(self, w, "rename", &from, Err(e)),
                }
            }
            Op::Chmod { disk, path, mode } => {
                let i = self.mirror(disk)?;
                let res = self.chmod(i, &path, mode);
                done(self, w, "chmod", &path, res)
            }
            Op::Entry { disk, path, kind, meta } => {
                self.mirror(disk)?;
                self.listing_bytes += path.len();
                if self.listing.len() >= MAX_ENTRIES || self.listing_bytes > MAX_LISTING_BYTES {
                    return Err(refuse(format!("a listing of more than {MAX_ENTRIES} entries or {MAX_LISTING_BYTES} bytes of paths")));
                }
                self.listing.push((disk, path, kind, meta));
                Ok(())
            }
            Op::ListEnd => {
                let mut listing = std::mem::take(&mut self.listing);
                self.listing_bytes = 0;
                listing.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
                let mut needs = Vec::new();
                let mut at = 0;
                for i in 0..self.folders.len() {
                    let t = Instant::now();
                    let end = at + listing[at..].iter().take_while(|e| usize::from(e.0) == i).count();
                    let guest: HashMap<&[u8], (Kind, Meta)> = listing[at..end].iter().map(|(_, p, k, m)| (p.as_slice(), (*k, *m))).collect();
                    let plan = self.reconcile(i, &guest)?;
                    at = end;
                    let pushed = self.push_all(i, &plan.pushes, r, w)?;
                    eprintln!(
                        "securecore-fpm: sync: folder {i} reconciled in {:.0} ms: {} listed, {} to send, {} to the trash, {} pushed to the guest ({} bytes)",
                        t.elapsed().as_secs_f64() * 1000.0,
                        guest.len(),
                        plan.needs.len(),
                        plan.trashed,
                        pushed.0,
                        pushed.1,
                    );
                    needs.extend(plan.needs.into_iter().map(|p| (i as u8, p)));
                }
                for (disk, path) in needs {
                    Self::reply(w, &Reply::Need { disk, path })?;
                }
                Self::reply(w, &Reply::Ok)
            }
            Op::Pushed { .. } => Err(refuse("a push answer with no push".into())),
        }
    }

    /// The folder `rel` of folder `i` (missing folders made and recorded when `create`). A link,
    /// a file, another mount or anything else where a folder belongs is the host's: refused.
    fn open_dir(&mut self, i: usize, rel: &[u8], create: bool) -> io::Result<Result<OwnedFd, Kept>> {
        let mut cur = open_beneath(self.folders[i].dir.as_raw_fd(), b"", DIR_FLAGS)?;
        let mut at: Vec<u8> = Vec::new();
        for name in rel.split(|b| *b == b'/').filter(|n| !n.is_empty()) {
            at = join(&at, name);
            let c = cbytes(name)?;
            match stat_opt(cur.as_raw_fd(), &c)? {
                Some(st) if kind_of(&st) == Some(Kind::Dir) && st.st_dev == self.folders[i].dev => {}
                Some(_) => return Ok(Err(Kept(format!("{} is not a folder on the host (the host's entry is kept)", show(&at))))),
                None if !create => return Err(io::Error::from_raw_os_error(libc::ENOENT)),
                None => {
                    if self.folders[i].entries >= MAX_ENTRIES {
                        return Ok(Err(Kept(format!("the folder already holds {MAX_ENTRIES} entries"))));
                    }
                    // SAFETY: mkdirat(2) of a plain name in a folder we hold.
                    if unsafe { libc::mkdirat(cur.as_raw_fd(), c.as_ptr(), 0o755) } < 0 {
                        let e = io::Error::last_os_error();
                        if e.raw_os_error() != Some(libc::EEXIST) {
                            return Err(e);
                        }
                    } else {
                        self.folders[i].entries += 1;
                        if let Ok(st) = stat_at(cur.as_raw_fd(), &c) {
                            self.note_set(i, &at, &st);
                        }
                    }
                }
            }
            cur = open_beneath(cur.as_raw_fd(), name, DIR_FLAGS)?;
        }
        Ok(Ok(cur))
    }

    fn mkdir(&mut self, i: usize, path: &[u8], mode: u32) -> io::Result<Result<(), Kept>> {
        let d = match self.open_dir(i, path, true)? {
            Ok(d) => d,
            Err(k) => return Ok(Err(k)),
        };
        let st = fstat(d.as_raw_fd())?;
        if self.folders[i].record.get(path).is_none() {
            // A folder the host made with the same name: the two agree.
            self.note_set(i, path, &st);
        } else if self.folders[i].record.matches(path, &st) && st.st_mode & 0o777 != mode & 0o777 {
            fchmod(d.as_raw_fd(), mode)?;
        }
        Ok(Ok(()))
    }

    /// Is the host entry `name` in `dir` (path `path`) one the guest may replace or remove? `None`
    /// when there is none.
    fn owned(&self, i: usize, dir: RawFd, name: &CStr, path: &[u8]) -> io::Result<Result<Option<libc::stat>, Kept>> {
        let Some(st) = stat_opt(dir, name)? else { return Ok(Ok(None)) };
        if st.st_dev != self.folders[i].dev || kind_of(&st).is_none() {
            return Ok(Err(Kept(format!("{} is a link, a device or another mount on the host: never replaced", show(path)))));
        }
        if !self.folders[i].record.matches(path, &st) {
            return Ok(Err(Kept(format!(
                "{} changed on the host since the sync last wrote it: the host's copy wins, and reaches the guest at the next start",
                show(path)
            ))));
        }
        Ok(Ok(Some(st)))
    }

    /// One [`Op::Put`]: the decision (refused, linked or go), then the data.
    fn put(&mut self, i: usize, path: &[u8], meta: &Meta, r: &mut impl Read, w: &mut impl Write) -> io::Result<()> {
        let refused = |me: &mut Writer, w: &mut dyn Write, why: String| -> io::Result<()> {
            me.log(&format!("put {}: {why}", show(path)));
            w.write_all(&Reply::Err(why).encode())
        };
        let (parent, name) = split(path);
        let c = cbytes(name)?;
        let dir = match self.open_dir(i, parent, true) {
            Ok(Ok(d)) => d,
            Ok(Err(Kept(why))) => return refused(self, w, why),
            Err(e) => return refused(self, w, format!("its folder: {e}")),
        };
        let old = match self.owned(i, dir.as_raw_fd(), &c, path) {
            Ok(Ok(old)) => old,
            Ok(Err(Kept(why))) => return refused(self, w, why),
            Err(e) => return refused(self, w, e.to_string()),
        };
        if old.as_ref().is_some_and(|st| kind_of(st) != Some(Kind::File)) {
            return refused(self, w, format!("{} is a folder on the host", show(path)));
        }
        // A file's blocks count once, however many names it has.
        let old_blocks = old.as_ref().filter(|st| st.st_nlink <= 1).map_or(0, |st| st.st_blocks as u64 * 512);
        let (cap, used) = (self.folders[i].cap, self.folders[i].used.saturating_sub(old_blocks));
        let room = cap.saturating_sub(used);
        if old.is_none() && self.folders[i].entries >= MAX_ENTRIES {
            return refused(self, w, format!("the folder already holds {MAX_ENTRIES} entries"));
        }
        if meta.nlink > 1
            && let Some(src) = self.links.get(&(i as u8, meta.ino)).cloned()
            && src != path
            && self.link(i, &src, &dir, &c, path, meta, old.is_some())?
        {
            return Self::reply(w, &Reply::Linked);
        }
        if meta.blocks > room {
            return refused(self, w, format!("{} takes {} bytes; its folder has {room} left under its cap of {cap}", show(path), meta.blocks));
        }
        Self::reply(w, &Reply::Go)?;
        w.flush()?;
        let (tmp, named) = match tmpfile(dir.as_raw_fd(), &mut self.seq) {
            Ok(t) => (Some(t.0), t.1),
            Err(e) => {
                read_chunks(r, None, meta.size, 0, &mut None)?;
                read_u8(r)?;
                return refused(self, w, format!("a temporary file: {e}"));
            }
        };
        let tmp = tmp.ok_or_else(|| io::Error::other("no temporary file"))?;
        let fd = tmp.as_raw_fd();
        let drop_named = |named: &Option<CString>| {
            if let Some(n) = named {
                unlink(dir.as_raw_fd(), n);
            }
        };
        // SAFETY: ftruncate(2) on our file: its length, with holes where no data comes.
        let sized = cvt(unsafe { libc::ftruncate(fd, meta.size as libc::off_t) });
        let got = match read_chunks(r, sized.is_ok().then_some(fd), meta.size, room, &mut Some(&mut self.bytes)) {
            Ok(g) => g,
            Err(e) => {
                drop_named(&named);
                return Err(e);
            }
        };
        let commit = read_u8(r)? == 1;
        let err = sized.err().or(got.err);
        if let Some(e) = err {
            drop_named(&named);
            return refused(self, w, e.to_string());
        }
        if !commit {
            drop_named(&named);
            return Self::reply(w, &Reply::Ok);
        }
        let res = (|| -> io::Result<Result<libc::stat, Kept>> {
            fchmod(fd, meta.mode)?;
            set_mtime(fd, meta.mtime)?;
            fsync(fd)?;
            let tmp_name = name_tmp(dir.as_raw_fd(), fd, named.clone(), &mut self.seq)?;
            // Checked again just before: the site owner may have written it meanwhile.
            let still = self.owned(i, dir.as_raw_fd(), &c, path)?;
            let ok = match still {
                Ok(now) if now.map(|s| s.st_ino) == old.as_ref().map(|s| s.st_ino) => renameat(dir.as_raw_fd(), &tmp_name, dir.as_raw_fd(), &c, old.is_none()),
                Ok(_) => Err(io::Error::from_raw_os_error(libc::EEXIST)),
                Err(k) => {
                    unlink(dir.as_raw_fd(), &tmp_name);
                    return Ok(Err(k));
                }
            };
            if let Err(e) = ok {
                unlink(dir.as_raw_fd(), &tmp_name);
                return Err(e);
            }
            fsync(dir.as_raw_fd())?;
            fstat(fd).map(Ok)
        })();
        match res {
            Ok(Ok(st)) => {
                let m = &mut self.folders[i];
                m.used = used + st.st_blocks as u64 * 512;
                if old.is_none() {
                    m.entries += 1;
                }
                self.note_set(i, path, &st);
                if meta.nlink > 1 {
                    self.links.insert((i as u8, meta.ino), path.to_vec());
                }
                Self::reply(w, &Reply::Ok)
            }
            Ok(Err(Kept(why))) => refused(self, w, why),
            Err(e) => refused(self, w, e.to_string()),
        }
    }

    /// `path` made a hard link of the host's copy `src` of the same guest file, if that copy is
    /// still what the sync wrote and is the guest's size and mtime. `false`: not linked.
    #[allow(clippy::too_many_arguments)] // reason: the parts of one put, already opened by the caller
    fn link(&mut self, i: usize, src: &[u8], dir: &OwnedFd, name: &CStr, path: &[u8], meta: &Meta, replaces: bool) -> io::Result<bool> {
        let (sp, sn) = split(src);
        let Ok(Ok(sdir)) = self.open_dir(i, sp, false) else { return Ok(false) };
        let sc = cbytes(sn)?;
        let Ok(Ok(Some(st))) = self.owned(i, sdir.as_raw_fd(), &sc, src) else { return Ok(false) };
        if kind_of(&st) != Some(Kind::File) || st.st_size as u64 != meta.size || mtime_of(&st) != meta.mtime {
            return Ok(false);
        }
        let tmp = temp_name(&mut self.seq)?;
        // SAFETY: linkat(2) of a plain name in one folder we hold to a new plain name in another.
        if unsafe { libc::linkat(sdir.as_raw_fd(), sc.as_ptr(), dir.as_raw_fd(), tmp.as_ptr(), 0) } < 0 {
            return Ok(false);
        }
        if renameat(dir.as_raw_fd(), &tmp, dir.as_raw_fd(), name, !replaces).is_err() {
            unlink(dir.as_raw_fd(), &tmp);
            return Ok(false);
        }
        fsync(dir.as_raw_fd())?;
        if !replaces {
            self.folders[i].entries += 1;
        }
        let st = stat_at(dir.as_raw_fd(), name)?;
        self.note_set(i, path, &st);
        Ok(true)
    }

    /// The trash folder's copy of `path`'s parent, made as needed, and a free name in it.
    fn trash_slot(&mut self, i: usize, path: &[u8]) -> io::Result<(OwnedFd, CString)> {
        let (parent, name) = split(path);
        let mut cur = open_beneath(self.folders[i].trash.as_raw_fd(), b"", DIR_FLAGS)?;
        for n in parent.split(|b| *b == b'/').filter(|n| !n.is_empty()) {
            let c = cbytes(n)?;
            // SAFETY: mkdirat(2) of a plain name in a folder we hold.
            unsafe { libc::mkdirat(cur.as_raw_fd(), c.as_ptr(), 0o700) };
            cur = open_beneath(cur.as_raw_fd(), n, DIR_FLAGS)?;
        }
        let mut cand = name.to_vec();
        let mut n = 0;
        loop {
            let c = cbytes(&cand)?;
            if stat_opt(cur.as_raw_fd(), &c)?.is_none() {
                return Ok((cur, c));
            }
            n += 1;
            cand = name.to_vec();
            cand.extend_from_slice(format!(".{n}").as_bytes());
            if n > 10_000 {
                return Err(io::Error::other("no free name in the trash"));
            }
        }
    }

    /// Moves the file `name` of `dir` (path `path`, stat `st`) into the trash: a rename, or a copy
    /// and an unlink when the trash is on another filesystem.
    fn trash(&mut self, i: usize, dir: RawFd, name: &CStr, path: &[u8], st: &libc::stat) -> io::Result<()> {
        let (tdir, tname) = self.trash_slot(i, path)?;
        match renameat(dir, name, tdir.as_raw_fd(), &tname, true) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
                let src = cvt(unsafe {
                    // SAFETY: openat(2) of a plain name in a folder we hold, never followed.
                    libc::openat(dir, name.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                })?;
                // SAFETY: just returned.
                let src = unsafe { std::fs::File::from_raw_fd(src) };
                let flags = libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
                // SAFETY: as above, a new name in the trash folder we hold.
                let dst = cvt(unsafe { libc::openat(tdir.as_raw_fd(), tname.as_ptr(), flags, 0o600) })?;
                // SAFETY: just returned.
                let mut dst = unsafe { std::fs::File::from_raw_fd(dst) };
                io::copy(&mut (&src).take(st.st_size as u64), &mut dst)?;
                fsync(dst.as_raw_fd())?;
                // SAFETY: unlinkat(2) of the plain name just copied.
                cvt(unsafe { libc::unlinkat(dir, name.as_ptr(), 0) })?;
            }
            Err(e) => return Err(e),
        }
        let m = &mut self.folders[i];
        if st.st_nlink <= 1 {
            m.used = m.used.saturating_sub(st.st_blocks as u64 * 512);
        }
        m.entries = m.entries.saturating_sub(1);
        self.note_del(i, path);
        Ok(())
    }

    /// Removes `path` as the guest did: a recorded file to the trash; a recorded folder with the
    /// recorded entries in it (kept, with the folder, when it holds anything the host made).
    fn remove(&mut self, i: usize, path: &[u8]) -> io::Result<Result<(), Kept>> {
        let (parent, name) = split(path);
        let dir = match self.open_dir(i, parent, false) {
            Ok(Ok(d)) => d,
            Ok(Err(_)) => return Ok(Ok(())),
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP | libc::EXDEV)) => return Ok(Ok(())),
            Err(e) => return Err(e),
        };
        let c = cbytes(name)?;
        let st = match self.owned(i, dir.as_raw_fd(), &c, path)? {
            Ok(Some(st)) => st,
            Ok(None) => {
                self.note_del(i, path);
                return Ok(Ok(()));
            }
            Err(k) => return Ok(Err(k)),
        };
        let kept = if kind_of(&st) == Some(Kind::Dir) { self.remove_tree(i, dir.as_raw_fd(), &c, path, 0)? } else {
            self.trash(i, dir.as_raw_fd(), &c, path, &st)?;
            0
        };
        fsync(dir.as_raw_fd())?;
        if kept > 0 {
            return Ok(Err(Kept(format!("{kept} entries the host made or changed are kept in {}", show(path)))));
        }
        Ok(Ok(()))
    }

    /// The recorded folder `name` of `dir`: its recorded files to the trash, then it and its
    /// folders once empty. The count of host entries kept.
    fn remove_tree(&mut self, i: usize, dir: RawFd, name: &CStr, path: &[u8], depth: usize) -> io::Result<usize> {
        if depth > MAX_DEPTH {
            return Ok(1);
        }
        let sub = open_beneath(dir, name.to_bytes(), DIR_FLAGS)?;
        let mut kept = 0;
        for n in list_dir(sub.as_raw_fd())? {
            let p = join(path, n.to_bytes());
            match self.owned(i, sub.as_raw_fd(), &n, &p)? {
                Ok(Some(st)) if kind_of(&st) == Some(Kind::Dir) => kept += self.remove_tree(i, sub.as_raw_fd(), &n, &p, depth + 1)?,
                Ok(Some(st)) => self.trash(i, sub.as_raw_fd(), &n, &p, &st)?,
                Ok(None) => {}
                Err(_) => kept += 1,
            }
        }
        drop(sub);
        if kept == 0 {
            // SAFETY: unlinkat(2) of the now empty folder.
            match cvt(unsafe { libc::unlinkat(dir, name.as_ptr(), libc::AT_REMOVEDIR) }) {
                Ok(_) => {
                    self.folders[i].entries = self.folders[i].entries.saturating_sub(1);
                    self.note_del(i, path);
                }
                Err(_) => kept += 1,
            }
        }
        Ok(kept)
    }

    /// `Ok(false)`: the host has no recorded `from` (the guest then sends `to` whole).
    fn rename(&mut self, i: usize, from: &[u8], to: &[u8]) -> io::Result<Result<bool, Kept>> {
        let ((fp, fname), (tp, tname)) = (split(from), split(to));
        let src = match self.open_dir(i, fp, false) {
            Ok(Ok(d)) => d,
            Ok(Err(_)) => return Ok(Ok(false)),
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP | libc::EXDEV)) => return Ok(Ok(false)),
            Err(e) => return Err(e),
        };
        let (fc, tc) = (cbytes(fname)?, cbytes(tname)?);
        let Ok(Some(_)) = self.owned(i, src.as_raw_fd(), &fc, from)? else { return Ok(Ok(false)) };
        let dst = match self.open_dir(i, tp, true)? {
            Ok(d) => d,
            Err(k) => return Ok(Err(k)),
        };
        let old = match self.owned(i, dst.as_raw_fd(), &tc, to)? {
            Ok(old) => old,
            Err(k) => return Ok(Err(k)),
        };
        if let Some(o) = &old {
            if kind_of(o) == Some(Kind::Dir) {
                return Ok(Err(Kept(format!("{} is a folder on the host", show(to)))));
            }
            // Replaced: the old file goes to the trash first, so nothing is unlinked.
            self.trash(i, dst.as_raw_fd(), &tc, to, o)?;
        }
        renameat(src.as_raw_fd(), &fc, dst.as_raw_fd(), &tc, true)?;
        fsync(dst.as_raw_fd())?;
        fsync(src.as_raw_fd())?;
        self.note(i, format!("> {} {}\n", hex(from), hex(to)));
        Ok(Ok(true))
    }

    /// The mode of a recorded entry. Never through a file with more than one name: a hard link
    /// the site owner made to a file outside the folder would carry the change there.
    fn chmod(&mut self, i: usize, path: &[u8], mode: u32) -> io::Result<Result<(), Kept>> {
        let fd = match open_beneath(self.folders[i].dir.as_raw_fd(), path, libc::O_RDONLY | libc::O_NONBLOCK) {
            Ok(fd) => fd,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP | libc::EXDEV)) => return Ok(Ok(())),
            Err(e) => return Err(e),
        };
        let st = fstat(fd.as_raw_fd())?;
        if !self.folders[i].record.matches(path, &st) {
            return Ok(Err(Kept(format!("{} is not the sync's on the host: its mode is the host's", show(path)))));
        }
        if kind_of(&st) == Some(Kind::File) && st.st_nlink > 1 {
            return Ok(Err(Kept(format!("{} has {} names on the host: its mode is never changed through one", show(path), st.st_nlink))));
        }
        fchmod(fd.as_raw_fd(), mode).map(Ok)
    }

    /// Folder `i` against the guest's listing (see the module's doc): records what agrees, asks
    /// for what the guest changed, trashes what it removed, and returns the host's entries to
    /// push. Linear in the entries (each path's folder is looked up once).
    fn reconcile(&mut self, i: usize, guest: &HashMap<&[u8], (Kind, Meta)>) -> io::Result<Plan> {
        let host = self.walk(i)?;
        let mut plan = Plan::default();
        let mut on_host: HashSet<&[u8]> = HashSet::new();
        let mut trash_files: Vec<(Vec<u8>, libc::stat)> = Vec::new();
        let mut rm_dirs: Vec<Vec<u8>> = Vec::new();
        let mut skipped: Vec<(&'static str, Vec<u8>)> = Vec::new();
        let mut set: Vec<(Vec<u8>, libc::stat)> = Vec::new();
        let mut chmods: Vec<(Vec<u8>, u32)> = Vec::new();
        {
            let rec = &self.folders[i].record;
            for (p, h) in &host {
                on_host.insert(p.as_slice());
                let Some(kind) = h.kind else {
                    skipped.push((if h.st.st_mode & libc::S_IFMT == libc::S_IFLNK { "a symlink" } else { "a device, socket or other mount" }, p.clone()));
                    continue;
                };
                if std::str::from_utf8(p).is_err() && rec.get(p).is_none() {
                    skipped.push(("a name that isn't UTF-8", p.clone()));
                    continue;
                }
                let matched = rec.matches(p, &h.st);
                match (kind, guest.get(p.as_slice())) {
                    (Kind::File, Some((Kind::File, g))) => {
                        if g.size == h.st.st_size as u64 && g.mtime == mtime_of(&h.st) {
                            set.push((p.clone(), h.st));
                            if g.nlink > 1 {
                                self.links.insert((i as u8, g.ino), p.clone());
                            }
                            if matched && g.mode & 0o777 != h.st.st_mode & 0o777 && h.st.st_nlink <= 1 {
                                chmods.push((p.clone(), g.mode));
                            }
                        } else if matched {
                            plan.needs.push(p.clone());
                        } else {
                            plan.pushes.push((p.clone(), Kind::File));
                        }
                    }
                    (Kind::Dir, Some((Kind::Dir, g))) => {
                        if !matched && rec.get(p).is_none() {
                            set.push((p.clone(), h.st));
                        }
                        if matched && g.mode & 0o777 != h.st.st_mode & 0o777 {
                            chmods.push((p.clone(), g.mode));
                        }
                    }
                    (Kind::File, _) if matched => trash_files.push((p.clone(), h.st)),
                    (Kind::Dir, _) if matched => rm_dirs.push(p.clone()),
                    (k, _) => plan.pushes.push((p.clone(), k)),
                }
            }
        }
        for (what, p) in skipped {
            self.skip(what, &p);
        }
        for (p, st) in set {
            self.note_set(i, &p, &st);
        }
        for (p, mode) in chmods {
            if let Err(e) = self.chmod(i, &p, mode) {
                self.log(&format!("chmod {}: {e}", show(&p)));
            }
        }
        let mut made: Vec<Vec<u8>> = Vec::new();
        for (p, (k, _)) in guest {
            if on_host.contains(p) {
                continue;
            }
            // Gone from the host (or never there): the record forgets it, the guest's copy comes.
            self.note_del(i, p);
            match k {
                Kind::File => plan.needs.push(p.to_vec()),
                Kind::Dir => made.push(p.to_vec()),
            }
        }
        made.sort();
        for p in made {
            let mode = guest.get(p.as_slice()).map_or(0o755, |(_, m)| m.mode);
            match self.mkdir(i, &p, mode) {
                Ok(Ok(())) => {}
                Ok(Err(Kept(why))) => self.log(&format!("mkdir {}: {why}", show(&p))),
                Err(e) => self.log(&format!("mkdir {}: {e}", show(&p))),
            }
        }
        for (p, st) in trash_files {
            let (parent, name) = split(&p);
            let res = match self.open_dir(i, parent, false) {
                Ok(Ok(d)) => cbytes(name).and_then(|c| self.trash(i, d.as_raw_fd(), &c, &p, &st)),
                Ok(Err(Kept(why))) => Err(io::Error::other(why)),
                Err(e) => Err(e),
            };
            match res {
                Ok(()) => plan.trashed += 1,
                Err(e) => self.log(&format!("to the trash {}: {e}", show(&p))),
            }
        }
        // Deepest first; a folder that still holds anything stays.
        rm_dirs.sort_by(|a, b| b.cmp(a));
        for p in rm_dirs {
            let (parent, name) = split(&p);
            if let Ok(Ok(d)) = self.open_dir(i, parent, false)
                && let Ok(c) = cbytes(name)
                // SAFETY: unlinkat(2) of a plain name: it fails unless the folder is empty.
                && unsafe { libc::unlinkat(d.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) } == 0
            {
                self.folders[i].entries = self.folders[i].entries.saturating_sub(1);
                self.note_del(i, &p);
            }
        }
        plan.needs.sort();
        // A folder's path sorts before everything in it: parents are pushed first.
        plan.pushes.sort_by(|a, b| a.0.cmp(&b.0));
        self.measure(i)?;
        Ok(plan)
    }

    /// Pushes the host's entries to the guest (folders first, parents before children), each
    /// answered by an [`Op::Pushed`]; what the guest took is recorded. (count, bytes) pushed.
    fn push_all(&mut self, i: usize, pushes: &[(Vec<u8>, Kind)], r: &mut impl Read, w: &mut impl Write) -> io::Result<(u64, u64)> {
        let (mut n, mut bytes) = (0, 0);
        for (p, k) in pushes {
            let opened = if *k == Kind::Dir {
                open_beneath(self.folders[i].dir.as_raw_fd(), p, DIR_FLAGS)
            } else {
                open_beneath(self.folders[i].dir.as_raw_fd(), p, libc::O_RDONLY | libc::O_NONBLOCK)
            };
            let Ok(fd) = opened else { continue };
            let st = fstat(fd.as_raw_fd())?;
            if kind_of(&st) != Some(*k) {
                continue;
            }
            let disk = i as u8;
            let commit = if *k == Kind::Dir {
                Self::reply(w, &Reply::PushDir { disk, path: p.clone(), mode: st.st_mode & 0o777 })?;
                true
            } else {
                let size = st.st_size as u64;
                Self::reply(w, &Reply::Push { disk, path: p.clone(), mode: st.st_mode & 0o777, mtime: mtime_of(&st), size })?;
                let mut counted = CountingWriter { w: &mut *w, n: 0 };
                let whole = write_chunks(&mut counted, fd.as_raw_fd(), size)?;
                bytes += counted.n;
                self.bytes.take(counted.n);
                let now = fstat(fd.as_raw_fd())?;
                let same = whole && now.st_size == st.st_size && mtime_of(&now) == mtime_of(&st);
                w.write_all(&[u8::from(same)])?;
                same
            };
            w.flush()?;
            match Op::read(r)? {
                Some(Op::Pushed { disk: d, path, ok }) if d == disk && &path == p => {
                    if ok && commit {
                        n += 1;
                        self.note_set(i, p, &st);
                    }
                }
                other => return Err(refuse(format!("want the answer to the push of {}, got {other:?}", show(p)))),
            }
        }
        self.pushed.0 += n;
        self.pushed.1 += bytes;
        Ok((n, bytes))
    }
}

struct CountingWriter<'a, W: Write> {
    w: &'a mut W,
    n: u64,
}

impl<W: Write> Write for CountingWriter<'_, W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.w.write(b)?;
        self.n += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

/// What a listing decided for one folder.
#[derive(Default)]
struct Plan {
    needs: Vec<Vec<u8>>,
    pushes: Vec<(Vec<u8>, Kind)>,
    trashed: usize,
}

/// The fds `securecore-fpm --sync-writer` gets per folder, from fd 3 on: the folder, its trash
/// folder, its record (read-only).
pub const WRITER_FIRST_FD: RawFd = 3;
pub const WRITER_FDS_PER_FOLDER: RawFd = 3;
/// The writer's address space, at most (its own `RLIMIT_AS`): a listing's worst case
/// ([`MAX_ENTRIES`], [`MAX_LISTING_BYTES`]) fits with room to spare.
pub const WRITER_MEMORY: u64 = 1 << 30;

/// Landlock and seccomp for the writer, after it holds its fds: it may touch nothing but what is
/// beneath `dirs` (its folders and their trash), and make only the system calls it needs. No new
/// privileges first (the launcher set it too).
pub fn confine(dirs: &[RawFd]) -> Result<(), String> {
    use landlock::{ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus};
    // SAFETY: prctl(2) with constant arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(format!("no_new_privs: {}", io::Error::last_os_error()));
    }
    let abi = ABI::V3;
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V1))
        .and_then(|r| r.set_compatibility(CompatLevel::BestEffort).handle_access(AccessFs::from_all(abi)))
        .and_then(|r| r.create())
        .map_err(|e| format!("Landlock: {e}"))?;
    for &fd in dirs {
        // SAFETY: a borrow of an fd the writer holds for its whole life.
        let b = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
        ruleset = ruleset.add_rule(PathBeneath::new(b, AccessFs::from_all(abi))).map_err(|e| format!("Landlock: {e}"))?;
    }
    let status = ruleset.restrict_self().map_err(|e| format!("Landlock: {e}"))?;
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err("Landlock: this kernel doesn't enforce it".into());
    }
    seccomp().map_err(|e| format!("seccomp: {e}"))
}

/// The writer's system calls; any other fails with EPERM.
fn seccomp() -> Result<(), String> {
    use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
    #[cfg(target_arch = "x86_64")]
    let arch = TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = TargetArch::aarch64;
    let mut calls = vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_lseek,
        libc::SYS_close,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_getdents64,
        libc::SYS_fcntl,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_ftruncate,
        libc::SYS_fchmod,
        libc::SYS_utimensat,
        libc::SYS_linkat,
        libc::SYS_renameat2,
        libc::SYS_unlinkat,
        libc::SYS_mkdirat,
        libc::SYS_copy_file_range,
        libc::SYS_sendfile,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_futex,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_tgkill,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_sched_yield,
        libc::SYS_getrandom,
        libc::SYS_ppoll,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];
    #[cfg(target_arch = "x86_64")]
    calls.extend([libc::SYS_poll, libc::SYS_renameat]);
    calls.sort();
    calls.dedup();
    let rules = calls.into_iter().map(|c| (c, Vec::new())).collect();
    let filter = SeccompFilter::new(rules, SeccompAction::Errno(libc::EPERM as u32), SeccompAction::Allow, arch).map_err(|e| e.to_string())?;
    let prog: seccompiler::BpfProgram = filter.try_into().map_err(|e: seccompiler::BackendError| e.to_string())?;
    seccompiler::apply_filter(&prog).map_err(|e| e.to_string())
}

/// `securecore-fpm --sync-writer <cap>[,<cap>…]`: the connection on fd 0, record changes
/// reported on fd 1, and per cap, from fd 3 on, a folder, its trash and its record. Refuses to
/// run as root; confines itself ([`confine`]) before it reads a byte from the guest. Returns the
/// exit code.
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
    let mut folders = Vec::new();
    let mut dirs = Vec::new();
    for (n, &cap) in caps.iter().enumerate() {
        let at = WRITER_FIRST_FD + WRITER_FDS_PER_FOLDER * n as RawFd;
        // SAFETY: the launcher put these three fds in place before exec.
        let (dir, trash, rec) = unsafe { (OwnedFd::from_raw_fd(at), OwnedFd::from_raw_fd(at + 1), std::fs::File::from_raw_fd(at + 2)) };
        let mut text = String::new();
        if let Err(e) = (&rec).take(256 << 20).read_to_string(&mut text) {
            eprintln!("securecore-fpm: sync: folder {n}'s record: {e}");
            return 1;
        }
        drop(rec);
        dirs.extend([dir.as_raw_fd(), trash.as_raw_fd()]);
        folders.push(Folder { dir, cap, trash, record: Record::parse(&text) });
    }
    if let Err(e) = confine(&dirs) {
        eprintln!("securecore-fpm: sync: the writer can't confine itself ({e}); refusing");
        return 125;
    }
    // SAFETY: fd 1 is the launcher's pipe for the record's changes.
    let report = unsafe { std::fs::File::from_raw_fd(1) };
    let mut writer = match Writer::new(folders, Limits::DEFAULT, Box::new(report)) {
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

/// What [`Guest::each`] calls for each entry: its path, kind and stat.
type EachFn<'a> = dyn FnMut(&[u8], Kind, &libc::stat) -> io::Result<()> + 'a;

struct Event {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: Option<Vec<u8>>,
}

/// One connection's worth of the guest's side: the disks' mount points, a handle on each, the
/// inotify watches, and the connection.
struct Guest<'a, R: Read, W: Write> {
    mounts: &'a [String],
    roots: Vec<OwnedFd>,
    ino: OwnedFd,
    wds: HashMap<i32, (u8, Vec<u8>)>,
    /// MOVED_FROM events still waiting for their MOVED_TO.
    moved: Vec<(u32, u8, Vec<u8>, bool)>,
    /// Files the host pushed in this connection (size, mtime): their own events aren't sent back.
    pushed: HashMap<(u8, Vec<u8>), (u64, Time)>,
    seq: u64,
    r: R,
    w: BufWriter<W>,
    log: &'a dyn Fn(&str),
}

/// Serves one host connection from the guest: watches every disk, sends the whole listing (and
/// takes what the host pushes), then every change, until the connection ends. `conn` is read
/// from `r` and written to `w` (two handles on it); `hangup` is its fd, watched for the host's
/// close.
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
        let c = cbytes(m.as_bytes())?;
        let fd = openat2_raw(libc::AT_FDCWD, &c, libc::O_PATH | libc::O_DIRECTORY, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: just returned.
        roots.push(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    let mut g = Guest {
        mounts,
        roots,
        ino,
        wds: HashMap::new(),
        moved: Vec::new(),
        pushed: HashMap::new(),
        seq: 0,
        r,
        w: BufWriter::with_capacity(256 << 10, w),
        log,
    };
    for d in 0..mounts.len() {
        g.watch_tree(d as u8, b"")?;
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

    fn root(&self, disk: u8) -> RawFd {
        self.roots[usize::from(disk)].as_raw_fd()
    }

    /// Watches the folder `rel` of `disk` and every folder in it.
    fn watch_tree(&mut self, disk: u8, rel: &[u8]) -> io::Result<()> {
        let mut stack = vec![(rel.to_vec(), 0usize)];
        while let Some((rel, depth)) = stack.pop() {
            let Ok(dir) = open_beneath(self.root(disk), &rel, DIR_FLAGS) else { continue };
            // Watched through its handle, so a link put in its place is never watched.
            let c = cbytes(format!("/proc/self/fd/{}", dir.as_raw_fd()).as_bytes())?;
            // SAFETY: inotify_add_watch(2) on a path; IN_DONT_FOLLOW|IN_ONLYDIR: a link isn't watched.
            let wd = unsafe { libc::inotify_add_watch(self.ino.as_raw_fd(), c.as_ptr(), WATCH_MASK & !libc::IN_DONT_FOLLOW) };
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
            for n in list_dir(dir.as_raw_fd())? {
                let name = n.to_bytes();
                if (rel.is_empty() && name == LOST_FOUND) || is_temp(name) {
                    continue;
                }
                if stat_at(dir.as_raw_fd(), &n).ok().and_then(|s| kind_of(&s)) == Some(Kind::Dir) {
                    stack.push((join(&rel, name), depth + 1));
                }
            }
        }
        Ok(())
    }

    /// Each file and folder under `rel` of `disk` (parents first), with its stat. Names that
    /// aren't UTF-8 are listed as their bytes.
    fn each(&self, disk: u8, rel: &[u8], f: &mut EachFn<'_>) -> io::Result<()> {
        let mut stack = vec![(rel.to_vec(), 0usize)];
        while let Some((rel, depth)) = stack.pop() {
            let Ok(dir) = open_beneath(self.root(disk), &rel, DIR_FLAGS) else { continue };
            let mut names = list_dir(dir.as_raw_fd())?;
            names.sort();
            for n in names {
                let name = n.to_bytes();
                if (rel.is_empty() && name == LOST_FOUND) || is_temp(name) {
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

    /// The whole tree; then what the host pushes, taken; then the files the host asks for.
    fn listing(&mut self) -> io::Result<()> {
        let mut ops = Vec::new();
        for d in 0..self.mounts.len() as u8 {
            self.each(d, b"", &mut |path, kind, st| {
                ops.push(Op::Entry { disk: d, path: path.to_vec(), kind, meta: meta_of(st) });
                Ok(())
            })?;
        }
        for op in &ops {
            self.send(op)?;
        }
        drop(ops);
        self.send(&Op::ListEnd)?;
        let mut needs = Vec::new();
        loop {
            match self.reply()? {
                Reply::Ok => break,
                Reply::Need { disk, path } => needs.push((disk, path)),
                Reply::Push { disk, path, mode, mtime, size } => {
                    let ok = self.take_push(disk, &path, mode, mtime, size)?;
                    self.send(&Op::Pushed { disk, path, ok })?;
                }
                Reply::PushDir { disk, path, mode } => {
                    let ok = self.take_dir(disk, &path, mode);
                    self.send(&Op::Pushed { disk, path, ok })?;
                }
                Reply::Err(e) => {
                    (self.log)(&format!("the host refused the listing: {e}"));
                    return Err(io::Error::other(e));
                }
                other => return Err(bad(format!("{other:?} in the listing's answer"))),
            }
        }
        for (disk, path) in needs {
            if usize::from(disk) < self.mounts.len() {
                self.put_tree(disk, &path)?;
            }
        }
        Ok(())
    }

    /// The folder `rel` of `disk`, made (with its parents) as needed.
    fn guest_dir(&self, disk: u8, rel: &[u8]) -> io::Result<OwnedFd> {
        let mut cur = open_beneath(self.root(disk), b"", DIR_FLAGS)?;
        for n in rel.split(|b| *b == b'/').filter(|n| !n.is_empty()) {
            let c = cbytes(n)?;
            // SAFETY: mkdirat(2) of a plain name in a folder we hold (EEXIST is fine).
            unsafe { libc::mkdirat(cur.as_raw_fd(), c.as_ptr(), 0o755) };
            cur = open_beneath(cur.as_raw_fd(), n, DIR_FLAGS)?;
        }
        Ok(cur)
    }

    fn take_dir(&self, disk: u8, rel: &[u8], mode: u32) -> bool {
        if usize::from(disk) >= self.mounts.len() {
            return false;
        }
        self.guest_dir(disk, rel).and_then(|d| fchmod(d.as_raw_fd(), mode)).is_ok()
    }

    /// A file the host pushed: its data read whole (always, to stay in step), written to a
    /// temporary file and renamed over `rel`. `false`: not taken (a folder is there, or an error).
    fn take_push(&mut self, disk: u8, rel: &[u8], mode: u32, mtime: Time, size: u64) -> io::Result<bool> {
        let (parent, name) = split(rel);
        let target = (usize::from(disk) < self.mounts.len())
            .then(|| self.guest_dir(disk, parent).ok())
            .flatten()
            .and_then(|d| tmpfile(d.as_raw_fd(), &mut self.seq).ok().map(|t| (d, t)));
        let fd = target.as_ref().map(|(_, (f, _))| f.as_raw_fd());
        if let Some(fd) = fd {
            // SAFETY: ftruncate(2) on our temporary file.
            unsafe { libc::ftruncate(fd, size as libc::off_t) };
        }
        let got = read_chunks(&mut self.r, fd, size, u64::MAX, &mut None)?;
        let commit = read_u8(&mut self.r)? == 1;
        let Some((dir, (tmp, named))) = target else { return Ok(false) };
        let drop_named = |n: &Option<CString>| {
            if let Some(n) = n {
                unlink(dir.as_raw_fd(), n);
            }
        };
        if got.err.is_some() || !commit {
            drop_named(&named);
            return Ok(false);
        }
        let res = (|| -> io::Result<()> {
            fchmod(tmp.as_raw_fd(), mode)?;
            set_mtime(tmp.as_raw_fd(), mtime)?;
            fsync(tmp.as_raw_fd())?;
            let n = name_tmp(dir.as_raw_fd(), tmp.as_raw_fd(), named.clone(), &mut self.seq)?;
            let c = cbytes(name)?;
            if let Err(e) = renameat(dir.as_raw_fd(), &n, dir.as_raw_fd(), &c, false) {
                unlink(dir.as_raw_fd(), &n);
                return Err(e);
            }
            fsync(dir.as_raw_fd())
        })();
        if let Err(e) = res {
            (self.log)(&format!("taking the host's {}: {e}", show(rel)));
            return Ok(false);
        }
        self.pushed.insert((disk, rel.to_vec()), (size, mtime));
        Ok(true)
    }

    /// Sends the file `rel` of `disk`, after making it durable on the guest's disk: its header,
    /// then (if the host says go) its data extents and the commit byte.
    fn put(&mut self, disk: u8, rel: &[u8]) -> io::Result<()> {
        let root = self.root(disk);
        let fd = match open_beneath(root, rel, libc::O_RDONLY | libc::O_NONBLOCK) {
            Ok(fd) => fd,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)) => return Ok(()),
            Err(e) => return Err(e),
        };
        let st = fstat(fd.as_raw_fd())?;
        if kind_of(&st) != Some(Kind::File) {
            return Ok(());
        }
        let key = (disk, rel.to_vec());
        if self.pushed.get(&key) == Some(&(st.st_size as u64, mtime_of(&st))) {
            // The host's own push, as written here: nothing to send back.
            return Ok(());
        }
        self.pushed.remove(&key);
        // Durable here before the host has it: a crash after this loses nothing (the next
        // listing sends it again).
        fsync(fd.as_raw_fd())?;
        if let Ok(parent) = open_beneath(root, split(rel).0, DIR_FLAGS) {
            let _ = fsync(parent.as_raw_fd());
        }
        let st = fstat(fd.as_raw_fd())?;
        let what = show(rel);
        self.send(&Op::Put { disk, path: rel.to_vec(), meta: meta_of(&st) })?;
        match self.reply()? {
            Reply::Go => {}
            Reply::Linked => return Ok(()),
            Reply::Err(e) => {
                (self.log)(&format!("the host refused {what}: {e}"));
                return Ok(());
            }
            other => return Err(bad(format!("{other:?} for a put"))),
        }
        let whole = write_chunks(&mut self.w, fd.as_raw_fd(), st.st_size as u64)?;
        let now = fstat(fd.as_raw_fd())?;
        let same = now.st_size == st.st_size && mtime_of(&now) == mtime_of(&st);
        self.w.write_all(&[u8::from(whole && same)])?;
        self.ok_or_log(&what)?;
        Ok(())
    }

    /// `rel` of `disk` whole: a file, or a folder with everything in it.
    fn put_tree(&mut self, disk: u8, rel: &[u8]) -> io::Result<()> {
        let Ok(fd) = open_beneath(self.root(disk), rel, libc::O_PATH) else { return Ok(()) };
        let st = fstat(fd.as_raw_fd())?;
        match kind_of(&st) {
            Some(Kind::File) => self.put(disk, rel),
            Some(Kind::Dir) => {
                let mut items = vec![(rel.to_vec(), Kind::Dir, st.st_mode & 0o777)];
                self.each(disk, rel, &mut |p, k, s| {
                    items.push((p.to_vec(), k, s.st_mode & 0o777));
                    Ok(())
                })?;
                for (p, k, mode) in items {
                    match k {
                        Kind::Dir => {
                            self.send(&Op::Mkdir { disk, path: p.clone(), mode })?;
                            self.ok_or_log(&show(&p))?;
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
            self.simple(Op::Remove { disk, path: rel.clone() }, &show(&rel))?;
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
            let name = raw.split(|b| *b == 0).next().filter(|s| !s.is_empty()).map(<[u8]>::to_vec);
            out.push(Event { wd: ev.wd, mask: ev.mask, cookie: ev.cookie, name });
            at += head + len;
        }
        Ok(out)
    }

    fn unwatch(&mut self, disk: u8, rel: &[u8], is_dir: bool) {
        if !is_dir {
            return;
        }
        let mut prefix = rel.to_vec();
        prefix.push(b'/');
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
                self.watch_tree(d, b"")?;
            }
            return self.listing();
        }
        if ev.mask & libc::IN_IGNORED != 0 {
            self.wds.remove(&ev.wd);
            return Ok(());
        }
        let (Some((disk, dir)), Some(name)) = (self.wds.get(&ev.wd).cloned(), ev.name) else { return Ok(()) };
        if (dir.is_empty() && name == LOST_FOUND) || is_temp(&name) {
            return Ok(());
        }
        let rel = join(&dir, &name);
        if check_path(&rel).is_err() {
            return Ok(());
        }
        let is_dir = ev.mask & libc::IN_ISDIR != 0;
        let what = show(&rel);
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
                            let mut prefix = from.clone();
                            prefix.push(b'/');
                            for (d, p) in self.wds.values_mut() {
                                if *d == disk && (*p == from || p.starts_with(&prefix)) {
                                    let mut moved = rel.clone();
                                    moved.extend_from_slice(&p[from.len()..]);
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
                let linked = open_beneath(self.root(disk), &rel, libc::O_PATH).and_then(|f| fstat(f.as_raw_fd())).is_ok_and(|s| s.st_nlink > 1 && kind_of(&s) == Some(Kind::File));
                if linked {
                    self.put(disk, &rel)?;
                }
            }
        } else if ev.mask & libc::IN_CLOSE_WRITE != 0 {
            self.put(disk, &rel)?;
        } else if ev.mask & libc::IN_DELETE != 0 {
            self.simple(Op::Remove { disk, path: rel }, &what)?;
        } else if ev.mask & libc::IN_ATTRIB != 0
            && let Ok(st) = open_beneath(self.root(disk), &rel, libc::O_PATH).and_then(|f| fstat(f.as_raw_fd()))
            && kind_of(&st).is_some()
        {
            self.simple(Op::Chmod { disk, path: rel, mode: st.st_mode & 0o777 }, &what)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
