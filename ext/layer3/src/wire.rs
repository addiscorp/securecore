//! Layer 3's wire (Linux): how the php-fpm workers, the helper and the isolated children talk.
//!
//! - **The control socket** is a `SOCK_SEQPACKET` socketpair made at MINIT. php-fpm's master
//!   keeps one end, so every worker inherits it; the helper gets the other. Each message is one
//!   packet, so workers sharing the socket never interleave. A worker sends `R` with one end of a
//!   fresh per-request socketpair attached (`SCM_RIGHTS`), or `K<pid>` to have an isolated child
//!   killed. The helper turns on `SO_PASSCRED`, so the kernel stamps each packet with the
//!   sender's uid and gid: the helper drops to the pool user it sees, and ignores any other.
//! - **The request socket** is that per-request socketpair (`SOCK_STREAM`), carrying
//!   length-prefixed frames ([`write_frame`], [`read_frame`]): the worker's [`Hello`], the
//!   helper's `snapshot?` and the worker's snapshot, then the child's `ready` and, per call, the
//!   worker's call and the child's answer.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::Instant;

/// The largest frame either side accepts (a snapshot, a call's arguments or its answer).
pub const MAX_FRAME: usize = 32 << 20;
/// The largest control packet (a [`Hello`] forwarded to a zygote, with its tag).
pub const MAX_PACKET: usize = 64 << 10;

/// The helper's first frame back when its booted WordPress is not from this snapshot.
pub const NEED_SNAPSHOT: &[u8] = b"snapshot?";
/// A child's first frame: `ready <pid>\n` then the registrations (PHP-serialized).
pub const READY: &[u8] = b"ready ";
/// A frame the helper or child sends instead of `ready` when it can't serve the request.
pub const ERROR: &[u8] = b"error ";

fn cvt(r: libc::ssize_t) -> io::Result<usize> {
    usize::try_from(r).map_err(|_| io::Error::last_os_error())
}

/// An `AF_UNIX` socketpair of `kind` (`SOCK_STREAM` / `SOCK_SEQPACKET`), close-on-exec.
pub fn socketpair(kind: libc::c_int) -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: a two-int out array, as socketpair(2) takes.
    if unsafe { libc::socketpair(libc::AF_UNIX, kind | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: two fresh descriptors this call owns.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Waits until `fd` is ready for `events`, or `deadline` passes (`TimedOut`).
fn wait(fd: BorrowedFd<'_>, events: libc::c_short, deadline: Option<Instant>) -> io::Result<()> {
    loop {
        let timeout = match deadline {
            None => -1,
            Some(d) => {
                let left = d.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                libc::c_int::try_from(left.as_millis().max(1)).unwrap_or(libc::c_int::MAX)
            }
        };
        let mut p = libc::pollfd { fd: fd.as_raw_fd(), events, revents: 0 };
        // SAFETY: one pollfd.
        match unsafe { libc::poll(&mut p, 1, timeout) } {
            0 => {}
            n if n > 0 => return Ok(()),
            _ => {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
    }
}

fn send_all(fd: BorrowedFd<'_>, mut buf: &[u8], deadline: Option<Instant>) -> io::Result<()> {
    while !buf.is_empty() {
        wait(fd, libc::POLLOUT, deadline)?;
        // SAFETY: a live buffer; MSG_NOSIGNAL so a closed peer is EPIPE, never SIGPIPE.
        match cvt(unsafe { libc::send(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) }) {
            Ok(n) => buf = &buf[n..],
            Err(e) if matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Fills `buf`. `Ok(false)`: the peer closed before the first byte.
fn recv_exact(fd: BorrowedFd<'_>, buf: &mut [u8], deadline: Option<Instant>) -> io::Result<bool> {
    let mut got = 0;
    while got < buf.len() {
        wait(fd, libc::POLLIN, deadline)?;
        let rest = &mut buf[got..];
        // SAFETY: a live buffer of rest.len() bytes.
        match cvt(unsafe { libc::recv(fd.as_raw_fd(), rest.as_mut_ptr().cast(), rest.len(), libc::MSG_DONTWAIT) }) {
            Ok(0) if got == 0 => return Ok(false),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Writes one frame: a 4-byte big-endian length, then `body`.
pub fn write_frame(fd: BorrowedFd<'_>, body: &[u8], deadline: Option<Instant>) -> io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(io::Error::other(format!("frame of {} bytes is over the {MAX_FRAME}-byte limit", body.len())));
    }
    let len = u32::try_from(body.len()).map_err(io::Error::other)?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    send_all(fd, &out, deadline)
}

/// Reads one frame. `Ok(None)`: the peer closed between frames.
pub fn read_frame(fd: BorrowedFd<'_>, deadline: Option<Instant>) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    if !recv_exact(fd, &mut len, deadline)? {
        return Ok(None);
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::other(format!("frame of {len} bytes is over the {MAX_FRAME}-byte limit")));
    }
    let mut body = vec![0; len];
    if len > 0 && !recv_exact(fd, &mut body, deadline)? {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(Some(body))
}

/// A control packet as received: its bytes, the descriptor attached to it, and (with
/// `SO_PASSCRED` on) the sender's uid and gid as the kernel saw them.
#[derive(Debug)]
pub struct Packet {
    pub body: Vec<u8>,
    pub fd: Option<OwnedFd>,
    pub creds: Option<(u32, u32)>,
}

/// Turns on `SO_PASSCRED`: every packet received on `sock` carries its sender's credentials.
pub fn pass_credentials(sock: BorrowedFd<'_>) -> io::Result<()> {
    let on: libc::c_int = 1;
    // SAFETY: an int option of the right size.
    let r = unsafe {
        libc::setsockopt(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PASSCRED, (&raw const on).cast(), size_of::<libc::c_int>() as libc::socklen_t)
    };
    if r != 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Sends one packet, with `fd` attached when given. Blocks (control packets are tiny).
pub fn send_packet(sock: BorrowedFd<'_>, body: &[u8], fd: Option<BorrowedFd<'_>>) -> io::Result<()> {
    let mut iov = libc::iovec { iov_base: body.as_ptr().cast_mut().cast(), iov_len: body.len() };
    // Room for one SCM_RIGHTS with one int, aligned as cmsg(3) wants.
    let mut control = [0u64; 4];
    // SAFETY: a zeroed msghdr, filled in below with live pointers.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    if let Some(fd) = fd {
        // SAFETY: CMSG_SPACE/CMSG_LEN are pure; the buffer is large enough for one int.
        unsafe {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as _;
            libc::CMSG_DATA(cmsg).cast::<libc::c_int>().write_unaligned(fd.as_raw_fd());
        }
    }
    loop {
        // SAFETY: msg points at live buffers for the call.
        match cvt(unsafe { libc::sendmsg(sock.as_raw_fd(), &raw const msg, libc::MSG_NOSIGNAL) }) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Receives one packet, waiting until `deadline` (`TimedOut`) or forever. `Ok(None)`: the peer
/// closed. A received descriptor is close-on-exec.
pub fn recv_packet(sock: BorrowedFd<'_>, deadline: Option<Instant>) -> io::Result<Option<Packet>> {
    let mut body = vec![0u8; MAX_PACKET];
    let mut iov = libc::iovec { iov_base: body.as_mut_ptr().cast(), iov_len: body.len() };
    // Room for SCM_RIGHTS (a few ints) and SCM_CREDENTIALS.
    let mut control = [0u64; 16];
    loop {
        wait(sock, libc::POLLIN, deadline)?;
        // SAFETY: a zeroed msghdr pointing at live buffers.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of_val(&control) as _;
        // SAFETY: as above.
        let n = match cvt(unsafe { libc::recvmsg(sock.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT) }) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock) => continue,
            Err(e) => return Err(e),
        };
        let mut fd = None;
        let mut creds = None;
        // SAFETY: walking the control messages the kernel wrote into `control`.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            while let Some(c) = cmsg.as_ref() {
                if c.cmsg_level == libc::SOL_SOCKET && c.cmsg_type == libc::SCM_RIGHTS {
                    let data = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
                    let count = c.cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize) / size_of::<libc::c_int>();
                    for i in 0..count {
                        let owned = OwnedFd::from_raw_fd(data.add(i).read_unaligned());
                        // Keep the first; any extra one closes when dropped here.
                        if fd.is_none() {
                            fd = Some(owned);
                        }
                    }
                } else if c.cmsg_level == libc::SOL_SOCKET && c.cmsg_type == libc::SCM_CREDENTIALS {
                    let cred = libc::CMSG_DATA(cmsg).cast::<libc::ucred>().read_unaligned();
                    creds = Some((cred.uid, cred.gid));
                }
                cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
            }
        }
        if n == 0 && fd.is_none() {
            return Ok(None);
        }
        body.truncate(n);
        return Ok(Some(Packet { body, fd, creds }));
    }
}

/// What a worker tells the helper about one request for one isolated plugin. Text, one field per
/// line, so neither side needs PHP to read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// The isolated plugin's slug.
    pub slug: String,
    /// The plugin file WordPress is loading (absolute).
    pub file: String,
    /// WordPress's `ABSPATH`.
    pub abspath: String,
    /// The table prefix.
    pub prefix: String,
    /// sha256 of the worker's core-options snapshot: the helper re-boots when it differs.
    pub snapshot_sha: String,
    /// sha256 of the worker's live securecore.json: the child reloads when it differs.
    pub config_sha: String,
    /// The worker's connection facts the child's `$wpdb` reports without a connection (no
    /// credential: no host, user, password or database name).
    pub db: DbFacts,
}

/// What `$wpdb` knows about its connection that WordPress and plugins read without querying:
/// `$wpdb->charset` / `collate` (`get_charset_collate()`, dbDelta), `db_version()` (`has_cap()`)
/// and `db_server_info()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DbFacts {
    pub charset: String,
    pub collate: String,
    pub version: String,
    pub server_info: String,
}

const HELLO_MAGIC: &str = "securecore-layer3/2";

impl Hello {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let d = &self.db;
        let fields = [
            &self.slug,
            &self.file,
            &self.abspath,
            &self.prefix,
            &self.snapshot_sha,
            &self.config_sha,
            &d.charset,
            &d.collate,
            &d.version,
            &d.server_info,
        ];
        if let Some(bad) = fields.iter().find(|f| f.contains('\n') || f.contains('\0')) {
            return Err(format!("layer3: a hello field contains a newline or NUL: {bad:?}"));
        }
        let mut out = String::from(HELLO_MAGIC);
        for f in fields {
            out.push('\n');
            out.push_str(f);
        }
        Ok(out.into_bytes())
    }

    pub fn decode(bytes: &[u8]) -> Result<Hello, String> {
        let text = std::str::from_utf8(bytes).map_err(|_| "layer3: hello is not UTF-8".to_owned())?;
        let mut lines = text.split('\n');
        if lines.next() != Some(HELLO_MAGIC) {
            return Err("layer3: not a hello".into());
        }
        let mut next = || lines.next().map(str::to_owned).ok_or_else(|| "layer3: hello is short".to_owned());
        let hello = Hello {
            slug: next()?,
            file: next()?,
            abspath: next()?,
            prefix: next()?,
            snapshot_sha: next()?,
            config_sha: next()?,
            db: DbFacts { charset: next()?, collate: next()?, version: next()?, server_info: next()? },
        };
        if lines.next().is_some() {
            return Err("layer3: hello has extra lines".into());
        }
        Ok(hello)
    }
}

/// A child's `ready` frame: its pid and the payload.
pub fn encode_ready(pid: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = format!("ready {pid}\n").into_bytes();
    out.extend_from_slice(payload);
    out
}

/// The pid and payload of a `ready` frame.
pub fn decode_ready(frame: &[u8]) -> Option<(i32, &[u8])> {
    let rest = frame.strip_prefix(READY)?;
    let nl = rest.iter().position(|&b| b == b'\n')?;
    let pid = std::str::from_utf8(&rest[..nl]).ok()?.parse().ok()?;
    Some((pid, &rest[nl + 1..]))
}

/// A kill request: `K` and the pid.
pub fn encode_kill(pid: i32) -> Vec<u8> {
    let mut out = vec![b'K'];
    out.extend_from_slice(&pid.to_be_bytes());
    out
}

pub fn decode_kill(body: &[u8]) -> Option<i32> {
    let rest = body.strip_prefix(b"K")?;
    Some(i32::from_be_bytes(rest.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::time::Duration;

    #[test]
    fn hello_round_trips_and_rejects_newlines() {
        let h = Hello {
            slug: "hello".into(),
            file: "/var/www/html/wp-content/plugins/hello.php".into(),
            abspath: "/var/www/html/".into(),
            prefix: "wp_".into(),
            snapshot_sha: "ab".repeat(32),
            config_sha: "cd".repeat(32),
            db: DbFacts {
                charset: "utf8mb4".into(),
                collate: "utf8mb4_unicode_520_ci".into(),
                version: "11.4.4".into(),
                server_info: "11.4.4-MariaDB-ubu2404".into(),
            },
        };
        assert_eq!(Hello::decode(&h.encode().unwrap()).unwrap(), h);
        let bad = Hello { db: DbFacts { server_info: "x\ny".into(), ..h.db.clone() }, ..h.clone() };
        assert!(bad.encode().is_err(), "a newline in the db facts is refused too");
        let bad = Hello { slug: "a\nb".into(), ..h.clone() };
        assert!(bad.encode().is_err());
        assert!(Hello::decode(b"other\n").is_err());
        let mut extra = h.encode().unwrap();
        extra.extend_from_slice(b"\nmore");
        assert!(Hello::decode(&extra).is_err());
    }

    #[test]
    fn ready_and_kill_round_trip() {
        let f = encode_ready(4242, b"a:0:{}");
        assert_eq!(decode_ready(&f), Some((4242, &b"a:0:{}"[..])));
        assert_eq!(decode_ready(b"error nope"), None);
        assert_eq!(decode_kill(&encode_kill(77)), Some(77));
        assert_eq!(decode_kill(b"R"), None);
    }

    /// A hostile peer's length prefix is checked before anything is allocated or read: a header
    /// claiming more than MAX_FRAME is refused at once, with its body never sent.
    #[test]
    fn an_oversized_frame_is_refused_from_its_header() {
        let (a, b) = socketpair(libc::SOCK_STREAM).unwrap();
        let len = u32::try_from(MAX_FRAME + 1).unwrap();
        send_all(a.as_fd(), &len.to_be_bytes(), None).unwrap();
        let e = read_frame(b.as_fd(), Some(Instant::now() + Duration::from_secs(5))).unwrap_err();
        assert!(e.to_string().contains("over the"), "{e}");
        send_all(a.as_fd(), &u32::MAX.to_be_bytes(), None).unwrap();
        assert!(read_frame(b.as_fd(), Some(Instant::now() + Duration::from_secs(5))).is_err());
        // And a writer can't send one.
        assert!(write_frame(a.as_fd(), &vec![0; MAX_FRAME + 1], None).is_err());
    }

    #[test]
    fn frames_cross_a_socketpair_and_time_out() {
        let (a, b) = socketpair(libc::SOCK_STREAM).unwrap();
        let big = vec![7u8; 3 << 20];
        let writer = std::thread::spawn({
            let big = big.clone();
            move || {
                write_frame(a.as_fd(), b"one", None).unwrap();
                write_frame(a.as_fd(), &big, None).unwrap();
                write_frame(a.as_fd(), b"", None).unwrap();
                a
            }
        });
        assert_eq!(read_frame(b.as_fd(), None).unwrap().unwrap(), b"one");
        assert_eq!(read_frame(b.as_fd(), None).unwrap().unwrap(), big);
        assert_eq!(read_frame(b.as_fd(), None).unwrap().unwrap(), b"");
        let a = writer.join().unwrap();
        // Nothing more is coming: a deadline turns the wait into TimedOut, not a hang.
        let e = read_frame(b.as_fd(), Some(Instant::now() + Duration::from_millis(50))).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        drop(a);
        assert!(read_frame(b.as_fd(), None).unwrap().is_none(), "a closed peer is a clean end");
    }

    #[test]
    fn packets_carry_a_descriptor_and_the_senders_credentials() {
        let (ctl_a, ctl_b) = socketpair(libc::SOCK_SEQPACKET).unwrap();
        pass_credentials(ctl_b.as_fd()).unwrap();
        let (req_a, req_b) = socketpair(libc::SOCK_STREAM).unwrap();
        send_packet(ctl_a.as_fd(), b"R", Some(req_b.as_fd())).unwrap();
        drop(req_b);
        let p = recv_packet(ctl_b.as_fd(), None).unwrap().unwrap();
        assert_eq!(p.body, b"R");
        // SAFETY: plain getters.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        assert_eq!(p.creds, Some((uid, gid)));
        // The descriptor received is the other end of req_a.
        let got = p.fd.unwrap();
        write_frame(req_a.as_fd(), b"through", None).unwrap();
        assert_eq!(read_frame(got.as_fd(), None).unwrap().unwrap(), b"through");
        send_packet(ctl_a.as_fd(), &encode_kill(9), None).unwrap();
        let k = recv_packet(ctl_b.as_fd(), None).unwrap().unwrap();
        assert_eq!(decode_kill(&k.body), Some(9));
        assert!(k.fd.is_none());
        drop(ctl_a);
        assert!(recv_packet(ctl_b.as_fd(), None).unwrap().is_none());
    }
}
