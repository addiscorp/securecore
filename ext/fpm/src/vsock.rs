//! vsock and the byte bridges between sockets (addiscorp/securecore#71), shared by the host
//! driver ([`crate::vm`]) and the guest's init ([`crate::guest`]). Linux only.
//!
//! Two rules from #70 live here, because both sides need them:
//! - [`join_closing`]: Firecracker drops a guest's half-close (a vsock SHUTDOWN carrying only
//!   SEND never reaches the host's socket), so the guest's forwarders shut both sockets down
//!   completely as soon as either direction ends. A forwarder that only half-closed left every
//!   FastCGI request hanging after its headers.
//! - [`connect_through`]: the `CONNECT <port>` line on Firecracker's host-side socket goes out
//!   in one write. Firecracker reads it without blocking, and a line split over several writes
//!   was dropped ("error adding local-init connection: WouldBlock"), giving nginx a 502.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::Duration;

/// The host's CID, as the guest dials it.
pub const HOST_CID: u32 = libc::VMADDR_CID_HOST;

/// An `AF_VSOCK` stream socket (std has none).
pub struct Vsock(OwnedFd);

fn sockaddr(cid: u32, port: u32) -> libc::sockaddr_vm {
    libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: cid,
        svm_zero: [0; 4],
    }
}

fn check(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
}

impl Vsock {
    fn socket() -> io::Result<OwnedFd> {
        // SAFETY: socket(2) with constant arguments; a non-negative result is a new fd we own.
        let fd = check(unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) })?;
        // SAFETY: fd was just returned by socket(2) and nothing else owns it.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Connects to `cid:port` (from the guest: the host is [`HOST_CID`]).
    pub fn connect(cid: u32, port: u32) -> io::Result<Vsock> {
        let fd = Vsock::socket()?;
        let a = sockaddr(cid, port);
        let len = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
        // SAFETY: a valid sockaddr_vm of the size passed, on a socket we own.
        check(unsafe { libc::connect(fd.as_raw_fd(), (&raw const a).cast(), len) })?;
        Ok(Vsock(fd))
    }

    /// Listens on `port` for any CID (in the guest: connections from the host).
    pub fn listen(port: u32) -> io::Result<Vsock> {
        let fd = Vsock::socket()?;
        let a = sockaddr(libc::VMADDR_CID_ANY, port);
        let len = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
        // SAFETY: as in connect; listen(2) on the socket just bound.
        check(unsafe { libc::bind(fd.as_raw_fd(), (&raw const a).cast(), len) })?;
        // SAFETY: listen(2) on a bound socket we own.
        check(unsafe { libc::listen(fd.as_raw_fd(), 128) })?;
        Ok(Vsock(fd))
    }

    /// The next connection, and the CID it came from (the host is [`HOST_CID`]).
    pub fn accept(&self) -> io::Result<(Vsock, u32)> {
        let mut peer = sockaddr(0, 0);
        let mut len = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
        // SAFETY: accept4(2) writing at most `len` bytes into `peer`; a non-negative result is
        // a new fd we own.
        let fd = check(unsafe {
            libc::accept4(self.0.as_raw_fd(), (&raw mut peer).cast(), &mut len, libc::SOCK_CLOEXEC)
        })?;
        // SAFETY: fd was just returned by accept4(2).
        Ok((Vsock(unsafe { OwnedFd::from_raw_fd(fd) }), peer.svm_cid))
    }

    /// SO_RCVTIMEO: a read waits at most `t`.
    pub fn set_read_timeout(&self, t: Duration) -> io::Result<()> {
        let tv = libc::timeval { tv_sec: t.as_secs() as libc::time_t, tv_usec: t.subsec_micros() as libc::suseconds_t };
        let len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
        // SAFETY: setsockopt(2) reading the timeval passed, on a socket we own.
        check(unsafe { libc::setsockopt(self.0.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&raw const tv).cast(), len) })?;
        Ok(())
    }
}

impl AsRawFd for Vsock {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}

impl Read for Vsock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: buf is valid for buf.len() bytes, on an fd we own.
        let n = unsafe { libc::read(self.0.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
    }
}

impl Write for Vsock {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: buf is valid for buf.len() bytes, on an fd we own.
        let n = unsafe { libc::write(self.0.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
        if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One end of a bridged connection: it can be duplicated (one copy per direction) and shut.
pub trait Half: Read + Write + Send + Sized + 'static {
    fn dup(&self) -> io::Result<Self>;
    fn shut(&self, how: std::net::Shutdown);
}

impl Half for Vsock {
    fn dup(&self) -> io::Result<Self> {
        Ok(Vsock(self.0.try_clone()?))
    }
    fn shut(&self, how: std::net::Shutdown) {
        let how = match how {
            std::net::Shutdown::Read => libc::SHUT_RD,
            std::net::Shutdown::Write => libc::SHUT_WR,
            std::net::Shutdown::Both => libc::SHUT_RDWR,
        };
        // SAFETY: shutdown(2) on an fd we own.
        unsafe { libc::shutdown(self.0.as_raw_fd(), how) };
    }
}

impl Half for UnixStream {
    fn dup(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shut(&self, how: std::net::Shutdown) {
        let _ = self.shutdown(how);
    }
}

impl Half for TcpStream {
    fn dup(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shut(&self, how: std::net::Shutdown) {
        let _ = self.shutdown(how);
    }
}

/// Copies both ways, each direction half-closing its destination when its source ends. For the
/// host side, where Firecracker passes the host's half-close on to the guest.
pub fn join<A: Half, B: Half>(a: A, b: B) -> io::Result<()> {
    let (a2, b2) = (a.dup()?, b.dup()?);
    thread::spawn(move || {
        let (mut a, mut b2) = (a, b2);
        let _ = io::copy(&mut a, &mut b2);
        b2.shut(std::net::Shutdown::Write);
    });
    thread::spawn(move || {
        let (mut b, mut a2) = (b, a2);
        let _ = io::copy(&mut b, &mut a2);
        a2.shut(std::net::Shutdown::Write);
    });
    Ok(())
}

/// [`join`] for the guest: the first direction to end shuts both connections down completely,
/// as `socat -t 0` does (see the module header).
pub fn join_closing<A: Half, B: Half>(a: A, b: B) -> io::Result<()> {
    let (a2, b2) = (a.dup()?, b.dup()?);
    let (a3, b3) = (a.dup()?, b.dup()?);
    let (a4, b4) = (a.dup()?, b.dup()?);
    thread::spawn(move || {
        let (mut a, mut b2) = (a, b2);
        let _ = io::copy(&mut a, &mut b2);
        a3.shut(std::net::Shutdown::Both);
        b3.shut(std::net::Shutdown::Both);
    });
    thread::spawn(move || {
        let (mut b, mut a2) = (b, a2);
        let _ = io::copy(&mut b, &mut a2);
        a4.shut(std::net::Shutdown::Both);
        b4.shut(std::net::Shutdown::Both);
    });
    Ok(())
}

/// A connection from the host to guest `port`, through Firecracker's host-side vsock socket
/// `uds`: the `CONNECT` line in one write (see the module header), then Firecracker's `OK`.
pub fn connect_through(uds: &Path, port: u32, timeout: Duration) -> io::Result<UnixStream> {
    let mut s = UnixStream::connect(uds)?;
    s.set_read_timeout(Some(timeout))?;
    s.write_all(format!("CONNECT {port}\n").as_bytes())?;
    // Byte by byte, so nothing after the handshake line is consumed here.
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        if s.read(&mut b)? == 0 {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("vsock {port}: closed before OK")));
        }
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
    }
    if !line.starts_with(b"OK ") {
        return Err(io::Error::other(format!("vsock {port}: {}", String::from_utf8_lossy(&line))));
    }
    s.set_read_timeout(None)?;
    Ok(s)
}
