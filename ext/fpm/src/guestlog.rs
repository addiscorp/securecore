//! The guest's log channel to the host (vsock 1514, addiscorp/securecore#86): php-fpm's output
//! and the init's own lines, delivered so that no line is ever lost without the launcher saying so.
//!
//! A `write()` that returns in the guest only means the guest's kernel took the bytes: a restore
//! resets every vsock connection, and Firecracker drops what a guest sends on a connection whose
//! host side is closing. So the guest keeps every line until the host has acknowledged it:
//!
//! ```text
//!   guest → host   K <key hex>\n         first, on every connection: this VM's log key
//!                  L <seq> <text>\n      one line (text holds no newline)
//!                  X <seq> <count>\n     <count> lines dropped here (the guest's buffer was full)
//!   host → guest   A <seq>\n             every frame up to <seq> is in the launcher's log
//! ```
//!
//! - **Only the init writes the log.** Any process in the guest can open a vsock connection to
//!   host port 1514, so the host takes frames only from a connection that first presents this
//!   VM's log key: [`KEY_LEN`] random bytes the launcher makes per VM (kept with a snapshot, which
//!   holds it in the init's memory) and gives the init over the control port, which only the host
//!   can reach. A connection without it is refused, and the refusals are counted in the
//!   launcher's own log ([`LogServer`]). It gets [`HELLO_TIMEOUT`] to present the key; at most
//!   [`MAX_PENDING`] connections wait at once (the oldest is dropped for a new one), so nothing in
//!   the guest can hold the port, and keyed connections have places of their own.
//! - **The guest** ([`Outbox`], [`send`]) numbers each line, queues it (up to [`OUTBOX_BYTES`]),
//!   sends it on one connection and drops it once acknowledged. A broken connection, or one on
//!   which nothing is acknowledged for [`ACK_STALL`], is replaced, and every unacknowledged frame
//!   is sent again; reconnects back off while no connection gets an acknowledgement. A line that
//!   doesn't fit in the buffer is counted, and the count goes out as a frame of its own, in order,
//!   before the next line.
//! - **The host** ([`Inbox`], [`serve`]) logs each frame once (a frame sent again is skipped by
//!   its number), every line marked `guest: `, and acknowledges only what it has written. A count
//!   frame, or a gap in the numbers, becomes the launcher's own line `securecore-fpm: N guest log
//!   lines lost (…)`; a gap larger than the guest's buffer could ever make ends the connection.
//!
//! Plain Rust over any connection ([`Conn`]), so the tests drive it over unix sockets.

use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// The longest guest log line kept whole; a longer one is cut there and marked.
pub const MAX_LINE: usize = 8 * 1024;
/// What the guest holds for the host before it starts counting lines as lost.
pub const OUTBOX_BYTES: usize = 4 << 20;
/// A connection on which unacknowledged frames wait this long without an acknowledgement is
/// replaced (the host may be gone without the guest's kernel knowing).
pub const ACK_STALL: Duration = Duration::from_secs(2);
/// The log key's length in bytes (sent as hex).
pub const KEY_LEN: usize = 32;
/// How long a connection has to present the key.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(1);
/// Connections waiting to present the key at once: a new one replaces the oldest.
pub const MAX_PENDING: usize = 16;
/// Keyed connections at once (the init's current one, and one it is giving up): a new one
/// replaces the oldest.
pub const MAX_STREAMS: usize = 2;
/// The most frames the guest's buffer can hold (each line counts at least 64 bytes against
/// [`OUTBOX_BYTES`]): a jump in the numbers larger than this is no loss but a broken stream.
pub const MAX_JUMP: u64 = (OUTBOX_BYTES / 64) as u64;

/// The part of the guest's buffer only the init's own lines may use.
pub const INIT_RESERVE: usize = 256 << 10;
/// A log key: [`KEY_LEN`] random bytes.
pub type Key = [u8; KEY_LEN];
/// Where the host's log lines go (whole lines, each call one write).
pub type Emit = Box<dyn Fn(&str) -> io::Result<()> + Send + Sync>;

/// One frame from the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// php-fpm's output (its master's and every worker's stderr).
    Line { seq: u64, text: Vec<u8> },
    /// The init's own line: tagged apart on the wire, so nothing php-fpm writes can read as it.
    Init { seq: u64, text: Vec<u8> },
    Lost { seq: u64, count: u64 },
}

impl Frame {
    pub fn seq(&self) -> u64 {
        match self {
            Frame::Line { seq, .. } | Frame::Init { seq, .. } | Frame::Lost { seq, .. } => *seq,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Frame::Line { seq, text } | Frame::Init { seq, text } => {
                let kind = if matches!(self, Frame::Init { .. }) { "I" } else { "L" };
                let mut out = format!("{kind} {seq} ").into_bytes();
                out.extend_from_slice(text);
                out.push(b'\n');
                out
            }
            Frame::Lost { seq, count } => format!("X {seq} {count}\n").into_bytes(),
        }
    }

    /// One received line, without its newline. `None`: not a frame.
    pub fn parse(line: &[u8]) -> Option<Frame> {
        let (kind, rest) = (line.first()?, line.get(1..)?);
        let rest = rest.strip_prefix(b" ")?;
        let sp = rest.iter().position(|&b| b == b' ');
        let (num, tail) = match sp {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, &b""[..]),
        };
        let seq = std::str::from_utf8(num).ok()?.parse::<u64>().ok().filter(|s| *s > 0)?;
        match kind {
            b'L' if sp.is_some() => Some(Frame::Line { seq, text: tail.to_vec() }),
            b'I' if sp.is_some() => Some(Frame::Init { seq, text: tail.to_vec() }),
            b'X' => Some(Frame::Lost { seq, count: std::str::from_utf8(tail).ok()?.parse().ok()? }),
            _ => None,
        }
    }
}

/// The host's acknowledgement of every frame up to `seq`.
pub fn ack_line(seq: u64) -> String {
    format!("A {seq}\n")
}

fn parse_ack(line: &str) -> Option<u64> {
    line.strip_prefix("A ")?.trim_end().parse().ok()
}

/// The first line of every log connection.
pub fn hello_line(key: &Key) -> String {
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    format!("K {hex}\n")
}

/// A key line's length, its newline included.
const HELLO_LEN: usize = 2 + 2 * KEY_LEN + 1;

/// Bytes waiting to be read on `c` (0 if it can't say).
fn waiting(c: &UnixStream) -> usize {
    use std::os::fd::AsRawFd as _;
    let mut n: libc::c_int = 0;
    // SAFETY: FIONREAD writes one int, on a socket we hold.
    if unsafe { libc::ioctl(c.as_raw_fd(), libc::FIONREAD, &mut n) } < 0 { 0 } else { n.max(0) as usize }
}

/// The first line of a connection, read a byte at a time (so nothing after it is taken), by
/// `deadline` at the latest, however slowly the bytes come: `None` when none came in time, or
/// the connection ended first, or it is longer than a key line.
fn read_hello(mut c: &UnixStream, deadline: Instant) -> Option<Vec<u8>> {
    let mut line = Vec::with_capacity(HELLO_LEN);
    let mut b = [0u8; 1];
    loop {
        let left = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())?;
        c.set_read_timeout(Some(left)).ok()?;
        match c.read(&mut b) {
            Ok(1) if b[0] == b'\n' => return Some(line),
            Ok(1) if line.len() < HELLO_LEN => line.push(b[0]),
            _ => return None,
        }
    }
}

/// Whether `line` (without its newline) presents `key`. Compared in constant time.
pub fn hello_ok(line: &[u8], key: &Key) -> bool {
    let want = hello_line(key);
    let want = want.trim_end().as_bytes();
    if line.len() != want.len() {
        return false;
    }
    line.iter().zip(want).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// Reads one line of at most `cap` bytes into `line` (without its newline, a trailing `\r`
/// dropped): `Some(cut)` when a line was read (`cut`: it was longer, and the rest was skipped),
/// `None` at the end of the stream with nothing read. Never buffers more than `cap`.
pub fn read_capped(r: &mut impl BufRead, line: &mut Vec<u8>, cap: usize) -> Option<bool> {
    line.clear();
    let mut cut = false;
    loop {
        let buf = match r.fill_buf() {
            Ok([]) | Err(_) => {
                return if line.is_empty() && !cut { None } else { Some(cut) };
            }
            Ok(b) => b,
        };
        let (take, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (i, true),
            None => (buf.len(), false),
        };
        let room = cap.saturating_sub(line.len());
        line.extend_from_slice(&buf[..take.min(room)]);
        cut |= take > room;
        r.consume(if done { take + 1 } else { take });
        if done {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Some(cut);
        }
    }
}

#[derive(Debug, Default)]
struct Queue {
    /// Unacknowledged frames, oldest first, each with its encoding.
    frames: VecDeque<(u64, Vec<u8>)>,
    bytes: usize,
    /// The last number given out.
    seq: u64,
    /// Lines dropped since the last count frame.
    lost: u64,
    /// Bumped each time the connection in use is given up.
    conn: u64,
    /// When an acknowledgement last arrived (or the connection was made).
    acked_at: Option<Instant>,
    /// Acknowledgements that moved the queue on, ever: a connection that adds none counts as a
    /// failed one, and the next waits longer.
    acks: u64,
    /// This VM's log key, once the host has given it.
    key: Option<Key>,
}

impl Queue {
    fn push(&mut self, frame: impl FnOnce(u64) -> Frame) {
        self.seq += 1;
        let bytes = frame(self.seq).encode();
        self.bytes += bytes.len();
        self.frames.push_back((self.seq, bytes));
    }

    fn push_lost(&mut self) {
        if self.lost > 0 {
            let count = std::mem::take(&mut self.lost);
            self.push(|seq| Frame::Lost { seq, count });
        }
    }
}

/// The guest's lines for the host, held until acknowledged ([`send`] delivers them).
pub struct Outbox {
    q: Mutex<Queue>,
    cv: Condvar,
    cap: usize,
}

impl Outbox {
    pub const fn new(cap: usize) -> Outbox {
        Outbox {
            q: Mutex::new(Queue { frames: VecDeque::new(), bytes: 0, seq: 0, lost: 0, conn: 0, acked_at: None, acks: 0, key: None }),
            cv: Condvar::new(),
            cap,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.q.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The key the host takes this VM's lines with. A new one ends the connection in use (the
    /// next one presents the new key).
    pub fn set_key(&self, key: Key) {
        let mut q = self.lock();
        if q.key != Some(key) {
            q.key = Some(key);
            q.conn += 1;
        }
        self.cv.notify_all();
    }

    /// Queues one line (cut at [`MAX_LINE`]); it is never written to the caller's stream, so a
    /// slow host never blocks php-fpm. When the buffer is full the line is counted as lost, and
    /// the count is sent, in order, before the next line that fits.
    pub fn line(&self, text: &[u8]) {
        self.queue(text, false);
    }

    /// The init's own line ([`Frame::Init`]): it may use the last [`INIT_RESERVE`] bytes of the
    /// buffer, which php-fpm's lines never take, so a flood on php-fpm's stderr can't crowd it
    /// out (#86 verification review).
    pub fn init_line(&self, text: &[u8]) {
        self.queue(text, true);
    }

    fn queue(&self, text: &[u8], init: bool) {
        let mut text = text.to_vec();
        if text.len() > MAX_LINE {
            text.truncate(MAX_LINE);
            text.extend_from_slice(" …[cut]".as_bytes());
        }
        let mut q = self.lock();
        // A count frame is small; the line must fit beside it.
        let need = text.len() + 64;
        let room = if init { self.cap } else { self.cap.saturating_sub(INIT_RESERVE.min(self.cap / 2)) };
        if q.bytes + need > room {
            q.lost += 1;
            return;
        }
        q.push_lost();
        q.push(|seq| if init { Frame::Init { seq, text } } else { Frame::Line { seq, text } });
        self.cv.notify_all();
    }

    /// The host has every frame up to `seq`.
    pub fn ack(&self, seq: u64) {
        let mut q = self.lock();
        let mut progressed = false;
        while q.frames.front().is_some_and(|(s, _)| *s <= seq) {
            let (_, b) = q.frames.pop_front().unwrap_or_default();
            q.bytes -= b.len();
            progressed = true;
        }
        if progressed {
            q.acked_at = Some(Instant::now());
            q.acks += 1;
        }
        self.cv.notify_all();
    }

    /// Frames not yet acknowledged (and lines counted but not yet sent as a count).
    pub fn pending(&self) -> (usize, u64) {
        let q = self.lock();
        (q.frames.len(), q.lost)
    }

    /// Waits up to `timeout` for the host to have every line; the count still pending if not.
    /// A count of lost lines is queued first, so the host hears of them too.
    pub fn drain(&self, timeout: Duration) -> Result<(), usize> {
        let t = Instant::now();
        let mut q = self.lock();
        if q.lost > 0 {
            q.push_lost();
            self.cv.notify_all();
        }
        while !q.frames.is_empty() {
            let left = timeout.saturating_sub(t.elapsed());
            if left.is_zero() {
                return Err(q.frames.len());
            }
            q = self.cv.wait_timeout(q, left).unwrap_or_else(|p| p.into_inner()).0;
        }
        Ok(())
    }

    /// Gives up connection `conn` (if it is still the one in use).
    fn broken(&self, conn: u64) {
        let mut q = self.lock();
        if q.conn == conn {
            q.conn += 1;
        }
        self.cv.notify_all();
    }
}

/// A connection the log goes over: duplicated for the acknowledgement reader, and shut to end it.
pub trait Conn: Read + Write + Send + Sized + 'static {
    fn dup(&self) -> io::Result<Self>;
    fn shut(&self);
}

impl Conn for UnixStream {
    fn dup(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shut(&self) {
        let _ = self.shutdown(std::net::Shutdown::Both);
    }
}

#[cfg(target_os = "linux")]
impl Conn for crate::vsock::Vsock {
    fn dup(&self) -> io::Result<Self> {
        crate::vsock::Half::dup(self)
    }
    fn shut(&self) {
        crate::vsock::Half::shut(self, std::net::Shutdown::Both);
    }
}

/// The first wait between two connections that got nothing acknowledged, and the longest.
const BACKOFF: (Duration, Duration) = (Duration::from_millis(10), Duration::from_secs(1));

/// Delivers `outbox` for ever over connections from `connect`: one at a time, once the host has
/// given the key; each new one presents the key, then every unacknowledged frame again. A
/// connection that fails, or ends without moving the queue on (the host refused it), makes the
/// next wait longer, up to a second.
pub fn send<C: Conn>(outbox: &'static Outbox, connect: impl Fn() -> io::Result<C>) -> ! {
    let mut backoff = BACKOFF.0;
    loop {
        // Nothing to send, or no key yet: wait before connecting.
        let (key, acks) = {
            let mut q = outbox.lock();
            while q.frames.is_empty() || q.key.is_none() {
                q = outbox.cv.wait(q).unwrap_or_else(|p| p.into_inner());
            }
            (q.key.unwrap_or_default(), q.acks)
        };
        let moved_on = match connect() {
            Ok(conn) => {
                let _ = deliver(outbox, conn, &key);
                outbox.lock().acks != acks
            }
            Err(_) => false,
        };
        if moved_on {
            backoff = BACKOFF.0;
        } else {
            thread::sleep(backoff);
            backoff = (backoff * 2).min(BACKOFF.1);
        }
    }
}

/// One connection's life: the key, then its acknowledgements read on a thread of their own and
/// frames written from the oldest unacknowledged one on, until it breaks or stalls. Every way out
/// shuts it.
fn deliver<C: Conn>(outbox: &'static Outbox, mut conn: C, key: &Key) -> io::Result<()> {
    let id = {
        let mut q = outbox.lock();
        q.acked_at = Some(Instant::now());
        q.conn
    };
    if let Err(e) = conn.write_all(hello_line(key).as_bytes()) {
        conn.shut();
        return Err(e);
    }
    let reader = conn.dup()?;
    let acks = thread::spawn(move || {
        let mut r = BufReader::new(reader);
        let mut line = Vec::new();
        while let Some(false) = read_capped(&mut r, &mut line, 64) {
            match std::str::from_utf8(&line).ok().and_then(parse_ack) {
                Some(seq) => outbox.ack(seq),
                None => break,
            }
        }
        outbox.broken(id);
    });
    let mut sent = 0u64;
    let result = loop {
        let batch: Vec<u8> = {
            let mut q = outbox.lock();
            loop {
                if q.conn != id {
                    break;
                }
                let stalled = !q.frames.is_empty() && q.acked_at.is_some_and(|t| t.elapsed() > ACK_STALL);
                if stalled {
                    q.conn += 1;
                    break;
                }
                if q.frames.back().is_some_and(|(s, _)| *s > sent) {
                    break;
                }
                q = outbox.cv.wait_timeout(q, Duration::from_millis(250)).unwrap_or_else(|p| p.into_inner()).0;
            }
            if q.conn != id {
                break Ok(());
            }
            // Nothing sent before is still waiting: the wait for an acknowledgement starts now.
            if q.frames.front().is_some_and(|(s, _)| *s > sent) {
                q.acked_at = Some(Instant::now());
            }
            let mut batch = Vec::new();
            let from = sent;
            for (s, b) in q.frames.iter().filter(|(s, _)| *s > from) {
                if batch.len() + b.len() > 256 << 10 && !batch.is_empty() {
                    break;
                }
                batch.extend_from_slice(b);
                sent = *s;
            }
            batch
        };
        if let Err(e) = conn.write_all(&batch) {
            outbox.broken(id);
            break Err(e);
        }
    };
    conn.shut();
    let _ = acks.join();
    result
}

/// The host's view of one guest's log: the last frame logged.
#[derive(Debug, Default)]
pub struct Inbox {
    last: Option<u64>,
    /// The guest's last few lines, for the launcher to quote when the VM stops on its own (#87).
    recent: VecDeque<String>,
}

/// How many of the guest's last lines an [`Inbox`] keeps to quote.
pub const RECENT: usize = 6;

impl Inbox {
    /// What `frame` adds to the launcher's log: nothing for a frame already logged; a count of
    /// the lines lost for a gap before it or a count frame; the guest's line marked as the guest's.
    /// A jump larger than [`MAX_JUMP`] is refused: no buffer of the guest's could make it.
    pub fn take(&mut self, frame: &Frame, cut: bool) -> Result<Vec<String>, String> {
        let seq = frame.seq();
        let mut out = Vec::new();
        if let Some(last) = self.last {
            if seq <= last {
                return Ok(out);
            }
            if seq - last > MAX_JUMP {
                return Err(format!("frame {seq} after frame {last}: a jump no guest buffer can make"));
            }
            if seq > last + 1 {
                out.push(lost_line(seq - last - 1, "missing from the guest's numbered stream"));
            }
        }
        self.last = Some(seq);
        match frame {
            Frame::Line { text, .. } | Frame::Init { text, .. } => {
                let init = matches!(frame, Frame::Init { .. });
                if self.recent.len() == RECENT {
                    self.recent.pop_front();
                }
                // Quoted with its label (#87): which of the guest's lines is the init's own.
                let label = if init { "guest-init: " } else { "" };
                self.recent.push_back(format!("{label}{}", String::from_utf8_lossy(text).chars().take(1024).collect::<String>()));
                out.push(if init { init_line(text, cut) } else { guest_line(text, cut) });
            }
            Frame::Lost { count, .. } => out.push(lost_line(*count, "the guest's log buffer was full")),
        }
        Ok(out)
    }

    pub fn last(&self) -> Option<u64> {
        self.last
    }

    /// The guest's last lines, oldest first, as one quotable string (`a | b | c`).
    pub fn recent(&self) -> String {
        // Each line quoted and escaped (#87 review): what the guest wrote can't close the quote,
        // start a line of its own or read as the launcher's words inside the launcher's line.
        self.recent.iter().map(|l| format!("{l:?}")).collect::<Vec<_>>().join(" | ")
    }
}

/// Why lines still in the guest's buffer when it stops are lost (the guest's `sync` reply).
pub const UNACKED_AT_STOP: &str = "not acknowledged by the host before the stop";

/// The launcher's own line for lines that never arrived.
pub fn lost_line(count: u64, why: &str) -> String {
    format!("securecore-fpm: {}", lost(count, why))
}

/// `N guest log lines lost (why)`: the count the launcher logs, whichever side found it.
pub fn lost(count: u64, why: &str) -> String {
    format!("{count} guest log line{} lost ({why})", if count == 1 { "" } else { "s" })
}

/// A guest's line as the launcher logs it: marked, so it never reads as the launcher's own.
pub fn guest_line(text: &[u8], cut: bool) -> String {
    format!("guest: {}{}", escaped(text), if cut { " …[cut]" } else { "" })
}

/// The init's own line as the launcher logs it: a label of its own, which nothing php-fpm writes
/// can produce (its lines are always `guest: `).
pub fn init_line(text: &[u8], cut: bool) -> String {
    format!("guest-init: {}{}", escaped(text), if cut { " …[cut]" } else { "" })
}

/// A guest's text with every control character but the tab, and the Unicode line separators
/// (U+0085, U+2028, U+2029), written as `\u{…}` (#86 verification review): one guest line stays
/// one log line, whatever a terminal or a log viewer makes of its bytes. (A tab can't end a line
/// or move the cursor back, and SQL in PHP's lines is full of them.)
pub fn escaped(text: &[u8]) -> String {
    let mut out = String::with_capacity(text.len());
    for c in String::from_utf8_lossy(text).chars() {
        if (c.is_control() && c != '\t') || matches!(c, '\u{85}' | '\u{2028}' | '\u{2029}') {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// The longest frame line the host reads whole: a line, its number and its kind.
const MAX_FRAME: usize = MAX_LINE + 64;

/// Why [`serve`] stopped before the end of its stream.
#[derive(Debug, PartialEq, Eq)]
pub enum Stop {
    /// The launcher's log couldn't be written: nothing more is acknowledged, so the guest keeps
    /// the lines and sends them again.
    Log(String),
    /// The stream broke the protocol.
    Protocol(String),
}

/// One keyed log connection on the host: frames from `from`, written with `emit` through `inbox`
/// (the guest's one stream state, shared by its connections), each batch acknowledged on `ack`
/// once it is written, never before. A line that isn't a frame is logged as the guest's,
/// unnumbered.
pub fn serve(from: impl Read, mut ack: impl Write, inbox: &Mutex<Inbox>, emit: &dyn Fn(&str) -> io::Result<()>) -> Result<(), Stop> {
    let mut r = BufReader::with_capacity(64 << 10, from);
    let mut line = Vec::with_capacity(256);
    while let Some(cut) = read_capped(&mut r, &mut line, MAX_FRAME) {
        {
            // Held while the lines are written: a frame counts as logged only once it is.
            let mut inbox = inbox.lock().unwrap_or_else(|p| p.into_inner());
            let before = inbox.last;
            let out = match Frame::parse(&line) {
                Some(frame) => inbox.take(&frame, cut).map_err(Stop::Protocol)?,
                None => vec![guest_line(&line, cut)],
            };
            if !out.is_empty() {
                let mut text = out.join("\n");
                text.push('\n');
                if let Err(e) = emit(&text) {
                    inbox.last = before;
                    return Err(Stop::Log(e.to_string()));
                }
            }
        }
        // Once what has arrived is logged: acknowledge it.
        if r.buffer().is_empty() {
            let last = inbox.lock().unwrap_or_else(|p| p.into_inner()).last();
            if let Some(last) = last
                && ack.write_all(ack_line(last).as_bytes()).is_err()
            {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// The host's end of one guest's log port: every connection to it goes through [`LogServer::take`],
/// which lets in only those that present `key`, and logs everything with `emit` (the launcher's
/// stderr). Refused connections are counted, and said at most once a second.
pub struct LogServer {
    key: Key,
    inbox: Mutex<Inbox>,
    emit: Emit,
    pending: Mutex<VecDeque<(u64, UnixStream)>>,
    streams: Mutex<VecDeque<(u64, UnixStream)>>,
    next: AtomicU64,
    refused: AtomicU64,
    said: Mutex<(Option<Instant>, u64)>,
    /// A restored VM's snapshot key: the restored init presents it until it gets this VM's own
    /// (a moment later), so it is refused quietly, counted apart, and never let in.
    stale: Option<Key>,
    stale_refused: AtomicU64,
}

impl LogServer {
    pub fn new(key: Key, stale: Option<Key>, emit: Emit) -> LogServer {
        LogServer {
            key,
            inbox: Mutex::new(Inbox::default()),
            emit,
            pending: Mutex::new(VecDeque::new()),
            streams: Mutex::new(VecDeque::new()),
            next: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            said: Mutex::new((None, 0)),
            stale,
            stale_refused: AtomicU64::new(0),
        }
    }

    /// Says what hasn't been said yet (the last second's refusals, the stale key's), when the VM
    /// stops (#86 verification review).
    pub fn flush(&self) {
        let n = self.refused();
        let mut said = self.said.lock().unwrap_or_else(|p| p.into_inner());
        if n > said.1 {
            let _ = (self.emit)(&format!(
                "securecore-fpm: refused {} more guest log connection{} without this VM's log key before the stop ({n} in all)\n",
                n - said.1,
                if n - said.1 == 1 { "" } else { "s" }
            ));
            *said = (Some(Instant::now()), n);
        }
        let stale = self.stale_refused.swap(0, Ordering::SeqCst);
        if stale > 0 {
            let _ = (self.emit)(&format!(
                "securecore-fpm: refused {stale} guest log connection{} with the snapshot's old log key (the restored init's, until this VM's own reached it)\n",
                if stale == 1 { "" } else { "s" }
            ));
        }
    }

    /// The guest's stream state (for the launcher to quote, #87).
    pub fn inbox(&self) -> &Mutex<Inbox> {
        &self.inbox
    }

    /// Connections refused so far (no key, a wrong one, or none in time).
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::SeqCst)
    }

    /// Keeps `conn` among at most `max` in `set`, shutting one out to make room: the oldest that
    /// hasn't a whole key line waiting to be read. One that has (the init's, its hello written the
    /// moment it connected) is spared, so a churn of keyless connections can't keep evicting it
    /// (#86 verification review). Its id.
    fn hold(&self, set: &Mutex<VecDeque<(u64, UnixStream)>>, conn: &UnixStream, max: usize) -> u64 {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let mut s = set.lock().unwrap_or_else(|p| p.into_inner());
        while s.len() >= max {
            let victim = s.iter().position(|(_, c)| waiting(c) < HELLO_LEN).unwrap_or(0);
            if let Some((_, old)) = s.remove(victim) {
                let _ = old.shutdown(std::net::Shutdown::Both);
            }
        }
        if let Ok(c) = conn.try_clone() {
            s.push_back((id, c));
        }
        id
    }

    fn release(&self, set: &Mutex<VecDeque<(u64, UnixStream)>>, id: u64) {
        set.lock().unwrap_or_else(|p| p.into_inner()).retain(|(i, _)| *i != id);
    }

    fn refuse(&self, why: &str) {
        let n = self.refused.fetch_add(1, Ordering::SeqCst) + 1;
        let mut said = self.said.lock().unwrap_or_else(|p| p.into_inner());
        if said.0.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
            let _ = (self.emit)(&format!(
                "securecore-fpm: refused {} guest log connection{} without this VM's log key ({why}; {n} so far): only the guest's init writes the log\n",
                n - said.1,
                if n - said.1 == 1 { "" } else { "s" }
            ));
            *said = (Some(Instant::now()), n);
        }
    }

    /// Serves one connection to the log port, to its end.
    pub fn take(&self, conn: UnixStream) {
        let id = self.hold(&self.pending, &conn, MAX_PENDING);
        let hello = read_hello(&conn, Instant::now() + HELLO_TIMEOUT);
        self.release(&self.pending, id);
        match hello {
            Some(h) if hello_ok(&h, &self.key) => {}
            Some(h) if self.stale.is_some_and(|k| hello_ok(&h, &k)) => {
                let _ = conn.shutdown(std::net::Shutdown::Both);
                self.stale_refused.fetch_add(1, Ordering::SeqCst);
                return;
            }
            None => {
                let _ = conn.shutdown(std::net::Shutdown::Both);
                return self.refuse("it sent no key line within a second");
            }
            Some(_) => {
                let _ = conn.shutdown(std::net::Shutdown::Both);
                return self.refuse("it sent something else first");
            }
        }
        let r = BufReader::with_capacity(64 << 10, conn);
        let conn = r.get_ref();
        let _ = conn.set_read_timeout(None);
        let id = self.hold(&self.streams, conn, MAX_STREAMS);
        let Ok(ack) = conn.try_clone() else {
            self.release(&self.streams, id);
            return;
        };
        let result = serve(r, &ack, &self.inbox, &*self.emit);
        self.release(&self.streams, id);
        match result {
            Ok(()) => {}
            Err(Stop::Log(e)) => {
                // Most likely unwritable too, but the guest keeps the lines either way.
                eprintln!("securecore-fpm: the launcher's log can't be written ({e}); the guest keeps its lines until it can");
            }
            Err(Stop::Protocol(e)) => {
                let _ = (self.emit)(&format!("securecore-fpm: closed a guest log connection: {e}\n"));
            }
        }
        let _ = ack.shutdown(std::net::Shutdown::Both);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    fn leak(cap: usize) -> &'static Outbox {
        Box::leak(Box::new(Outbox::new(cap)))
    }

    /// A log in memory, written as the launcher's stderr is.
    #[derive(Clone, Default)]
    struct Log(Arc<Mutex<Vec<u8>>>);
    impl Log {
        fn emit(&self) -> Emit {
            let l = self.0.clone();
            Box::new(move |s| {
                l.lock().expect("log").extend_from_slice(s.as_bytes());
                Ok(())
            })
        }
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("log").clone()).expect("utf8")
        }
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sc-guestlog-{name}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("log.sock");
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn frames_round_trip_and_junk_is_no_frame() {
        for f in [Frame::Line { seq: 7, text: b"PHP message: a b  c".to_vec() }, Frame::Line { seq: 1, text: Vec::new() }, Frame::Lost { seq: 9, count: 12 }] {
            let e = f.encode();
            assert_eq!(e.last(), Some(&b'\n'));
            assert_eq!(Frame::parse(&e[..e.len() - 1]), Some(f.clone()), "{f:?}");
        }
        for junk in [&b"NOTICE: ready"[..], b"L x hi", b"L 0 hi", b"L 5", b"X 5 many", b"", b"A 5"] {
            assert_eq!(Frame::parse(junk), None, "{}", String::from_utf8_lossy(junk));
        }
        assert_eq!(parse_ack("A 42\n"), Some(42));
        let key = [7u8; KEY_LEN];
        let hello = hello_line(&key);
        assert!(hello_ok(hello.trim_end().as_bytes(), &key));
        assert!(!hello_ok(hello_line(&[8u8; KEY_LEN]).trim_end().as_bytes(), &key), "another key");
        assert!(!hello_ok(b"K 0707", &key), "a short one");
    }

    /// A frame sent again (after a reconnect) is logged once; a gap is counted; a count frame is
    /// the launcher's own line; the guest can't write a line that reads as the launcher's; a jump
    /// no buffer can make is refused.
    #[test]
    fn the_host_logs_each_frame_once_and_counts_what_is_missing() {
        let mut inbox = Inbox::default();
        let line = |seq, t: &str| Frame::Line { seq, text: t.as_bytes().to_vec() };
        assert_eq!(inbox.take(&line(3, "a"), false).expect("ok"), ["guest: a"]);
        assert_eq!(inbox.take(&line(4, "securecore-fpm: forged"), false).expect("ok"), ["guest: securecore-fpm: forged"]);
        assert!(inbox.take(&line(3, "a"), false).expect("ok").is_empty(), "sent again: logged once");
        assert_eq!(inbox.take(&line(7, "d"), false).expect("ok"), ["securecore-fpm: 2 guest log lines lost (missing from the guest's numbered stream)", "guest: d"]);
        assert_eq!(inbox.take(&Frame::Lost { seq: 8, count: 1 }, false).expect("ok"), ["securecore-fpm: 1 guest log line lost (the guest's log buffer was full)"]);
        assert_eq!(inbox.take(&line(9, "long"), true).expect("ok"), ["guest: long …[cut]"]);
        assert!(inbox.take(&line(u64::MAX, "x"), false).is_err(), "a jump to the end of the numbers");
        assert_eq!(inbox.last(), Some(9), "and it moved nothing");
        assert_eq!(inbox.take(&line(10, "next"), false).expect("ok"), ["guest: next"]);
        // The last RECENT lines, to quote when the guest stops on its own (#87), each quoted and
        // escaped (#87 review), so a guest line can't end the quote or start a line of its own.
        for i in 11..20 {
            inbox.take(&line(i, &format!("l{i}")), false).expect("ok");
        }
        inbox.take(&line(20, "x\" | securecore-fpm: forged\nsecurecore-fpm: also"), false).expect("ok");
        assert_eq!(inbox.recent(), r#""l15" | "l16" | "l17" | "l18" | "l19" | "x\" | securecore-fpm: forged\nsecurecore-fpm: also""#);
        assert!(!inbox.recent().contains('\n'));
    }

    /// A line is acknowledged only once it is in the launcher's log (#86 review): a write that
    /// fails stops the connection, acknowledges nothing, and leaves the frame unlogged, so the
    /// guest's copy is sent again and logged then.
    #[test]
    fn a_line_the_log_could_not_take_is_never_acknowledged() {
        let inbox = Mutex::new(Inbox::default());
        let mut acks = Vec::new();
        let broken = |_: &str| -> io::Result<()> { Err(io::Error::other("disk full")) };
        let r = serve(&b"L 1 audit\n"[..], &mut acks, &inbox, &broken);
        assert_eq!(r, Err(Stop::Log("disk full".into())));
        assert!(acks.is_empty(), "nothing acknowledged: {:?}", String::from_utf8_lossy(&acks));
        assert_eq!(inbox.lock().expect("inbox").last(), None, "not counted as logged");
        let log = Log::default();
        let mut acks = Vec::new();
        serve(&b"L 1 audit\n"[..], &mut acks, &inbox, &*log.emit()).expect("serves");
        assert_eq!(log.text(), "guest: audit\n", "sent again, logged then");
        assert_eq!(acks, b"A 1\n");
    }

    #[test]
    fn long_lines_are_cut_and_never_buffered_whole() {
        let long = format!("{}\nnext\r\n", "x".repeat(MAX_FRAME * 3));
        let mut r = BufReader::new(long.as_bytes());
        let mut line = Vec::new();
        assert_eq!(read_capped(&mut r, &mut line, MAX_FRAME), Some(true));
        assert_eq!(line.len(), MAX_FRAME);
        assert_eq!(read_capped(&mut r, &mut line, MAX_FRAME), Some(false));
        assert_eq!(line, b"next");
        assert_eq!(read_capped(&mut r, &mut line, MAX_FRAME), None);
        let ob = leak(1 << 20);
        ob.line("y".repeat(MAX_LINE * 2).as_bytes());
        let q = ob.lock();
        let f = Frame::parse(q.frames[0].1.strip_suffix(b"\n").expect("newline")).expect("a frame");
        let Frame::Line { text, .. } = f else { panic!("a line") };
        assert!(text.len() < MAX_LINE + 16 && text.ends_with(" …[cut]".as_bytes()));
    }

    /// A full buffer drops lines, but never silently: their count arrives in order, as the
    /// launcher's own line, before the next line that fit.
    #[test]
    fn a_full_buffer_is_counted_and_the_count_is_delivered() {
        let ob = leak(400);
        for i in 0..20 {
            ob.line(format!("line {i:02} {}", "z".repeat(40)).as_bytes());
        }
        let (queued, lost) = ob.pending();
        assert!(queued > 0 && lost > 0 && queued as u64 + lost == 20, "queued {queued} lost {lost}");
        ob.ack(u64::MAX);
        ob.line(b"after");
        let log = Log::default();
        let inbox = Mutex::new(Inbox { last: Some(queued as u64), ..Inbox::default() });
        let frames: Vec<u8> = ob.lock().frames.iter().flat_map(|(_, b)| b.clone()).collect();
        serve(&frames[..], io::sink(), &inbox, &*log.emit()).expect("serves");
        assert_eq!(log.text(), format!("securecore-fpm: {lost} guest log lines lost (the guest's log buffer was full)\nguest: after\n"));
    }

    /// The host's side of the stress below: a keyed log server that, for its first `drops`
    /// connections, reads a few frames and then closes without a word (a restore's reset, a dying
    /// connection) or keeps silent (Firecracker dropping a closing connection's data); then
    /// serves for real.
    fn flaky_host(l: UnixListener, drops: usize, server: Arc<LogServer>, conns: Arc<AtomicUsize>) {
        for (n, c) in l.incoming().flatten().enumerate() {
            conns.fetch_add(1, Ordering::SeqCst);
            if n < drops {
                let mut r = BufReader::new(c);
                let mut line = Vec::new();
                for _ in 0..(n * 7 % 50) {
                    if read_capped(&mut r, &mut line, MAX_FRAME).is_none() {
                        break;
                    }
                }
                if n % 2 == 1 {
                    // Silent: holds the connection, reads and never acknowledges.
                    let mut sink = Vec::new();
                    let _ = r.get_mut().set_read_timeout(Some(Duration::from_secs(3)));
                    let _ = r.read_to_end(&mut sink);
                }
                continue;
            }
            let server = server.clone();
            thread::spawn(move || server.take(c));
        }
    }

    /// Every line arrives exactly once, in order, through connections that die mid-stream or
    /// swallow what they get: the guest sends again whatever the host hasn't acknowledged.
    #[test]
    fn every_line_arrives_once_through_connections_that_die_or_stall() {
        let path = scratch("stall");
        let l = UnixListener::bind(&path).expect("bind");
        let key = [3u8; KEY_LEN];
        let log = Log::default();
        let server = Arc::new(LogServer::new(key, None, log.emit()));
        let conns = Arc::new(AtomicUsize::new(0));
        {
            let (server, conns) = (server.clone(), conns.clone());
            thread::spawn(move || flaky_host(l, 4, server, conns));
        }
        let ob = leak(OUTBOX_BYTES);
        ob.set_key(key);
        let p = path.clone();
        thread::spawn(move || send(ob, move || UnixStream::connect(&p)));
        let writers: Vec<_> = (0..4)
            .map(|w| {
                thread::spawn(move || {
                    for i in 0..500 {
                        ob.line(format!("w{w} line {i:03}").as_bytes());
                        if i % 100 == 0 {
                            thread::sleep(Duration::from_millis(20));
                        }
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().expect("writer");
        }
        ob.drain(Duration::from_secs(30)).expect("the host acknowledged every line");
        let log = log.text();
        assert!(!log.contains("lost"), "nothing lost: {}", &log[..log.len().min(400)]);
        for w in 0..4 {
            let mine: Vec<&str> = log.lines().filter(|l| l.starts_with(&format!("guest: w{w} "))).collect();
            let want: Vec<String> = (0..500).map(|i| format!("guest: w{w} line {i:03}")).collect();
            assert_eq!(mine, want, "writer {w}: every line once, in order");
        }
        assert!(conns.load(Ordering::SeqCst) > 4, "the dead and the silent connections were replaced");
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// A hostile process in the guest (#86 review) opens its own connections to the log port: it
    /// forges a frame numbered at the end of the numbers (which would make every later init line
    /// look already logged), count frames and launcher-looking lines, presents a wrong key, and
    /// squats connections that never say anything. None of it reaches the log; the init's lines
    /// all do, once; the refusals are the launcher's own counted line.
    #[test]
    fn a_hostile_connection_can_neither_hide_the_inits_lines_nor_write_the_launchers() {
        let path = scratch("hostile");
        let l = UnixListener::bind(&path).expect("bind");
        let key = [9u8; KEY_LEN];
        let log = Log::default();
        let server = Arc::new(LogServer::new(key, None, log.emit()));
        {
            let server = server.clone();
            thread::spawn(move || {
                for c in l.incoming().flatten() {
                    let server = server.clone();
                    thread::spawn(move || server.take(c));
                }
            });
        }
        // Squatters first: more than every waiting place, holding them open, silent.
        let squatters: Vec<UnixStream> = (0..3 * MAX_PENDING).map(|_| UnixStream::connect(&path).expect("connect")).collect();
        let forge = |hello: Option<String>| {
            let mut c = UnixStream::connect(&path).expect("connect");
            if let Some(h) = hello {
                let _ = c.write_all(h.as_bytes());
            }
            let _ = c.write_all(format!("L {} x\nX 5 999\nL 6 securecore-fpm: 999 guest log lines lost (forged)\n", u64::MAX).as_bytes());
            let mut sink = Vec::new();
            let _ = c.set_read_timeout(Some(Duration::from_secs(3)));
            let _ = c.read_to_end(&mut sink);
            sink
        };
        let no_key = forge(None);
        let wrong_key = forge(Some(hello_line(&[1u8; KEY_LEN])));
        assert!(no_key.is_empty() && wrong_key.is_empty(), "a refused connection gets no acknowledgement");
        let ob = leak(OUTBOX_BYTES);
        ob.set_key(key);
        let p = path.clone();
        thread::spawn(move || send(ob, move || UnixStream::connect(&p)));
        for i in 0..300 {
            ob.line(format!("init line {i:03}").as_bytes());
            if i == 150 {
                // More forgeries while the init's stream runs.
                let _ = forge(None);
            }
        }
        ob.drain(Duration::from_secs(30)).expect("the host acknowledged every init line");
        drop(squatters);
        let text = log.text();
        let mine: Vec<&str> = text.lines().filter(|l| l.starts_with("guest: init line ")).collect();
        let want: Vec<String> = (0..300).map(|i| format!("guest: init line {i:03}")).collect();
        assert_eq!(mine, want, "every init line, once, in order");
        assert!(!text.contains("guest: x") && !text.contains("forged") && !text.contains("lines lost"), "nothing forged: {text}");
        let launcher: Vec<&str> = text.lines().filter(|l| l.starts_with("securecore-fpm: ")).collect();
        assert!(!launcher.is_empty() && launcher.iter().all(|l| l.starts_with("securecore-fpm: refused ")), "only refusal counts: {launcher:?}");
        assert!(server.refused() >= 3, "the forgers were counted: {}", server.refused());
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// K4: the init's lines have a label of their own, which a php-fpm line can't produce, and a
    /// part of the buffer php-fpm's lines can't fill.
    #[test]
    fn the_inits_lines_are_labelled_apart_and_never_crowded_out() {
        let ob = leak(OUTBOX_BYTES);
        let flood = "w".repeat(1000);
        for _ in 0..(OUTBOX_BYTES / 1000) {
            ob.line(flood.as_bytes());
        }
        assert!(ob.pending().1 > 0, "php-fpm's flood filled its part and was counted");
        ob.line(format!("securecore-init: php-fpm exited (forged by a worker) {flood}").as_bytes());
        ob.init_line(b"php-fpm exited at boot (exit code 78)");
        let log = Log::default();
        let frames: Vec<u8> = ob.lock().frames.iter().flat_map(|(_, b)| b.clone()).collect();
        serve(&frames[..], io::sink(), &Mutex::new(Inbox::default()), &*log.emit()).expect("serves");
        let text = log.text();
        assert!(text.lines().any(|l| l == "guest-init: php-fpm exited at boot (exit code 78)"), "the init's line is there, under its label");
        assert!(!text.contains("forged by a worker"), "the worker's line was counted as lost, not queued");
        assert_eq!(guest_line(b"securecore-init: forged", false), "guest: securecore-init: forged", "a worker's line is always guest:");
        assert!(text.lines().filter(|l| l.starts_with("guest-init: ")).count() == 1);
    }

    /// N1: control characters and the Unicode line separators are escaped; a tab is kept.
    #[test]
    fn a_guest_line_stays_one_line() {
        let s = escaped("a\rb\u{1b}[2Jc\u{85}d\u{2028}e\u{2029}f\tg\u{7f}".as_bytes());
        assert_eq!(s, "a\\u{d}b\\u{1b}[2Jc\\u{85}d\\u{2028}e\\u{2029}f\tg\\u{7f}");
        assert!(!s.chars().any(|c| (c.is_control() && c != '\t') || matches!(c, '\u{85}' | '\u{2028}' | '\u{2029}')));
        assert_eq!(init_line(b"x\x08y", false), "guest-init: x\\u{8}y");
    }

    /// K2 and K3: a restored init's old key is refused quietly and counted apart; a key line
    /// dripped a byte at a time past the deadline is refused; the refusals not yet said are said
    /// by `flush` (N3).
    #[test]
    fn an_old_key_and_a_slow_hello_are_refused_and_said_at_the_stop() {
        let path = scratch("stale");
        let l = UnixListener::bind(&path).expect("bind");
        let (key, old) = ([5u8; KEY_LEN], [6u8; KEY_LEN]);
        let log = Log::default();
        let server = Arc::new(LogServer::new(key, Some(old), log.emit()));
        {
            let server = server.clone();
            thread::spawn(move || {
                for c in l.incoming().flatten() {
                    let server = server.clone();
                    thread::spawn(move || server.take(c));
                }
            });
        }
        let mut c = UnixStream::connect(&path).expect("connect");
        c.write_all(format!("{}L 1 from the snapshot's key\n", hello_line(&old)).as_bytes()).expect("write");
        let mut sink = Vec::new();
        let _ = c.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = c.read_to_end(&mut sink);
        assert!(sink.is_empty(), "nothing acknowledged");
        // A key line dripped slower than the deadline: refused, though each byte came in time.
        let t = Instant::now();
        let mut d = UnixStream::connect(&path).expect("connect");
        for b in hello_line(&key).bytes().take(20) {
            if d.write_all(&[b]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let mut sink = Vec::new();
        let _ = d.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = d.read_to_end(&mut sink);
        assert!(t.elapsed() < Duration::from_secs(3), "cut at the deadline");
        thread::sleep(Duration::from_millis(100));
        server.flush();
        let text = log.text();
        assert!(!text.contains("from the snapshot's key"), "{text}");
        assert!(text.contains("refused 1 guest log connection with the snapshot's old log key"), "{text}");
        assert!(text.contains("guest log connection") && server.refused() == 1, "the slow one: {text}");
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }
}
