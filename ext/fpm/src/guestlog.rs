//! The guest's log channel to the host (vsock 1514, addiscorp/securecore#86): php-fpm's output
//! and the init's own lines, delivered so that no line is ever lost without the launcher saying so.
//!
//! A `write()` that returns in the guest only means the guest's kernel took the bytes: a restore
//! resets every vsock connection, and Firecracker drops what a guest sends on a connection whose
//! host side is closing. So the guest keeps every line until the host has acknowledged it:
//!
//! ```text
//!   guest → host   L <seq> <text>\n      one line (text holds no newline)
//!                  X <seq> <count>\n     <count> lines dropped here (the guest's buffer was full)
//!   host → guest   A <seq>\n             every frame up to <seq> is in the launcher's log
//! ```
//!
//! - **The guest** ([`Outbox`], [`send`]) numbers each line, queues it (up to [`OUTBOX_BYTES`]),
//!   sends it on one connection and drops it once acknowledged. A broken connection, or one on
//!   which nothing is acknowledged for [`ACK_STALL`], is replaced, and every unacknowledged frame
//!   is sent again. A line that doesn't fit in the buffer is counted, and the count goes out as a
//!   frame of its own, in order, before the next line.
//! - **The host** ([`Inbox`], [`serve`]) logs each frame once (a frame sent again is skipped by
//!   its number), every line marked `guest: ` so the guest can't write the launcher's own lines,
//!   and acknowledges. A count frame, or a gap in the numbers, becomes the launcher's own line
//!   `securecore-fpm: N guest log lines lost (…)`.
//!
//! Plain Rust over any connection ([`Conn`]), so the tests drive it over unix sockets.

use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Read, Write};
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

/// One frame from the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Line { seq: u64, text: Vec<u8> },
    Lost { seq: u64, count: u64 },
}

impl Frame {
    pub fn seq(&self) -> u64 {
        match self {
            Frame::Line { seq, .. } | Frame::Lost { seq, .. } => *seq,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Frame::Line { seq, text } => {
                let mut out = format!("L {seq} ").into_bytes();
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
            q: Mutex::new(Queue { frames: VecDeque::new(), bytes: 0, seq: 0, lost: 0, conn: 0, acked_at: None }),
            cv: Condvar::new(),
            cap,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.q.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Queues one line (cut at [`MAX_LINE`]); it is never written to the caller's stream, so a
    /// slow host never blocks php-fpm. When the buffer is full the line is counted as lost, and
    /// the count is sent, in order, before the next line that fits.
    pub fn line(&self, text: &[u8]) {
        let mut text = text.to_vec();
        if text.len() > MAX_LINE {
            text.truncate(MAX_LINE);
            text.extend_from_slice(" …[cut]".as_bytes());
        }
        let mut q = self.lock();
        // A count frame is small; the line must fit beside it.
        let need = text.len() + 64;
        if q.bytes + need > self.cap {
            q.lost += 1;
            return;
        }
        q.push_lost();
        q.push(|seq| Frame::Line { seq, text });
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

impl Conn for std::os::unix::net::UnixStream {
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

/// Delivers `outbox` for ever over connections from `connect`: one at a time; each new one starts
/// with every unacknowledged frame again.
pub fn send<C: Conn>(outbox: &'static Outbox, connect: impl Fn() -> io::Result<C>) -> ! {
    let mut backoff = Duration::from_millis(10);
    loop {
        // Nothing to send: wait for a line before connecting.
        {
            let mut q = outbox.lock();
            while q.frames.is_empty() {
                q = outbox.cv.wait(q).unwrap_or_else(|p| p.into_inner());
            }
        }
        let conn = match connect() {
            Ok(c) => c,
            Err(_) => {
                thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_millis(500));
                continue;
            }
        };
        backoff = Duration::from_millis(10);
        let _ = deliver(outbox, conn);
    }
}

/// One connection's life: its acknowledgements read on a thread of their own, frames written
/// from the oldest unacknowledged one on, until it breaks or stalls. Every way out shuts it.
fn deliver<C: Conn>(outbox: &'static Outbox, mut conn: C) -> io::Result<()> {
    let id = {
        let mut q = outbox.lock();
        q.acked_at = Some(Instant::now());
        q.conn
    };
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
    pub fn take(&mut self, frame: &Frame, cut: bool) -> Vec<String> {
        let seq = frame.seq();
        let mut out = Vec::new();
        if let Some(last) = self.last {
            if seq <= last {
                return out;
            }
            if seq > last + 1 {
                out.push(lost_line(seq - last - 1, "missing from the guest's numbered stream"));
            }
        }
        self.last = Some(seq);
        match frame {
            Frame::Line { text, .. } => {
                if self.recent.len() == RECENT {
                    self.recent.pop_front();
                }
                self.recent.push_back(String::from_utf8_lossy(text).chars().take(1024).collect());
                out.push(guest_line(text, cut));
            }
            Frame::Lost { count, .. } => out.push(lost_line(*count, "the guest's log buffer was full")),
        }
        out
    }

    pub fn last(&self) -> Option<u64> {
        self.last
    }

    /// The guest's last lines, oldest first, as one quotable string (`a | b | c`).
    pub fn recent(&self) -> String {
        self.recent.iter().map(String::as_str).collect::<Vec<_>>().join(" | ")
    }
}

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
    format!("guest: {}{}", String::from_utf8_lossy(text), if cut { " …[cut]" } else { "" })
}

/// The longest frame line the host reads whole: a line, its number and its kind.
const MAX_FRAME: usize = MAX_LINE + 64;

/// One log connection on the host: frames from `from`, logged to `to` through `inbox` (shared by
/// every connection of one guest), each batch acknowledged on `ack`. A line that isn't a frame
/// is logged as the guest's, unnumbered.
pub fn serve(from: impl Read, mut ack: impl Write, inbox: &Mutex<Inbox>, to: &mut impl Write) {
    let mut r = BufReader::with_capacity(64 << 10, from);
    let mut line = Vec::with_capacity(256);
    while let Some(cut) = read_capped(&mut r, &mut line, MAX_FRAME) {
        let out = match Frame::parse(&line) {
            Some(frame) => inbox.lock().unwrap_or_else(|p| p.into_inner()).take(&frame, cut),
            None => vec![guest_line(&line, cut)],
        };
        if !out.is_empty() {
            let mut text = out.join("\n");
            text.push('\n');
            let _ = to.write_all(text.as_bytes());
        }
        // Once what has arrived is logged: acknowledge it.
        if r.buffer().is_empty() {
            let last = inbox.lock().unwrap_or_else(|p| p.into_inner()).last();
            if let Some(last) = last
                && ack.write_all(ack_line(last).as_bytes()).is_err()
            {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn leak(cap: usize) -> &'static Outbox {
        Box::leak(Box::new(Outbox::new(cap)))
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
    }

    /// A frame sent again (after a reconnect) is logged once; a gap is counted; a count frame is
    /// the launcher's own line; the guest can't write a line that reads as the launcher's.
    #[test]
    fn the_host_logs_each_frame_once_and_counts_what_is_missing() {
        let mut inbox = Inbox::default();
        let line = |seq, t: &str| Frame::Line { seq, text: t.as_bytes().to_vec() };
        assert_eq!(inbox.take(&line(3, "a"), false), ["guest: a"]);
        assert_eq!(inbox.take(&line(4, "securecore-fpm: forged"), false), ["guest: securecore-fpm: forged"]);
        assert!(inbox.take(&line(3, "a"), false).is_empty(), "sent again: logged once");
        assert_eq!(inbox.take(&line(7, "d"), false), ["securecore-fpm: 2 guest log lines lost (missing from the guest's numbered stream)", "guest: d"]);
        assert_eq!(inbox.take(&Frame::Lost { seq: 8, count: 1 }, false), ["securecore-fpm: 1 guest log line lost (the guest's log buffer was full)"]);
        assert_eq!(inbox.take(&line(9, "long"), true), ["guest: long …[cut]"]);
        // The last RECENT lines, to quote when the guest stops on its own (#87).
        for i in 10..20 {
            inbox.take(&line(i, &format!("l{i}")), false);
        }
        assert_eq!(inbox.recent(), "l14 | l15 | l16 | l17 | l18 | l19");
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
        let mut log = Vec::new();
        let inbox = Mutex::new(Inbox { last: Some(queued as u64), ..Inbox::default() });
        let frames: Vec<u8> = ob.lock().frames.iter().flat_map(|(_, b)| b.clone()).collect();
        serve(&frames[..], io::sink(), &inbox, &mut log);
        let log = String::from_utf8(log).expect("utf8");
        assert_eq!(log, format!("securecore-fpm: {lost} guest log lines lost (the guest's log buffer was full)\nguest: after\n"));
    }

    /// The host's side of the stress below: a log listener that, for its first `drops`
    /// connections, reads a few frames and then closes without a word (a restore's reset, a dying
    /// connection) or keeps silent (Firecracker dropping a closing connection's data); then
    /// serves for real.
    fn flaky_host(l: UnixListener, drops: usize, inbox: Arc<Mutex<Inbox>>, log: Arc<Mutex<Vec<u8>>>, conns: Arc<AtomicUsize>) {
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
            let (inbox, log) = (inbox.clone(), log.clone());
            thread::spawn(move || {
                let ack = c.try_clone().expect("dup");
                serve(c, ack, &inbox, &mut Writer(log));
            });
        }
    }

    #[derive(Clone)]
    struct Writer(Arc<Mutex<Vec<u8>>>);
    impl Write for Writer {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("log").extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Every line arrives exactly once, in order, through connections that die mid-stream or
    /// swallow what they get: the guest sends again whatever the host hasn't acknowledged.
    #[test]
    fn every_line_arrives_once_through_connections_that_die_or_stall() {
        let dir = std::env::temp_dir().join(format!("sc-guestlog-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("log.sock");
        let _ = std::fs::remove_file(&path);
        let l = UnixListener::bind(&path).expect("bind");
        let (inbox, log, conns) = (Arc::new(Mutex::new(Inbox::default())), Arc::new(Mutex::new(Vec::new())), Arc::new(AtomicUsize::new(0)));
        {
            let (inbox, log, conns) = (inbox.clone(), log.clone(), conns.clone());
            thread::spawn(move || flaky_host(l, 4, inbox, log, conns));
        }
        let ob = leak(OUTBOX_BYTES);
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
        let log = String::from_utf8(log.lock().expect("log").clone()).expect("utf8");
        assert!(!log.contains("lost"), "nothing lost: {}", &log[..log.len().min(400)]);
        for w in 0..4 {
            let mine: Vec<&str> = log.lines().filter(|l| l.starts_with(&format!("guest: w{w} "))).collect();
            let want: Vec<String> = (0..500).map(|i| format!("guest: w{w} line {i:03}")).collect();
            assert_eq!(mine, want, "writer {w}: every line once, in order");
        }
        assert!(conns.load(Ordering::SeqCst) > 4, "the dead and the silent connections were replaced");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
