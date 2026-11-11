use super::*;
use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("securecore-sync-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch");
    fs::canonicalize(&dir).expect("canonical")
}

fn handle(p: &Path) -> OwnedFd {
    crate::jail::open_dir_beneath(p, Path::new("")).expect("handle")
}

/// What a writer reported (the record's changes), shared with the test.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("sink").extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Sink {
    /// The record the launcher would hold for disk 0 after these reports.
    fn record(&self) -> Record {
        let text = String::from_utf8(self.0.lock().expect("sink").clone()).expect("utf8");
        let mut r = Record::default();
        for line in text.lines() {
            let (disk, rest) = line.split_once(' ').expect("disk");
            assert_eq!(disk, "0");
            assert!(r.apply(rest), "{line}");
        }
        r
    }
}

struct Host {
    dir: PathBuf,
    trash: PathBuf,
    sink: Sink,
}

fn host(name: &str) -> Host {
    Host { dir: scratch(name), trash: scratch(&format!("{name}-trash")), sink: Sink::default() }
}

fn writer_with(h: &Host, cap: u64, record: Record) -> Writer {
    let f = Folder { dir: handle(&h.dir), cap, trash: handle(&h.trash), record };
    Writer::new(vec![f], Limits::DEFAULT, Box::new(h.sink.clone())).expect("writer")
}

fn writer(h: &Host, cap: u64) -> Writer {
    writer_with(h, cap, Record::default())
}

const T: Time = Time { secs: 1_700_000_000, nanos: 5 };

fn meta(size: u64) -> Meta {
    Meta { mode: 0o640, mtime: T, size, blocks: size.div_ceil(4096) * 4096, ino: 0, nlink: 1 }
}

/// A put as the guest sends it when the host says go: header, the body as one extent, commit.
fn put(path: impl AsRef<[u8]>, body: &[u8], commit: bool) -> Vec<u8> {
    let mut b = Op::Put { disk: 0, path: path.as_ref().to_vec(), meta: meta(body.len() as u64) }.encode();
    b.extend(body_bytes(body));
    b.push(u8::from(commit));
    b
}

fn body_bytes(body: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    for (n, c) in body.chunks(CHUNK).enumerate() {
        b.extend_from_slice(&(c.len() as u32).to_be_bytes());
        b.extend_from_slice(&((n * CHUNK) as u64).to_be_bytes());
        b.extend_from_slice(c);
    }
    b.extend_from_slice(&0u32.to_be_bytes());
    b
}

/// Runs `bytes` (ops, with bodies) through a writer and returns its replies.
fn run(w: &mut Writer, bytes: Vec<u8>) -> (io::Result<()>, Vec<Reply>) {
    let mut r = &bytes[..];
    let mut out = Vec::new();
    let res = w.serve(&mut r, &mut out);
    let mut replies = Vec::new();
    let mut o = &out[..];
    while !o.is_empty() {
        let reply = Reply::read(&mut o).expect("reply");
        if let Reply::Push { size, .. } = &reply {
            // Its data and commit byte follow.
            read_chunks(&mut o, None, *size, u64::MAX, &mut None).expect("a push's data");
            read_u8(&mut o).expect("a push's commit byte");
        }
        replies.push(reply);
    }
    (res, replies)
}

#[test]
fn ops_and_replies_round_trip() {
    let t = Time { secs: -3, nanos: 999_999_999 };
    let m = Meta { mode: 0o644, mtime: t, size: 42, blocks: 4096, ino: 7, nlink: 2 };
    for op in [
        Op::Put { disk: 1, path: b"2026/11/a.jpg".to_vec(), meta: m },
        Op::Mkdir { disk: 0, path: b"2026".to_vec(), mode: 0o755 },
        Op::Remove { disk: 0, path: b"x".to_vec() },
        Op::Rename { disk: 2, from: b"a".to_vec(), to: b"b/c".to_vec() },
        Op::Chmod { disk: 0, path: b"a".to_vec(), mode: 0o600 },
        Op::Entry { disk: 0, path: b"a\xff".to_vec(), kind: Kind::Dir, meta: m },
        Op::ListEnd,
        Op::Pushed { disk: 0, path: b"p".to_vec(), ok: true },
    ] {
        assert_eq!(Op::read(&mut &op.encode()[..]).expect("read"), Some(op.clone()), "{op:?}");
    }
    for r in [
        Reply::Ok,
        Reply::Go,
        Reply::Linked,
        Reply::Need { disk: 3, path: b"a/b".to_vec() },
        Reply::Err("no".into()),
        Reply::Push { disk: 0, path: b"h.txt".to_vec(), mode: 0o644, mtime: t, size: 9 },
        Reply::PushDir { disk: 0, path: b"d".to_vec(), mode: 0o755 },
    ] {
        assert_eq!(Reply::read(&mut &r.encode()[..]).expect("read"), r);
    }
    assert_eq!(Op::read(&mut &[][..]).expect("eof"), None, "a clean end");
    let long = Reply::Err("é".repeat(MAX_MESSAGE));
    assert!(matches!(Reply::read(&mut &long.encode()[..]), Ok(Reply::Err(m)) if m.len() <= MAX_MESSAGE));
}

#[test]
fn only_plain_relative_paths_decode_and_any_bytes_are_a_name() {
    for p in [&b"../x"[..], b"/etc/passwd", b"a/../../b", b"a//b", b".", b"a/./b", b"", b"a/", b"a\0b"] {
        assert!(check_path(p).is_err(), "{}", show(p));
        let op = Op::Remove { disk: 0, path: p.to_vec() };
        let e = Op::read(&mut &op.encode()[..]).expect_err("refused");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{}", show(p));
    }
    assert!(check_path(&b"a/".repeat(MAX_DEPTH)[..MAX_DEPTH * 2 - 1]).is_ok());
    assert!(check_path(&b"a/".repeat(MAX_DEPTH + 1)[..(MAX_DEPTH + 1) * 2 - 1]).is_err(), "too deep");
    assert!(check_path(&b"n".repeat(MAX_NAME + 1)).is_err(), "too long a name");
    check_path(b"2026/11/photo-1.jpg").expect("an upload");
    check_path(b"caf\xe9.jpg").expect("a Latin-1 name is a name: it travels as its bytes");
}

#[test]
fn the_record_sets_removes_and_moves_whole_trees() {
    let mut r = Record::default();
    let rec = Rec { kind: Kind::File, size: 3, mtime: T, ino: 9 };
    assert!(r.apply(set_line(b"a/x", &rec).trim_end()));
    assert!(r.apply(set_line(b"a/y\xff", &rec).trim_end()));
    assert!(r.apply(set_line(b"ab", &rec).trim_end()));
    assert!(r.apply(&format!("> {} {}", hex(b"a"), hex(b"b/c"))));
    assert!(r.get(b"a/x").is_none() && r.get(b"b/c/x") == Some(&rec) && r.get(b"b/c/y\xff") == Some(&rec));
    assert_eq!(r.get(b"ab"), Some(&rec), "a sibling with the same prefix stays");
    assert!(r.apply(&format!("- {}", hex(b"b"))));
    assert_eq!(r.len(), 1);
    assert!(!r.apply("+ zz f 1 2 3 4") && !r.apply("rm -rf /") && !r.apply(&format!("+ {} f 1 2 3 4", hex(b"../x"))), "lines that aren't one change nothing");
    assert_eq!(Record::parse(&r.text()), r, "the compacted text is the same record");
}

#[test]
fn the_writer_mirrors_puts_folders_renames_removes_and_modes() {
    let h = host("mirror");
    let mut w = writer(&h, 1 << 20);
    let mut b = put("2026/11/a.txt", b"hello", true);
    b.extend(Op::Mkdir { disk: 0, path: b"2026/12".to_vec(), mode: 0o750 }.encode());
    b.extend(put("2026/11/b.txt", b"bee", true));
    b.extend(Op::Rename { disk: 0, from: b"2026/11/b.txt".to_vec(), to: b"2026/12/b.txt".to_vec() }.encode());
    b.extend(Op::Chmod { disk: 0, path: b"2026/11/a.txt".to_vec(), mode: 0o4755 }.encode());
    b.extend(put("2026/11/gone.txt", b"x", true));
    b.extend(Op::Remove { disk: 0, path: b"2026/11/gone.txt".to_vec() }.encode());
    b.extend(Op::Rename { disk: 0, from: b"never-sent".to_vec(), to: b"2026/x".to_vec() }.encode());
    b.extend(put("2026/11/dropped.txt", b"half", false));
    b.extend(put(b"raw-\xff.bin", b"bytes", true));
    let (res, replies) = run(&mut w, b);
    res.expect("a clean end");
    let want = [
        Reply::Go,
        Reply::Ok,
        Reply::Ok,
        Reply::Go,
        Reply::Ok,
        Reply::Ok,
        Reply::Ok,
        Reply::Go,
        Reply::Ok,
        Reply::Ok,
        Reply::Need { disk: 0, path: b"2026/x".to_vec() },
        Reply::Go,
        Reply::Ok,
        Reply::Go,
        Reply::Ok,
    ];
    assert_eq!(replies, want);
    assert_eq!(fs::read(h.dir.join("2026/11/a.txt")).expect("a"), b"hello");
    let m = fs::metadata(h.dir.join("2026/11/a.txt")).expect("meta");
    assert_eq!(m.permissions().mode() & 0o7777, 0o755, "the mode, without setuid");
    assert_eq!((m.mtime(), m.mtime_nsec()), (1_700_000_000, 5), "the guest's mtime");
    assert_eq!(fs::read(h.dir.join("2026/12/b.txt")).expect("b"), b"bee", "renamed");
    assert!(!h.dir.join("2026/11/b.txt").exists());
    assert_eq!(fs::metadata(h.dir.join("2026/12")).expect("dir").permissions().mode() & 0o777, 0o750);
    assert!(!h.dir.join("2026/11/gone.txt").exists(), "removed");
    assert_eq!(fs::read(h.trash.join("2026/11/gone.txt")).expect("in the trash"), b"x", "a removal moves the file to the trash");
    assert!(!h.dir.join("2026/11/dropped.txt").exists(), "a put the guest dropped leaves nothing");
    assert_eq!(fs::read(h.dir.join(std::ffi::OsStr::from_bytes(b"raw-\xff.bin"))).expect("raw"), b"bytes", "a name that isn't UTF-8, as its bytes");
    let names: Vec<_> = fs::read_dir(h.dir.join("2026/11")).expect("ls").flatten().map(|e| e.file_name()).collect();
    assert_eq!(names, ["a.txt"], "no temporary file left behind");
    let rec = h.sink.record();
    let st = fs::metadata(h.dir.join("2026/12/b.txt")).expect("b");
    assert_eq!(rec.get(b"2026/12/b.txt"), Some(&Rec { kind: Kind::File, size: 3, mtime: T, ino: st.ino() }), "the record follows the rename");
    assert!(rec.get(b"2026/11/gone.txt").is_none() && rec.get(b"2026/11/b.txt").is_none());
    // A recorded folder removed with everything in it.
    let mut b = put("t/deep/x", b"1", true);
    b.extend(Op::Remove { disk: 0, path: b"t".to_vec() }.encode());
    let (res, replies) = run(&mut w, b);
    res.expect("ok");
    assert_eq!(replies, [Reply::Go, Reply::Ok, Reply::Ok]);
    assert!(!h.dir.join("t").exists());
    assert_eq!(fs::read(h.trash.join("t/deep/x")).expect("trash"), b"1");
}

/// A link the site owner put in the host folder is never followed and never replaced or removed:
/// the guest's op is refused (and the connection kept), and the place it points to is untouched.
#[test]
fn a_link_in_the_host_folder_is_kept_never_followed() {
    let h = host("link");
    let outside = scratch("link-outside");
    std::os::unix::fs::symlink(&outside, h.dir.join("evil")).expect("link");
    std::os::unix::fs::symlink(outside.join("target.txt"), h.dir.join("file-link")).expect("link");
    fs::write(outside.join("target.txt"), "keep").expect("target");
    let mut w = writer(&h, 1 << 20);
    let mut b = Op::Put { disk: 0, path: b"evil/x.php".to_vec(), meta: meta(5) }.encode();
    b.extend(Op::Put { disk: 0, path: b"file-link".to_vec(), meta: meta(8) }.encode());
    b.extend(Op::Chmod { disk: 0, path: b"file-link".to_vec(), mode: 0o600 }.encode());
    b.extend(Op::Remove { disk: 0, path: b"evil".to_vec() }.encode());
    b.extend(Op::Remove { disk: 0, path: b"file-link".to_vec() }.encode());
    b.extend(put("after.txt", b"the connection goes on", true));
    let (res, replies) = run(&mut w, b);
    res.expect("ok");
    assert_eq!(replies.len(), 7, "{replies:?}");
    assert!(replies[..5].iter().all(|r| matches!(r, Reply::Err(_) | Reply::Ok)), "{replies:?}");
    assert!(matches!(&replies[0], Reply::Err(m) if m.contains("not a folder on the host")), "{replies:?}");
    assert!(matches!(&replies[1], Reply::Err(m) if m.contains("never replaced")), "{replies:?}");
    assert_eq!(&replies[5..], [Reply::Go, Reply::Ok]);
    assert_eq!(fs::read_dir(&outside).expect("ls").count(), 1, "nothing written outside");
    assert_eq!(fs::read_to_string(outside.join("target.txt")).expect("t"), "keep");
    assert_eq!(fs::metadata(outside.join("target.txt")).expect("m").permissions().mode() & 0o777, 0o644, "never chmod through a link");
    assert!(fs::symlink_metadata(h.dir.join("file-link")).expect("m").file_type().is_symlink(), "the host's link is kept");
    assert!(fs::symlink_metadata(h.dir.join("evil")).expect("m").file_type().is_symlink(), "the host's link is kept");
    // A path that leaves the folder is refused, and the connection closed.
    let mut b = Op::Remove { disk: 0, path: b"../link-outside".to_vec() }.encode();
    b.extend(put("never.txt", b"x", true));
    let (res, replies) = run(&mut w, b);
    assert_eq!(res.expect_err("refused").kind(), io::ErrorKind::InvalidData);
    assert!(matches!(&replies[..], [Reply::Err(m)] if m.contains("not a plain relative path")), "{replies:?}");
    assert!(outside.exists() && !h.dir.join("never.txt").exists());
    let (res, _) = run(&mut w, Op::Remove { disk: 7, path: b"x".to_vec() }.encode());
    assert!(res.expect_err("no disk 7").to_string().contains("1 sync folders"));
}

/// A file the site owner changed (or made) on the host wins over the guest's: never overwritten,
/// renamed over or removed; one the sync wrote and nobody touched since is the guest's.
#[test]
fn a_host_file_that_changed_since_the_record_wins() {
    let h = host("wins");
    let mut w = writer(&h, 1 << 20);
    let (res, _) = run(&mut w, put("ours.txt", b"v1", true));
    res.expect("ok");
    fs::write(h.dir.join("mine.txt"), "the owner's").expect("mine");
    let mut b = put("ours.txt", b"v2", true);
    b.extend(Op::Put { disk: 0, path: b"mine.txt".to_vec(), meta: meta(3) }.encode());
    b.extend(Op::Remove { disk: 0, path: b"mine.txt".to_vec() }.encode());
    b.extend(Op::Rename { disk: 0, from: b"ours.txt".to_vec(), to: b"mine.txt".to_vec() }.encode());
    let (res, replies) = run(&mut w, b);
    res.expect("the connection is kept");
    assert_eq!(replies[..2], [Reply::Go, Reply::Ok], "a recorded file is the guest's to replace");
    assert!(replies[2..].iter().all(|r| matches!(r, Reply::Err(m) if m.contains("host's copy wins"))), "{replies:?}");
    assert_eq!(fs::read_to_string(h.dir.join("mine.txt")).expect("mine"), "the owner's");
    assert_eq!(fs::read_to_string(h.dir.join("ours.txt")).expect("ours"), "v2");
    // The owner edits the guest's file: it is theirs now.
    fs::write(h.dir.join("ours.txt"), "edited on the host").expect("edit");
    let (res, replies) = run(&mut w, Op::Remove { disk: 0, path: b"ours.txt".to_vec() }.encode());
    res.expect("ok");
    assert!(matches!(&replies[..], [Reply::Err(m)] if m.contains("changed on the host")), "{replies:?}");
    assert_eq!(fs::read_to_string(h.dir.join("ours.txt")).expect("ours"), "edited on the host");
    assert_eq!(fs::read_dir(&h.trash).expect("trash").count(), 0, "nothing of the owner's in the trash");
}

#[test]
fn a_cap_refuses_one_file_and_keeps_the_connection() {
    let h = host("cap");
    fs::write(h.dir.join("old.bin"), vec![7u8; 600 * 1024]).expect("old");
    let mut w = writer(&h, 1 << 20);
    let mut b = Op::Put { disk: 0, path: b"big.bin".to_vec(), meta: meta(2 << 20) }.encode();
    b.extend(Op::Put { disk: 0, path: b"more.bin".to_vec(), meta: meta(500 * 1024) }.encode());
    b.extend(put("small.bin", &[1u8; 1000], true));
    let (res, replies) = run(&mut w, b);
    res.expect("the connection is kept");
    assert!(matches!(&replies[0], Reply::Err(m) if m.contains("left under its cap")), "{replies:?}");
    assert!(matches!(&replies[1], Reply::Err(m) if m.contains("left under its cap")), "600 KiB + 500 KiB > 1 MiB: {replies:?}");
    assert_eq!(replies[2..], [Reply::Go, Reply::Ok], "the next file still syncs");
    assert!(!h.dir.join("more.bin").exists() && !h.dir.join("big.bin").exists());
    // A sparse file counts its blocks: 1 GiB long, one 4 KiB extent.
    let mut b = Op::Put { disk: 0, path: b"sparse.img".to_vec(), meta: Meta { size: 1 << 30, blocks: 4096, ..meta(0) } }.encode();
    b.extend_from_slice(&4096u32.to_be_bytes());
    b.extend_from_slice(&(512u64 << 20).to_be_bytes());
    b.extend_from_slice(&[9u8; 4096]);
    b.extend_from_slice(&0u32.to_be_bytes());
    b.push(1);
    let (res, replies) = run(&mut w, b);
    res.expect("ok");
    assert_eq!(replies, [Reply::Go, Reply::Ok]);
    let m = fs::metadata(h.dir.join("sparse.img")).expect("sparse");
    assert_eq!(m.len(), 1 << 30, "its length");
    assert!(m.blocks() * 512 <= 64 << 10, "and only its data on disk: {} bytes", m.blocks() * 512);
    // A guest that lies about its blocks gets its data stopped at the cap, and the file refused.
    let lie = vec![3u8; 900 * 1024];
    let mut b = Op::Put { disk: 0, path: b"liar.bin".to_vec(), meta: Meta { blocks: 4096, ..meta(lie.len() as u64) } }.encode();
    b.extend(body_bytes(&lie));
    b.push(1);
    let (res, replies) = run(&mut w, b);
    res.expect("the connection is kept");
    assert!(matches!(&replies[..], [Reply::Go, Reply::Err(m)] if m.contains("more data than")), "{replies:?}");
    assert!(!h.dir.join("liar.bin").exists());
}

/// A lowered `--write-disk-mib` (a cap below what the guest holds): each listed file over the
/// cap is refused once, the listing ends, and the connection stays (no reconnect loop).
#[test]
fn a_cap_below_the_guests_files_ends_the_listing_without_a_loop() {
    let h = host("lowered");
    let mut w = writer(&h, 64 << 10);
    let mut b = Vec::new();
    for n in 0..3 {
        b.extend(Op::Entry { disk: 0, path: format!("f{n}").into_bytes(), kind: Kind::File, meta: meta(40 << 10) }.encode());
    }
    b.extend(Op::ListEnd.encode());
    for n in 0..3 {
        // As the guest answers each Need: the header, and the body only after a Go.
        b.extend(Op::Put { disk: 0, path: format!("f{n}").into_bytes(), meta: meta(40 << 10) }.encode());
        if n == 0 {
            b.extend(body_bytes(&[1u8; 40 << 10]));
            b.push(1);
        }
    }
    let (res, replies) = run(&mut w, b);
    res.expect("one connection, to its end");
    let needs = replies.iter().filter(|r| matches!(r, Reply::Need { .. })).count();
    assert_eq!(needs, 3);
    assert_eq!(replies[3], Reply::Ok, "the listing ends");
    assert_eq!(replies[4..6], [Reply::Go, Reply::Ok], "the first fits");
    assert!(replies[6..].iter().all(|r| matches!(r, Reply::Err(_))), "the others are refused before their bodies: {replies:?}");
}

/// Hard links reach the host as links: the content once, the cap counted once.
#[test]
fn hard_links_are_links_on_the_host() {
    let h = host("links");
    let mut w = writer(&h, 1 << 20);
    let body = vec![5u8; 700 * 1024];
    let m = Meta { ino: 42, nlink: 2, ..meta(body.len() as u64) };
    let mut b = Op::Put { disk: 0, path: b"a.bin".to_vec(), meta: m }.encode();
    b.extend(body_bytes(&body));
    b.push(1);
    b.extend(Op::Put { disk: 0, path: b"dir/b.bin".to_vec(), meta: m }.encode());
    b.extend(Op::Chmod { disk: 0, path: b"a.bin".to_vec(), mode: 0o666 }.encode());
    let (res, replies) = run(&mut w, b);
    res.expect("ok");
    assert_eq!(replies[..3], [Reply::Go, Reply::Ok, Reply::Linked], "the second name is a link, its body never sent");
    let (a, bb) = (fs::metadata(h.dir.join("a.bin")).expect("a"), fs::metadata(h.dir.join("dir/b.bin")).expect("b"));
    assert_eq!((a.ino(), a.nlink()), (bb.ino(), 2), "one file, two names");
    assert!(matches!(&replies[3], Reply::Err(m) if m.contains("2 names")), "a file with two names is never chmodded: {replies:?}");
    assert_eq!(a.permissions().mode() & 0o777, 0o640);
    assert!(w.folders[0].used < 800 * 1024, "counted once: {}", w.folders[0].used);
}

/// A site owner's hard link from the uploads folder to a file outside it (wp-config.php): the
/// guest can't change its mode, replace or remove it through the sync.
#[test]
fn a_hard_link_the_owner_made_is_never_changed_through() {
    let h = host("owner-link");
    let outside = scratch("owner-link-outside");
    fs::write(outside.join("wp-config.php"), "<?php // secrets").expect("config");
    fs::set_permissions(outside.join("wp-config.php"), fs::Permissions::from_mode(0o600)).expect("mode");
    fs::hard_link(outside.join("wp-config.php"), h.dir.join("x.txt")).expect("link");
    let mut w = writer(&h, 1 << 20);
    let mut b = Op::Chmod { disk: 0, path: b"x.txt".to_vec(), mode: 0o666 }.encode();
    b.extend(Op::Remove { disk: 0, path: b"x.txt".to_vec() }.encode());
    let (res, replies) = run(&mut w, b);
    res.expect("ok");
    assert!(replies.iter().all(|r| matches!(r, Reply::Err(_))), "{replies:?}");
    assert_eq!(fs::metadata(outside.join("wp-config.php")).expect("m").permissions().mode() & 0o777, 0o600, "its mode is the owner's");
    // Even with a forged record entry for it (the record is only what the sync wrote), two names
    // mean no chmod.
    let st = fs::metadata(h.dir.join("x.txt")).expect("x");
    let mut rec = Record::default();
    rec.apply(set_line(b"x.txt", &Rec { kind: Kind::File, size: st.len(), mtime: Time { secs: st.mtime(), nanos: st.mtime_nsec() as u32 }, ino: st.ino() }).trim_end());
    let mut w = writer_with(&h, 1 << 20, rec);
    let (_, replies) = run(&mut w, Op::Chmod { disk: 0, path: b"x.txt".to_vec(), mode: 0o666 }.encode());
    assert!(matches!(&replies[..], [Reply::Err(m)] if m.contains("names")), "{replies:?}");
    assert_eq!(fs::metadata(outside.join("wp-config.php")).expect("m").permissions().mode() & 0o777, 0o600);
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

fn entry(path: &[u8], kind: Kind, size: u64, mtime: Time) -> Vec<u8> {
    let mode = if kind == Kind::Dir { 0o755 } else { 0o644 };
    Op::Entry { disk: 0, path: path.to_vec(), kind, meta: Meta { mode, mtime, size, ..Meta::default() } }.encode()
}

fn mtime(p: &Path) -> Time {
    let m = fs::symlink_metadata(p).expect("m");
    Time { secs: m.mtime(), nanos: m.mtime_nsec() as u32 }
}

/// The listing against the record: agreement recorded, the guest's changes asked for, its
/// removals trashed (only what the record has), the host's own entries pushed, and links, other
/// mounts and unknown names that aren't UTF-8 left alone.
#[test]
fn a_listing_trashes_only_recorded_entries_and_pushes_the_hosts() {
    let h = host("listing");
    fs::create_dir_all(h.dir.join("same")).expect("dirs");
    fs::write(h.dir.join("same/a.txt"), "aaa").expect("a");
    fs::write(h.dir.join("guest-removed.txt"), "x").expect("removed");
    fs::create_dir_all(h.dir.join("old/sub")).expect("old");
    fs::write(h.dir.join("guest-changed.txt"), "v1").expect("changed");
    fs::write(h.dir.join("owners.txt"), "made on the host").expect("owners");
    fs::write(h.dir.join(std::ffi::OsStr::from_bytes(b"latin-\xe9.txt")), "raw").expect("raw");
    std::os::unix::fs::symlink("/etc", h.dir.join("link")).expect("link");
    // The record: what the sync wrote last time (everything but the owner's own files).
    let mut rec = Record::default();
    for p in ["same", "same/a.txt", "guest-removed.txt", "old", "old/sub", "guest-changed.txt"] {
        let st = fs::symlink_metadata(h.dir.join(p)).expect("st");
        let kind = if st.is_dir() { Kind::Dir } else { Kind::File };
        let r = if kind == Kind::Dir { Rec { kind, size: 0, mtime: Time::default(), ino: st.ino() } } else { Rec { kind, size: st.len(), mtime: mtime(&h.dir.join(p)), ino: st.ino() } };
        rec.apply(set_line(p.as_bytes(), &r).trim_end());
    }
    let mut w = writer_with(&h, 1 << 20, rec);
    let at = mtime(&h.dir.join("same/a.txt"));
    let mut b = Vec::new();
    b.extend(entry(b"same", Kind::Dir, 0, at));
    b.extend(entry(b"same/a.txt", Kind::File, 3, at));
    b.extend(entry(b"guest-changed.txt", Kind::File, 2, Time { secs: 1, nanos: 0 }));
    b.extend(entry(b"new/deep", Kind::Dir, 0, at));
    b.extend(entry(b"new/deep/n.txt", Kind::File, 1, at));
    b.extend(Op::ListEnd.encode());
    // The guest takes the host's push.
    b.extend(Op::Pushed { disk: 0, path: b"owners.txt".to_vec(), ok: true }.encode());
    let (res, replies) = run(&mut w, b);
    res.expect("ok");
    assert!(matches!(&replies[0], Reply::Push { path, size: 16, .. } if path == b"owners.txt"), "the owner's file goes to the guest: {replies:?}");
    let tail: Vec<&Reply> = replies.iter().filter(|r| matches!(r, Reply::Need { .. } | Reply::Ok)).collect();
    assert_eq!(
        tail,
        [&Reply::Need { disk: 0, path: b"guest-changed.txt".to_vec() }, &Reply::Need { disk: 0, path: b"new/deep/n.txt".to_vec() }, &Reply::Ok],
        "only what the guest changed is asked for"
    );
    assert!(!h.dir.join("guest-removed.txt").exists() && !h.dir.join("old").exists(), "what the guest removed is gone");
    assert_eq!(fs::read_to_string(h.trash.join("guest-removed.txt")).expect("trash"), "x", "into the trash");
    assert_eq!(fs::read_to_string(h.dir.join("owners.txt")).expect("o"), "made on the host", "the owner's file stays");
    assert!(fs::symlink_metadata(h.dir.join("link")).expect("l").file_type().is_symlink(), "a link is never removed");
    assert!(h.dir.join(std::ffi::OsStr::from_bytes(b"latin-\xe9.txt")).exists(), "an unknown name that isn't UTF-8 is never removed");
    assert!(!replies.iter().any(|r| matches!(r, Reply::Push { path, .. } if path.starts_with(b"latin") || path == b"link")), "nor pushed");
    assert!(h.dir.join("new/deep").is_dir(), "folders are made");
    let rec = w.folders[0].record.clone();
    assert!(rec.get(b"owners.txt").is_some(), "a push the guest took is recorded");
    assert!(rec.get(b"same/a.txt").is_some() && rec.get(b"guest-removed.txt").is_none());
}

/// The writer's confinement, in a child process of this test binary (Landlock and seccomp apply
/// to a whole process): it may write its folder, and nothing else; no socket but unix.
#[test]
fn the_writer_is_confined_to_its_folders() {
    if let Ok(dirs) = std::env::var("SC_SYNC_CONFINE_CHILD") {
        let (inside, outside) = dirs.split_once(':').expect("two dirs");
        let fd = handle(Path::new(inside));
        // The connection, as the writer has it: made before, used after.
        let (a, b) = UnixStream::pair().expect("pair");
        if let Err(e) = confine(&[fd.as_raw_fd()]) {
            println!("confine-failed: {e}");
            return;
        }
        let ok = |r: bool, what: &str| println!("{what}={}", if r { "yes" } else { "no" });
        let mut got = [0u8; 4];
        ok((&a).write_all(b"ping").is_ok() && (&b).read_exact(&mut got).is_ok() && &got == b"ping", "unix-io");
        ok(open_beneath(fd.as_raw_fd(), b"", DIR_FLAGS).and_then(|d| tmpfile(d.as_raw_fd(), &mut 0)).is_ok(), "write-inside");
        ok(fs::write(Path::new(outside).join("x"), "x").is_ok(), "write-outside");
        ok(fs::read_to_string("/etc/hostname").is_ok() || fs::read_dir("/etc").is_ok(), "read-etc");
        // SAFETY: socket(2) with constant arguments; closed right after.
        let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        ok(s >= 0, "inet-socket");
        // A call the writer never makes (harmless either way): EPERM under the seccomp filter.
        // SAFETY: getppid(2) takes nothing.
        ok(unsafe { libc::syscall(libc::SYS_getppid) } > 0, "unlisted-syscall");
        // (NoNewPrivs and Seccomp are checked on the real writer, in test/ext-microvm.sh.)
        return;
    }
    let (inside, outside) = (scratch("confine-in"), scratch("confine-out"));
    let out = std::process::Command::new(std::env::current_exe().expect("exe"))
        .args(["--exact", "sync::tests::the_writer_is_confined_to_its_folders", "--nocapture", "--test-threads=1"])
        .env("SC_SYNC_CONFINE_CHILD", format!("{}:{}", inside.display(), outside.display()))
        .output()
        .expect("child");
    let text = String::from_utf8_lossy(&out.stdout);
    // Only where the kernel lists no Landlock (a container without securityfs, an old kernel)
    // is this skipped; the KVM host and the CI runner have it.
    let lsm = fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    if text.contains("confine-failed: Landlock") && !lsm.contains("landlock") {
        eprintln!("no Landlock here ({text}): checked on the KVM host");
        return;
    }
    for (what, want) in [("unix-io", "yes"), ("write-inside", "yes"), ("write-outside", "no"), ("read-etc", "no"), ("inet-socket", "no"), ("unlisted-syscall", "no")] {
        assert!(text.contains(&format!("{what}={want}")), "{what} should be {want}: {text}\n{}", String::from_utf8_lossy(&out.stderr));
    }
}

/// A mount inside the host folder is never written to or removed from (RESOLVE_NO_XDEV), and
/// never walked. Root only (it mounts a tmpfs).
#[test]
fn a_mount_inside_the_folder_is_never_crossed() {
    // SAFETY: geteuid(2) can't fail.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("not root: checked on the KVM host");
        return;
    }
    let h = host("xdev");
    let m = h.dir.join("mnt");
    fs::create_dir(&m).expect("mnt");
    let c = CString::new(m.as_os_str().as_bytes()).expect("c");
    // SAFETY: mount(2) of a tmpfs on our scratch folder, unmounted below.
    assert_eq!(unsafe { libc::mount(c"tmpfs".as_ptr(), c.as_ptr(), c"tmpfs".as_ptr(), 0, c"size=1m".as_ptr().cast()) }, 0);
    fs::write(m.join("theirs.txt"), "on another filesystem").expect("theirs");
    let mut w = writer(&h, 1 << 20);
    // Refused before its body: the header alone.
    let mut b = Op::Put { disk: 0, path: b"mnt/x.txt".to_vec(), meta: meta(1) }.encode();
    b.extend(Op::Remove { disk: 0, path: b"mnt/theirs.txt".to_vec() }.encode());
    b.extend(Op::Remove { disk: 0, path: b"mnt".to_vec() }.encode());
    b.extend(Op::ListEnd.encode());
    let (res, replies) = run(&mut w, b);
    let x = m.join("x.txt").exists();
    let theirs = fs::read_to_string(m.join("theirs.txt")).ok();
    // SAFETY: umount2(2) of the tmpfs mounted above.
    unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
    res.expect("ok");
    assert!(!x, "nothing written into the mount: {replies:?}");
    assert_eq!(theirs.as_deref(), Some("on another filesystem"), "nothing removed from it");
    assert!(!replies.iter().any(|r| matches!(r, Reply::Push { path, .. } if path.starts_with(b"mnt"))), "never walked: {replies:?}");
}

/// The guest's side against the host's, over a socket pair, no VM: every kind of change in the
/// guest's folder reaches the host's, a drain waits for it, and a file the owner made on the host
/// reaches the guest without coming back.
#[test]
fn changes_in_the_guest_folder_reach_the_host_folder_and_back() {
    let guest = scratch("e2e-guest");
    let h = host("e2e-host");
    fs::create_dir_all(guest.join("2025/01")).expect("dirs");
    fs::write(guest.join("2025/01/before.txt"), "made before the connection").expect("before");
    fs::write(h.dir.join("owners.txt"), "only on the host").expect("owner's");
    fs::create_dir_all(h.dir.join("owners-dir")).expect("owner's dir");
    fs::write(h.dir.join("owners-dir/in.txt"), "deep, on the host").expect("owner's deep");
    let (g, hs) = UnixStream::pair().expect("pair");
    let (dir, trash, sink) = (h.dir.clone(), h.trash.clone(), h.sink.clone());
    let writer_thread = thread::spawn(move || {
        let f = Folder { dir: handle(&dir), cap: 1 << 30, trash: handle(&trash), record: Record::default() };
        let mut w = Writer::new(vec![f], Limits::DEFAULT, Box::new(sink)).expect("writer");
        let mut r = BufReader::new(hs.try_clone().expect("clone"));
        let mut out = hs;
        let res = w.serve(&mut r, &mut out);
        (res, w.pushed)
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
    assert_eq!(fs::read_to_string(h.dir.join("2025/01/before.txt")).expect("before"), "made before the connection", "the listing");
    assert_eq!(fs::read_to_string(guest.join("owners.txt")).expect("pushed"), "only on the host", "the host's file reached the guest");
    assert_eq!(fs::read_to_string(guest.join("owners-dir/in.txt")).expect("pushed"), "deep, on the host");
    assert_eq!(mtime(&guest.join("owners.txt")), mtime(&h.dir.join("owners.txt")), "with its mtime");
    fs::write(guest.join("2025/01/up.jpg"), vec![9u8; 3 << 20]).expect("upload");
    fs::create_dir_all(guest.join("2026/02/x")).expect("mkdir -p");
    fs::write(guest.join("2026/02/x/in-new-dir.txt"), "deep").expect("deep");
    fs::rename(guest.join("2025/01/before.txt"), guest.join("2025/renamed.txt")).expect("rename");
    fs::rename(guest.join("2026/02"), guest.join("2026/03")).expect("rename a folder");
    fs::write(guest.join("2026/03/x/after-dir-rename.txt"), "watched at its new path").expect("after");
    fs::write(guest.join("del.txt"), "x").expect("del");
    fs::set_permissions(guest.join("2025/01/up.jpg"), fs::Permissions::from_mode(0o600)).expect("chmod");
    fs::remove_file(guest.join("del.txt")).expect("rm");
    fs::hard_link(guest.join("2025/01/up.jpg"), guest.join("2025/up-link.jpg")).expect("link");
    {
        let f = fs::File::create(guest.join("sparse.img")).expect("sparse");
        f.set_len(256 << 20).expect("len");
        std::os::unix::fs::FileExt::write_at(&f, b"end", (256 << 20) - 3).expect("tail");
    }
    fs::remove_file(guest.join("owners.txt")).expect("the guest removes what the host pushed");
    drain.wait(Duration::from_secs(10)).expect("drained");
    assert_eq!(fs::read(h.dir.join("2025/01/up.jpg")).expect("up").len(), 3 << 20);
    assert_eq!(fs::metadata(h.dir.join("2025/01/up.jpg")).expect("m").permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::read_to_string(h.dir.join("2025/renamed.txt")).expect("renamed"), "made before the connection");
    assert!(!h.dir.join("2025/01/before.txt").exists());
    assert_eq!(fs::read_to_string(h.dir.join("2026/03/x/in-new-dir.txt")).expect("moved"), "deep");
    assert_eq!(fs::read_to_string(h.dir.join("2026/03/x/after-dir-rename.txt")).expect("after"), "watched at its new path");
    assert!(!h.dir.join("2026/02").exists() && !h.dir.join("del.txt").exists());
    assert_eq!(fs::metadata(h.dir.join("2025/up-link.jpg")).expect("link").ino(), fs::metadata(h.dir.join("2025/01/up.jpg")).expect("up").ino(), "a hard link stays one");
    let sparse = fs::metadata(h.dir.join("sparse.img")).expect("sparse");
    assert!(sparse.len() == 256 << 20 && sparse.blocks() * 512 < 1 << 20, "a sparse file stays sparse: {} bytes on disk", sparse.blocks() * 512);
    assert!(!h.dir.join("owners.txt").exists(), "a pushed file the guest removed afterwards is removed (it was recorded)");
    assert_eq!(fs::read_to_string(h.trash.join("owners.txt")).expect("trash"), "only on the host");
    g.shutdown(std::net::Shutdown::Both).expect("close");
    guest_thread.join().expect("guest").expect("guest ended cleanly");
    let (_, pushed) = writer_thread.join().expect("writer");
    assert_eq!(pushed.0, 3, "two files and a folder pushed, each once (none came back)");
    assert!(drain.wait(Duration::from_secs(1)).is_err(), "no connection: a drain says so");
}
