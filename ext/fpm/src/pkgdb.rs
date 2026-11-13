//! The host's package database, as the microVM's capture reads it (addiscorp/securecore#101):
//! which package installed a file, and the checksum the package manager recorded for it, so a
//! binary or library the guest gets from the host is the one its package shipped.
//!
//! - **dpkg** (Debian, Ubuntu): `var/lib/dpkg/info/<pkg>.md5sums` (MD5 per regular file) and
//!   `<pkg>.list` (every path the package owns: links and folders too). Read directly.
//! - **apk** (Alpine): `lib/apk/db/installed`: `P:` the package, `F:` a folder, `R:` a file in
//!   it, `Z:Q1<base64>` its SHA-1. Read directly.
//! - **rpm** (Fedora, RHEL, SUSE): the database is SQLite or Berkeley DB, so it is read through
//!   the host's own `rpm -qa` (chrooted into the PHP root, as nobody, with no environment):
//!   each file's digest and the package's digest algorithm (MD5, SHA-1, SHA-256, SHA-512).
//!
//! Paths are absolute. A merged `/usr` (`/lib` a link to `/usr/lib`) means a package may record
//! either form, so a lookup tries both ([`PkgDb::lookup`]).

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

/// Which package manager a database belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dpkg,
    Apk,
    Rpm,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Dpkg => "dpkg",
            Kind::Apk => "apk",
            Kind::Rpm => "rpm",
        }
    }
}

/// A recorded checksum's algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    /// An algorithm the capture can't compute (rpm's number): the file is refused, never let
    /// through on its ownership alone.
    Unknown(u16),
}

/// What the package manager recorded for one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub pkg: String,
    /// The regular file's checksum (lowercase hex); `None` for a link or folder, or a file the
    /// package manager records no checksum for.
    pub digest: Option<(Algo, String)>,
}

/// One host's package database.
#[derive(Debug, Clone, Default)]
pub struct PkgDb {
    pub kind: Option<Kind>,
    /// Every package's record of a path (a diverted path has two: dpkg's diversions).
    files: HashMap<String, Vec<Entry>>,
    /// dpkg's diversions: the path a package's file was moved away from, where it went, and the
    /// package that diverted it (`:` for the administrator).
    diversions: Vec<(String, String, String)>,
}

/// The checksums of one file's bytes, in every algorithm a database may hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sums {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
}

impl Sums {
    pub fn of(bytes: &[u8]) -> Sums {
        use sha2::Digest as _;
        Sums {
            md5: hex(&md5::Md5::digest(bytes)),
            sha1: hex(&sha1::Sha1::digest(bytes)),
            sha256: hex(&sha2::Sha256::digest(bytes)),
            sha512: hex(&sha2::Sha512::digest(bytes)),
        }
    }

    fn get(&self, algo: Algo) -> String {
        match algo {
            Algo::Md5 => self.md5.clone(),
            Algo::Sha1 => self.sha1.clone(),
            Algo::Sha256 => self.sha256.clone(),
            Algo::Sha512 => self.sha512.clone(),
            Algo::Sha224 | Algo::Sha384 | Algo::Unknown(_) => String::new(),
        }
    }
}

/// `bytes` hashed with `algo`, lowercase hex (empty for an algorithm it can't compute).
pub fn digest_of(algo: Algo, bytes: &[u8]) -> String {
    use sha2::Digest as _;
    match algo {
        Algo::Md5 => hex(&md5::Md5::digest(bytes)),
        Algo::Sha1 => hex(&sha1::Sha1::digest(bytes)),
        Algo::Sha224 => hex(&sha2::Sha224::digest(bytes)),
        Algo::Sha256 => hex(&sha2::Sha256::digest(bytes)),
        Algo::Sha384 => hex(&sha2::Sha384::digest(bytes)),
        Algo::Sha512 => hex(&sha2::Sha512::digest(bytes)),
        Algo::Unknown(_) => String::new(),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// What the database says about a file's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A package recorded this path with this checksum, and the bytes match it.
    Matches { pkg: String },
    /// A package recorded this path with another checksum: the file was changed after its
    /// package installed it.
    Differs { pkg: String, recorded: String, algo: Algo },
    /// A package owns the path but recorded no checksum for it.
    NoChecksum { pkg: String },
    /// A package recorded a checksum in an algorithm the capture can't compute.
    Unverifiable { pkg: String, algo: Algo },
    /// No package owns the path.
    Unpackaged,
}

impl PkgDb {
    /// The database of the system under `root`: dpkg, apk or rpm, whichever it has (none: an
    /// empty database, so every file is unpackaged).
    pub fn open(root: &Path) -> Result<PkgDb, String> {
        PkgDb::open_with(root, "rpm")
    }

    /// Whether the system under `root` keeps an rpm database (and no dpkg or apk one).
    pub fn is_rpm(root: &Path) -> bool {
        !root.join("var/lib/dpkg/info").is_dir()
            && !root.join("lib/apk/db/installed").is_file()
            && (root.join("var/lib/rpm").is_dir() || root.join("usr/lib/sysimage/rpm").is_dir())
    }

    /// [`PkgDb::open`], running `rpm` (a path the caller checked) for an rpm database.
    pub fn open_with(root: &Path, rpm: &str) -> Result<PkgDb, String> {
        let dpkg = root.join("var/lib/dpkg/info");
        if dpkg.is_dir() {
            let mut db = PkgDb::read_dpkg(&dpkg).map_err(|e| format!("{}: {e}", dpkg.display()))?;
            let div = root.join("var/lib/dpkg/diversions");
            if div.is_file() {
                let text = fs::read_to_string(&div).map_err(|e| format!("{}: {e}", div.display()))?;
                db.add_dpkg_diversions(&text);
            }
            return Ok(db);
        }
        let apk = root.join("lib/apk/db/installed");
        if apk.is_file() {
            let text = fs::read_to_string(&apk).map_err(|e| format!("{}: {e}", apk.display()))?;
            return Ok(PkgDb::parse_apk(&text));
        }
        if root.join("var/lib/rpm").is_dir() || root.join("usr/lib/sysimage/rpm").is_dir() {
            return rpm_query(root, rpm).map(|out| PkgDb::parse_rpm(&out));
        }
        Ok(PkgDb::default())
    }

    /// dpkg's `info` folder: every `<pkg>.list` and `<pkg>.md5sums`.
    pub fn read_dpkg(info: &Path) -> io::Result<PkgDb> {
        let mut db = PkgDb { kind: Some(Kind::Dpkg), ..PkgDb::default() };
        let mut names: Vec<_> = fs::read_dir(info)?.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        // The lists first, so a file's checksum replaces its bare entry.
        names.sort_by_key(|n| (!n.ends_with(".list"), n.clone()));
        for name in names {
            if let Some(pkg) = name.strip_suffix(".list") {
                let text = fs::read_to_string(info.join(&name))?;
                db.add_dpkg_list(pkg, &text);
            } else if let Some(pkg) = name.strip_suffix(".md5sums") {
                let text = fs::read_to_string(info.join(&name))?;
                db.add_dpkg_md5sums(pkg, &text);
            }
        }
        Ok(db)
    }

    /// One `<pkg>.list`: a path per line.
    pub fn add_dpkg_list(&mut self, pkg: &str, text: &str) {
        let pkg = pkg.split(':').next().unwrap_or(pkg);
        for line in text.lines().filter(|l| l.starts_with('/')) {
            self.add(line, Entry { pkg: pkg.to_owned(), digest: None });
        }
    }

    /// A package's record of `path`: one per package, a checksum replacing a bare entry.
    fn add(&mut self, path: &str, e: Entry) {
        let v = self.files.entry(path.to_owned()).or_default();
        match v.iter_mut().find(|x| x.pkg == e.pkg) {
            Some(x) if e.digest.is_some() || x.digest.is_none() => *x = e,
            Some(_) => {}
            None => v.push(e),
        }
    }

    /// dpkg's `diversions`: three lines each, the path a package's file was moved away from,
    /// where it went, and the diverting package (`:` for the administrator).
    pub fn add_dpkg_diversions(&mut self, text: &str) {
        let lines: Vec<&str> = text.lines().collect();
        for d in lines.chunks(3) {
            if let [from, to, by] = d {
                self.diversions.push(((*from).to_owned(), (*to).to_owned(), (*by).to_owned()));
            }
        }
    }

    /// One `<pkg>.md5sums`: `<md5>  <path without the leading slash>` per line.
    pub fn add_dpkg_md5sums(&mut self, pkg: &str, text: &str) {
        let pkg = pkg.split(':').next().unwrap_or(pkg);
        for line in text.lines() {
            let Some((sum, path)) = line.split_once("  ") else { continue };
            if sum.len() != 32 || !sum.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let path = format!("/{}", path.trim_start_matches('/'));
            self.add(&path, Entry { pkg: pkg.to_owned(), digest: Some((Algo::Md5, sum.to_ascii_lowercase())) });
        }
    }

    /// apk's `installed` database.
    pub fn parse_apk(text: &str) -> PkgDb {
        let mut db = PkgDb { kind: Some(Kind::Apk), ..PkgDb::default() };
        let (mut pkg, mut dir, mut last): (String, String, Option<String>) = (String::new(), String::new(), None);
        for line in text.lines() {
            if line.is_empty() {
                (pkg, dir, last) = (String::new(), String::new(), None);
                continue;
            }
            let Some((tag, value)) = line.split_once(':') else { continue };
            match tag {
                "P" => pkg = value.to_owned(),
                "F" => {
                    dir = value.trim_matches('/').to_owned();
                    db.add(&format!("/{dir}"), Entry { pkg: pkg.clone(), digest: None });
                    last = None;
                }
                "R" => {
                    let path = if dir.is_empty() { format!("/{value}") } else { format!("/{dir}/{value}") };
                    db.add(&path, Entry { pkg: pkg.clone(), digest: None });
                    last = Some(path);
                }
                // A file's checksum follows its R: line. Q1 is base64 of the SHA-1.
                "Z" => {
                    if let (Some(path), Some(b64)) = (&last, value.strip_prefix("Q1"))
                        && let Some(raw) = base64_decode(b64)
                        && raw.len() == 20
                    {
                        db.add(path, Entry { pkg: pkg.clone(), digest: Some((Algo::Sha1, hex(&raw))) });
                    }
                }
                _ => {}
            }
        }
        db
    }

    /// `rpm -qa --qf '[%{FILENAMES}\t%{FILEDIGESTS}\t%{FILEDIGESTALGO}\t%{NAME}\n]'`'s output.
    pub fn parse_rpm(text: &str) -> PkgDb {
        let mut db = PkgDb { kind: Some(Kind::Rpm), ..PkgDb::default() };
        for line in text.lines() {
            let mut f = line.split('\t');
            let (Some(path), Some(digest), Some(algo), Some(pkg)) = (f.next(), f.next(), f.next(), f.next()) else { continue };
            if !path.starts_with('/') {
                continue;
            }
            // rpm's PGPHASHALGO numbers; a package without the tag is MD5. Any other number is
            // kept as unknown, so the file is refused rather than let through unchecked.
            let algo = match algo.trim() {
                "1" | "(none)" | "" => Algo::Md5,
                "2" => Algo::Sha1,
                "8" => Algo::Sha256,
                "9" => Algo::Sha384,
                "10" => Algo::Sha512,
                "11" => Algo::Sha224,
                n => Algo::Unknown(n.parse().unwrap_or(0)),
            };
            let digest = (!digest.is_empty()).then(|| (algo, digest.to_ascii_lowercase()));
            db.add(path, Entry { pkg: pkg.to_owned(), digest });
        }
        db
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The entry for `path` (absolute, with no link in it), or for its other merged-`/usr`
    /// form: `/usr/lib/x` is also looked up as `/lib/x`, and the other way round.
    pub fn lookup(&self, path: &str) -> Option<&Entry> {
        self.records(path).and_then(|(p, v)| self.chosen(&p, v))
    }

    /// Every package's record of `path` (or of its other merged-`/usr` form), and the form found.
    fn records(&self, path: &str) -> Option<(String, &Vec<Entry>)> {
        if let Some(v) = self.files.get(path) {
            return Some((path.to_owned(), v));
        }
        const MERGED: [&str; 6] = ["lib", "lib32", "lib64", "libx32", "bin", "sbin"];
        let other = if let Some(rest) = path.strip_prefix("/usr/") {
            MERGED.contains(&rest.split('/').next().unwrap_or("")).then(|| format!("/{rest}"))
        } else {
            MERGED.contains(&path.trim_start_matches('/').split('/').next().unwrap_or("")).then(|| format!("/usr{path}"))
        }?;
        self.files.get(&other).map(|v| (other, v))
    }

    /// Which package's record holds for the file at `path`, dpkg's diversions applied: at a
    /// diverted path the diverting package's (none when the administrator diverted it); the
    /// file the diversion moved away keeps its own package's record, at the path it came from.
    fn chosen<'a>(&'a self, path: &str, v: &'a [Entry]) -> Option<&'a Entry> {
        if let Some((_, _, by)) = self.diversions.iter().find(|(from, _, _)| from == path) {
            return v.iter().find(|e| e.pkg == by.split(':').next().unwrap_or(by));
        }
        // Several packages listing one path (folders): the one with a checksum.
        v.iter().find(|e| e.digest.is_some()).or(v.first())
    }

    /// For a file a diversion moved here: its own package's record, from the path it came from.
    fn diverted_here(&self, path: &str) -> Option<&Entry> {
        let (from, _, by) = self.diversions.iter().find(|(_, to, _)| to == path)?;
        let by = by.split(':').next().unwrap_or(by);
        self.files.get(from)?.iter().find(|e| e.pkg != by && e.digest.is_some())
    }

    /// Whether a link at `path` is one a package installed.
    pub fn owns(&self, path: &str) -> Option<&str> {
        self.lookup(path).map(|e| e.pkg.as_str())
    }

    /// The bytes `sums` (of the file at `path`) against what the database recorded.
    pub fn check(&self, path: &str, sums: &Sums) -> Verdict {
        self.check_with(path, |algo| sums.get(algo).to_owned())
    }

    /// The file's bytes against what the database recorded, hashing them only with the
    /// recorded algorithm.
    pub fn check_bytes(&self, path: &str, bytes: &[u8]) -> Verdict {
        self.check_with(path, |algo| digest_of(algo, bytes))
    }

    fn check_with(&self, path: &str, got: impl Fn(Algo) -> String) -> Verdict {
        match self.diverted_here(path).or_else(|| self.lookup(path)) {
            None => Verdict::Unpackaged,
            Some(Entry { pkg, digest: None }) => Verdict::NoChecksum { pkg: pkg.clone() },
            Some(Entry { pkg, digest: Some((algo @ Algo::Unknown(_), _)) }) => Verdict::Unverifiable { pkg: pkg.clone(), algo: *algo },
            Some(Entry { pkg, digest: Some((algo, want)) }) => {
                if got(*algo) == *want {
                    Verdict::Matches { pkg: pkg.clone() }
                } else {
                    Verdict::Differs { pkg: pkg.clone(), recorded: want.clone(), algo: *algo }
                }
            }
        }
    }
}

/// Standard base64 (with or without padding); `None` on anything else.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// The rpm query's format: every file of every package, its digest, the package's digest
/// algorithm and its name, tab-separated.
/// (`%{=TAG}` repeats a package's single value on each file's line.)
pub const RPM_QUERY: &str = "[%{FILENAMES}\\t%{FILEDIGESTS}\\t%{=FILEDIGESTALGO}\\t%{=NAME}\\n]";

/// `rpm -qa` with [`RPM_QUERY`], run inside `root` as nobody with no environment.
#[cfg(target_os = "linux")]
fn rpm_query(root: &Path, rpm: &str) -> Result<String, String> {
    let out = crate::capture::run_in_root(root, &[rpm, "-qa", "--qf", RPM_QUERY], std::time::Duration::from_secs(60))?;
    if out.is_empty() {
        return Err("rpm -qa listed no files".into());
    }
    Ok(out)
}

#[cfg(not(target_os = "linux"))]
fn rpm_query(_: &Path, _: &str) -> Result<String, String> {
    Err("reading rpm's database needs Linux".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg_md5sums_and_lists() {
        let mut db = PkgDb { kind: Some(Kind::Dpkg), ..PkgDb::default() };
        db.add_dpkg_list("libxml2:amd64", "/.\n/usr\n/usr/lib/x86_64-linux-gnu/libxml2.so.2\n/usr/lib/x86_64-linux-gnu/libxml2.so.2.9.14\n");
        let sums = Sums::of(b"libxml2 bytes");
        db.add_dpkg_md5sums("libxml2:amd64", &format!("{}  usr/lib/x86_64-linux-gnu/libxml2.so.2.9.14\n", sums.md5));
        assert_eq!(db.check("/usr/lib/x86_64-linux-gnu/libxml2.so.2.9.14", &sums), Verdict::Matches { pkg: "libxml2".into() });
        // The link is the package's, with no checksum.
        assert_eq!(db.owns("/usr/lib/x86_64-linux-gnu/libxml2.so.2"), Some("libxml2"));
        // Changed bytes differ.
        let other = Sums::of(b"tampered");
        assert!(matches!(db.check("/usr/lib/x86_64-linux-gnu/libxml2.so.2.9.14", &other), Verdict::Differs { .. }));
        assert_eq!(db.check("/usr/local/lib/php/extensions/x.so", &sums), Verdict::Unpackaged);
    }

    #[test]
    fn dpkg_diversions_pick_the_package_whose_file_is_there() {
        let (orig, local) = (Sums::of(b"the package's own php.so"), Sums::of(b"the diverter's php.so"));
        let mut db = PkgDb { kind: Some(Kind::Dpkg), ..PkgDb::default() };
        db.add_dpkg_md5sums("php8.3-common", &format!("{}  usr/lib/php/x.so\n", orig.md5));
        db.add_dpkg_md5sums("sc-divert", &format!("{}  usr/lib/php/x.so\n", local.md5));
        db.add_dpkg_diversions("/usr/lib/php/x.so\n/usr/lib/php/x.so.distrib\nsc-divert\n");
        // At the diverted path: the diverting package's file, checked against its record.
        assert_eq!(db.check("/usr/lib/php/x.so", &local), Verdict::Matches { pkg: "sc-divert".into() });
        assert!(matches!(db.check("/usr/lib/php/x.so", &orig), Verdict::Differs { .. }), "the original's bytes aren't the diverter's file");
        // Where the original went: its own package's record.
        assert_eq!(db.check("/usr/lib/php/x.so.distrib", &orig), Verdict::Matches { pkg: "php8.3-common".into() });
        assert!(matches!(db.check("/usr/lib/php/x.so.distrib", &local), Verdict::Differs { .. }));
        // The administrator's diversion (":"): no package's file is at the path.
        let mut db2 = PkgDb { kind: Some(Kind::Dpkg), ..PkgDb::default() };
        db2.add_dpkg_md5sums("php8.3-common", &format!("{}  usr/lib/php/y.so\n", orig.md5));
        db2.add_dpkg_diversions("/usr/lib/php/y.so\n/usr/lib/php/y.so.orig\n:\n");
        assert_eq!(db2.check("/usr/lib/php/y.so", &orig), Verdict::Unpackaged);
        assert_eq!(db2.check("/usr/lib/php/y.so.orig", &orig), Verdict::Matches { pkg: "php8.3-common".into() });
    }

    #[test]
    fn rpm_sha384_and_sha224_are_checked_and_unknown_algorithms_refused() {
        let b = b"rpm file";
        let text = format!(
            "/a\t{}\t9\tp384\n/b\t{}\t11\tp224\n/c\tabcd\t99\tpx\n",
            digest_of(Algo::Sha384, b),
            digest_of(Algo::Sha224, b)
        );
        let db = PkgDb::parse_rpm(&text);
        assert_eq!(db.check_bytes("/a", b), Verdict::Matches { pkg: "p384".into() });
        assert_eq!(db.check_bytes("/b", b), Verdict::Matches { pkg: "p224".into() });
        assert!(matches!(db.check_bytes("/a", b"other"), Verdict::Differs { algo: Algo::Sha384, .. }));
        assert!(matches!(db.check_bytes("/b", b"other"), Verdict::Differs { algo: Algo::Sha224, .. }));
        assert_eq!(db.check_bytes("/c", b), Verdict::Unverifiable { pkg: "px".into(), algo: Algo::Unknown(99) });
    }

    #[test]
    fn merged_usr_is_looked_up_both_ways() {
        let mut db = PkgDb { kind: Some(Kind::Dpkg), ..PkgDb::default() };
        let sums = Sums::of(b"libc");
        db.add_dpkg_md5sums("libc6", &format!("{}  lib/x86_64-linux-gnu/libc.so.6\n", sums.md5));
        assert_eq!(db.check("/usr/lib/x86_64-linux-gnu/libc.so.6", &sums), Verdict::Matches { pkg: "libc6".into() });
        let mut db2 = PkgDb { kind: Some(Kind::Dpkg), ..PkgDb::default() };
        db2.add_dpkg_md5sums("dash", &format!("{}  usr/bin/dash\n", sums.md5));
        assert_eq!(db2.check("/bin/dash", &sums), Verdict::Matches { pkg: "dash".into() });
        // Not for folders outside the merged set.
        db2.add_dpkg_md5sums("x", &format!("{}  usr/share/x\n", sums.md5));
        assert_eq!(db2.check("/share/x", &sums), Verdict::Unpackaged);
    }

    #[test]
    fn apk_installed() {
        let sums = Sums::of(b"php-fpm");
        // Q1 + base64 of the raw SHA-1.
        let raw: Vec<u8> = (0..20).map(|i| u8::from_str_radix(&sums.sha1[i * 2..i * 2 + 2], 16).unwrap()).collect();
        let b64 = base64_encode(&raw);
        let text = format!("C:Q1abc=\nP:php83-fpm\nV:8.3.0-r0\nF:usr/sbin\nR:php-fpm83\na:0:0:755\nZ:Q1{b64}\n\nP:other\nF:etc\nR:x\n");
        let db = PkgDb::parse_apk(&text);
        assert_eq!(db.check("/usr/sbin/php-fpm83", &sums), Verdict::Matches { pkg: "php83-fpm".into() });
        assert!(matches!(db.check("/usr/sbin/php-fpm83", &Sums::of(b"x")), Verdict::Differs { algo: Algo::Sha1, .. }));
        assert_eq!(db.check("/etc/x", &sums), Verdict::NoChecksum { pkg: "other".into() });
        assert_eq!(db.owns("/usr/sbin"), Some("php83-fpm"));
    }

    #[test]
    fn rpm_query_output() {
        let s = Sums::of(b"rpm file");
        let text = format!(
            "/usr/sbin/php-fpm\t{}\t8\tphp-fpm\n/usr/lib64/libx.so.1\t\t8\tlibx\n/etc/old\t{}\t(none)\told\n",
            s.sha256, s.md5
        );
        let db = PkgDb::parse_rpm(&text);
        assert_eq!(db.check("/usr/sbin/php-fpm", &s), Verdict::Matches { pkg: "php-fpm".into() });
        assert_eq!(db.check("/usr/lib64/libx.so.1", &s), Verdict::NoChecksum { pkg: "libx".into() });
        assert_eq!(db.check("/etc/old", &s), Verdict::Matches { pkg: "old".into() });
        assert!(matches!(db.check("/usr/sbin/php-fpm", &Sums::of(b"other")), Verdict::Differs { algo: Algo::Sha256, .. }));
    }

    #[test]
    fn base64_round_trip() {
        for n in 0..40u8 {
            let raw: Vec<u8> = (0..n).map(|i| i.wrapping_mul(37).wrapping_add(n)).collect();
            assert_eq!(base64_decode(&base64_encode(&raw)).unwrap(), raw);
        }
        assert_eq!(base64_decode("not base64!"), None);
    }

    fn base64_encode(raw: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in raw.chunks(3) {
            let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= c.len() {
                    s.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    s.push('=');
                }
            }
        }
        s
    }

    /// The readers against a real database, when this host has one (the `check` target is
    /// Debian: dpkg; `test/ext-capture.sh` runs the same in Alpine and Fedora containers).
    #[test]
    fn this_hosts_database_verifies_its_own_files() {
        let db = PkgDb::open(Path::new("/")).expect("open");
        let Some(kind) = db.kind else { return };
        // Some packaged file with a checksum, read and checked.
        let mut checked = 0;
        let diverted = |p: &str| db.diversions.iter().any(|(f, t, _)| f == p || t == p);
        for (path, v) in db.files.iter().filter(|(p, v)| v.len() == 1 && v[0].digest.is_some() && p.starts_with("/usr/bin/") && !diverted(p)).take(20) {
            let Ok(bytes) = fs::read(path) else { continue };
            let got = db.check_bytes(path, &bytes);
            assert_eq!(got, Verdict::Matches { pkg: v[0].pkg.clone() }, "{} {path}", kind.as_str());
            checked += 1;
        }
        assert!(checked > 0, "no file of {} checked", kind.as_str());
    }
}
