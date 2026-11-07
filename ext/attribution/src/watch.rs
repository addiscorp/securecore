//! The file opens SecureCore records (E2a), and how each is named in the log.
//!
//! Two kinds: include/require (every one, whether or not opcache has the file), and the PHP
//! functions that open a path through the plain-files stream wrapper. The extension observes
//! exactly the functions in [`WATCHED`]; [`writes`] tells the report which ops write, from the
//! same table.

/// One path argument of a watched function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathArg {
    /// 1-based argument position.
    pub arg: u32,
    /// The op token in the log line.
    pub op: &'static str,
    /// Whether the op writes. Ignored when the function has a `mode` argument (fopen).
    pub writes: bool,
}

/// A PHP function (or method) whose path arguments are recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watched {
    /// Lowercase class name for a method, as PHP stores it in `ce->name` (case kept).
    pub class: Option<&'static str>,
    /// Lowercase function name.
    pub function: &'static str,
    pub paths: &'static [PathArg],
    /// 1-based position of an fopen-style mode argument: the op becomes `<op>:<mode>` and
    /// writes when the mode does.
    pub mode: Option<u32>,
}

const fn read(arg: u32, op: &'static str) -> PathArg {
    PathArg { arg, op, writes: false }
}

const fn write(arg: u32, op: &'static str) -> PathArg {
    PathArg { arg, op, writes: true }
}

const fn f(function: &'static str, paths: &'static [PathArg]) -> Watched {
    Watched { class: None, function, paths, mode: None }
}

/// Every function whose file access is recorded. Metadata-only calls (file_exists, is_file,
/// stat, filemtime …) are not opens and are left out.
pub const WATCHED: &[Watched] = &[
    Watched { class: None, function: "fopen", paths: &[read(1, "fopen")], mode: Some(2) },
    Watched { class: Some("SplFileObject"), function: "__construct", paths: &[read(1, "splfileobject")], mode: Some(2) },
    f("file_get_contents", &[read(1, "file_get_contents")]),
    f("file_put_contents", &[write(1, "file_put_contents")]),
    f("file", &[read(1, "file")]),
    f("readfile", &[read(1, "readfile")]),
    f("parse_ini_file", &[read(1, "parse_ini_file")]),
    f("md5_file", &[read(1, "md5_file")]),
    f("sha1_file", &[read(1, "sha1_file")]),
    f("hash_file", &[read(2, "hash_file")]),
    f("opendir", &[read(1, "opendir")]),
    f("scandir", &[read(1, "scandir")]),
    f("dir", &[read(1, "dir")]),
    f("glob", &[read(1, "glob")]),
    f("unlink", &[write(1, "unlink")]),
    f("mkdir", &[write(1, "mkdir")]),
    f("rmdir", &[write(1, "rmdir")]),
    f("touch", &[write(1, "touch")]),
    f("chmod", &[write(1, "chmod")]),
    f("tempnam", &[write(1, "tempnam")]),
    f("rename", &[write(1, "rename-from"), write(2, "rename-to")]),
    f("copy", &[read(1, "copy-from"), write(2, "copy-to")]),
    f("move_uploaded_file", &[write(2, "move_uploaded_file")]),
];

/// The watched entry for a function about to be called (PHP's names: the function lowercase,
/// the class as declared).
pub fn watched(class: Option<&str>, function: &str) -> Option<&'static Watched> {
    WATCHED.iter().find(|w| {
        w.function.eq_ignore_ascii_case(function)
            && match (w.class, class) {
                (None, None) => true,
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                _ => false,
            }
    })
}

/// The op token for an fopen-style call: `fopen:rb`. Spaces (not valid in a mode) are dropped
/// so the token stays one word.
pub fn with_mode(op: &str, mode: &str) -> String {
    let mode: String = mode.chars().filter(|c| !c.is_whitespace()).collect();
    format!("{op}:{}", if mode.is_empty() { "r" } else { &mode })
}

/// A mode that can create or change the file: anything but plain read.
fn mode_writes(mode: &str) -> bool {
    mode.contains(['w', 'a', 'x', 'c', '+'])
}

/// The include op for `ZEND_INCLUDE_OR_EVAL`'s `extended_value` (Zend/zend_compile.h); `None`
/// for eval, which opens no file.
pub fn include_op(extended_value: u32) -> Option<&'static str> {
    match extended_value {
        2 => Some("include"),
        4 => Some("include_once"),
        8 => Some("require"),
        16 => Some("require_once"),
        _ => None,
    }
}

/// Whether a logged op token writes (`fopen:w`, `unlink`, …), from the same table the
/// extension records with. Includes read.
pub fn writes(op: &str) -> bool {
    let (name, mode) = match op.split_once(':') {
        Some((n, m)) => (n, Some(m)),
        None => (op, None),
    };
    for w in WATCHED {
        for p in w.paths {
            if p.op == name {
                return match (w.mode, mode) {
                    (Some(_), Some(m)) => mode_writes(m),
                    _ => p.writes,
                };
            }
        }
    }
    false
}

/// A path argument that the plain-files wrapper handles: no scheme, or `file://`. Returns the
/// path without the scheme; `None` for any other wrapper (php://, https://, phar:// …).
pub fn plain_path(arg: &str) -> Option<&str> {
    if let Some(rest) = arg.strip_prefix("file://") {
        return Some(rest);
    }
    match arg.find("://") {
        // A scheme is letters, digits, + - . before "://" (main/streams/streams.c).
        Some(i) if i > 0 && arg[..i].bytes().all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b)) => None,
        _ if arg.is_empty() => None,
        _ => Some(arg),
    }
}
