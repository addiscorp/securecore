//! The E2a measurement (addiscorp/securecore#53): reads the extension's attribution log lines
//! (`securecore: attribution <rule> <component> <op> <path>`) and prints, per rule, which paths
//! each component touched outside its own folder, grouped as core code, uploads, cache, other
//! components' folders and other.
//!
//!   securecore-attribution-report --root /var/www/html [--detail FILE] LOG...
//!
//! The paths in the log are already resolved by the extension, so the map is the lexical one
//! for the default WordPress layout under `--root` (the site's root as the extension saw it).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use securecore_attribution::{watch, Component, ComponentMap, Layout, Place, Rule};

const MARK: &str = "securecore: attribution ";

struct Open {
    rule: Rule,
    actor: Component,
    op: String,
    path: PathBuf,
}

fn parse_line(line: &str) -> Option<Open> {
    let rest = &line[line.find(MARK)? + MARK.len()..];
    let mut words = rest.splitn(4, ' ');
    let rule = Rule::parse(words.next()?)?;
    let actor = Component::parse(words.next()?)?;
    let op = words.next()?.to_owned();
    let path = PathBuf::from(words.next()?.trim_end());
    Some(Open { rule, actor, op, path })
}

#[derive(Default)]
struct Touch {
    reads: usize,
    writes: usize,
}

/// Per rule → component → place → path → counts.
type Tally = BTreeMap<Rule, BTreeMap<Component, BTreeMap<Place, BTreeMap<PathBuf, Touch>>>>;

const GROUPS: [&str; 5] = ["core code", "uploads", "cache", "other components' folders", "other"];

fn group(place: &Place) -> Option<usize> {
    match place {
        Place::Own => None,
        Place::CoreCode => Some(0),
        Place::Uploads => Some(1),
        Place::Cache => Some(2),
        Place::OtherComponent(_) => Some(3),
        Place::Other => Some(4),
    }
}

fn rw(reads: usize, writes: usize) -> &'static str {
    match (reads > 0, writes > 0) {
        (true, true) => "rw",
        (false, true) => "w",
        _ => "r",
    }
}

/// A short key for a path in a table cell: the first `depth` parts below `base`.
fn key(base: &Path, path: &Path, depth: usize) -> String {
    let rel = path.strip_prefix(base).unwrap_or(path);
    let parts: Vec<_> = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    if parts.len() <= depth {
        return parts.join("/");
    }
    format!("{}/…", parts[..depth].join("/"))
}

fn cell(map: &ComponentMap, place_paths: &[(&Place, &BTreeMap<PathBuf, Touch>)]) -> String {
    // key → (distinct files, reads, writes)
    let mut keys: BTreeMap<String, (BTreeSet<&Path>, usize, usize)> = BTreeMap::new();
    for (place, paths) in place_paths {
        for (path, t) in *paths {
            let k = match place {
                Place::CoreCode => key(map.root(), path, 1),
                Place::Uploads => format!("uploads/{}", key(map.uploads(), path, 1)),
                Place::Cache => format!("cache/{}", key(map.cache(), path, 1)),
                Place::OtherComponent(c) => c.to_string(),
                _ => format!("/{}", key(Path::new("/"), path, 3)),
            };
            let e = keys.entry(k).or_default();
            e.0.insert(path);
            e.1 += t.reads;
            e.2 += t.writes;
        }
    }
    if keys.is_empty() {
        return "·".into();
    }
    keys.iter()
        .map(|(k, (files, r, w))| format!("`{k}` {} {}", files.len(), rw(*r, *w)))
        .collect::<Vec<_>>()
        .join("<br>")
}

fn report(tally: &Tally, map: &ComponentMap) -> String {
    let mut out = String::new();
    for (rule, components) in tally {
        let title = match rule {
            Rule::Frame => "Rule (a), `frame`: the innermost user-code frame's file",
            Rule::Component => "Rule (b), `component`: the innermost component frame on the stack",
        };
        let total: usize = components.values().flat_map(|p| p.values()).flat_map(|p| p.values()).map(|t| t.reads + t.writes).sum();
        let _ = writeln!(out, "### {title}\n\n{total} recorded opens. Cell: `place` distinct-files r/w.\n");
        let _ = writeln!(out, "| component | opens | own folder | {} |", GROUPS.join(" | "));
        let _ = writeln!(out, "|---|--:|--:|{}|", GROUPS.map(|_| "---").join("|"));
        for (component, places) in components {
            let opens: usize = places.values().flat_map(|p| p.values()).map(|t| t.reads + t.writes).sum();
            let own: usize = places.get(&Place::Own).map_or(0, |p| p.values().map(|t| t.reads + t.writes).sum());
            let cells: Vec<String> = (0..GROUPS.len())
                .map(|g| {
                    let in_group: Vec<_> = places.iter().filter(|(p, _)| group(p) == Some(g)).collect();
                    cell(map, &in_group)
                })
                .collect();
            let _ = writeln!(out, "| `{component}` | {opens} | {own} | {} |", cells.join(" | "));
        }
        out.push('\n');
    }
    out
}

fn detail(tally: &Tally) -> String {
    let mut out = String::new();
    for (rule, components) in tally {
        for (component, places) in components {
            for (place, paths) in places {
                let Some(g) = group(place) else { continue };
                for (path, t) in paths {
                    let _ = writeln!(out, "{}\t{component}\t{}\t{}\t{}\t{}", rule.as_str(), GROUPS[g], rw(t.reads, t.writes), t.reads + t.writes, path.display());
                }
            }
        }
    }
    out
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut root = None;
    let mut detail_file = None;
    let mut logs = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--root" => root = args.next(),
            "--detail" => detail_file = args.next(),
            _ => logs.push(a),
        }
    }
    let (Some(root), false) = (root, logs.is_empty()) else {
        eprintln!("usage: securecore-attribution-report --root <site root> [--detail <file>] <log>...");
        return ExitCode::from(2);
    };
    let map = ComponentMap::lexical(&Layout::wordpress(Path::new(&root), None, None, None));
    let mut tally = Tally::new();
    let mut lines = 0usize;
    for log in &logs {
        let text = match fs::read(log) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => {
                eprintln!("{log}: {e}");
                return ExitCode::FAILURE;
            }
        };
        for open in text.lines().filter_map(parse_line) {
            lines += 1;
            let place = map.place(&open.actor, &open.path);
            let t = tally.entry(open.rule).or_default().entry(open.actor).or_default().entry(place).or_default().entry(open.path).or_default();
            if watch::writes(&open.op) {
                t.writes += 1;
            } else {
                t.reads += 1;
            }
        }
    }
    if lines == 0 {
        eprintln!("no attribution lines in {}", logs.join(" "));
        return ExitCode::FAILURE;
    }
    print!("{}", report(&tally, &map));
    if let Some(f) = detail_file
        && let Err(e) = fs::write(&f, detail(&tally))
    {
        eprintln!("{f}: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
