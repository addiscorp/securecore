//! Attribution for SecureCore layer 2 (addiscorp/securecore#53, phase E2a): which component a
//! file belongs to, and which component is responsible for what the code running now does.
//!
//! Plain Rust with no PHP dependency, so every rule here is unit-tested without PHP. The
//! extension (`securecore-php`) supplies the inputs: the app root (the folder containing
//! securecore.json), WordPress's directory constants, and the files of the frames on the PHP
//! stack.
//!
//! - [`ComponentMap`]: path → [`Component`] for `layer2.app = "wordpress"`.
//! - [`responsible`]: the two attribution rules ([`Rule`]) over a stack of frames.
//! - [`watch`]: the PHP functions whose file opens are recorded, and how an op is named.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Component as PathPart, Path, PathBuf};
use std::time::{Duration, Instant};

pub mod hosts;
pub mod policy;
pub mod watch;

/// What a file belongs to. Its [`Display`](fmt::Display) form is the token in the log lines:
/// `core`, `plugin:<slug>`, `mu-plugin:<name>`, `theme:<slug>`, `outside`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Component {
    /// The app's own code and everything under the root that no component owns.
    Core,
    /// A folder under the plugins directory, or a single-file plugin there, by slug.
    Plugin(String),
    /// An entry in the mu-plugins directory (file or folder), by name without `.php`.
    MuPlugin(String),
    /// A folder under the themes directory, by slug.
    Theme(String),
    /// Not under the app root or any component (e.g. /tmp, PHP's own files).
    Outside,
}

impl Component {
    /// A plugin, mu-plugin or theme: something with its own folder that layer 2 restricts.
    pub fn is_component(&self) -> bool {
        matches!(self, Component::Plugin(_) | Component::MuPlugin(_) | Component::Theme(_))
    }

    /// The inverse of `Display`.
    pub fn parse(token: &str) -> Option<Component> {
        Some(match token {
            "core" => Component::Core,
            "outside" => Component::Outside,
            _ => match token.split_once(':')? {
                ("plugin", s) if !s.is_empty() => Component::Plugin(s.to_owned()),
                ("mu-plugin", s) if !s.is_empty() => Component::MuPlugin(s.to_owned()),
                ("theme", s) if !s.is_empty() => Component::Theme(s.to_owned()),
                _ => return None,
            },
        })
    }
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Component::Core => f.write_str("core"),
            Component::Plugin(s) => write!(f, "plugin:{s}"),
            Component::MuPlugin(s) => write!(f, "mu-plugin:{s}"),
            Component::Theme(s) => write!(f, "theme:{s}"),
            Component::Outside => f.write_str("outside"),
        }
    }
}

/// SecureCore's own mu-plugins. They are part of SecureCore, so they count as core: the loader
/// (worker era) and the vault mu-plugin (E3), which defines the native `wp_salt`/`wp_hash`.
pub const SECURECORE_LOADER: &str = "securecore-loader.php";
pub const SECURECORE_VAULT_MU: &str = "securecore-vault.php";

/// Whether a mu-plugin file is one of SecureCore's own (counted as core).
fn is_securecore_mu(name: &str) -> bool {
    name == SECURECORE_LOADER || name == SECURECORE_VAULT_MU
}

/// Where a WordPress site keeps its components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub root: PathBuf,
    pub content: PathBuf,
    pub plugins: PathBuf,
    pub mu_plugins: PathBuf,
    pub themes: PathBuf,
}

impl Layout {
    /// WordPress's defaults (wp-includes/default-constants.php), overridden by the constants a
    /// site defines in wp-config.php: `WP_CONTENT_DIR`, `WP_PLUGIN_DIR`, `WPMU_PLUGIN_DIR`.
    /// Themes live in `WP_CONTENT_DIR/themes` (get_theme_root()). A relative constant is taken
    /// relative to the root.
    pub fn wordpress(root: &Path, content_dir: Option<&str>, plugin_dir: Option<&str>, mu_plugin_dir: Option<&str>) -> Layout {
        let at = |p: &str| if Path::new(p).is_absolute() { PathBuf::from(p) } else { root.join(p) };
        let content = content_dir.map_or_else(|| root.join("wp-content"), at);
        Layout {
            root: root.to_owned(),
            plugins: plugin_dir.map_or_else(|| content.join("plugins"), at),
            mu_plugins: mu_plugin_dir.map_or_else(|| content.join("mu-plugins"), at),
            themes: content.join("themes"),
            content,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Plugins,
    MuPlugins,
    Themes,
}

/// Where a path sits relative to the component that touched it (the measurement's groups).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Place {
    /// The component's own folder (for core: core's files outside uploads and cache).
    Own,
    /// Core's code and other files core owns, outside uploads and cache.
    CoreCode,
    /// The uploads folder (`wp-content/uploads`).
    Uploads,
    /// The cache folder (`wp-content/cache`).
    Cache,
    /// Another component's folder.
    OtherComponent(Component),
    /// Outside the root and every component.
    Other,
}

/// Path → component for `layer2.app = "wordpress"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentMap {
    root: PathBuf,
    content: PathBuf,
    dirs: Vec<(PathBuf, Kind)>,
    uploads: PathBuf,
    cache: PathBuf,
    /// Entries of the component directories that are symlinks: their resolved target and the
    /// component they are. Longest target first.
    links: Vec<(PathBuf, Component)>,
}

impl ComponentMap {
    /// The map from the paths alone, without looking at the filesystem: no symlinks are
    /// resolved. For paths that are already resolved (the report on logged paths).
    pub fn lexical(layout: &Layout) -> ComponentMap {
        ComponentMap::with(layout, normalize, Vec::new())
    }

    /// The map for the site on disk: every directory with its symlinks resolved, and every
    /// symlinked entry of the plugins, mu-plugins and themes directories mapped from where it
    /// points, so a file PHP reports by its real path is still the right component.
    pub fn resolve(layout: &Layout) -> ComponentMap {
        let mut links = Vec::new();
        for (dir, kind) in [(&layout.plugins, Kind::Plugins), (&layout.mu_plugins, Kind::MuPlugins), (&layout.themes, Kind::Themes)] {
            let Ok(entries) = fs::read_dir(dir) else { continue };
            for entry in entries.flatten() {
                let is_link = entry.file_type().is_ok_and(|t| t.is_symlink());
                if !is_link {
                    continue;
                }
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
                let Some(component) = entry_component(kind, &name) else { continue };
                if let Ok(target) = fs::canonicalize(entry.path()) {
                    links.push((target, component));
                }
            }
        }
        links.sort_by(|a, b| b.0.as_os_str().len().cmp(&a.0.as_os_str().len()).then_with(|| a.0.cmp(&b.0)));
        ComponentMap::with(layout, real_path, links)
    }

    fn with(layout: &Layout, fix: fn(&Path) -> PathBuf, links: Vec<(PathBuf, Component)>) -> ComponentMap {
        let content = fix(&layout.content);
        let mut dirs = vec![(fix(&layout.plugins), Kind::Plugins), (fix(&layout.mu_plugins), Kind::MuPlugins), (fix(&layout.themes), Kind::Themes)];
        // Most specific first, in case one directory is configured inside another.
        dirs.sort_by_key(|d| std::cmp::Reverse(d.0.as_os_str().len()));
        ComponentMap {
            root: fix(&layout.root),
            uploads: content.join("uploads"),
            cache: content.join("cache"),
            content,
            dirs,
            links,
        }
    }

    /// The component an absolute, normalized path belongs to (see [`real_path`]).
    pub fn classify(&self, path: &Path) -> Component {
        for (target, component) in &self.links {
            if path.starts_with(target) {
                return component.clone();
            }
        }
        for (dir, kind) in &self.dirs {
            let Ok(rest) = path.strip_prefix(dir) else { continue };
            let mut parts = rest.components();
            let Some(PathPart::Normal(first)) = parts.next() else {
                return Component::Core; // the directory itself
            };
            let Some(first) = first.to_str() else { return Component::Core };
            let file_directly_in_dir = parts.next().is_none() && first.ends_with(".php");
            return if file_directly_in_dir {
                single_file_component(*kind, first).unwrap_or(Component::Core)
            } else {
                entry_component(*kind, first).unwrap_or(Component::Core)
            };
        }
        if path.starts_with(&self.root) || path.starts_with(&self.content) {
            Component::Core
        } else {
            Component::Outside
        }
    }

    /// Where `target` sits for `actor`: its own folder, or which group outside it.
    pub fn place(&self, actor: &Component, target: &Path) -> Place {
        let owner = self.classify(target);
        if owner == *actor && owner != Component::Core {
            return Place::Own;
        }
        match owner {
            Component::Core if target.starts_with(&self.uploads) => Place::Uploads,
            Component::Core if target.starts_with(&self.cache) => Place::Cache,
            Component::Core if *actor == Component::Core => Place::Own,
            Component::Core => Place::CoreCode,
            Component::Outside => Place::Other,
            other => Place::OtherComponent(other),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn uploads(&self) -> &Path {
        &self.uploads
    }

    pub fn cache(&self) -> &Path {
        &self.cache
    }
}

/// An entry (folder, or anything not a `.php` file) directly in a component directory.
fn entry_component(kind: Kind, name: &str) -> Option<Component> {
    if name.ends_with(".php") {
        return single_file_component(kind, name);
    }
    Some(match kind {
        Kind::Plugins => Component::Plugin(name.to_owned()),
        Kind::MuPlugins => Component::MuPlugin(name.to_owned()),
        Kind::Themes => Component::Theme(name.to_owned()),
    })
}

/// A `.php` file directly in a component directory: a single-file plugin or a mu-plugin.
/// `index.php` ("Silence is golden"), files directly in the themes directory and SecureCore's
/// own loader are core.
fn single_file_component(kind: Kind, name: &str) -> Option<Component> {
    let stem = name.strip_suffix(".php")?;
    if name == "index.php" || stem.is_empty() {
        return None;
    }
    match kind {
        Kind::Plugins => Some(Component::Plugin(stem.to_owned())),
        Kind::MuPlugins if is_securecore_mu(name) => None,
        Kind::MuPlugins => Some(Component::MuPlugin(stem.to_owned())),
        Kind::Themes => None,
    }
}

/// Removes `.` and resolves `..` without touching the filesystem.
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            PathPart::CurDir => {}
            PathPart::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// `path` absolute, normalized and with symlinks resolved as far as it exists: the longest
/// existing ancestor is resolved and the rest appended, so a file about to be created still
/// gets the folder it will be in.
pub fn real_path(path: &Path) -> PathBuf {
    let path = normalize(path);
    if let Ok(real) = fs::canonicalize(&path) {
        return real;
    }
    let mut existing = path.as_path();
    let mut rest = Vec::new();
    while let Some(parent) = existing.parent() {
        if let Some(name) = existing.file_name() {
            rest.push(name.to_owned());
        }
        existing = parent;
        if let Ok(mut real) = fs::canonicalize(existing) {
            for name in rest.iter().rev() {
                real.push(name);
            }
            return real;
        }
    }
    path
}

/// The file an op_array's filename names: eval'd code is `<file>(<line>) : eval()'d code`.
pub fn frame_file(filename: &str) -> &str {
    match filename.strip_suffix(" : eval()'d code") {
        Some(head) => match head.rfind('(') {
            Some(i) if head.ends_with(')') => &head[..i],
            _ => head,
        },
        None => filename,
    }
}

/// The two ways to decide who is responsible for what the running code does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Rule {
    /// (a) The innermost user-code frame's file. A plugin calling a core API that does the
    /// work charges core.
    Frame,
    /// (b) The innermost frame on the stack that belongs to a component (plugin, mu-plugin or
    /// theme); core only when no component is on the stack. A plugin calling a core API that
    /// does the work is still the one responsible.
    Component,
}

impl Rule {
    pub const ALL: [Rule; 2] = [Rule::Frame, Rule::Component];

    pub fn parse(s: &str) -> Option<Rule> {
        match s {
            "frame" | "a" => Some(Rule::Frame),
            "component" | "b" => Some(Rule::Component),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Rule::Frame => "frame",
            Rule::Component => "component",
        }
    }
}

/// Who is responsible, given the components of the user-code frames on the stack, innermost
/// first. The iterator is consumed lazily: rule (a) looks at one frame, rule (b) stops at the
/// first component. No user code on the stack at all means core.
pub fn responsible<I: IntoIterator<Item = Component>>(rule: Rule, frames: I) -> Component {
    let mut frames = frames.into_iter();
    let Some(innermost) = frames.next() else { return Component::Core };
    match rule {
        Rule::Frame => innermost,
        Rule::Component if innermost.is_component() => innermost,
        Rule::Component => frames.find(Component::is_component).unwrap_or(innermost),
    }
}

/// Modification stamps of the component directories: a plugin installed, removed or
/// symlinked in changes its directory's mtime.
type Stamps = Vec<Option<(i64, i64)>>;

fn stamps(layout: &Layout) -> Stamps {
    use std::os::unix::fs::MetadataExt as _;
    [&layout.plugins, &layout.mu_plugins, &layout.themes]
        .iter()
        .map(|d| fs::metadata(d).ok().map(|m| (m.mtime(), m.mtime_nsec())))
        .collect()
}

/// A [`ComponentMap`] kept in step with the site, and a cache of frame file → component, for
/// a process that asks many times (a php-fpm worker). Rebuilt when the layout changes, or when
/// a component directory's mtime changes (checked at most once per `interval`).
#[derive(Debug)]
pub struct MapCache {
    interval: Duration,
    built: Option<Built>,
}

#[derive(Debug)]
struct Built {
    layout: Layout,
    stamps: Stamps,
    next_check: Instant,
    map: ComponentMap,
    files: HashMap<String, Component>,
}

impl MapCache {
    pub const fn new(interval: Duration) -> MapCache {
        MapCache { interval, built: None }
    }

    fn current(&mut self, layout: &Layout, now: Instant) -> &mut Built {
        let stale = match &mut self.built {
            None => true,
            Some(b) if b.layout != *layout => true,
            Some(b) if now >= b.next_check => {
                b.next_check = now + self.interval;
                stamps(layout) != b.stamps
            }
            Some(_) => false,
        };
        if stale {
            self.built = Some(Built {
                stamps: stamps(layout),
                next_check: now + self.interval,
                map: ComponentMap::resolve(layout),
                layout: layout.clone(),
                files: HashMap::new(),
            });
        }
        self.built.as_mut().unwrap_or_else(|| unreachable!("built above"))
    }

    pub fn map(&mut self, layout: &Layout, now: Instant) -> &ComponentMap {
        &self.current(layout, now).map
    }

    /// The component of a frame's file (an op_array filename), cached per distinct name.
    pub fn frame(&mut self, layout: &Layout, now: Instant, filename: &str) -> Component {
        let built = self.current(layout, now);
        if let Some(c) = built.files.get(filename) {
            return c.clone();
        }
        let file = frame_file(filename);
        let path = Path::new(file);
        let c = if path.is_absolute() { built.map.classify(&real_path(path)) } else { Component::Outside };
        built.files.insert(filename.to_owned(), c.clone());
        c
    }
}

#[cfg(test)]
mod tests;
