use super::*;
use std::os::unix::fs::symlink;

fn plugin(s: &str) -> Component {
    Component::Plugin(s.into())
}

fn site() -> ComponentMap {
    ComponentMap::lexical(&Layout::wordpress(Path::new("/srv/site"), None, None, None))
}

fn at(map: &ComponentMap, p: &str) -> Component {
    map.classify(Path::new(p))
}

#[test]
fn wordpress_default_layout() {
    let m = site();
    // Plugins: folder → slug; single-file plugin → its name without .php; index.php is core.
    assert_eq!(at(&m, "/srv/site/wp-content/plugins/contact-form-7/includes/form.php"), plugin("contact-form-7"));
    assert_eq!(at(&m, "/srv/site/wp-content/plugins/wordpress-seo/wp-seo.php"), plugin("wordpress-seo"));
    assert_eq!(at(&m, "/srv/site/wp-content/plugins/wordpress-seo"), plugin("wordpress-seo"), "the folder itself");
    assert_eq!(at(&m, "/srv/site/wp-content/plugins/hello.php"), plugin("hello"));
    assert_eq!(at(&m, "/srv/site/wp-content/plugins/index.php"), Component::Core);
    assert_eq!(at(&m, "/srv/site/wp-content/plugins"), Component::Core);
    // mu-plugins: each entry; SecureCore's loader is core.
    assert_eq!(at(&m, "/srv/site/wp-content/mu-plugins/cache-tweaks.php"), Component::MuPlugin("cache-tweaks".into()));
    assert_eq!(at(&m, "/srv/site/wp-content/mu-plugins/agency/lib.php"), Component::MuPlugin("agency".into()));
    assert_eq!(at(&m, "/srv/site/wp-content/mu-plugins/securecore-loader.php"), Component::Core);
    // SecureCore's vault mu-plugin (E3) is core too, so its native wp_salt/wp_hash are not a
    // restricted component.
    assert_eq!(at(&m, "/srv/site/wp-content/mu-plugins/securecore-vault.php"), Component::Core);
    // Themes: each folder; files directly in themes/ are core.
    assert_eq!(at(&m, "/srv/site/wp-content/themes/twentytwentyfive/functions.php"), Component::Theme("twentytwentyfive".into()));
    assert_eq!(at(&m, "/srv/site/wp-content/themes/index.php"), Component::Core);
    // Everything else under the root is core; outside it is outside.
    for p in ["/srv/site/wp-includes/plugin.php", "/srv/site/wp-admin/index.php", "/srv/site/wp-config.php",
        "/srv/site/wp-content/uploads/2026/11/a.jpg", "/srv/site/wp-content/languages/de_DE.mo", "/srv/site/wp-content/object-cache.php"] {
        assert_eq!(at(&m, p), Component::Core, "{p}");
    }
    assert_eq!(at(&m, "/srv/site-other/wp-includes/plugin.php"), Component::Outside, "a prefix of the name is not inside");
    assert_eq!(at(&m, "/tmp/upload123"), Component::Outside);
    assert_eq!(at(&m, "/srv/wp-config.php"), Component::Outside, "wp-config.php one level up is outside the root");
}

#[test]
fn constants_move_the_directories() {
    let root = Path::new("/srv/site");
    let l = Layout::wordpress(root, Some("/data/content"), Some("/data/ext"), None);
    assert_eq!(l.plugins, Path::new("/data/ext"));
    assert_eq!(l.mu_plugins, Path::new("/data/content/mu-plugins"), "WPMU_PLUGIN_DIR defaults under WP_CONTENT_DIR");
    assert_eq!(l.themes, Path::new("/data/content/themes"));
    let m = ComponentMap::lexical(&l);
    assert_eq!(at(&m, "/data/ext/akismet/akismet.php"), plugin("akismet"));
    assert_eq!(at(&m, "/data/content/themes/t/style.css"), Component::Theme("t".into()));
    assert_eq!(at(&m, "/data/content/uploads/x.png"), Component::Core, "the content dir is core even outside the root");
    assert_eq!(at(&m, "/srv/site/wp-content/plugins/akismet/akismet.php"), Component::Core, "the default folder no longer holds plugins");
    let l = Layout::wordpress(root, None, None, Some("/data/mu"));
    assert_eq!(at(&ComponentMap::lexical(&l), "/data/mu/x.php"), Component::MuPlugin("x".into()));
    // Relative constants are relative to the root.
    let l = Layout::wordpress(root, Some("content"), None, None);
    assert_eq!(l.plugins, Path::new("/srv/site/content/plugins"));
}

#[test]
fn nested_directories_pick_the_most_specific() {
    // mu-plugins configured inside the plugins directory.
    let l = Layout::wordpress(Path::new("/s"), None, Some("/s/p"), Some("/s/p/mu"));
    let m = ComponentMap::lexical(&l);
    assert_eq!(at(&m, "/s/p/mu/a.php"), Component::MuPlugin("a".into()));
    assert_eq!(at(&m, "/s/p/b/b.php"), plugin("b"));
}

#[test]
fn places_group_what_a_component_touches() {
    let m = site();
    let cf7 = plugin("contact-form-7");
    let place = |actor: &Component, p: &str| m.place(actor, Path::new(p));
    assert_eq!(place(&cf7, "/srv/site/wp-content/plugins/contact-form-7/x.php"), Place::Own);
    assert_eq!(place(&cf7, "/srv/site/wp-includes/version.php"), Place::CoreCode);
    assert_eq!(place(&cf7, "/srv/site/wp-content/uploads/wpcf7_uploads/a"), Place::Uploads);
    assert_eq!(place(&cf7, "/srv/site/wp-content/cache/x"), Place::Cache);
    assert_eq!(place(&cf7, "/srv/site/wp-content/plugins/akismet/a.php"), Place::OtherComponent(plugin("akismet")));
    assert_eq!(place(&cf7, "/tmp/x"), Place::Other);
    assert_eq!(place(&Component::Core, "/srv/site/wp-includes/version.php"), Place::Own);
    assert_eq!(place(&Component::Core, "/srv/site/wp-content/uploads/a"), Place::Uploads);
    assert_eq!(place(&Component::Core, "/srv/site/wp-content/plugins/akismet/a.php"), Place::OtherComponent(plugin("akismet")));
}

#[test]
fn normalize_and_frame_files() {
    assert_eq!(normalize(Path::new("/a/./b/../c")), Path::new("/a/c"));
    assert_eq!(normalize(Path::new("/srv/site/wp-content/uploads/../plugins/x/y.php")), Path::new("/srv/site/wp-content/plugins/x/y.php"));
    assert_eq!(at(&site(), &normalize(Path::new("/srv/site/wp-content/uploads/../plugins/x/y.php")).to_string_lossy()), plugin("x"));
    assert_eq!(frame_file("/srv/site/wp-content/plugins/x/a.php(12) : eval()'d code"), "/srv/site/wp-content/plugins/x/a.php");
    assert_eq!(frame_file("/srv/site/index.php"), "/srv/site/index.php");
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("securecore-attribution-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch dir");
    fs::canonicalize(&dir).expect("canonical scratch")
}

/// A plugin, a mu-plugin and a theme symlinked in from elsewhere, and a site root reached
/// through a symlink: each file is still its component when PHP reports its real path.
#[test]
fn symlinks_are_resolved() {
    let dir = scratch("links");
    let real_root = dir.join("real-site");
    let content = real_root.join("wp-content");
    for d in ["plugins", "mu-plugins", "themes"] {
        fs::create_dir_all(content.join(d)).expect("mkdir");
    }
    let shared = dir.join("shared");
    for d in ["seo", "agency", "brand"] {
        fs::create_dir_all(shared.join(d)).expect("mkdir");
        fs::write(shared.join(d).join("main.php"), "<?php").expect("write");
    }
    fs::write(shared.join("one.php"), "<?php").expect("write");
    symlink(shared.join("seo"), content.join("plugins/seo")).expect("symlink");
    symlink(shared.join("one.php"), content.join("plugins/one.php")).expect("symlink");
    symlink(shared.join("agency"), content.join("mu-plugins/agency")).expect("symlink");
    symlink(shared.join("brand"), content.join("themes/brand")).expect("symlink");
    let link_root = dir.join("site");
    symlink(&real_root, &link_root).expect("symlink root");

    let m = ComponentMap::resolve(&Layout::wordpress(&link_root, None, None, None));
    assert_eq!(m.classify(&shared.join("seo/main.php")), plugin("seo"));
    assert_eq!(m.classify(&shared.join("one.php")), plugin("one"));
    assert_eq!(m.classify(&shared.join("agency/main.php")), Component::MuPlugin("agency".into()));
    assert_eq!(m.classify(&shared.join("brand/main.php")), Component::Theme("brand".into()));
    assert_eq!(m.classify(&real_path(&link_root.join("wp-content/plugins/seo/main.php"))), plugin("seo"));
    assert_eq!(m.classify(&real_path(&link_root.join("wp-includes/x.php"))), Component::Core, "the root through its symlink");
    assert_eq!(m.root(), real_root);
    // Without resolving, the real paths are outside.
    let lexical = ComponentMap::lexical(&Layout::wordpress(&link_root, None, None, None));
    assert_eq!(lexical.classify(&shared.join("seo/main.php")), Component::Outside);
    // real_path resolves the existing part of a path that doesn't exist yet.
    assert_eq!(real_path(&link_root.join("wp-content/uploads/new/file.txt")), real_root.join("wp-content/uploads/new/file.txt"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn map_cache_follows_new_plugins() {
    let dir = scratch("cache");
    let root = dir.join("site");
    let content = root.join("wp-content");
    fs::create_dir_all(content.join("plugins")).expect("mkdir");
    let shared = dir.join("elsewhere/late");
    fs::create_dir_all(&shared).expect("mkdir");
    let layout = Layout::wordpress(&root, None, None, None);
    let mut cache = MapCache::new(Duration::from_secs(1));
    let t0 = Instant::now();
    let file = shared.join("late.php");
    let name = file.to_string_lossy().into_owned();
    assert_eq!(cache.frame(&layout, t0, &name), Component::Outside);
    // Symlinked in after the map was built: seen after the interval, not before.
    std::thread::sleep(Duration::from_millis(20)); // a distinct directory mtime
    symlink(&shared, content.join("plugins/late")).expect("symlink");
    assert_eq!(cache.frame(&layout, t0 + Duration::from_millis(10), &name), Component::Outside, "cached until the next check");
    assert_eq!(cache.frame(&layout, t0 + Duration::from_secs(2), &name), plugin("late"));
    // A different layout rebuilds at once.
    let moved = Layout::wordpress(&root, None, Some(&shared.parent().expect("parent").to_string_lossy()), None);
    assert_eq!(cache.frame(&moved, t0 + Duration::from_secs(2), &name), plugin("late"));
    assert_eq!(cache.frame(&moved, t0, "relative.php"), Component::Outside);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rule_frame_is_the_innermost_user_frame() {
    // A plugin calling a core API that opens the file: core's frame is innermost.
    let stack = [Component::Core, Component::Core, plugin("cf7"), Component::Core];
    assert_eq!(responsible(Rule::Frame, stack.clone()), Component::Core);
    assert_eq!(responsible(Rule::Frame, [plugin("cf7"), Component::Core]), plugin("cf7"));
    assert_eq!(responsible(Rule::Frame, []), Component::Core, "no user code: core");
}

#[test]
fn rule_component_is_the_innermost_component_on_the_stack() {
    let stack = [Component::Core, Component::Core, plugin("cf7"), Component::Core, plugin("outer")];
    assert_eq!(responsible(Rule::Component, stack), plugin("cf7"));
    let theme = [Component::Core, Component::Theme("t".into())];
    assert_eq!(responsible(Rule::Component, theme), Component::Theme("t".into()));
    assert_eq!(responsible(Rule::Component, [Component::Core, Component::Core]), Component::Core);
    assert_eq!(responsible(Rule::Component, [Component::Outside, Component::Core]), Component::Outside, "no component: the innermost frame");
    assert_eq!(responsible(Rule::Component, []), Component::Core);
}

#[test]
fn rules_read_the_stack_lazily() {
    let mut seen = 0;
    let frames = [Component::Core, plugin("a"), plugin("b")].into_iter().inspect(|_| seen += 1);
    assert_eq!(responsible(Rule::Frame, frames), Component::Core);
    assert_eq!(seen, 1, "rule (a) reads one frame");
    let mut seen = 0;
    let frames = [Component::Core, plugin("a"), plugin("b")].into_iter().inspect(|_| seen += 1);
    assert_eq!(responsible(Rule::Component, frames), plugin("a"));
    assert_eq!(seen, 2, "rule (b) stops at the first component");
}

#[test]
fn component_tokens_round_trip() {
    for c in [Component::Core, plugin("wordpress-seo"), Component::MuPlugin("m".into()), Component::Theme("t".into()), Component::Outside] {
        assert_eq!(Component::parse(&c.to_string()), Some(c));
    }
    assert_eq!(Component::parse("plugin:"), None);
    assert_eq!(Component::parse("widget:x"), None);
    assert_eq!(Rule::parse("frame"), Some(Rule::Frame));
    assert_eq!(Rule::parse("component"), Some(Rule::Component));
    assert_eq!(Rule::parse("both"), None);
}

#[test]
fn watched_ops_and_writes() {
    assert!(watch::watched(None, "fopen").is_some());
    assert!(watch::watched(None, "FOPEN").is_some(), "PHP names are case-insensitive");
    assert!(watch::watched(Some("SplFileObject"), "__construct").is_some());
    assert!(watch::watched(None, "__construct").is_none());
    assert!(watch::watched(None, "file_exists").is_none(), "metadata is not an open");
    assert_eq!(watch::with_mode("fopen", "rb"), "fopen:rb");
    assert_eq!(watch::with_mode("fopen", ""), "fopen:r");
    assert!(!watch::writes("fopen:rb"));
    for m in ["w", "ab", "x", "c+", "r+"] {
        assert!(watch::writes(&watch::with_mode("fopen", m)), "{m}");
    }
    assert!(watch::writes("file_put_contents") && watch::writes("unlink") && watch::writes("copy-to"));
    assert!(!watch::writes("file_get_contents") && !watch::writes("copy-from") && !watch::writes("require_once"));
    assert_eq!(watch::include_op(16), Some("require_once"));
    assert_eq!(watch::include_op(1), None, "eval opens no file");
    // Every op token is one word and maps back to its own write flag.
    for w in watch::WATCHED {
        for p in w.paths {
            assert!(!p.op.contains([' ', ':']), "{}", p.op);
            if w.mode.is_none() {
                assert_eq!(watch::writes(p.op), p.writes, "{}", p.op);
            }
        }
    }
}

#[test]
fn only_plain_file_paths_are_recorded() {
    assert_eq!(watch::plain_path("/var/www/html/a.txt"), Some("/var/www/html/a.txt"));
    assert_eq!(watch::plain_path("file:///var/www/html/a.txt"), Some("/var/www/html/a.txt"));
    assert_eq!(watch::plain_path("relative/a.txt"), Some("relative/a.txt"));
    for p in ["php://input", "https://example.com/", "phar:///x.phar/a", "compress.zlib:///a.gz", ""] {
        assert_eq!(watch::plain_path(p), None, "{p}");
    }
    assert_eq!(watch::plain_path("/a/b://c"), Some("/a/b://c"), "not a scheme");
}
