<?php
// Aggregate the per-plugin results into aggregate.json and tables.md (issue #40).
//
// Usage: php aggregate.php <corpus.json> <plugins-dir> <index.json> <aggregate.json> <tables.md>
declare(strict_types=1);

[$_, $corpusPath, $pluginsDir, $indexPath, $aggPath, $mdPath] = $argv + array_fill(0, 6, null);
if (!$mdPath) {
    fwrite(STDERR, "usage: php aggregate.php <corpus.json> <plugins-dir> <index.json> <aggregate.json> <tables.md>\n");
    exit(2);
}
$corpus = json_decode((string) file_get_contents($corpusPath), true);
$I = json_decode((string) file_get_contents($indexPath), true);
$P = [];
foreach ($corpus as $c) {
    $f = "$pluginsDir/{$c['slug']}.json";
    if (is_file($f)) {
        $P[$c['slug']] = json_decode((string) file_get_contents($f), true) + ['corpus' => $c];
    }
}
$N = count($P);
$md = [];
$agg = ['plugins' => $N, 'wordpress_version' => $I['wordpress_version'], 'woocommerce_version' => $I['woocommerce_version']];

// What the sweep (#29, docs/compatibility.md on claude/compat-29) saw at run time, per plugin.
const SWEEP = [
    'wordpress-seo' => [30, 32, 35], 'elementor' => [30], 'contact-form-7' => [30, 31, 34, 35], 'classic-editor' => [32, 36],
    'akismet' => [34], 'wpforms-lite' => [32], 'jetpack' => [32], 'google-site-kit' => [32, 35], 'updraftplus' => [31, 32, 34],
    'all-in-one-seo-pack' => [31], 'litespeed-cache' => [33], 'wp-mail-smtp' => [30, 37], 'really-simple-ssl' => [31],
    'wordfence' => [31], 'redirection' => [35],
];
// Globals that hold objects (or arrays of objects): a copy is not enough, they need a proxy.
const OBJECT_GLOBALS = ['wpdb', 'wp_query', 'wp_the_query', 'wp_rewrite', 'wp', 'wp_roles', 'wp_filesystem', 'wp_scripts',
    'wp_styles', 'wp_admin_bar', 'wp_locale', 'wp_widget_factory', 'wp_embed', 'current_screen', 'post', 'wp_post_types',
    'wp_taxonomies', 'wp_meta_boxes', 'wp_registered_widgets', 'wp_registered_sidebars', 'wp_object_cache', 'wp_customize',
    'wp_filter', 'wp_actions', 'wp_current_filter', 'wp_settings_sections', 'wp_settings_fields', 'wp_registered_widget_controls',
    'authordata', 'comment', 'wp_xmlrpc_server', 'wp_list_table', 'wp_hasher', 'current_user', 'wp_sitemaps', 'wp_textdomain_registry',
    'wp_theme_directories', 'menu', 'submenu', 'wp_version_check', 'wp_plugin_paths', 'l10n', 'wp_locale_switcher', 'wp_post_statuses',
    'shortcode_tags', 'wp_meta_keys', 'wp_registered_settings', 'allowedposttags', 'wp_wp_editor', 'wp_importers', 'wp_rest_server',
    'wp_block_types', 'wp_interactivity', 'wp_term_query', 'wp_user_roles', 'wp_did_header', 'wp_editor_styles', 'post_type_meta_caps'];
const SANDBOX_HAS = ['ABSPATH', 'WPINC']; // constants the current sandbox already defines

function u(array $p, string ...$path): array
{
    $out = [];
    foreach (['own', 'vendor'] as $s) {
        $x = $p[$s];
        foreach ($path as $k) {
            $x = $x[$k] ?? [];
        }
        foreach ($x as $k => $v) {
            $out[$k] = isset($out[$k]) && is_array($v) && isset($v['n']) ? ['n' => $out[$k]['n'] + $v['n'], 'at' => $out[$k]['at']] : ($out[$k] ?? $v);
        }
    }
    return $out;
}

function ul(array $p, string ...$path): array
{
    $out = [];
    foreach (['own', 'vendor'] as $s) {
        $x = $p[$s];
        foreach ($path as $k) {
            $x = $x[$k] ?? [];
        }
        foreach ($x as $row) {
            $out[] = $row + ['scope' => $s];
        }
    }
    return $out;
}

function pct(int $n, int $of): string
{
    return $of ? round(100 * $n / $of) . '%' : '-';
}

/** item => number of plugins needing it, sorted. */
function freq(array $needs): array
{
    $f = [];
    foreach ($needs as $set) {
        foreach ($set as $k => $_) {
            $f[$k] = ($f[$k] ?? 0) + 1;
        }
    }
    arsort($f);
    return $f;
}

/**
 * Smallest set (greedy) that fully satisfies at least $k plugins: repeatedly take the plugin
 * whose needs add the fewest new items.
 */
function cover(array $needs, int $k): array
{
    $have = [];
    $done = [];
    while (count($done) < $k) {
        $best = null;
        $bestAdd = PHP_INT_MAX;
        foreach ($needs as $slug => $set) {
            if (isset($done[$slug])) {
                continue;
            }
            $add = count(array_diff_key($set, $have));
            if ($add < $bestAdd) {
                [$best, $bestAdd] = [$slug, $add];
            }
        }
        if ($best === null) {
            break;
        }
        $done[$best] = true;
        $have += $needs[$best];
    }
    ksort($have);
    return array_keys($have);
}

function table(array $head, array $rows): string
{
    $s = '| ' . implode(' | ', $head) . " |\n|" . str_repeat(' --- |', count($head)) . "\n";
    foreach ($rows as $r) {
        $s .= '| ' . implode(' | ', array_map(fn($c) => str_replace(['|', "\n"], ['\\|', ' '], (string) $c), $r)) . " |\n";
    }
    return $s;
}

function coverage_block(string $title, array $needs, int $N, int $topN = 40): array
{
    $f = freq($needs);
    $k90 = (int) ceil(0.9 * $N);
    $k99 = (int) ceil(0.99 * $N);
    $c90 = cover($needs, $k90);
    $c99 = cover($needs, $k99);
    $zero = count(array_filter($needs, fn($s) => !$s));
    $ge10 = array_filter($f, fn($n) => $n >= 0.1 * $N);
    return [
        'title' => $title,
        'distinct' => count($f),
        'plugins_needing_none' => $zero,
        'needed_by_ge_10pct' => $ge10,
        'cover_90' => ['plugins' => $k90, 'size' => count($c90), 'items' => $c90],
        'cover_99' => ['plugins' => $k99, 'size' => count($c99), 'items' => $c99],
        'top' => array_slice($f, 0, $topN, true),
    ];
}

// ------------------------------------------------------------------ per plugin needs

$needs = ['core_files' => [], 'functions' => [], 'function_files' => [], 'globals' => [], 'object_globals' => [],
    'constants' => [], 'classes_extend' => [], 'classes_use' => [], 'woo_classes_extend' => [], 'woo_functions' => []];
$rows = [];
$causes = [];
foreach ($P as $slug => $p) {
    $fnWp = u($p, 'functions', 'wp');
    $needs['functions'][$slug] = array_fill_keys(array_keys($fnWp), true);
    $ff = [];
    foreach ($fnWp as $f => $_) {
        $ff[$I['wp']['functions'][$f] ?? '?'] = true;
    }
    $needs['function_files'][$slug] = $ff;
    $needs['woo_functions'][$slug] = array_fill_keys(array_keys(u($p, 'functions', 'woo')), true);
    $needs['core_files'][$slug] = array_fill_keys(array_keys(u($p, 'includes', 'core_files')), true);
    $g = u($p, 'globals', 'wp') + u($p, 'globals', 'wp_page_scope');
    $needs['globals'][$slug] = array_fill_keys(array_keys($g), true);
    $needs['object_globals'][$slug] = array_fill_keys(array_values(array_intersect(array_keys($g), OBJECT_GLOBALS)), true);
    $needs['constants'][$slug] = array_fill_keys(array_keys(u($p, 'constants', 'wp')), true);
    $ext = array_merge(array_keys(u($p, 'classes', 'wp', 'extends')), array_keys(u($p, 'classes', 'wp', 'implements')));
    $needs['classes_extend'][$slug] = array_fill_keys($ext, true);
    $use = [];
    foreach (['new', 'static', 'extends', 'implements', 'instanceof', 'catch'] as $h) {
        foreach (u($p, 'classes', 'wp', $h) as $c => $_) {
            $use[$c] = true;
        }
    }
    $needs['classes_use'][$slug] = $use;
    $needs['woo_classes_extend'][$slug] = array_fill_keys(array_merge(array_keys(u($p, 'classes', 'woo', 'extends')), array_keys(u($p, 'classes', 'woo', 'implements'))), true);

    // causes #30–#37, as static analysis sees them
    $writes = ul($p, 'fs_writes');
    $readsOut = ul($p, 'fs_reads_outside_own');
    $uploads = u($p, 'uploads') || array_filter(array_merge($writes, $readsOut), fn($w) => $w['class'] === 'uploads');
    $wpContent = (bool) array_filter(array_merge($writes, $readsOut), fn($w) => in_array($w['class'], ['wp-content', 'drop-in', 'mu-plugins', 'wp-content/languages'], true));
    $consts33 = array_diff(array_keys($needs['constants'][$slug]), SANDBOX_HAS);
    $dynHooks = count(u($p, 'hooks', 'add_dynamic')) + count(u($p, 'hooks', 'add_folded')) + count(u($p, 'lifecycle_hooks'));
    $scbWp = u($p, 'string_callbacks', 'wp');
    $c = [
        30 => $p['method_named_like_called_core_function'],
        31 => ['core_files' => array_keys($needs['core_files'][$slug]), 'uploads' => (bool) $uploads, 'wp_content' => $wpContent],
        32 => array_keys($needs['globals'][$slug]),
        33 => array_values($consts33),
        34 => array_keys($use),
        35 => $dynHooks,
        36 => array_keys($scbWp),
        37 => array_keys(u($p, 'objects_crossing')),
    ];
    $flags = [
        30 => (bool) $c[30], 31 => $c[31]['core_files'] || $c[31]['uploads'] || $c[31]['wp_content'], 32 => (bool) $c[32],
        33 => (bool) $c[33], 34 => (bool) $c[34], 35 => $c[35] > 0, 36 => (bool) $c[36], 37 => (bool) $c[37],
    ];
    $causes[$slug] = ['flags' => $flags, 'detail' => $c];
}

// ------------------------------------------------------------------ corpus table
$md[] = "## Corpus\n\nWordPress {$I['wordpress_version']}, WooCommerce {$I['woocommerce_version']}, analyzed on PHP {$I['php_version']} with nikic/PHP-Parser. Own = the plugin's code; vendor = bundled third-party code (`vendor/`, `vendor_prefixed/`, `jetpack_vendor/`, `third-party/`, `node_modules/`).\n";
$cr = [];
$tot = ['files' => 0, 'own' => 0, 'vendor' => 0];
foreach ($P as $slug => $p) {
    $c = $p['corpus'];
    $cr[] = [$c['rank'], $slug, $c['version'], number_format($c['active_installs']), round($c['zip_bytes'] / 1048576, 1) . ' MB',
        $p['php_files'], $p['own']['files'], $p['vendor']['files'], $c['group'], $p['header']['Requires PHP'] ?? ($c['requires_php'] ?: '-'),
        count($p['parse_error_files'])];
    $tot['files'] += $p['php_files'];
    $tot['own'] += $p['own']['files'];
    $tot['vendor'] += $p['vendor']['files'];
}
$md[] = table(['rank', 'slug', 'version', 'installs', 'zip', 'php files', 'own', 'vendor', 'group', 'requires PHP', 'parse-error files'], $cr);
$md[] = "Total: {$tot['files']} PHP files ({$tot['own']} own, {$tot['vendor']} vendor).\n";
$agg['php_files'] = $tot;
$agg['parse_error_files'] = array_filter(array_map(fn($p) => $p['parse_error_files'], $P));

// ------------------------------------------------------------------ causes matrix
$md[] = "## The sweep's causes (#30–#37) across all $N plugins\n\nStatic predictions: a plugin is marked when its code (own or vendor) contains the pattern behind the cause. #31 = includes a core file, or touches uploads / wp-content outside its folder; #33 = WordPress constants other than ABSPATH/WPINC; #34 = uses a core class (extend, implement, new, static call, instanceof, catch); #35 = hook tags not literal in source (built from constants, `__FILE__` or variables) or activation/deactivation hooks; #37 = passes an object it built (`\$this`, `new`) into an option/transient/meta/cache or a hook it fires (lower bound).\n";
$crow = [];
$counts = array_fill_keys([30, 31, 32, 33, 34, 35, 36, 37], 0);
$allClear = 0;
foreach ($causes as $slug => $c) {
    $r = [$slug];
    foreach ($c['flags'] as $k => $v) {
        $r[] = $v ? 'x' : '';
        $counts[$k] += $v ? 1 : 0;
    }
    if (!array_filter($c['flags'])) {
        $allClear++;
    }
    $sw = SWEEP[$slug] ?? null;
    $r[] = $sw === null ? '' : implode(' ', array_map(fn($x) => "#$x", $sw));
    $crow[] = $r;
}
$md[] = table(['plugin', '#30', '#31', '#32', '#33', '#34', '#35', '#36', '#37', 'sweep saw'], $crow);
$md[] = table(['cause', 'plugins (of ' . $N . ')', 'share'], array_map(fn($k) => ["#$k", $counts[$k], pct($counts[$k], $N)], array_keys($counts)));
$md[] = "Plugins hit by none of the eight: $allClear of $N.\n";
// prediction vs sweep
$agree = [];
foreach (SWEEP as $slug => $seen) {
    if (!isset($causes[$slug])) {
        continue;
    }
    $pred = array_keys(array_filter($causes[$slug]['flags']));
    $missed = array_diff($seen, $pred);
    $agree[] = [$slug, implode(' ', array_map(fn($x) => "#$x", $seen)), implode(' ', array_map(fn($x) => "#$x", $pred)),
        $missed ? 'MISSED ' . implode(' ', array_map(fn($x) => "#$x", $missed)) : 'all seen causes predicted'];
}
$md[] = "### Static prediction vs what the sweep saw at run time\n\nThe sweep stops at the first fatal, so it sees a subset of each plugin's causes; static analysis should predict every cause the sweep saw (a miss is an analyzer blind spot) and usually more.\n";
$md[] = table(['plugin', 'sweep saw', 'static analysis predicts', 'check'], $agree);
$agg['causes'] = ['counts' => $counts, 'none' => $allClear, 'per_plugin' => $causes, 'vs_sweep' => $agree];

// ------------------------------------------------------------------ coverage
$blocks = [
    'core_files' => 'Core files `require`d / `include`d explicitly',
    'globals' => 'WordPress globals read or written',
    'object_globals' => 'WordPress globals that hold objects (need a proxy, not a copy)',
    'constants' => 'WordPress / wp-config constants read',
    'classes_extend' => 'Core classes extended or implemented',
    'classes_use' => 'Core classes used at all (extend, implement, new, static, instanceof, catch)',
    'functions' => 'Core functions called',
    'function_files' => 'Core files that define the functions they call',
    'woo_classes_extend' => 'WooCommerce classes extended or implemented (extensions)',
];
$agg['coverage'] = [];
foreach ($blocks as $k => $title) {
    $nd = $needs[$k];
    if ($k === 'woo_classes_extend') {
        $nd = array_filter($nd, fn($s, $slug) => $P[$slug]['corpus']['group'] === 'woo-extension', ARRAY_FILTER_USE_BOTH);
    }
    $b = coverage_block($title, $nd, count($nd));
    $agg['coverage'][$k] = $b;
    $n = count($nd);
    $md[] = "## $title\n\nDistinct: **{$b['distinct']}**. Plugins needing none: {$b['plugins_needing_none']} of $n. "
        . "Smallest set (greedy) for **{$b['cover_90']['plugins']}/$n plugins (90%)**: **{$b['cover_90']['size']}**; "
        . "for **{$b['cover_99']['plugins']}/$n (99%)**: **{$b['cover_99']['size']}**.\n";
    $show = array_slice($b['top'], 0, $k === 'functions' ? 60 : 40, true);
    $md[] = table(['item', 'plugins', 'share'], array_map(fn($item, $cnt) => ["`$item`", $cnt, pct($cnt, $n)], array_keys($show), $show));
    if (in_array($k, ['core_files', 'globals', 'constants', 'classes_extend', 'object_globals'], true)) {
        $md[] = "Set for 90%: " . ($b['cover_90']['items'] ? '`' . implode('`, `', $b['cover_90']['items']) . '`' : '(none)') . "\n";
        if ($b['cover_99']['size'] <= 150) {
            $md[] = "Set for 99%: " . ($b['cover_99']['items'] ? '`' . implode('`, `', $b['cover_99']['items']) . '`' : '(none)') . "\n";
        }
    }
}
// functions per plugin
$fpp = array_map('count', $needs['functions']);
arsort($fpp);
$md[] = "### Distinct core functions per plugin\n\n" . table(['plugin', 'core functions', 'Woo functions'], array_map(fn($s, $n) => [$s, $n, count($needs['woo_functions'][$s])], array_keys($fpp), $fpp));
// call-site frequency
$sites = [];
foreach ($P as $slug => $p) {
    foreach (u($p, 'functions', 'wp') as $f => $b) {
        $sites[$f] = ($sites[$f] ?? 0) + $b['n'];
    }
}
arsort($sites);
$agg['function_call_sites'] = array_slice($sites, 0, 300, true);
$agg['function_call_sites_total'] = array_sum($sites);
// admin-only files
$adminFns = 0;
$adminPlugins = [];
foreach ($needs['functions'] as $slug => $set) {
    foreach ($set as $f => $_) {
        if (str_starts_with($I['wp']['functions'][$f] ?? '', 'wp-admin/')) {
            $adminPlugins[$slug] = ($adminPlugins[$slug] ?? 0) + 1;
        }
    }
}
$agg['plugins_calling_wp_admin_functions'] = $adminPlugins;

// ------------------------------------------------------------------ secrets
$md[] = "## Secrets: DB_* constants, keys and salts, \$wpdb credentials, wp-config.php read\n";
$sec = [];
$secPlugins = [];
foreach ($P as $slug => $p) {
    foreach (ul($p, 'secrets') as $r) {
        $sec[] = [$slug, $r['scope'], $r['what'], $r['at'], $r['in'], '`' . substr($r['line'], 0, 140) . '`'];
        $secPlugins[$slug][$r['what']] = true;
    }
}
$md[] = "Plugins with any: **" . count($secPlugins) . "** of $N.\n";
$md[] = table(['plugin', 'what they read'], array_map(fn($s, $w) => [$s, implode(', ', array_keys($w))], array_keys($secPlugins), $secPlugins));
$md[] = "Every site (" . count($sec) . "):\n";
$md[] = table(['plugin', 'scope', 'what', 'where', 'in', 'line'], $sec);
$salted = [];
foreach ($P as $slug => $p) {
    $s = u($p, 'salted');
    if ($s) {
        $salted[$slug] = array_keys($s);
    }
}
$saltCount = [];
foreach ($salted as $fns) {
    foreach ($fns as $f) {
        $saltCount[$f] = ($saltCount[$f] ?? 0) + 1;
    }
}
arsort($saltCount);
$md[] = "### Core functions that use the keys and salts\n\nPlugins calling at least one: **" . count($salted) . "** of $N. (These need the secrets *in the process that runs them*: if the sandbox holds a read-only WordPress without the salts, these calls must still go to core.)\n";
$md[] = table(['function', 'plugins'], array_map(fn($f, $n) => ["`$f`", $n], array_keys($saltCount), $saltCount));
$agg['secrets'] = ['plugins' => $secPlugins, 'sites' => $sec, 'salted_plugins' => $salted, 'salted_functions' => $saltCount];

// ------------------------------------------------------------------ sensitive capabilities
// Core functions and classes that change who is logged in, who exists, which code runs, or
// what leaves the site. Whatever runs in the sandbox, these are the calls a policy must gate.
const SENSITIVE = [
    'log a user in / out' => ['wp_set_auth_cookie', 'wp_set_current_user', 'wp_clear_auth_cookie', 'wp_signon'],
    'create / change / delete users' => ['wp_insert_user', 'wp_create_user', 'wp_update_user', 'wp_delete_user', 'grant_super_admin', 'add_role', 'remove_role'],
    'activate / deactivate / delete plugins' => ['activate_plugin', 'activate_plugins', 'deactivate_plugins', 'delete_plugins'],
    'install / update code (upgraders)' => ['Plugin_Upgrader', 'Theme_Upgrader', 'Language_Pack_Upgrader', 'Core_Upgrader', 'WP_Upgrader', 'unzip_file', 'download_url'],
    'switch theme' => ['switch_theme'],
    'schedule cron' => ['wp_schedule_event', 'wp_schedule_single_event'],
    'send mail' => ['wp_mail'],
    'handle uploads' => ['wp_handle_upload', 'wp_handle_sideload', 'media_handle_upload', 'media_handle_sideload', 'wp_upload_bits'],
    'change options (any)' => ['update_option', 'add_option', 'delete_option'],
];
$sens = [];
foreach ($P as $slug => $p) {
    $fns = u($p, 'functions', 'wp');
    $cls = u($p, 'classes', 'wp', 'new') + u($p, 'classes', 'wp', 'extends');
    foreach (SENSITIVE as $label => $names) {
        foreach ($names as $nm) {
            if (isset($fns[strtolower($nm)]) || isset($cls[$nm])) {
                $sens[$label][$slug] = true;
            }
        }
    }
}
$md[] = "## Sensitive core capabilities, by plugins\n\nCore functions/classes that log users in, change users, plugins or code, schedule work or send data out. Whatever the sandbox design, these are the calls a policy has to gate.\n";
$md[] = table(['capability', 'via', 'plugins', 'share'], array_map(fn($l) => [$l, '`' . implode('`, `', SENSITIVE[$l]) . '`', count($sens[$l] ?? []), pct(count($sens[$l] ?? []), $N)], array_keys(SENSITIVE)));
$agg['sensitive'] = array_map('array_keys', $sens);

// ------------------------------------------------------------------ files written
$md[] = "## Files written\n\nWrite calls: `file_put_contents`, `fopen` (w/a/x/c), `mkdir`, `wp_mkdir_p`, `rename`, `copy`, `unlink`, `rmdir`, `touch`, `chmod`, `move_uploaded_file`, `insert_with_markers`, `unzip_file`, `copy_dir`, `\$wp_filesystem->put_contents/mkdir/delete/move/copy`, `->extractTo`, and `save_mod_rewrite_rules` / hard `flush_rewrite_rules` (core then writes `.htaccess`). Target = the path argument, resolved where possible.\n";
$wcls = [];
$wplug = [];
$specialW = [];
$dynHint = [];
foreach ($P as $slug => $p) {
    foreach (ul($p, 'fs_writes') as $w) {
        $key = $w['class'] . ($w['how'] === 'resolved' ? '' : " ({$w['how']})");
        $wcls[$key] = ($wcls[$key] ?? 0) + 1;
        $wplug[$w['class']][$slug] = true;
        if (in_array($w['class'], ['wp-config.php', '.htaccess (site root)', 'drop-in', 'mu-plugins', 'php config', 'server config', 'core', 'site root', 'plugins folder'], true)) {
            $specialW[] = [$slug, $w['scope'], $w['class'] . ($w['how'] === 'resolved' ? '' : " ({$w['how']})"), $w['fn'], '`' . $w['path'] . '`', $w['at'], $w['in']];
        }
        if ($w['class'] === 'dynamic') {
            // Heuristic only: what the variable holding the path is called.
            $label = strtolower(preg_match('/^\{([^}]*)\}/', $w['path'], $mm) ? $mm[1] : $w['path']);
            $hint = 'other / generic name ($file, $path, …)';
            foreach (['upload' => 'upload', 'cache' => 'cache', 'log' => 'log', 'backup|updraft|archive|zip|dump|package|snapshot' => 'backup / archive',
                'tmp|temp' => 'temp', 'font' => 'fonts', 'lang|l10n|mo|po' => 'translations', 'css|js|asset|style|script' => 'assets (css/js)',
                'plugin' => 'plugins', 'theme' => 'themes', 'config|htaccess|home|root|abspath' => 'site config / root', 'image|thumb|media|attach' => 'media'] as $re => $h) {
                if (preg_match("/($re)/", $label)) {
                    $hint = $h;
                    break;
                }
            }
            $dynHint[$hint][$slug] = ($dynHint[$hint][$slug] ?? 0) + 1;
        }
    }
}
uasort($dynHint, fn($a, $b) => array_sum($b) <=> array_sum($a));
arsort($wcls);
$md[] = table(['target', 'plugins', 'share'], array_map(fn($k, $v) => [$k, count($v), pct(count($v), $N)], array_keys($wplug), $wplug));
$md[] = table(['target (how resolved)', 'call sites'], array_map(fn($k, $v) => [$k, $v], array_keys($wcls), $wcls));
$md[] = "Write sites with a fully dynamic path, by what the path variable is called (heuristic; a name is not a destination):\n\n"
    . table(['hint', 'call sites', 'plugins'], array_map(fn($h, $v) => [$h, array_sum($v), count($v)], array_keys($dynHint), $dynHint));
$md[] = "### Writes into wp-config.php, the site's .htaccess, drop-ins, mu-plugins, core, the site root or other plugins (resolved, partly resolved, or by name heuristic)\n\n`.htaccess via core (rewrite flush)` (a hard `flush_rewrite_rules()`; core writes the file) is counted in the target table above, not listed here.\n";
$md[] = table(['plugin', 'scope', 'target', 'call', 'path', 'where', 'in'], $specialW);
$lk = [];
foreach ($P as $slug => $p) {
    foreach (ul($p, 'likely_writes') as $l) {
        $lk[$l['special']][$slug][] = $l['in'] . ' [' . $l['scope'] . ']: ' . implode('; ', $l['writes']);
    }
}
$md[] = "### Functions that name a special file and also write a file (likely writes, dynamic paths)\n\nThe path in these writes is a variable, so the call above can't be classified; but the same function names the file. A strong hint, not proof: each needs reading (see REPORT.md spot checks).\n";
$lrows = [];
foreach ($lk as $sf => $byPlugin) {
    $lrows[] = ["`$sf`", count($byPlugin), implode(', ', array_keys($byPlugin))];
}
$md[] = table(['file', 'plugins', 'which'], $lrows);
$agg['writes'] = ['by_target_plugins' => array_map(fn($v) => array_keys($v), $wplug), 'by_target_sites' => $wcls, 'special' => $specialW, 'likely' => $lk];

// ------------------------------------------------------------------ database
$md[] = "## Database\n";
$dbr = [];
$coreT = [];
$ownT = [];
$direct = [];
$dqPlugins = 0;
foreach ($P as $slug => $p) {
    $m = u($p, 'wpdb_methods');
    $dq = 0;
    foreach (['query', 'get_results', 'get_row', 'get_var', 'get_col'] as $q) {
        $dq += $m[$q]['n'] ?? 0;
    }
    $dqPlugins += $dq ? 1 : 0;
    $tables = array_keys(u($p, 'sql_tables'));
    $core = [];
    $own = [];
    $dyn = 0;
    foreach ($tables as $t) {
        if (preg_match('/^\{prefix\}(' . implode('|', ['posts', 'postmeta', 'comments', 'commentmeta', 'terms', 'termmeta', 'term_taxonomy', 'term_relationships', 'options', 'links', 'users', 'usermeta', 'blogs', 'blogmeta', 'signups', 'site', 'sitemeta', 'registration_log']) . ')$/', $t, $mm)) {
            $core[$mm[1]] = true;
            $coreT[$mm[1]][$slug] = true;
        } elseif (str_starts_with($t, '{prefix}') && !str_contains(substr($t, 8), '{')) {
            $own[$t] = true;
            $ownT[$t][$slug] = true;
        } else {
            $dyn++;
        }
    }
    $created = array_keys(u($p, 'tables_created'));
    $dd = isset(u($p, 'db_calls')['dbdelta']);
    foreach (ul($p, 'direct_db') as $d) {
        $direct[] = [$slug, $d['scope'], $d['what'], $d['at'], $d['in']];
    }
    $dbr[] = [$slug, $dq, implode(' ', array_keys($core)), count($own), $dyn, count($created) . ($dd ? ' (dbDelta)' : ''),
        implode(' ', array_slice(array_map(fn($t) => str_replace('{prefix}', '', $t), $created), 0, 8)) . (count($created) > 8 ? ' …' : '')];
}
$md[] = "Plugins running direct queries through `\$wpdb` (`query`, `get_results`, `get_row`, `get_var`, `get_col`): **$dqPlugins** of $N.\n";
$md[] = table(['plugin', 'direct $wpdb queries', 'core tables named in SQL', 'own tables named', 'table names not resolved', 'tables created', 'created (first 8)'], $dbr);
$md[] = "Core tables named in SQL, by plugins:\n\n" . table(['table', 'plugins'], array_map(fn($t, $s) => [$t, count($s)], array_keys($coreT), $coreT));
$md[] = "Database connections outside \$wpdb (mysqli / PDO / mysql_*):\n\n" . table(['plugin', 'scope', 'what', 'where', 'in'], $direct);
$agg['database'] = ['direct_query_plugins' => $dqPlugins, 'rows' => $dbr, 'core_tables' => array_map('array_keys', $coreT), 'own_tables' => array_map('array_keys', $ownT), 'direct_connections' => $direct];

// ------------------------------------------------------------------ network
$md[] = "## Network\n";
$nrow = [];
$hostsN = [];
$netPlugins = [];
foreach ($P as $slug => $p) {
    $n = u($p, 'network');
    $kinds = [];
    foreach ($n as $fn => $b) {
        $k = str_starts_with($fn, 'wp_remote') || str_starts_with($fn, 'wp_safe_remote') || $fn === 'download_url' ? 'wp_remote_*' :
            (str_starts_with($fn, 'curl') ? 'curl' : (in_array($fn, ['wp_mail', 'mail'], true) ? 'mail' : 'sockets/other'));
        $kinds[$k] = ($kinds[$k] ?? 0) + $b['n'];
    }
    foreach (array_keys($kinds) as $k) {
        $netPlugins[$k][$slug] = true;
    }
    foreach (u($p, 'network_hosts') as $h => $_) {
        $hostsN[$h][$slug] = true;
    }
    $nrow[] = [$slug, $kinds['wp_remote_*'] ?? 0, $kinds['curl'] ?? 0, $kinds['sockets/other'] ?? 0, $kinds['mail'] ?? 0,
        implode(' ', array_slice(array_keys(u($p, 'network_hosts')), 0, 6))];
}
$md[] = table(['kind', 'plugins'], array_map(fn($k, $v) => [$k, count($v)], array_keys($netPlugins), $netPlugins));
$md[] = table(['plugin', 'wp_remote_*', 'curl', 'sockets/ftp/dns', 'mail', 'literal hosts in remote calls (first 6)'], $nrow);
uasort($hostsN, fn($a, $b) => count($b) <=> count($a));
$md[] = "Hosts named literally in a remote call's URL, by plugins (top 30):\n\n" . table(['host', 'plugins'], array_map(fn($h, $s) => [$h, count($s)], array_slice(array_keys($hostsN), 0, 30), array_slice($hostsN, 0, 30)));
$agg['network'] = ['by_kind' => array_map('array_keys', $netPlugins), 'hosts' => array_map('array_keys', $hostsN)];

// ------------------------------------------------------------------ risky
$md[] = "## Risky code (own / vendor, plugins)\n";
$rk = [];
foreach ($P as $slug => $p) {
    foreach (['own', 'vendor'] as $s) {
        foreach ($p[$s]['risky'] as $k => $b) {
            $rk[$k][$s][$slug] = $b['n'];
        }
    }
}
ksort($rk);
$md[] = table(['pattern', 'plugins (own code)', 'plugins (vendor code)', 'own: which'], array_map(fn($k, $v) => [$k, count($v['own'] ?? []), count($v['vendor'] ?? []),
    implode(', ', array_slice(array_keys($v['own'] ?? []), 0, 12)) . (count($v['own'] ?? []) > 12 ? ' …' : '')], array_keys($rk), $rk));
$ex = [];
foreach ($P as $slug => $p) {
    foreach (ul($p, 'exec') as $e) {
        $ex[] = [$slug, $e['scope'], $e['what'], $e['at'], $e['in'], '`' . substr($e['line'], 0, 120) . '`'];
    }
    foreach (ul($p, 'eval') as $e) {
        $ex[] = [$slug, $e['scope'], 'eval', $e['at'], $e['in'], '`' . substr($e['line'], 0, 120) . '`'];
    }
}
$md[] = "### Every process-spawning call and eval\n\n" . table(['plugin', 'scope', 'what', 'where', 'in', 'line'], $ex);
$agg['risky'] = ['by_pattern' => $rk, 'exec_eval' => $ex];

// ------------------------------------------------------------------ hooks
$md[] = "## Hooks\n";
$coreHooks = [];
$dynPrefix = [];
$hrow = [];
foreach ($P as $slug => $p) {
    $core = u($p, 'hooks', 'add_core');
    foreach ($core as $t => $_) {
        $coreHooks[$t] = ($coreHooks[$t] ?? 0) + 1;
    }
    $dyn = u($p, 'hooks', 'add_dynamic');
    $fold = u($p, 'hooks', 'add_folded');
    foreach (array_merge(array_keys($dyn), array_keys($fold)) as $t) {
        $pre = preg_replace('/\{.*$/', '{…}', $t);
        if (isset($fold[$t])) {
            $pre = preg_match('/^(plugin_action_links_|network_admin_plugin_action_links_|activate_|deactivate_|option_|default_option_|update_option_|add_option_|pre_update_option_|pre_option_|site_option_|load-|admin_print_scripts-|admin_print_styles-|admin_head-|admin_footer-|manage_|wp_ajax_nopriv_|wp_ajax_|in_plugin_update_message-|after_plugin_row_|theme_mod_)/', $t, $mm) ? $mm[1] . '…' : '(a whole tag from a constant, e.g. self::HOOK)';
        }
        $dynPrefix[$pre][$slug] = true;
    }
    $t = $p['own']['totals'];
    $tv = $p['vendor']['totals'];
    $adds = ($t['hooks_add'] ?? 0) + ($tv['hooks_add'] ?? 0);
    $hrow[] = [$slug, $adds, count($core), count(u($p, 'hooks', 'add_woo')), count($fold), count($dyn), count(u($p, 'lifecycle_hooks'))];
}
arsort($coreHooks);
$md[] = table(['plugin', 'add_action/add_filter calls', 'distinct core hooks', 'distinct Woo hooks', 'tags folded from constants/__FILE__', 'tags dynamic', 'activation/deactivation/uninstall hooks'], $hrow);
$md[] = "Top core hooks, by plugins:\n\n" . table(['hook', 'plugins', 'share'], array_map(fn($h, $n) => ["`$h`", $n, pct($n, $N)], array_slice(array_keys($coreHooks), 0, 50), array_slice($coreHooks, 0, 50)));
uasort($dynPrefix, fn($a, $b) => count($b) <=> count($a));
$md[] = "Hook tags that are not literals in the source (#35), grouped by their literal prefix, by plugins (top 40):\n\n" . table(['prefix', 'plugins'], array_map(fn($k, $v) => ["`$k`", count($v)], array_slice(array_keys($dynPrefix), 0, 40), array_slice($dynPrefix, 0, 40)));
$scb = [];
foreach ($P as $slug => $p) {
    foreach (u($p, 'string_callbacks', 'wp') as $k => $_) {
        $scb[explode(' via ', $k)[0]][$slug] = true;
    }
}
uasort($scb, fn($a, $b) => count($b) <=> count($a));
$scbHook = [];
foreach ($P as $slug => $p) {
    foreach (u($p, 'string_callbacks', 'wp') as $k => $_) {
        [$fn, $via] = explode(' via ', $k);
        if (in_array($via, ['add_action', 'add_filter'], true)) {
            $scbHook[$fn][$slug] = true;
        }
    }
}
uasort($scbHook, fn($a, $b) => count($b) <=> count($a));
$hookPl = [];
foreach ($scbHook as $v) {
    $hookPl += $v;
}
$allPl = [];
foreach ($scb as $v) {
    $allPl += $v;
}
$md[] = "Core functions passed as string callbacks (#36). As a hook callback (`add_action` / `add_filter`, the case #36 describes): **" . count($hookPl) . "** of $N plugins. In any callback position (also `array_map`, `usort`, menu/settings callbacks, `call_user_func`; a token scan doesn't see these as calls either, so no stand-in is generated): **" . count($allPl) . "** of $N.\n";
$md[] = "As hook callbacks:\n\n" . table(['function', 'plugins'], array_map(fn($k, $v) => ["`$k`", count($v)], array_keys($scbHook), $scbHook));
$md[] = "In any callback position (top 30):\n\n" . table(['function', 'plugins'], array_map(fn($k, $v) => ["`$k`", count($v)], array_slice(array_keys($scb), 0, 30), array_slice($scb, 0, 30)));
$agg['hooks'] = ['core_hooks' => $coreHooks, 'dynamic_prefixes' => array_map('array_keys', $dynPrefix), 'string_callbacks' => array_map('array_keys', $scb),
    'string_callbacks_as_hooks' => array_map('array_keys', $scbHook), 'string_callback_hook_plugins' => count($hookPl), 'rows' => $hrow];

// ------------------------------------------------------------------ entry points
$md[] = "## Entry points: PHP files that do something when opened by URL\n\n*Bootstraps WordPress* = includes `wp-load.php` / `wp-config.php` / `wp-blog-header.php` / `wp-admin/admin.php`, or names `wp-load.php` in a string (finding it by walking up directories). *Runs without WordPress* = no `defined('ABSPATH')`-style guard, and its top-level code calls something other than WordPress functions before (or instead of) any WordPress function. *Fatal without WordPress* = unguarded, but its first top-level call is a WordPress function (opening it directly ends in an undefined-function fatal; at worst a path disclosure). Autoloaders and files with only inert top-level code are counted, not listed. Any of these runs outside a sandbox that is entered through WordPress's plugin loader, if the web server lets PHP under wp-content/plugins be requested directly.\n";
$erow = [];
$ekinds = [];
foreach ($P as $slug => $p) {
    foreach (['own', 'vendor'] as $s) {
        $by = [];
        foreach ($p[$s]['entry_points'] as $e) {
            $by[$e['kind']][] = $e['file'];
            $ekinds[$s][$e['kind']][$slug] = true;
        }
        if (isset($by['bootstraps WordPress']) || isset($by['names wp-load.php']) || isset($by['runs without WordPress']) || isset($by['fatal without WordPress'])) {
            $list = fn(string $k, int $n) => implode(' ', array_slice($by[$k] ?? [], 0, $n)) . (count($by[$k] ?? []) > $n ? ' …' : '');
            $erow[] = [$slug, $s, count($by['bootstraps WordPress'] ?? []), $list('bootstraps WordPress', 4), $list('names wp-load.php', 3), count($by['runs without WordPress'] ?? []),
                $list('runs without WordPress', 4), count($by['fatal without WordPress'] ?? []), count($by['autoloader'] ?? []) + count($by['inert'] ?? [])];
        }
    }
}
$md[] = table(['scope', 'kind', 'plugins'], array_merge(...array_map(fn($s) => array_map(fn($k, $v) => [$s, $k, count($v)], array_keys($ekinds[$s] ?? []), $ekinds[$s] ?? []), ['own', 'vendor'])));
$md[] = table(['plugin', 'scope', 'bootstraps WordPress', 'files (first 4)', 'names wp-load.php (string; may be a list or a loader)', 'runs without WordPress (upper bound)', 'files (first 4)', 'fatal without WordPress', 'autoloader / inert'], $erow);
$agg['entry_points'] = ['kinds' => array_map(fn($k) => array_map('array_keys', $k), $ekinds), 'rows' => $erow];

// ------------------------------------------------------------------ bundled
$md[] = "## Bundled code\n";
$brow = [];
$pk = [];
foreach ($P as $slug => $p) {
    $b = $p['bundled'];
    foreach ($b['composer_packages'] as $name => $_) {
        $pk[$name][$slug] = true;
    }
    $brow[] = [$slug, $p['vendor']['files'], implode(' ', array_keys($b['vendor_dirs'])) ?: '-', count($b['composer_packages']), $b['has_vendor_autoload'] ? 'yes' : '',
        count(u($p, 'autoloaders')) ? (array_sum(array_column(u($p, 'autoloaders'), 'n'))) : 0, $p['header']['Requires PHP'] ?? '-', $b['composer_php'] ?? '-'];
}
$md[] = table(['plugin', 'vendor php files', 'vendor dirs', 'composer packages', 'vendor/autoload.php', 'spl_autoload_register calls', 'Requires PHP (header)', 'composer php'], $brow);
uasort($pk, fn($a, $b) => count($b) <=> count($a));
$md[] = "Composer packages bundled by 3+ plugins:\n\n" . table(['package', 'plugins'], array_map(fn($k, $v) => [$k, count($v) . ': ' . implode(', ', array_keys($v))], array_keys(array_filter($pk, fn($v) => count($v) >= 3)), array_filter($pk, fn($v) => count($v) >= 3)));
$agg['bundled'] = ['rows' => $brow, 'packages' => array_map('array_keys', $pk)];

// ------------------------------------------------------------------ redefines
$rd = [];
foreach ($P as $slug => $p) {
    if ($p['redefines_core_functions']) {
        $rd[] = [$slug, implode(', ', array_map(fn($f, $file) => "`$f` ($file)", array_keys($p['redefines_core_functions']), $p['redefines_core_functions']))];
    }
}
$md[] = "## Plugins that define a function core also defines (pluggables, polyfills)\n\n" . table(['plugin', 'functions (core file)'], $rd);
$agg['redefines'] = $rd;

// ------------------------------------------------------------------ how much is dynamic
$md[] = "## How far static analysis can be trusted: the dynamic share\n";
$keys = [['fn_calls', 'fn_calls_dynamic', 'function calls with a computed name ($f())'], ['method_calls', 'method_calls_dynamic', 'method calls with a computed name ($o->$m())'],
    ['static_calls', 'static_calls_dynamic', 'static calls with a computed class or name'], ['new', 'new_dynamic', 'new with a computed class'],
    ['cuf', 'cuf_dynamic', 'call_user_func* with a non-literal callable (share of all call_user_func*)'], ['includes', 'includes_dynamic', 'includes with a fully dynamic path'],
    ['includes', 'includes_partial', 'includes with a partly resolved path'], ['hooks_add', 'hooks_add_dynamic', 'add_action/add_filter with a dynamic tag'],
    ['hooks_add', 'hooks_add_folded', 'add_action/add_filter tag resolved only by constant folding'], ['hooks_fire', 'hooks_fire_dynamic', 'do_action/apply_filters with a dynamic tag'],
    ['fs_writes', null, 'file writes (see the target table for unresolved paths)'], ['network_url_calls', 'network_url_dynamic', 'remote calls whose URL host is not literal']];
$drow = [];
$dagg = [];
foreach (['own', 'vendor'] as $s) {
    $T = [];
    foreach ($P as $p) {
        foreach ($p[$s]['totals'] as $k => $v) {
            $T[$k] = ($T[$k] ?? 0) + $v;
        }
    }
    $dagg[$s] = $T;
}
foreach ($keys as [$base, $dyn, $label]) {
    if ($dyn === null) {
        continue;
    }
    $r = [$label];
    foreach (['own', 'vendor'] as $s) {
        $b = $dagg[$s][$base] ?? 0;
        $d = $dagg[$s][$dyn] ?? 0;
        // fn_calls etc. count only static sites; the dynamic ones are extra
        $den = in_array($base, ['fn_calls', 'method_calls', 'static_calls', 'new'], true) ? $b + $d : $b;
        $r[] = "$d / $den (" . ($den ? round(100 * $d / $den, 1) : 0) . '%)';
    }
    $drow[] = $r;
}
$md[] = table(['what', 'own code', 'vendor code'], $drow);
$agg['dynamic_totals'] = $dagg;
$unk = [];
foreach ($P as $slug => $p) {
    $unk[$slug] = count(u($p, 'functions', 'unknown'));
}
arsort($unk);
$agg['unknown_functions_per_plugin'] = $unk;

json_out_simple($aggPath, $agg);
file_put_contents($mdPath, "# Plugin survey: generated tables\n\nGenerated by `aggregate.php` (run `research/plugin-survey/run.sh`). Read REPORT.md for what these mean.\n\n" . implode("\n", $md));
fprintf(STDERR, "aggregate: %d plugins\n", $N);

function json_out_simple(string $path, mixed $data): void
{
    file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n");
}
