<?php
// The sandbox child, "real WordPress" model (addiscorp/securecore#42, part 1).
//
// worker.php forks one child per request and calls serve_realwp_connection(). The child:
//   1. boots the site's own WordPress (sandbox/bootstrap.php), no plugins, DB over the socket;
//   2. loads its one plugin, which registers hooks, shortcodes, REST routes, scripts and menus
//      into this booted WordPress;
//   3. mirrors those registrations to the real core that is serving the request, as stubs that
//      call back in here when core fires them;
//   4. serves core's callbacks until the request ends, replaying request state when core sends it.
//
// It reuses the line protocol and the Conn/Callbacks/export_value helpers from setup.php.
// Messages added for this model:
//   sandbox → core: ['db', method, args]            run $wpdb->$method(...) in core
//                   ['pluggable', fn, args]          run a salted pluggable function in core
//                   ['ready', output, regs]          plugin loaded; new registrations to mirror
//                   ['return', value, output, regs]  a callback returned; plus new registrations
//   core → sandbox: ['boot', context]   ['setup', state]   ['call', id, args]   ['return', v]   ['end']
namespace SecureCore;

require_once __DIR__ . '/setup.php';
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/marshal.php';

// --- the two gateways the sandbox's WordPress calls into -------------------------------------

/** Run $wpdb->$method(...$args) in core; return the answer payload (see GatewayWpdb). */
function db_gateway(string $method, array $args): mixed
{
    if (Registry::$parentBoot) {
        // The worker parent is pre-booting and has no request socket (part 1b). The snapshot
        // $wpdb serves the options the boot needs; a query reaching here is unexpected — log
        // it and answer empty so the parent can finish booting rather than block on wait().
        fwrite(STDERR, gmdate('c') . " securecore-worker preboot: db_gateway($method) with no request; empty\n");
        return $method === 'query'
            ? ['return' => false, 'last_result' => [], 'last_error' => '', 'insert_id' => 0, 'rows_affected' => 0, 'num_rows' => 0]
            : null;
    }
    send(['db', $method, $args]);
    return wait();
}

/** Run a salted pluggable function (nonce/hash/auth/mail) in core; return its result. */
function pluggable_gateway(string $function, array $args): mixed
{
    if (Registry::$parentBoot) {
        fwrite(STDERR, gmdate('c') . " securecore-worker preboot: pluggable_gateway($function) with no request; null\n");
        return null;
    }
    send(['pluggable', $function, export_value($args)]);
    return wait();
}

// --- capturing the plugin's registrations ----------------------------------------------------
//
// We let the plugin register into this booted WordPress the normal way, then diff the relevant
// globals against a baseline and send the new entries to core. Each callback is kept here (as a
// numbered entry in Callbacks) and crosses as its number; core registers a stub that calls back.

final class Registry
{
    /** The baseline right after boot, before the plugin loaded. */
    public static array $base = [];
    /** True only while the worker parent pre-boots WordPress (no request socket; part 1b). */
    public static bool $parentBoot = false;
}

/** A snapshot of every registration surface we mirror. */
function snapshot(): array
{
    $hooks = [];
    foreach ($GLOBALS['wp_filter'] ?? [] as $tag => $hook) {
        if (!($hook instanceof \WP_Hook)) continue;
        foreach ($hook->callbacks as $priority => $callbacks) {
            foreach ($callbacks as $key => $spec) {
                $hooks["$tag\0$priority\0$key"] = [$tag, (int) $priority, (int) $spec['accepted_args'], $spec['function']];
            }
        }
    }

    $scripts = $GLOBALS['wp_scripts'] ?? null;
    $styles = $GLOBALS['wp_styles'] ?? null;

    return [
        'hooks' => $hooks,
        'shortcodes' => $GLOBALS['shortcode_tags'] ?? [],
        'rest' => did_action('rest_api_init') ? array_keys(rest_get_server()->get_routes()) : [],
        'scripts_reg' => $scripts ? $scripts->registered : [],
        'scripts_enq' => $scripts ? $scripts->queue : [],
        'styles_reg' => $styles ? $styles->registered : [],
        'styles_enq' => $styles ? $styles->queue : [],
        'menu' => $GLOBALS['menu'] ?? [],
        'submenu' => $GLOBALS['submenu'] ?? [],
        'registered_pages' => $GLOBALS['_registered_pages'] ?? [],
        'admin_page_hooks' => $GLOBALS['admin_page_hooks'] ?? [],
    ];
}

/** The registration ops added since $base: the list we send to core to mirror. */
function diff_registrations(array $base): array
{
    $now = snapshot();
    $ops = [];

    // Hooks → stubs. A new (tag, priority, callback) the plugin added.
    foreach ($now['hooks'] as $key => [$tag, $priority, $accepted, $callback]) {
        if (isset($base['hooks'][$key])) continue;
        if (!is_callable($callback)) continue;
        $ops[] = ['hook', $tag, Callbacks::add($callback), $priority, $accepted];
    }

    // Shortcodes.
    foreach ($now['shortcodes'] as $tag => $callback) {
        if (isset($base['shortcodes'][$tag])) continue;
        if (!is_callable($callback)) continue;
        $ops[] = ['shortcode', (string) $tag, Callbacks::add($callback)];
    }

    // REST routes. Each new route path, with its handlers (callbacks exported).
    if ($now['rest']) {
        $routes = rest_get_server()->get_routes();
        foreach ($now['rest'] as $path) {
            if (in_array($path, $base['rest'], true)) continue;
            if (!isset($routes[$path])) continue;
            $namespace = rest_namespace_of($path);
            $ops[] = ['rest', $namespace, $path, export_value(rest_handlers($routes[$path]))];
        }
    }

    // Scripts and styles: registrations, then what is enqueued, then inline/localized data.
    foreach (['script' => 'scripts', 'style' => 'styles'] as $kind => $k) {
        foreach ($now["{$k}_reg"] as $handle => $dep) {
            if (isset($base["{$k}_reg"][$handle])) continue;
            $ops[] = ["{$kind}_register", (string) $handle, $dep->src, $dep->deps, $dep->ver, $dep->args, $dep->extra];
        }
        foreach ($now["{$k}_enq"] as $handle) {
            if (in_array($handle, $base["{$k}_enq"], true)) continue;
            $ops[] = ["{$kind}_enqueue", (string) $handle];
        }
    }

    // Admin menus and submenus (string data only; the render callback crosses as a number).
    foreach ($now['menu'] as $i => $item) {
        if (isset($base['menu'][$i]) && $base['menu'][$i] === $item) continue;
        $ops[] = ['menu', $item];
    }
    foreach ($now['submenu'] as $parent => $items) {
        foreach ($items as $j => $item) {
            if (isset($base['submenu'][$parent][$j]) && $base['submenu'][$parent][$j] === $item) continue;
            $ops[] = ['submenu', (string) $parent, $item];
        }
    }
    // The page registries admin.php checks before it will render a plugin page: without these
    // mirrored, a sandboxed plugin's admin screen is a 403 even with the menu present.
    foreach ($now['registered_pages'] as $key => $_) {
        if (isset($base['registered_pages'][$key])) continue;
        $ops[] = ['registered_page', (string) $key];
    }
    foreach ($now['admin_page_hooks'] as $key => $val) {
        if (isset($base['admin_page_hooks'][$key])) continue;
        $ops[] = ['admin_page_hook', (string) $key, $val];
    }

    return $ops;
}

/** The namespace of a REST route path, e.g. "/wp/v2/posts" → "wp/v2". */
function rest_namespace_of(string $path): string
{
    $parts = array_values(array_filter(explode('/', $path)));
    return count($parts) >= 2 ? $parts[0] . '/' . $parts[1] : ($parts[0] ?? '');
}

/** Strip the per-request bits WordPress adds, leaving what register_route() wants back. */
function rest_handlers(array $endpoints): array
{
    $out = [];
    foreach ($endpoints as $key => $group) {
        if (!is_numeric($key)) continue; // skip route-level options like 'namespace'
        $out[] = $group;
    }
    return $out;
}

// --- pre-boot (addiscorp/securecore#42, part 1b) --------------------------------------------
//
// The worker parent boots WordPress once, before accepting connections, so each forked child
// inherits the booted state (copy-on-write) instead of running wp-settings.php per request.
// The parent has no database and no request socket, so it boots against the options snapshot
// core wrote to disk (make_snapshot_wpdb). These helpers read that snapshot and its hash; the
// worker re-boots (by exiting for its supervisor to restart it) when the hash changes.

function snapshot_path(string $manifestsDir): string
{
    return dirname($manifestsDir) . '/options-snapshot.php';
}

function snapshot_hash_path(string $manifestsDir): string
{
    return dirname($manifestsDir) . '/options-snapshot.hash';
}

/** The snapshot core wrote: ['prefix' => ?, 'options' => [...]], or null if none/invalid. */
function read_snapshot(string $manifestsDir): ?array
{
    $file = snapshot_path($manifestsDir);
    if (!is_file($file)) return null;
    $data = @include $file;
    return is_array($data) && isset($data['options']) && is_array($data['options']) ? $data : null;
}

/** The snapshot's current hash on disk, or '' if there is none. */
function snapshot_hash(string $manifestsDir): string
{
    $file = snapshot_hash_path($manifestsDir);
    return is_file($file) ? trim((string) @file_get_contents($file)) : '';
}

/** Boot WordPress in the worker parent from the snapshot, front-end shape. Throws on failure. */
function preboot_wordpress(string $wpRoot, array $snapshot): void
{
    $prefix = (string) ($snapshot['prefix'] ?? 'wp_');
    require_once rtrim($wpRoot, '/') . '/wp-includes/class-wpdb.php';
    Registry::$parentBoot = true;
    try {
        boot_wordpress($wpRoot, $prefix, make_snapshot_wpdb($prefix, $snapshot['options']));
        // Warm the REST server (core routes) in the parent too, so children inherit it and a
        // REST request does not rebuild it. The plugin's own routes are still registered and
        // mirrored per request in the child.
        if (function_exists('rest_get_server')) rest_get_server();
    } finally {
        Registry::$parentBoot = false;
    }
}

// --- the child ------------------------------------------------------------------------------

/**
 * Serve one request. $preBooted is true when the worker parent already booted WordPress and
 * this child inherited it (part 1b); false when the child boots WordPress itself per request
 * (part 1). Either way, from the plugin load onward the two paths are identical.
 */
function serve_realwp_connection($conn, string $wpRoot, bool $preBooted = false): void
{
    Conn::$in = $conn;
    Conn::$out = $conn;

    $boot = receive();
    if ($boot[0] !== 'boot') return;
    $context = $boot[1];
    $prefix = (string) ($context['prefix'] ?? 'wp_');

    // Request superglobals, so the plugin and its callbacks see the real request.
    $_GET = $context['get'] ?? [];
    $_POST = $context['post'] ?? [];
    $_REQUEST = array_merge($_GET, $_POST);
    $_SERVER = array_merge($_SERVER, $context['server'] ?? []);
    foreach (($context['constants'] ?? []) as $name => $value) {
        if (!defined($name)) define($name, $value);
    }

    ob_start();
    try {
        if ($preBooted) {
            // WordPress is already booted in this process (forked from the worker parent).
            // Point the database at this request's socket gateway and drop the parent's option
            // cache, so every option the plugin reads comes fresh through the gateway, not the
            // parent's copy (addiscorp/securecore#42, part 1b).
            $GLOBALS['wpdb'] = make_gateway_wpdb($prefix);
            // wp-settings.php runs wp_set_wpdb_vars() on the $wpdb it booted with; our swapped
            // one needs the same, or its table names ($wpdb->users, ->posts, …) and field
            // types are unset and queries become "SELECT * FROM  WHERE …".
            $GLOBALS['table_prefix'] = $prefix;
            if (function_exists('wp_set_wpdb_vars')) wp_set_wpdb_vars();
            else $GLOBALS['wpdb']->set_prefix($prefix);
            // Drop the parent's option cache so every option a plugin reads this request comes
            // fresh through the gateway, not the parent's copy.
            if (function_exists('wp_cache_delete')) {
                wp_cache_delete('alloptions', 'options');
                wp_cache_delete('notoptions', 'options');
            }
        } else {
            boot_wordpress($wpRoot, $prefix);
        }
        // Admin requests: load WordPress's admin API, so a plugin that extends WP_List_Table
        // or calls add_settings_field()/add_menu_page() at load has them, as in a real
        // wp-admin request (where wp-admin/admin.php loads these before plugins run). Under
        // pre-boot the parent booted the front-end shape, so this also brings the admin API
        // into the child when the request turns out to be an admin one.
        if (defined('WP_ADMIN') && WP_ADMIN) {
            require_once ABSPATH . 'wp-admin/includes/admin.php';
            set_current_screen();
        }
        // Build the REST server once now, so register_rest_route() inside a plugin callback
        // just registers instead of re-firing rest_api_init here.
        if (function_exists('rest_get_server')) rest_get_server();
    } catch (\Throwable $error) {
        send(['log', 'WordPress failed to boot in the sandbox: ' . $error->getMessage() . ' @ ' . $error->getFile() . ':' . $error->getLine()]);
        send(['ready', take_output(), []]);
        return;
    }

    // Different mt_rand stream per child, so two requests never share a sequence.
    mt_srand();

    Registry::$base = snapshot();

    // Load the one plugin. It registers into this WordPress; we mirror the diff.
    try {
        require $context['main'];
    } catch (\Throwable $error) {
        send(['log', 'plugin failed to load: ' . $error->getMessage() . ' @ ' . $error->getFile() . ':' . $error->getLine()]);
    }
    $regs = diff_registrations(Registry::$base);
    Registry::$base = snapshot();
    send(['ready', take_output(), $regs]);

    // Serve core's callbacks and setup messages until the request ends.
    for (;;) {
        $message = receive();
        switch ($message[0]) {
            case 'call':
                serve_realwp($message[1], $message[2], $message[3] ?? '');
                break;
            case 'setup':
                setup_request_state($message[1]);
                break;
            case 'end':
                return;
        }
    }
}

/** Run callback $id, then send its return value plus any registrations it just made. */
function serve_realwp(int $id, array $args, string $tag = ''): void
{
    take_output();
    try {
        $args = marshal_decode($args);
        $value = isset(Callbacks::$table[$id]) ? (Callbacks::$table[$id])(...$args) : ($args[0] ?? null);
        $regs = diff_registrations(Registry::$base);
        Registry::$base = snapshot();
        // export_value turns any closures the plugin returned into callback numbers; then
        // marshal_encode turns WordPress objects into markers core will rebuild.
        send(['return', marshal_encode(export_value($value)), take_output(), $regs]);
    } catch (\Throwable $error) {
        send(['throw', ($tag !== '' ? "[$tag] " : '') . $error->getMessage(), take_output(), diff_registrations(Registry::$base)]);
        Registry::$base = snapshot();
    }
}

/**
 * Replay the request state core has (the main query, the current user) into this WordPress,
 * so a callback sees the same post/query/user. The query runs through the gateway. This is
 * the part the spike reports on: what a callback can and cannot see.
 */
function setup_request_state(array $state): void
{
    take_output();
    if (isset($state['user_id'])) {
        wp_set_current_user((int) $state['user_id']);
    }
    if (isset($state['query_vars']) && isset($GLOBALS['wp_the_query'])) {
        // Replaying the main query: query_posts() asks the database (over the gateway) for the
        // same posts core resolved, and sets $wp_query, $post and the is_*() conditionals.
        $GLOBALS['wp_the_query']->query($state['query_vars']);
        $GLOBALS['wp_query'] = $GLOBALS['wp_the_query'];
        if (!empty($GLOBALS['wp_query']->post)) {
            $GLOBALS['post'] = $GLOBALS['wp_query']->post;
            setup_postdata($GLOBALS['post']);
        }
        if (isset($state['query_flags'])) {
            foreach ($state['query_flags'] as $flag => $value) {
                $GLOBALS['wp_query']->$flag = $value;
            }
        }
    }
    if (isset($state['constants'])) {
        foreach ($state['constants'] as $name => $value) {
            if (!defined($name)) define($name, $value);
        }
    }
    take_output();
}
