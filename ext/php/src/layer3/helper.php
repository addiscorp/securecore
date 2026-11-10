<?php
// SecureCore layer 3 (addiscorp/securecore#53, E7): the clean helper. The extension starts it at
// php-fpm's startup as `php -d securecore.layer3_role=helper -r <this file>`, with an empty
// environment and the control socket on fd 3. It runs in three processes, one after the other:
//
// 1. The supervisor: securecore_layer3_helper() waits for workers' requests natively and only
//    returns in a new zygote, forked when there is no WordPress booted from the worker's
//    current snapshot yet.
// 2. The zygote boots WordPress once, from the snapshot (WordPress's own options only, #47), with
//    no plugins, no mu-plugins and no theme code, against a $wpdb that has no connection (#46:
//    one object for the process's life). Then securecore_layer3_zygote() forks a child per
//    request and only returns in that child, already restricted (gelada, rlimits) and charged
//    to the isolated plugin.
// 3. The child loads the one plugin, tells the worker what it registered (hooks, shortcodes),
//    runs each call the worker forwards, and exits when the worker's request ends.
//
// Nothing here holds a secret: no wp-config.php, no DB password, no keys or salts.
namespace SecureCore\Layer3;

final class State
{
    /** True once forked into a child: the database is closed to it. */
    public static bool $child = false;
    public static string $slug = '';
    /** @var array<int, callable> id => the plugin's callback */
    public static array $callbacks = [];
    public static int $next = 1;
    /** @var array<string, true> queries already logged as refused in this child */
    public static array $refused = [];
}

/** A $wpdb with no connection: during the zygote's boot it serves wp_load_alloptions() from the
 *  snapshot and answers everything else empty; in a child it refuses every query. */
function make_wpdb(string $prefix, array $options): \wpdb
{
    return new class($prefix, $options) extends \wpdb {
        private array $snapshot;

        public function __construct(string $prefix, array $options)
        {
            // No parent constructor: it would connect.
            $this->ready = true;
            $this->prefix = $prefix;
            $this->base_prefix = $prefix;
            $this->field_types = [];
            $this->snapshot = $options;
        }

        public function query($query)
        {
            $this->flush();
            $this->last_query = (string) $query;
            if (State::$child) {
                refused_query((string) $query);
            }
            return false;
        }

        public function get_results($query = null, $output = OBJECT)
        {
            if (!State::$child && is_string($query) && stripos($query, 'option_name') !== false && stripos($query, 'autoload') !== false) {
                $rows = [];
                foreach ($this->snapshot as $name => $value) {
                    $rows[] = (object) ['option_name' => (string) $name, 'option_value' => $value];
                }
                return $rows;
            }
            return parent::get_results($query, $output);
        }

        public function _real_escape($data)
        {
            if (!is_scalar($data)) return '';
            return $this->add_placeholder_escape(addslashes((string) $data));
        }

        public function db_version() { return '8.0.0'; }
        public function db_server_info() { return '8.0.0'; }
        public function get_col_info($info_type = 'name', $col_offset = -1) { return []; }
        public function check_connection($allow_bail = true) { return true; }
        public function close() { return true; }

        /** The child keeps none of the snapshot (#47): it only carried the boot. */
        public function drop_snapshot(): void { $this->snapshot = []; }
    };
}

function refused_query(string $sql): void
{
    $sql = preg_replace('/\s+/', ' ', trim($sql));
    if (strlen($sql) > 160) $sql = substr($sql, 0, 160) . '...';
    if (isset(State::$refused[$sql])) return;
    State::$refused[$sql] = true;
    error_log('securecore: layer3 plugin:' . State::$slug . ' database refused (not yet available to an isolated plugin): ' . $sql);
}

/** Objects and resources don't cross to the worker yet: they become null. */
function plain($v, int $depth = 0)
{
    if (is_object($v) || is_resource($v) || $depth > 32) return null;
    if (is_array($v)) {
        foreach ($v as $k => $x) $v[$k] = plain($x, $depth + 1);
    }
    return $v;
}

/** What is registered now: every hook callback by (hook, priority, unique id), every shortcode. */
function registered(): array
{
    $hooks = [];
    foreach ($GLOBALS['wp_filter'] ?? [] as $hook => $h) {
        if (!$h instanceof \WP_Hook) continue;
        foreach ($h->callbacks as $priority => $callbacks) {
            foreach ($callbacks as $idx => $cb) {
                $hooks[$hook . "\0" . $priority . "\0" . $idx] = [(string) $hook, (int) $priority, $cb];
            }
        }
    }
    return ['hooks' => $hooks, 'shortcodes' => $GLOBALS['shortcode_tags'] ?? []];
}

/** What the plugin registered since $before, numbered for the worker to mirror. */
function added(array $before): array
{
    $now = registered();
    $out = [];
    foreach (array_diff_key($now['hooks'], $before['hooks']) as [$hook, $priority, $cb]) {
        $id = State::$next++;
        State::$callbacks[$id] = $cb['function'];
        $out[] = ['kind' => 'hook', 'name' => $hook, 'id' => $id, 'priority' => $priority, 'args' => (int) ($cb['accepted_args'] ?? 1)];
    }
    foreach ($now['shortcodes'] as $tag => $cb) {
        if (array_key_exists($tag, $before['shortcodes']) && $before['shortcodes'][$tag] === $cb) continue;
        $id = State::$next++;
        State::$callbacks[$id] = $cb;
        $out[] = ['kind' => 'shortcode', 'name' => (string) $tag, 'id' => $id];
    }
    return $out;
}

/** Runs $fn with output captured, whatever it does to the buffers. [return, output, error] */
function captured(callable $fn): array
{
    $level = ob_get_level();
    ob_start();
    $error = null;
    $ret = null;
    try {
        $ret = $fn();
    } catch (\Throwable $e) {
        $error = get_class($e) . ': ' . $e->getMessage();
        error_log('securecore: layer3 plugin:' . State::$slug . ' threw ' . $error);
    }
    $out = '';
    while (ob_get_level() > $level) $out = ob_get_clean() . $out;
    return [$ret, $out, $error];
}

/** After the plugin loaded: report what it registered, then answer calls until the worker's
 *  request ends (the socket closes). */
function serve(array $before, string $out, ?string $error): void
{
    \securecore_layer3_ready(serialize(['out' => $out, 'reg' => added($before), 'error' => $error]));
    while (($msg = \securecore_layer3_recv()) !== null) {
        $nl = strpos($msg, "\n");
        $id = (int) substr($msg, 0, $nl === false ? 0 : $nl);
        $args = $nl === false ? [] : unserialize(substr($msg, $nl + 1), ['allowed_classes' => false]);
        $args = is_array($args) ? array_values($args) : [];
        $before = registered();
        $fn = State::$callbacks[$id] ?? null;
        [$ret, $out, $error] = $fn === null
            ? [null, '', "no callback $id"]
            : captured(static fn () => $fn(...$args));
        \securecore_layer3_send(serialize(['out' => $out, 'ret' => plain($ret), 'reg' => added($before), 'error' => $error]));
    }
}

// --- 1. supervisor: returns only in a new zygote ------------------------------------------------
$boot = \securecore_layer3_helper();

// --- 2. zygote: boot WordPress from the snapshot --------------------------------------------------
$options = unserialize($boot['snapshot'], ['allowed_classes' => false]);
$options = is_array($options) ? $options : [];
define('ABSPATH', $boot['abspath']);
define('WP_DEBUG', false);
define('WP_DEBUG_DISPLAY', false);
define('WP_DEBUG_LOG', false);
define('DISABLE_WP_CRON', true);
// No mu-plugins here: each is another component, and the helper runs only the isolated plugin.
define('WPMU_PLUGIN_DIR', '/nonexistent/securecore-layer3/mu-plugins');
$GLOBALS['table_prefix'] = $boot['prefix'];
// No theme code either: wp-settings.php includes the theme's functions.php from these folders.
$nowhere = static fn () => '/nonexistent/securecore-layer3/theme';
$GLOBALS['wp_filter'] = [
    'template_directory' => [10 => [['function' => $nowhere, 'accepted_args' => 0]]],
    'stylesheet_directory' => [10 => [['function' => $nowhere, 'accepted_args' => 0]]],
];
@chdir(ABSPATH);
require_once ABSPATH . 'wp-includes/class-wpdb.php';
$GLOBALS['wpdb'] = make_wpdb($boot['prefix'], $options);
unset($boot, $options);
require ABSPATH . 'wp-settings.php';
remove_all_filters('template_directory');
remove_all_filters('stylesheet_directory');

// --- 3. child: returns once per request, in the forked child ------------------------------------
$request = \securecore_layer3_zygote();
State::$child = true;
State::$slug = $request['slug'];
$GLOBALS['wpdb']->drop_snapshot();
@ini_set('memory_limit', $request['memory_mb'] . 'M');
// The plugin loads at global scope, as wp-settings.php loads it (its top-level variables are
// globals), with its output captured.
$sc_before = registered();
$sc_level = ob_get_level();
ob_start();
$sc_error = null;
wp_register_plugin_realpath($request['file']);
try {
    include_once $request['file'];
} catch (\Throwable $e) {
    $sc_error = get_class($e) . ': ' . $e->getMessage();
    error_log('securecore: layer3 plugin:' . State::$slug . ' threw ' . $sc_error);
}
$sc_out = '';
while (ob_get_level() > $sc_level) $sc_out = ob_get_clean() . $sc_out;
serve($sc_before, $sc_out, $sc_error);
exit(0);
