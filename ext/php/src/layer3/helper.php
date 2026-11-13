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
    /** True once forked into a child: $wpdb is the database gateway from then on. */
    public static bool $child = false;
    public static string $slug = '';
    /** @var array<int, callable> id => the plugin's callback */
    public static array $callbacks = [];
    public static int $next = 1;
}

/** A $wpdb with no connection (and no credential). During the zygote's boot it serves
 *  wp_load_alloptions() from the snapshot and answers everything else empty. In a child it is
 *  the database gateway (#94): each query goes to the php-fpm worker, which runs it on its own
 *  connection under layer 2's policy, charged to this plugin, and answers with what its $wpdb
 *  saw. Everything else (get_results, get_row, get_var, get_col, prepare, insert, update,
 *  delete, replace, dbDelta) is wpdb's own code, on top of query(). */
function make_wpdb(string $prefix, array $options): \wpdb
{
    return new class($prefix, $options) extends \wpdb {
        private array $snapshot;
        private string $server_info = '8.0.0';
        private string $version = '8.0.0';
        /** @var list<string> the last result's column names (get_col_info('name')) */
        private array $col_names = [];

        public function __construct(string $prefix, array $options)
        {
            // No parent constructor: it would connect.
            $this->ready = true;
            $this->prefix = $prefix;
            $this->base_prefix = $prefix;
            $this->field_types = [];
            $this->snapshot = $options;
        }

        /** In the child: the worker's connection facts (never a credential). */
        public function become_gateway(array $facts): void
        {
            $this->charset = (string) ($facts['charset'] ?? '');
            $this->collate = (string) ($facts['collate'] ?? '');
            $this->version = (string) ($facts['db_version'] ?? '') ?: '8.0.0';
            $this->server_info = (string) ($facts['db_server_info'] ?? '') ?: $this->version;
            $this->snapshot = [];
        }

        public function query($query)
        {
            if (!State::$child) {
                $this->flush();
                $this->last_query = (string) $query;
                return false;
            }
            // As wpdb::query(): the plugin's own `query` filters run here, the worker's there.
            $query = apply_filters('query', $query);
            if (!$query) {
                $this->insert_id = 0;
                return false;
            }
            $this->flush();
            $this->func_call = "\$db->query(\"$query\")";
            $this->last_query = (string) $query;
            ++$this->num_queries;
            $answer = \securecore_layer3_db((string) $query);
            $a = is_string($answer) ? unserialize($answer, ['allowed_classes' => false]) : null;
            if (!is_array($a)) {
                $this->insert_id = 0;
                $this->last_error = 'securecore: the database gateway did not answer';
                return false;
            }
            $this->last_error = (string) ($a['error'] ?? '');
            $this->rows_affected = (int) ($a['affected'] ?? 0);
            // Only an INSERT/REPLACE sets it, as in wpdb::query().
            if (array_key_exists('insert_id', $a)) $this->insert_id = (int) $a['insert_id'];
            $this->col_names = is_array($a['cols'] ?? null) ? array_values($a['cols']) : [];
            $keys = is_array($a['keys'] ?? null) ? array_values($a['keys']) : [];
            $this->last_result = [];
            foreach (is_array($a['rows'] ?? null) ? $a['rows'] : [] as $row) {
                if (!is_array($row) || count($row) !== count($keys)) continue;
                $this->last_result[] = (object) array_combine($keys, array_values($row));
            }
            $this->num_rows = (int) ($a['num_rows'] ?? count($this->last_result));
            $ret = $a['ret'] ?? false;
            return is_int($ret) || is_bool($ret) ? $ret : false;
        }

        /** Escapes as mysqli_real_escape_string() does on a utf8mb4 (any ASCII-compatible)
         *  connection, so the worker receives the same text the plugin would send unisolated.
         *  Layer 2 refuses the charsets where this would differ. */
        public function _real_escape($data)
        {
            if (!is_scalar($data)) return '';
            $escaped = strtr((string) $data, ["\\" => "\\\\", "\0" => "\\0", "\n" => "\\n", "\r" => "\\r", "'" => "\\'", '"' => '\\"', "\x1a" => "\\Z"]);
            return $this->add_placeholder_escape($escaped);
        }

        public function get_col_info($info_type = 'name', $col_offset = -1)
        {
            // Names only: the rest of mysqli's field metadata does not cross (see ext/README.md).
            if ($info_type !== 'name' || $this->col_names === []) return null;
            return $col_offset === -1 ? $this->col_names : ($this->col_names[$col_offset] ?? null);
        }

        protected function load_col_info() {}

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

        public function db_version() { return $this->version; }
        public function db_server_info() { return $this->server_info; }
        public function check_connection($allow_bail = true) { return true; }
        public function close() { return true; }
    };
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
// The child keeps none of the snapshot (#47): it only carried the boot.
$GLOBALS['wpdb']->become_gateway($request);
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
