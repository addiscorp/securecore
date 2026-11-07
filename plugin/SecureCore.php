<?php
/**
 * SecureCore's core side. Lives in wp-content/plugins/securecore/ and is loaded early by the
 * mu-plugin loader (mu-plugins/securecore-loader.php) while the SecureCore plugin is active,
 * so it can keep sandboxed plugins out of core's plugin loader. (No plugin header here:
 * securecore.php is the plugin's main file.)
 *
 * Manifests live in wp-content/securecore/manifests/*.json, one per sandboxed plugin:
 *   { "plugin": "hello.php", "hooks": ["admin_notices", ...],
 *     "functions": ["wptexturize", ...] }   // WordPress functions this plugin may call
 * A plugin without a manifest loads normally.
 *
 * The sandbox is the worker (sandbox/worker.php, started by bin/securecore-worker): one
 * process for all plugins, a fork per request. This file connects to its socket per
 * request. If the worker is not up, the plugins it would sandbox do not load.
 *
 * wp-config.php settings (all optional):
 *   SECURECORE_DISABLED  true: load every plugin normally (baseline)
 *   SECURECORE_ENFORCE   false: allow and log calls the manifest does not grant (observe)
 *   SECURECORE_SOCKET    worker socket path (default wp-content/securecore/worker.sock)
 *   SECURECORE_DATA      where manifests live (default wp-content/securecore)
 *
 * Protocol: see sandbox/setup.php.
 */
namespace SecureCore;

if (defined('SECURECORE_DISABLED') && SECURECORE_DISABLED) return;
// wp-cli runs as the site owner, not as a web request; plugins load normally there.
if (defined('WP_CLI') && WP_CLI) return;
// Inside the sandbox's own WordPress (the "real WordPress" model, #42): this file is loaded
// by the mu-plugin loader there too. Load no plugins — core's active plugins must not
// auto-load, and the one sandboxed plugin is required directly by sandbox/realwp.php — and
// do nothing else, so the sandbox never tries to open a worker socket of its own.
if (defined('SECURECORE_SANDBOX') && SECURECORE_SANDBOX) {
    add_filter('option_active_plugins', '__return_empty_array', PHP_INT_MAX);
    add_filter('site_option_active_sitewide_plugins', '__return_empty_array', PHP_INT_MAX);
    return;
}

function audit(string $plugin, string $event, array $detail = []): void
{
    $line = json_encode(array_merge(['time' => gmdate('c'), 'plugin' => $plugin, 'event' => $event], $detail), JSON_UNESCAPED_SLASHES);
    file_put_contents(WP_CONTENT_DIR . '/securecore-audit.log', $line . "\n", FILE_APPEND | LOCK_EX);
}

function enforcing(): bool
{
    return !defined('SECURECORE_ENFORCE') || SECURECORE_ENFORCE;
}

final class Sandbox
{
    /** @var resource the socket to the worker: one connection = one fork = this request */
    private $in;
    /** @var resource */
    private $out;
    private bool $alive = true;

    public function __construct(public readonly string $plugin, private readonly array $manifest)
    {
        $socket = socket_path();
        $stream = @stream_socket_client("unix://$socket", $errno, $errstr, 5);
        if (!$stream) {
            $this->alive = false;
            audit($plugin, 'sandbox.fail', ['reason' => "no worker on $socket: $errstr"]);
            return;
        }
        $this->in = $this->out = $stream;
        // Time limit per call: a plugin that does not answer in 5 s is cut off.
        stream_set_timeout($stream, 5);
    }

    public function boot(): void
    {
        if (!$this->alive) return;
        $this->send(['boot', [
            'plugin' => $this->plugin,
            'get' => $_GET,
            'post' => $_POST,
            'server' => array_intersect_key($_SERVER, array_flip(['REQUEST_METHOD', 'REQUEST_URI', 'QUERY_STRING', 'HTTP_HOST', 'HTTPS', 'SERVER_NAME', 'HTTP_USER_AGENT'])),
        ]]);
        $this->until_reply();
    }

    /** Run the sandbox's callback number $id. A failed call leaves a filter's value unchanged. */
    public function call(int $id, array $args): mixed
    {
        if (!$this->alive) return $args[0] ?? null;
        $this->send(['call', $id, $args]);
        $reply = $this->until_reply();
        if ($reply === null || $reply[0] === 'throw') return $args[0] ?? null;
        return $reply[1];
    }

    public function end(): void
    {
        if (!$this->alive) return;
        $this->send(['end']);
        fclose($this->in);
        $this->alive = false;
    }

    private function send(array $message): void
    {
        try {
            $line = base64_encode(serialize($message));
        } catch (\Throwable $error) {
            $line = base64_encode(serialize(['throw', 'value cannot cross into the sandbox: ' . $error->getMessage()]));
        }
        fwrite($this->in, $line . "\n");
    }

    /** Serve the sandbox's requests until it answers ours. */
    private function until_reply(): ?array
    {
        while ($this->alive) {
            $line = fgets($this->out);
            if ($line === false) {
                $timeout = stream_get_meta_data($this->out)['timed_out'];
                audit($this->plugin, $timeout ? 'sandbox.timeout' : 'sandbox.exit');
                fclose($this->in);
                $this->alive = false;
                return null;
            }
            if ($line[0] === '#') {
                audit($this->plugin, 'sandbox.audit', json_decode(substr($line, 1), true) ?: []);
                continue;
            }
            // allowed_classes: false. A plugin must never get to pick which class core builds.
            $message = unserialize(base64_decode(trim($line)), ['allowed_classes' => false]);
            if (!is_array($message)) continue;
            switch ($message[0]) {
                case 'wp':
                    echo $message[3];
                    $this->wp($message[1], $message[2]);
                    break;
                case 'hook':
                    $this->hook(...array_slice($message, 1));
                    break;
                case 'log':
                    audit($this->plugin, 'sandbox.log', ['message' => $message[1]]);
                    break;
                case 'ready':
                case 'return':
                case 'throw':
                    echo $message[$message[0] === 'ready' ? 1 : 2];
                    if ($message[0] === 'throw') audit($this->plugin, 'sandbox.throw', ['message' => $message[1]]);
                    return $message;
            }
        }
        return null;
    }

    private function allowed(string $kind, string $name): bool
    {
        if (in_array($name, $this->manifest[$kind] ?? [], true)) return true;
        $event = $kind === 'functions' ? 'wp.deny' : 'hook.deny';
        audit($this->plugin, enforcing() ? $event : $event . '.observed', ['name' => $name]);
        return !enforcing();
    }

    private function wp(string $function, array $args): void
    {
        if (!$this->allowed('functions', $function) || !function_exists($function)) {
            $this->send(['throw', "SecureCore: $function is not granted to {$this->plugin}"]);
            return;
        }
        try {
            $this->send(['return', $function(...$this->import($args))]);
        } catch (\Throwable $error) {
            $this->send(['throw', $error->getMessage()]);
        }
    }

    private function hook(string $function, string $tag, int $id, int $priority, int $accepted): void
    {
        if (!$this->allowed('hooks', $tag)) {
            $this->send(['return', false]);
            return;
        }
        $function($tag, fn (...$args) => $this->call($id, $args), $priority, $accepted);
        $this->send(['return', true]);
    }

    /** Callbacks the plugin passed as arguments come back to the sandbox when core calls them. */
    private function import(mixed $value): mixed
    {
        if (is_array($value) && count($value) === 1 && isset($value['__securecore_callback'])) {
            $id = (int) $value['__securecore_callback'];
            return fn (...$args) => $this->call($id, $args);
        }
        return is_array($value) ? array_map($this->import(...), $value) : $value;
    }
}

/** The "real WordPress" model (addiscorp/securecore#42, part 1): define SECURECORE_REALWP. */
function realwp_enabled(): bool
{
    return defined('SECURECORE_REALWP') && SECURECORE_REALWP;
}

/**
 * Core side of the "real WordPress" sandbox. The plugin runs inside its own WordPress in the
 * worker (sandbox/realwp.php); this class is the other end of that request's socket. It
 *   - answers the sandbox's database calls against core's real $wpdb (the gateway);
 *   - answers the salted pluggable calls (nonces, hashes, auth, wp_mail) with core's own;
 *   - mirrors the registrations the plugin made in the sandbox into this, the serving
 *     WordPress — hooks, shortcodes, REST routes, scripts, styles and admin menus — as stubs
 *     that call back into the sandbox when core fires them;
 *   - replays the request state (main query, current user) into the sandbox so a callback
 *     sees the same post/query/user core does.
 *
 * Part 1 has no SQL policy yet (a later part of #42): the gateway runs whatever query the
 * sandbox sends. See the PR for what that leaves open.
 */
require_once __DIR__ . '/sandbox/marshal.php';

final class RealWpSandbox
{
    /** @var resource */
    private $sock;
    private bool $alive = true;
    /** Page-render callbacks for mirrored admin menus, by page hook suffix. */
    private array $pageHooks = [];

    public function __construct(public readonly string $plugin, private readonly array $manifest)
    {
        $socket = socket_path();
        $stream = @stream_socket_client("unix://$socket", $errno, $errstr, 15);
        if (!$stream) {
            $this->alive = false;
            audit($plugin, 'sandbox.fail', ['reason' => "no worker on $socket: $errstr"]);
            return;
        }
        $this->sock = $stream;
        stream_set_timeout($stream, 30);
    }

    public function alive(): bool
    {
        return $this->alive;
    }

    public function boot(): void
    {
        if (!$this->alive) return;
        $this->send(['boot', [
            'plugin' => $this->plugin,
            'main' => WP_PLUGIN_DIR . '/' . $this->plugin,
            'prefix' => $GLOBALS['wpdb']->prefix,
            'get' => $_GET,
            'post' => $_POST,
            'server' => array_intersect_key($_SERVER, array_flip(['REQUEST_METHOD', 'REQUEST_URI', 'QUERY_STRING', 'HTTP_HOST', 'HTTPS', 'SERVER_NAME', 'SERVER_PORT', 'HTTP_USER_AGENT', 'PATH_INFO'])),
            'constants' => $this->request_constants(),
        ]]);
        $this->pump('ready');
    }

    /** The request-shape constants the sandbox needs defined before it boots WordPress. */
    private function request_constants(): array
    {
        $out = [];
        foreach (['WP_ADMIN', 'DOING_AJAX', 'REST_REQUEST', 'DOING_CRON', 'WP_CLI', 'DOING_AUTOSAVE'] as $c) {
            if (defined($c)) $out[$c] = constant($c);
        }
        return $out;
    }

    /** Replay the request state into the sandbox (main query, current user). One-way. */
    public function setup_state(): void
    {
        if (!$this->alive) return;
        global $wp_query, $wp;
        $state = ['user_id' => get_current_user_id()];
        if (isset($wp_query) && $wp_query instanceof \WP_Query) {
            $state['query_vars'] = $wp_query->query_vars;
            $state['query_flags'] = [
                'is_single' => $wp_query->is_single, 'is_page' => $wp_query->is_page,
                'is_singular' => $wp_query->is_singular, 'is_home' => $wp_query->is_home,
                'is_front_page' => $wp_query->is_front_page, 'is_archive' => $wp_query->is_archive,
                'is_search' => $wp_query->is_search, 'is_404' => $wp_query->is_404,
                'is_admin' => is_admin(),
            ];
        }
        $this->send(['setup', $state]);
    }

    /** Run the sandbox callback $id with $args; return what it returned. */
    public function call(int $id, array $args, string $tag = ''): mixed
    {
        if (!$this->alive) return $args[0] ?? null;
        $this->send(['call', $id, $this->marshal_out($args), $tag]);
        $reply = $this->pump('return');
        if ($reply === null) return $args[0] ?? null;
        if ($reply[0] === 'throw') return $args[0] ?? null;
        return $this->marshal_in($reply[1]);
    }

    public function end(): void
    {
        if (!$this->alive) return;
        $this->send(['end']);
        fclose($this->sock);
        $this->alive = false;
    }

    // --- the loop -----------------------------------------------------------------------

    /**
     * Serve the sandbox's messages until it sends the one we are waiting for ($until is
     * 'ready' or 'return'). Returns that message, or null if the sandbox went away.
     */
    private function pump(string $until): ?array
    {
        while ($this->alive) {
            $line = fgets($this->sock);
            if ($line === false) {
                $timeout = stream_get_meta_data($this->sock)['timed_out'];
                audit($this->plugin, $timeout ? 'sandbox.timeout' : 'sandbox.exit');
                $this->alive = false;
                return null;
            }
            if ($line === "\n" || $line === "\r\n") continue;
            if ($line[0] === '#') {
                audit($this->plugin, 'sandbox.audit', json_decode(substr($line, 1), true) ?: []);
                continue;
            }
            $message = unserialize(base64_decode(trim($line)), ['allowed_classes' => false]);
            if (!is_array($message)) continue;
            switch ($message[0]) {
                case 'db':
                    $this->send(['return', db_answer($message[1], $message[2], $this->plugin)]);
                    break;
                case 'pluggable':
                    $this->pluggable($message[1], $message[2]);
                    break;
                case 'log':
                    audit($this->plugin, 'sandbox.log', ['message' => $message[1]]);
                    break;
                case 'ready':
                    echo $message[1];
                    $this->apply_regs($message[2] ?? []);
                    if ($until === 'ready') return $message;
                    break;
                case 'return':
                case 'throw':
                    // Buffered plugin output is at index 2 for both; index 1 of 'throw' is the
                    // error message (audited, never echoed into the page).
                    echo $message[2] ?? '';
                    $this->apply_regs($message[3] ?? []);
                    if ($message[0] === 'throw') audit($this->plugin, 'sandbox.throw', ['message' => $message[1]]);
                    return $message;
            }
        }
        return null;
    }

    private function pluggable(string $function, array $args): void
    {
        if (!function_exists($function)) {
            $this->send(['return', null]);
            return;
        }
        try {
            $this->send(['return', $function(...$this->import($args))]);
        } catch (\Throwable $error) {
            $this->send(['return', null]);
            audit($this->plugin, 'pluggable.fail', ['name' => $function, 'message' => $error->getMessage()]);
        }
    }

    // --- mirroring the sandbox's registrations into this WordPress ----------------------

    private function apply_regs(array $ops): void
    {
        foreach ($ops as $op) {
            try {
                $this->apply_reg($op);
            } catch (\Throwable $error) {
                audit($this->plugin, 'mirror.fail', ['op' => $op[0] ?? '?', 'message' => $error->getMessage()]);
            }
        }
    }

    private function apply_reg(array $op): void
    {
        $kind = $op[0];
        switch ($kind) {
            case 'hook': {
                [, $tag, $id, $priority, $accepted] = $op;
                add_filter($tag, fn (...$args) => $this->call($id, $args, $tag), $priority, max(1, $accepted));
                break;
            }
            case 'shortcode': {
                [, $tag, $id] = $op;
                add_shortcode($tag, fn ($atts, $content, $t) => (string) $this->call($id, [$atts, $content, $t]));
                break;
            }
            case 'rest': {
                [, $namespace, $route, $handlers] = $op;
                $route = '/' . ltrim(substr($route, strlen('/' . $namespace)), '/');
                register_rest_route($namespace, $route, array_map($this->import(...), $handlers), true);
                break;
            }
            case 'script_register':
            case 'style_register': {
                [, $handle, $src, $deps, $ver, $args, $extra] = $op;
                $deps = is_array($deps) ? $deps : [];
                $deps = array_values(array_filter($deps, 'is_string'));
                $reg = $kind === 'script_register' ? wp_scripts() : wp_styles();
                $reg->add($handle, $src, $deps, $ver, $kind === 'script_register' ? $args : ($args ?: 'all'));
                if (is_array($extra)) {
                    foreach ($extra as $k => $v) $reg->add_data($handle, $k, $v);
                }
                break;
            }
            case 'script_enqueue':
                wp_enqueue_script($op[1]);
                break;
            case 'style_enqueue':
                wp_enqueue_style($op[1]);
                break;
            case 'menu':
                $GLOBALS['menu'][] = $op[1];
                break;
            case 'submenu':
                $GLOBALS['submenu'][$op[1]][] = $op[2];
                break;
            case 'registered_page':
                $GLOBALS['_registered_pages'][$op[1]] = true;
                break;
            case 'admin_page_hook':
                $GLOBALS['admin_page_hooks'][$op[1]] = $op[2];
                break;
        }
    }

    // --- values crossing the socket -----------------------------------------------------

    /** Callback references the plugin passed come back to the sandbox when core calls them. */
    private function import(mixed $value): mixed
    {
        if (is_array($value) && count($value) === 1 && isset($value['__securecore_callback'])) {
            $id = (int) $value['__securecore_callback'];
            return fn (...$args) => $this->call($id, $args);
        }
        return is_array($value) ? array_map($this->import(...), $value) : $value;
    }

    // core → sandbox (marshal_out) and sandbox → core (marshal_in). WordPress objects cannot
    // cross the socket as themselves (unserialize forbids classes). Each side encodes them as
    // small markers and the other rebuilds them from its own WordPress — the post by id, the
    // main query and the $wp object from its own globals — so a callback works on the same
    // post/query/user core has. Unknown objects cross as null (reported, not fatal); this is
    // the request-state limit the spike reports on.
    private function marshal_out(mixed $value): mixed
    {
        return marshal_encode($value);
    }

    private function marshal_in(mixed $value): mixed
    {
        return marshal_decode($value, fn (int $id) => fn (...$args) => $this->call($id, $args));
    }

    private function send(array $message): void
    {
        try {
            $line = base64_encode(serialize($message));
        } catch (\Throwable $error) {
            $line = base64_encode(serialize(['return', null]));
        }
        if ($this->alive) fwrite($this->sock, $line . "\n");
    }
}

/**
 * The gateway: run one of the sandbox $wpdb's calls against core's real $wpdb and return the
 * answer for the connectionless GatewayWpdb. The method is allowlisted (addiscorp/securecore#42,
 * review note 1): the sandbox's $wpdb only ever needs these four, so core never calls an
 * arbitrary $wpdb method by name — a refused method is audited and returns null, ahead of the
 * per-row SQL policy that is a later part of #42.
 */
function db_answer(string $method, array $args, string $plugin = '(sandbox)'): mixed
{
    global $wpdb;
    switch ($method) {
        case 'query':
            // The sandbox's $wpdb::query() always sends a string; guard anyway so a malformed
            // call can never reach mysqli_query() with a non-string and take down the core
            // request. Audited, returns an empty result.
            if (!is_string($args[0] ?? '')) {
                audit($plugin, 'db.refused', ['method' => 'query', 'reason' => 'non-string: ' . gettype($args[0] ?? null)]);
                return ['return' => false, 'last_result' => [], 'last_error' => '', 'insert_id' => 0, 'rows_affected' => 0, 'num_rows' => 0];
            }
            $return = $wpdb->query($args[0] ?? '');
            return [
                'return' => $return,
                'last_result' => array_map(static fn ($r) => (array) $r, $wpdb->last_result ?: []),
                'last_error' => $wpdb->last_error,
                'insert_id' => $wpdb->insert_id,
                'rows_affected' => $wpdb->rows_affected ?? 0,
                'num_rows' => $wpdb->num_rows,
            ];
        case 'db_version':
        case 'db_server_info':
            return $wpdb->$method();
        case 'get_col_info':
            return $wpdb->get_col_info($args[0] ?? 'name', $args[1] ?? -1);
    }
    audit($plugin, 'db.refused', ['method' => $method]);
    return null;
}

/**
 * SecureCore's code: this plugin's folder (wp-content/plugins/securecore), holding the
 * sandbox scripts and the launcher. Replaced as a whole when SecureCore is upgraded.
 */
function code_dir(): string
{
    return __DIR__;
}

/**
 * SecureCore's data, kept across upgrades: the manifests (wp-content/securecore/manifests).
 * SECURECORE_DATA in wp-config.php moves it.
 */
function data_dir(): string
{
    return defined('SECURECORE_DATA') ? SECURECORE_DATA : WP_CONTENT_DIR . '/securecore';
}

/**
 * The worker's socket. Default: wp-content/securecore/worker.sock, next to the manifests, so
 * it works for a normal user on any OS with no setup. SECURECORE_SOCKET in wp-config.php
 * overrides it (the systemd and Docker templates use /run/securecore/worker.sock).
 */
function socket_path(): string
{
    return defined('SECURECORE_SOCKET') ? SECURECORE_SOCKET : data_dir() . '/worker.sock';
}

/**
 * Unix socket paths are short: 104 bytes on macOS and the BSDs, 108 on Linux, including the
 * final NUL. Returns why the socket path cannot work here, or null.
 */
function socket_path_problem(): ?string
{
    $max = (PHP_OS_FAMILY === 'Linux' ? 108 : 104) - 1;
    $len = strlen(socket_path());
    if ($len <= $max) return null;
    return sprintf(
        'The worker socket path is %d characters, over the %d this system allows for a unix socket (%s). Add a shorter one to wp-config.php, e.g. define( \'SECURECORE_SOCKET\', \'/tmp/securecore-%s.sock\' );',
        $len, $max, socket_path(), substr(md5(ABSPATH), 0, 8),
    );
}

/** @return array<string, array> manifests keyed by plugin file, e.g. "hello.php" */
function manifests(): array
{
    $found = [];
    foreach (glob(data_dir() . '/manifests/*.json') ?: [] as $file) {
        $manifest = json_decode((string) file_get_contents($file), true);
        if (is_array($manifest) && isset($manifest['plugin'])) $found[$manifest['plugin']] = $manifest;
    }
    return $found;
}

/** Is the worker accepting connections? Used by the admin screen and a future `wp securecore`. */
function worker_running(): bool
{
    $stream = @stream_socket_client('unix://' . socket_path(), $errno, $errstr, 1);
    if ($stream) { fclose($stream); return true; }
    return false;
}

/**
 * Start the worker if it is not already running. Returns [ok, message]. Works where
 * proc_open is available in core (a plain or systemd install); under Docker the worker is
 * its own container and this is not used. The same function backs a future `wp securecore`.
 */
function start_worker(): array
{
    if (worker_running()) return [true, 'already running'];
    $problem = socket_path_problem();
    if ($problem) return [false, $problem];
    if (!function_exists('proc_open') || in_array('proc_open', array_map('trim', explode(',', (string) ini_get('disable_functions'))), true)) {
        return [false, 'proc_open is disabled in core; start the worker yourself (see INSTALL.md)'];
    }
    $launcher = code_dir() . '/bin/securecore-worker';
    if (!is_file($launcher)) return [false, "launcher not found at $launcher"];
    @mkdir(dirname(socket_path()), 0755, true);
    $command = implode(' ', array_map('escapeshellarg', [$launcher, socket_path(), WP_PLUGIN_DIR, data_dir() . '/manifests']));
    // Detached, so the worker outlives this request and this PHP process: setsid where it
    // exists (Linux), nohup in the background otherwise (macOS).
    $log = escapeshellarg(data_dir() . '/worker.log');
    @exec(trim((string) shell_exec('command -v setsid 2>/dev/null')) !== ''
        ? "setsid -f $command >> $log 2>&1 < /dev/null"
        : "nohup $command >> $log 2>&1 < /dev/null &");
    for ($i = 0; $i < 40; $i++) {
        usleep(50000);
        if (worker_running()) return [true, 'started'];
    }
    return [false, 'worker did not come up; see ' . data_dir() . '/worker.log'];
}

/**
 * Generate a plugin's manifest from its code (the WordPress functions and hooks it uses),
 * store it, and return it. Run when a plugin is switched on, on its trusted version; a later
 * update that wants more is then visible as a change. Shares scan_plugin() with the worker.
 */
function generate_manifest(string $pluginFile): array
{
    require_once code_dir() . '/sandbox/scan.php';
    $path = WP_PLUGIN_DIR . '/' . $pluginFile;
    $dir = str_contains($pluginFile, '/') ? dirname($path) : $path;
    $scan = scan_plugin(is_dir($dir) ? $dir : $path);
    // Grant only names that are not PHP built-ins: WordPress and plugin functions, never
    // fsockopen/exec/curl_* (those must fail in the sandbox, not be forwarded to core).
    $internal = array_flip(get_defined_functions()['internal']);
    $functions = array_values(array_filter($scan['called'], fn ($n) => !isset($internal[$n])));
    sort($functions);
    sort($scan['hooks']);
    $manifest = ['plugin' => $pluginFile, 'hooks' => $scan['hooks'], 'functions' => $functions]
        + ($scan['dynamic'] ? ['dynamic_hooks' => true] : []);
    @mkdir(data_dir() . '/manifests', 0755, true);
    file_put_contents(data_dir() . '/manifests/' . manifest_name($pluginFile), json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    return $manifest;
}

function manifest_name(string $pluginFile): string
{
    return preg_replace('/[^a-z0-9._-]+/i', '-', str_replace('/', '-', $pluginFile)) . '.json';
}

/** The manifest file on disk for a plugin (matched by its "plugin" field), or null. */
function manifest_file(string $pluginFile): ?string
{
    foreach (glob(data_dir() . '/manifests/*.json') ?: [] as $file) {
        $manifest = json_decode((string) file_get_contents($file), true);
        if (is_array($manifest) && ($manifest['plugin'] ?? null) === $pluginFile) return $file;
    }
    return null;
}

/** The pre-boot options snapshot and its hash, in the data dir next to the manifests. */
function options_snapshot_path(): string
{
    return data_dir() . '/options-snapshot.php';
}

function options_snapshot_hash_path(): string
{
    return data_dir() . '/options-snapshot.hash';
}

/**
 * Write the pre-boot options snapshot (addiscorp/securecore#42, part 1b): the autoloaded
 * options the worker parent boots WordPress from, since the parent has no database of its own.
 * Values are the raw stored strings, exactly as wp_load_alloptions() holds them, so the parent
 * re-unserializes them like any request. The sandbox child does NOT read this copy — after it
 * forks it drops its options cache and reads every option fresh through the gateway; the
 * snapshot only carries the parent through its no-plugin bootstrap. Written atomically (a temp
 * file then rename) so the worker never includes a half-written file. The hash lets the worker
 * notice a change and re-boot.
 */
/**
 * The names of WordPress's own options: the ones populate_options() in wp-admin/includes/schema.php
 * seeds at install, plus the active theme's theme_mods_<stylesheet>. Parsed from the site's own
 * schema.php so it tracks the WordPress version. This is the allowlist for the pre-boot snapshot
 * (addiscorp/securecore#47) — a plugin's autoloaded options must never reach the parent. The regex
 * is deliberately generous (it also catches capability/array keys inside default values); that is
 * harmless because the snapshot intersects it with the autoloaded options, so only real options
 * survive, and a stray non-option name matches nothing. A core option boot needs that is NOT named
 * here (e.g. rewrite_rules, added after install) shows up as a parent-boot miss in the worker log.
 *
 * @return array<string,true> option name => true
 */
function core_option_names(): array
{
    static $names = null;
    if ($names !== null) return $names;
    $names = [];
    $schema = ABSPATH . 'wp-admin/includes/schema.php';
    $src = is_readable($schema) ? (string) file_get_contents($schema) : '';
    // Capture the whole populate_options() body: from its name to the first closing brace in
    // column 0 (its own; every brace inside the body is indented). Matching the signature's
    // parens would trip on the default `array()` in `populate_options( $options = array() )`.
    if ($src !== '' && preg_match('/function\s+populate_options\b(.*?)\n\}/s', $src, $m)) {
        // The option names: array keys in the $options literal and the add_option() calls.
        if (preg_match_all("/'([A-Za-z0-9_-]+)'\s*=>/", $m[1], $k)) {
            foreach ($k[1] as $n) $names[$n] = true;
        }
        if (preg_match_all("/add_option\(\s*'([A-Za-z0-9_-]+)'/", $m[1], $k2)) {
            foreach ($k2[1] as $n) $names[$n] = true;
        }
    }
    // The active theme's mods are WordPress's, not a plugin's.
    $stylesheet = get_option('stylesheet');
    if (is_string($stylesheet) && $stylesheet !== '') $names['theme_mods_' . $stylesheet] = true;
    return $names;
}

function write_options_snapshot(): void
{
    global $wpdb;
    // Snapshot ONLY WordPress's own options (addiscorp/securecore#47): the allowlist from
    // populate_options() plus the theme mods. A plugin's autoloaded options — license keys,
    // SMTP/API credentials — must never reach the pre-booted parent (and so every sandbox
    // child); the parent boots with no plugins and needs none of them. (#42: "no plugin options
    // and no secrets" in the parent.)
    $options = array_intersect_key(wp_load_alloptions(), core_option_names());
    // The sandbox forces the active-plugin lists empty (the SECURECORE_SANDBOX guard at the top
    // of this file), so never carry their values even if the allowlist names them.
    unset($options['active_plugins'], $options['active_sitewide_plugins']);
    $payload = ['prefix' => $wpdb->prefix, 'options' => $options];
    $php = '<?php return ' . var_export($payload, true) . ";\n";
    $hash = sha1($php);
    // Nothing that affects the parent's boot changed: leave the file (and its hash) alone, so
    // the worker does not re-boot for a no-op write.
    if (is_file(options_snapshot_hash_path()) && trim((string) @file_get_contents(options_snapshot_hash_path())) === $hash) return;
    $dir = data_dir();
    @mkdir($dir, 0755, true);
    $tmp = $dir . '/.options-snapshot.' . getmypid() . '.tmp';
    if (@file_put_contents($tmp, $php, LOCK_EX) === false) return;
    if (@rename($tmp, options_snapshot_path())) {
        @file_put_contents(options_snapshot_hash_path(), $hash . "\n", LOCK_EX);
    } else {
        @unlink($tmp);
    }
}

// --- admin screen -----------------------------------------------------------------------
// Settings → SecureCore: the worker's status, a Run-in-sandbox switch per installed plugin,
// and each sandboxed plugin's generated manifest. Always registered, so you can turn the
// first plugin on. Switching a plugin on generates its manifest from its code; off deletes
// it. The stored manifest is what the worker enforces.
add_action('admin_menu', function () {
    add_options_page('SecureCore', 'SecureCore', 'manage_options', 'securecore', __NAMESPACE__ . '\\admin_page');
});

function admin_page(): void
{
    if (!current_user_can('manage_options')) return;
    $notice = '';
    if (($_POST['securecore_action'] ?? '') !== '' && check_admin_referer('securecore')) {
        if ($_POST['securecore_action'] === 'start') {
            [$ok, $msg] = start_worker();
            $notice = ($ok ? 'Worker: ' : 'Could not start the worker: ') . $msg;
        } elseif ($_POST['securecore_action'] === 'save') {
            $want = array_map('sanitize_text_field', (array) ($_POST['sandbox'] ?? []));
            $have = array_keys(manifests());
            foreach (array_diff($want, $have) as $on) generate_manifest($on);
            foreach (array_diff($have, $want) as $off) { $f = manifest_file($off); if ($f) @unlink($f); }
            $notice = 'Saved. Sandboxed: ' . (count($want) ? implode(', ', $want) : 'none') . '.';
        }
    }
    if (!function_exists('get_plugins')) require_once ABSPATH . 'wp-admin/includes/plugin.php';
    $installed = get_plugins();
    $manifests = manifests();
    $running = worker_running();
    echo '<div class="wrap"><h1>SecureCore</h1>';
    if ($notice) printf('<div class="notice notice-info"><p>%s</p></div>', esc_html($notice));
    $problem = socket_path_problem();
    if ($problem) printf('<div class="notice notice-error"><p>%s</p></div>', esc_html($problem));
    printf(
        '<p>Worker: <strong style="color:%s">%s</strong> on <code>%s</code>.</p>',
        $running ? 'green' : 'crimson', $running ? 'running' : 'not running', esc_html(socket_path()),
    );
    if (!$running) {
        echo '<form method="post">';
        wp_nonce_field('securecore');
        echo '<input type="hidden" name="securecore_action" value="start"><p>';
        submit_button('Start worker', 'secondary', 'submit', false);
        printf(
            ' <span class="description">Works where this PHP may run <code>proc_open</code>; otherwise run <code>%s</code> yourself.</span></p></form>',
            esc_html(code_dir() . '/bin/securecore-worker'),
        );
    }
    echo '<p class="description">Switching a plugin on or off takes effect on the next request; the worker does not need a restart.</p>';
    echo '<form method="post"><table class="widefat striped"><thead><tr><th>Plugin</th><th>Run in sandbox</th><th>Manifest</th></tr></thead><tbody>';
    foreach ($installed as $file => $data) {
        if ($file === 'securecore-probe/securecore-probe.php' || $file === 'securecore/securecore.php') continue;
        $on = isset($manifests[$file]);
        $m = $manifests[$file] ?? null;
        printf(
            '<tr><td><strong>%s</strong></td><td><label><input type="checkbox" name="sandbox[]" value="%s"%s> sandbox</label></td><td>%s</td></tr>',
            esc_html($data['Name'] ?? $file), esc_attr($file), $on ? ' checked' : '',
            $m ? '<code>' . esc_html(count($m['functions'] ?? []) . ' functions, ' . count($m['hooks'] ?? []) . ' hooks') . (!empty($m['dynamic_hooks']) ? ' (dynamic hooks — review)' : '') . '</code>' : '—',
        );
    }
    echo '</tbody></table>';
    wp_nonce_field('securecore');
    echo '<input type="hidden" name="securecore_action" value="save">';
    submit_button('Save');
    echo '</form></div>';
}

$manifests = manifests();
$active = (array) get_option('active_plugins', []);
$sandboxed = array_values(array_intersect($active, array_keys($manifests)));
if (!$sandboxed) return;

// Pre-boot (addiscorp/securecore#42, part 1b): keep an on-disk snapshot of the autoloaded
// options so the worker parent can boot WordPress once, before any request, with no database
// of its own. Maintained whenever the real-WordPress model is on and something is sandboxed,
// so it is ready when the worker (re)starts. Only autoloaded options affect that boot, so we
// rewrite at most once per request — at shutdown, and only when one of them changed (or no
// snapshot exists yet). An option write that is not autoloaded (most transients) is ignored.
if (realwp_enabled()) {
    // The parent boots WordPress with no plugins, so only WordPress's own structural options
    // affect that boot; a plugin's options, WooCommerce's settings, transients and the cron
    // array do not (the parent never reads them, and the child reads every option fresh
    // through the gateway). So re-snapshot — and re-boot the worker — only when one of these
    // changes, not on the churn of ordinary option writes, which would re-boot it constantly.
    $boot_structural = array_flip([
        'siteurl', 'home', 'blogname', 'blogdescription', 'blog_charset', 'WPLANG',
        'timezone_string', 'gmt_offset', 'start_of_week', 'date_format', 'time_format',
        'permalink_structure', 'rewrite_rules', 'category_base', 'tag_base',
        'show_on_front', 'page_on_front', 'page_for_posts', 'posts_per_page',
        'template', 'stylesheet', 'current_theme', 'theme_switched', 'blog_public',
        'sidebars_widgets', 'default_role', 'db_version', 'secret',
    ]);
    $mark_dirty = function () { $GLOBALS['securecore_options_dirty'] = true; };
    $mark_if_structural = function ($option) use ($mark_dirty, $boot_structural) {
        if (is_string($option) && isset($boot_structural[$option])) $mark_dirty();
    };
    add_action('added_option', $mark_if_structural);
    add_action('updated_option', $mark_if_structural);
    add_action('deleted_option', $mark_if_structural);
    if (!file_exists(options_snapshot_path())) $mark_dirty();
    add_action('shutdown', function () {
        if (!empty($GLOBALS['securecore_options_dirty'])) write_options_snapshot();
    }, PHP_INT_MAX - 1);
}

// Core loads every active plugin with include_once. Hide the sandboxed ones from that loop
// only; the Plugins screen still shows them as active.
$hide = fn ($plugins) => array_values(array_diff((array) $plugins, $sandboxed));
add_filter('option_active_plugins', $hide, PHP_INT_MAX);
add_action('plugins_loaded', fn () => remove_filter('option_active_plugins', $hide, PHP_INT_MAX), PHP_INT_MIN);

// If the worker is down, the sandboxed plugins don't load; say so in wp-admin.
if (!worker_running()) {
    add_action('admin_notices', function () use ($sandboxed) {
        printf(
            '<div class="notice notice-error"><p><strong>SecureCore:</strong> the sandbox worker is not running, so these plugins are not active: %s. Start it on the SecureCore settings screen or as in INSTALL.md.</p></div>',
            esc_html(implode(', ', $sandboxed)),
        );
    });
    return;
}

// Start the sandboxes where core would have included the plugins.
add_action('muplugins_loaded', function () use ($sandboxed, $manifests) {
    $realwp = realwp_enabled();
    $sandboxes = [];
    foreach ($sandboxed as $plugin) {
        $sandboxes[] = $realwp
            ? new RealWpSandbox($plugin, $manifests[$plugin])
            : new Sandbox($plugin, $manifests[$plugin]);
    }
    foreach ($sandboxes as $sandbox) $sandbox->boot();

    // Real-WordPress model: once the request is resolved, replay its state (main query,
    // current user) into each sandbox so a callback sees the same post/query/user as core.
    if ($realwp) {
        $sent = false;
        $send_state = function () use ($sandboxes, &$sent) {
            if ($sent) return;
            $sent = true;
            foreach ($sandboxes as $sandbox) {
                if ($sandbox instanceof RealWpSandbox && $sandbox->alive()) $sandbox->setup_state();
            }
        };
        add_action('wp', $send_state, PHP_INT_MIN);                 // front end: after the main query
        add_action('current_screen', $send_state, PHP_INT_MIN);    // admin: after the screen is known
        add_action('rest_api_init', $send_state, PHP_INT_MIN);     // REST: before routes dispatch
    }

    add_action('shutdown', function () use ($sandboxes) {
        foreach ($sandboxes as $sandbox) $sandbox->end();
    }, PHP_INT_MAX);
    $report = function () use ($sandboxed) {
        $loaded = array_filter($sandboxed, fn ($p) => in_array(WP_PLUGIN_DIR . '/' . $p, get_included_files(), true));
        printf("\n<!-- securecore: sandboxed %s; included by core: %s -->\n", implode(',', $sandboxed), $loaded ? implode(',', $loaded) : 'none');
    };
    add_action('admin_footer', $report);
    add_action('wp_footer', $report);
});
