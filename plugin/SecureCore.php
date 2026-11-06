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
 *   SECURECORE_SOCKET    worker socket path (default /run/securecore/worker.sock)
 *   SECURECORE_DATA      where manifests live (default wp-content/securecore)
 *
 * Protocol: see sandbox/setup.php.
 */
namespace SecureCore;

if (defined('SECURECORE_DISABLED') && SECURECORE_DISABLED) return;
// wp-cli runs as the site owner, not as a web request; plugins load normally there.
if (defined('WP_CLI') && WP_CLI) return;

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
        $socket = defined('SECURECORE_SOCKET') ? SECURECORE_SOCKET : '/run/securecore/worker.sock';
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

function socket_path(): string
{
    return defined('SECURECORE_SOCKET') ? SECURECORE_SOCKET : '/run/securecore/worker.sock';
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
    if (!function_exists('proc_open') || in_array('proc_open', array_map('trim', explode(',', (string) ini_get('disable_functions'))), true)) {
        return [false, 'proc_open is disabled in core; start the worker yourself (see INSTALL.md)'];
    }
    $launcher = code_dir() . '/bin/securecore-worker';
    if (!is_file($launcher)) return [false, "launcher not found at $launcher"];
    @mkdir(dirname(socket_path()), 0755, true);
    $command = implode(' ', array_map('escapeshellarg', [$launcher, socket_path(), WP_PLUGIN_DIR, data_dir() . '/manifests']));
    // setsid -f: the worker outlives this request and this php-fpm process.
    @exec('setsid -f ' . $command . ' >> ' . escapeshellarg(WP_CONTENT_DIR . '/securecore-worker.log') . ' 2>&1 < /dev/null');
    for ($i = 0; $i < 40; $i++) {
        usleep(50000);
        if (worker_running()) return [true, 'started'];
    }
    return [false, 'worker did not come up; see wp-content/securecore-worker.log'];
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
    printf(
        '<p>Worker: <strong style="color:%s">%s</strong> on <code>%s</code>.</p>',
        $running ? 'green' : 'crimson', $running ? 'running' : 'not running', esc_html(socket_path()),
    );
    if (!$running) {
        echo '<form method="post">';
        wp_nonce_field('securecore');
        echo '<input type="hidden" name="securecore_action" value="start"><p>';
        submit_button('Start worker', 'secondary', 'submit', false);
        echo ' <span class="description">Works where core may run <code>proc_open</code>; otherwise start it as in INSTALL.md.</span></p></form>';
    }
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
    $sandboxes = [];
    foreach ($sandboxed as $plugin) $sandboxes[] = new Sandbox($plugin, $manifests[$plugin]);
    foreach ($sandboxes as $sandbox) $sandbox->boot();
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
