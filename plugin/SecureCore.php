<?php
/**
 * Plugin Name: SecureCore
 * Description: Runs plugins that have a SecureCore manifest in a separate sandbox process. Core stays on this PHP; every call between a sandboxed plugin and WordPress crosses here and is checked against the plugin's manifest.
 * Version: 0.1.0
 *
 * Install as a mu-plugin (wp-content/mu-plugins/SecureCore.php). Manifests live in
 * wp-content/securecore/manifests/*.json, one per sandboxed plugin:
 *   { "plugin": "hello.php", "hooks": ["admin_notices", ...],
 *     "functions": ["wptexturize", ...] }   // WordPress functions this plugin may call
 * A plugin without a manifest loads normally.
 *
 * The sandbox is the `securecore` worker (sandbox/worker.php) in its own container with no
 * network: one process for all plugins, a fork per request. This mu-plugin connects to its
 * socket per request. If the worker is not up, the plugins it would sandbox do not load.
 *
 * wp-config.php settings (all optional):
 *   SECURECORE_DISABLED  true: load every plugin normally (baseline)
 *   SECURECORE_ENFORCE   false: allow and log calls the manifest does not grant (observe)
 *   SECURECORE_SOCKET    worker socket path (default /run/securecore/worker.sock)
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

/** @return array<string, array> manifests keyed by plugin file, e.g. "hello.php" */
function manifests(): array
{
    $found = [];
    foreach (glob(WP_CONTENT_DIR . '/securecore/manifests/*.json') ?: [] as $file) {
        $manifest = json_decode((string) file_get_contents($file), true);
        if (is_array($manifest) && isset($manifest['plugin'])) $found[$manifest['plugin']] = $manifest;
    }
    return $found;
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
