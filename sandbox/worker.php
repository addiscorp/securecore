<?php
// One long-running sandbox process for all plugins, the way php-fpm's master works.
//
//   php -d opcache.enable_cli=1 worker.php <socket> <plugins-dir> <manifests-dir>
//
// Boots setup.php only (no plugin) and listens on one unix socket. Per connection
// (SecureCore.php opens one per plugin per request), pcntl_fork(): the child includes that
// one plugin's main file fresh — like PHP re-running a plugin each request, made cheap by
// opcache holding the compiled code in shared memory the children inherit — serves the
// conversation over the socket (the protocol in setup.php), and exits. State is clean per
// request because each child is a fresh process; a child only ever loads one plugin, so the
// per-plugin manifest checks in core still mean something.
//
// Isolation is where this runs, not PHP flags: its own container with no network, only
// wp-content/plugins (read-only) and the socket dir mounted, a clean environment, and
// disable_functions for exec/shell/proc. See docker/worker.Dockerfile.
//
// SECURECORE_NOFORK=1 serves in the parent without forking: used by a test to show state
// leaks between requests when the fork is removed.
namespace SecureCore;

define('SECURECORE_WORKER', true);
require __DIR__ . '/setup.php';

[$socketPath, $pluginsDir, $manifestsDir] = [$argv[1] ?? '', $argv[2] ?? '', $argv[3] ?? ''];
if (!$socketPath || !$pluginsDir || !$manifestsDir) {
    fwrite(STDERR, "usage: worker.php <socket> <plugins-dir> <manifests-dir>\n");
    exit(2);
}

// "Real WordPress" model (addiscorp/securecore#42, part 1): the child boots the site's own
// WordPress and loads its plugin into it, instead of running the plugin against forwarding
// stand-ins. Off by default, so the forward-stub worker (#11) stays available to benchmark
// against. The WordPress root is the parent of wp-content, derived from the plugins dir.
$realwp = (bool) getenv('SECURECORE_REALWP');
$wpRoot = $realwp ? dirname($pluginsDir, 2) : '';
// Pre-boot (addiscorp/securecore#42, part 1b): with SECURECORE_PREBOOT the parent boots
// WordPress once, from the options snapshot core wrote to disk, and every child forks from
// that booted state instead of running wp-settings.php per request. Without it, the
// real-WordPress worker behaves as part 1 (each child boots), which is the "booting per
// request" row in the benchmark.
$prebootRequested = $realwp && (bool) getenv('SECURECORE_PREBOOT');
if ($realwp) require __DIR__ . '/realwp.php';

function log_line(string $line): void
{
    fwrite(STDERR, gmdate('c') . " securecore-worker " . $line . "\n");
}

// In the parent, PHP warnings go to the log as plain text. setup.php's handler (underneath
// this one) sends them to core over the protocol, which only means something inside a
// conversation, so each child pops back to it before serving.
set_error_handler(function (int $level, string $message, string $file, int $line): bool {
    if (!(error_reporting() & $level)) return true; // silenced with @
    log_line("php: $message ($file:$line)");
    return true;
});

// Per plugin, the WordPress functions it calls (stand-ins). The child forwards each to core,
// which allows it only if the manifest grants it — so an ungranted call (a backdoor's
// wp_insert_user) is denied and logged, while a native call the launcher disabled fails in
// the sandbox and is never forwarded (see called_functions). Computed once here, inherited
// by every child. opcache's shared memory, set up here and inherited across forks, caches
// each plugin's compiled code the first time any child requires it; the rest hit that cache.
// (The plugin's own functions are never compiled in the parent — opcache_compile_file would
// define them here and each child would then redeclare them on require.)
/**
 * The manifests on disk right now, keyed by plugin: [file, content hash]. Read again by each child
 * at fork time, so switching a plugin on or off in wp-admin takes effect on the next request
 * without restarting the worker.
 */
function manifest_files(string $manifestsDir): array
{
    $found = [];
    foreach (glob("$manifestsDir/*.json") ?: [] as $file) {
        $manifest = json_decode((string) file_get_contents($file), true);
        if (is_array($manifest) && isset($manifest['plugin']) && is_string($manifest['plugin'])) {
            $found[$manifest['plugin']] = [$file, (string) sha1_file($file)];
        }
    }
    return $found;
}

/** A plugin's main file and its stand-ins (see called_functions). */
function plugin_entry(string $pluginsDir, string $plugin): array
{
    $path = $pluginsDir . '/' . $plugin;
    $dir = str_contains($plugin, '/') ? dirname($path) : $path;
    return [$path, called_functions(is_dir($dir) ? $dir : $path)];
}

// Warm cache, inherited by every child: each manifest's content hash, main file and stand-ins. A child
// uses an entry only while that manifest file is unchanged; anything new or changed since is
// read and scanned in the child.
$cache = [];
if (!$realwp) {
    foreach (manifest_files($manifestsDir) as $plugin => [$file, $hash]) {
        $cache[$plugin] = [$hash, ...plugin_entry($pluginsDir, $plugin)];
    }
}
log_line(($realwp ? 'ready (real-WordPress model); ' : 'ready: ' . count($cache) . ' plugins (' . implode(', ', array_keys($cache)) . '); ') . 'manifests are read per request');

// Pre-boot the parent now, before the server socket is up, so the first request already forks
// from a booted WordPress. If the snapshot is not there yet (core writes it on its next
// request), boot per request and restart once it appears (see the accept loop).
$preBooted = false;
$bootedHash = '';
if ($prebootRequested) {
    $bootedHash = snapshot_hash($manifestsDir);
    $snapshot = read_snapshot($manifestsDir);
    if ($snapshot === null) {
        log_line('preboot: no options snapshot at ' . snapshot_path($manifestsDir) . ' yet; booting per request until core writes one');
    } else {
        try {
            preboot_wordpress($wpRoot, $snapshot);
            $preBooted = true;
            log_line('preboot: booted WordPress from snapshot (' . count($snapshot['options']) . ' options, hash ' . substr($bootedHash, 0, 12) . ')');
        } catch (\Throwable $e) {
            log_line('preboot: boot failed, falling back to per-request boot: ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
        }
    }
}

// Serve one connection: one request for one plugin. Returns when the request ends. Only a
// plugin that has a manifest on disk at this moment is served.
function serve_connection($conn, array $cache, string $pluginsDir, string $manifestsDir): void
{
    Conn::$in = $conn;
    Conn::$out = $conn;
    $boot = receive();
    if ($boot[0] !== 'boot') return;
    $context = $boot[1];
    $plugin = (string) ($context['plugin'] ?? '');
    $current = manifest_files($manifestsDir);
    if (!isset($current[$plugin])) {
        send(['log', "no manifest for $plugin: not sandboxed"]);
        return;
    }
    [, $hash] = $current[$plugin];
    [$main, $standins] = isset($cache[$plugin]) && $cache[$plugin][0] === $hash
        ? [$cache[$plugin][1], $cache[$plugin][2]]
        : plugin_entry($pluginsDir, $plugin);
    $context['main'] = $main;
    serve_child($context, $standins);
}

// A socket left by a worker that stopped: remove it. (bin/securecore-worker has already
// refused to start if a worker is still answering on it.)
if (file_exists($socketPath) && !unlink($socketPath)) {
    log_line("cannot remove the old socket $socketPath");
    exit(1);
}
$server = stream_socket_server("unix://$socketPath", $errno, $errstr);
if (!$server) {
    log_line("cannot listen on $socketPath: $errstr");
    exit(1);
}
@chmod($socketPath, 0666);
$noFork = (bool) getenv('SECURECORE_NOFORK');
log_line("listening on $socketPath" . ($noFork ? ' (NO FORK: state leaks between requests)' : ''));

// Children reap themselves.
if (!$noFork) pcntl_signal(\SIGCHLD, \SIG_IGN);

if ($noFork) restore_error_handler();

// When pre-booting, the parent re-boots on an options-snapshot change by exiting for its
// supervisor (Docker `restart: unless-stopped`, or a systemd Restart=) to start it again — a
// booted WordPress cannot be re-initialised in place. The check runs once per accepted
// connection (driven by a request, not a timer), reading a tiny hash file; the just-served
// request used the previous snapshot. It also fires the first time the snapshot appears when
// preboot was asked for but none existed at startup, so the worker comes up pre-booted.
$restart_if_snapshot_changed = function () use ($prebootRequested, $manifestsDir, &$bootedHash, $server): void {
    if (!$prebootRequested) return;
    $now = snapshot_hash($manifestsDir);
    if ($now !== '' && $now !== $bootedHash) {
        log_line('preboot: options snapshot changed (' . substr($bootedHash, 0, 12) . ' -> ' . substr($now, 0, 12) . '); restarting to re-boot');
        @fclose($server);
        exit(75);
    }
};

for (;;) {
    $conn = @stream_socket_accept($server, -1);
    if (!$conn) continue;
    if ($noFork) {
        // One process reused for every request: statics and globals carry over. For the
        // isolation test, to show what forking prevents. Never use in production.
        if ($realwp) serve_realwp_connection($conn, $wpRoot, $preBooted);
        else serve_connection($conn, $cache, $pluginsDir, $manifestsDir);
        fclose($conn);
        $restart_if_snapshot_changed();
        continue;
    }
    $pid = pcntl_fork();
    if ($pid === 0) {
        restore_error_handler();
        fclose($server);
        if ($realwp) serve_realwp_connection($conn, $wpRoot, $preBooted);
        else serve_connection($conn, $cache, $pluginsDir, $manifestsDir);
        exit(0);
    }
    fclose($conn);
    $restart_if_snapshot_changed();
}
