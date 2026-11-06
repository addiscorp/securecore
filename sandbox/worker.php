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

function log_line(string $line): void
{
    fwrite(STDERR, gmdate('c') . " securecore-worker " . $line . "\n");
}

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
foreach (manifest_files($manifestsDir) as $plugin => [$file, $hash]) {
    $cache[$plugin] = [$hash, ...plugin_entry($pluginsDir, $plugin)];
}
log_line('ready: ' . count($cache) . ' plugins (' . implode(', ', array_keys($cache)) . '); manifests are read per request');

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

@unlink($socketPath);
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

for (;;) {
    $conn = @stream_socket_accept($server, -1);
    if (!$conn) continue;
    if ($noFork) {
        // One process reused for every request: statics and globals carry over. For the
        // isolation test, to show what forking prevents. Never use in production.
        serve_connection($conn, $cache, $pluginsDir, $manifestsDir);
        fclose($conn);
        continue;
    }
    $pid = pcntl_fork();
    if ($pid === 0) {
        fclose($server);
        serve_connection($conn, $cache, $pluginsDir, $manifestsDir);
        exit(0);
    }
    fclose($conn);
}
