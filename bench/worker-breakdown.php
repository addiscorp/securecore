<?php
// Measurement 1: the per-request cost split for the fork worker — fork, plugin include (with
// the opcache hit), and the first call across the socket. Runs in the worker container
// (pcntl + opcache). JSON out; non-zero exit on failure.
//
//   php -d opcache.enable_cli=1 bench/worker-breakdown.php <plugins-dir> <socket> [requests] [calls]
//
// fork + include are measured locally (a fork loop like the worker's, requiring the plugin
// directly). first_call + forwarded are measured against the running worker over its socket.
namespace SecureCore;

[$pluginsDir, $socket] = [$argv[1] ?? '', $argv[2] ?? ''];
$requests = (int) ($argv[3] ?? 30);
$calls = (int) ($argv[4] ?? 1000);
$main = "$pluginsDir/securecore-bench/securecore-bench.php";

// Stubs so the plugin's top-level add_action() runs during the include; these live in the
// parent and are inherited, but the plugin's own functions are only ever defined in a child.
define('ABSPATH', '/wordpress/');
if (!function_exists(__NAMESPACE__ . '\\pct')) {}
eval('function add_action(...$a){} function add_filter(...$a){}');

function percentiles(array $v): array
{
    sort($v);
    $n = count($v);
    return ['p50' => round($v[intdiv($n - 1, 2)], 3), 'p95' => round($v[(int) ceil(0.95 * $n) - 1], 3)];
}

// fork + include, with opcache warmed so the include is a cache hit (as in a live worker).
function fork_include(string $main): array
{
    $pair = stream_socket_pair(\STREAM_PF_UNIX, \STREAM_SOCK_STREAM, 0);
    $t0 = hrtime(true);
    $pid = pcntl_fork();
    if ($pid === 0) {
        fclose($pair[0]);
        $t = hrtime(true);
        require $main;
        fwrite($pair[1], json_encode(['include_us' => (hrtime(true) - $t) / 1000]) . "\n");
        fclose($pair[1]);
        exit(0);
    }
    $forkUs = (hrtime(true) - $t0) / 1000;
    fclose($pair[1]);
    $line = fgets($pair[0]);
    fclose($pair[0]);
    pcntl_waitpid($pid, $status);
    $r = json_decode(trim((string) $line), true) ?: ['include_us' => 0];
    return ['fork_us' => $forkUs, 'include_us' => $r['include_us']];
}

// One request to the live worker: time the first hook callback (core → sandbox → core) and
// the forwarded-call loop (sandbox → core → sandbox), from core's side.
function socket_calls(string $socket, int $calls): array
{
    $s = @stream_socket_client("unix://$socket", $e, $m, 5);
    if (!$s) throw new \RuntimeException("connect: $m");
    stream_set_timeout($s, 30);
    $send = fn (array $msg) => fwrite($s, base64_encode(serialize($msg)) . "\n");
    $recv = function () use ($s) {
        do { $line = fgets($s); if ($line === false) throw new \RuntimeException('worker closed'); } while ($line[0] === '#');
        return unserialize(base64_decode(trim($line)), ['allowed_classes' => false]);
    };
    $hooks = [];
    $send(['boot', ['plugin' => 'securecore-bench/securecore-bench.php', 'get' => [], 'post' => [], 'server' => []]]);
    for (;;) {
        $msg = $recv();
        if ($msg[0] === 'hook') { $hooks[$msg[2]] = $msg[3]; $send(['return', true]); }
        elseif ($msg[0] === 'wp') { $send(['return', null]); }
        elseif ($msg[0] === 'ready') break;
    }
    // Answer any 'wp' the hook makes (the forwarded calls) until it returns.
    $await = function () use ($recv, $send) {
        for (;;) {
            $msg = $recv();
            if ($msg[0] === 'wp') { $send(['return', null]); continue; }
            if ($msg[0] === 'return') return $msg;
        }
    };
    $t = hrtime(true);
    $send(['call', $hooks['securecore_bench_hook'], [1]]);
    $await();
    $firstUs = (hrtime(true) - $t) / 1000;
    $send(['call', $hooks['securecore_bench_calls'], [null, $calls]]);
    $forwardedUs = $await()[1];
    $send(['end']);
    fclose($s);
    return ['first_call_us' => $firstUs, 'forwarded_call_us' => $forwardedUs];
}

try {
    fork_include($main); // warm opcache
    for ($i = 0; $i < 5; $i++) socket_calls($socket, $calls); // warm the worker's slots
    $fi = [];
    $sc = [];
    for ($i = 0; $i < $requests; $i++) { $fi[] = fork_include($main); $sc[] = socket_calls($socket, $calls); }
    echo json_encode([
        'requests' => $requests, 'calls' => $calls,
        'fork_us' => percentiles(array_column($fi, 'fork_us')),
        'include_us' => percentiles(array_column($fi, 'include_us')),
        'first_call_us' => percentiles(array_column($sc, 'first_call_us')),
        'forwarded_call_us' => percentiles(array_column($sc, 'forwarded_call_us')),
    ], JSON_PRETTY_PRINT), "\n";
} catch (\Throwable $e) {
    fwrite(STDERR, 'worker-breakdown failed: ' . $e->getMessage() . "\n");
    exit(1);
}
