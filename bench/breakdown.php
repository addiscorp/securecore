<?php
// Measurement 1 and 4a: what one request costs inside a tab, without WordPress or a web
// server. Starts its own tab for the bench plugin, plays core's side of the protocol
// (sandbox/setup.php) over the tab's socket, and stops the tab at the end.
//
//   php bench/breakdown.php [requests] [calls]      inside the php container (bench/run.sh)
//
// Per request: connect + boot to 'ready', `calls` hook callbacks (core → sandbox) and
// `calls` forwarded function calls (sandbox → core), end. Also: the tab's start-up time
// (process start to first request served) and its RSS. JSON out; non-zero exit on failure.
$requests = (int) ($argv[1] ?? 30);
$calls = (int) ($argv[2] ?? 1000);
$binary = '/usr/local/bin/securecore';
$plugin = '/var/www/html/wp-content/plugins/securecore-bench';
$socket = sys_get_temp_dir() . '/securecore-bench-' . getmypid() . '.sock';

function send($s, array $message): void
{
    fwrite($s, base64_encode(serialize($message)) . "\n");
}

/** Read until the sandbox answers; serve its hook registrations and calls meanwhile. */
function reply($s, array &$hooks): array
{
    while (($line = fgets($s)) !== false) {
        if ($line[0] === '#') continue;
        $message = unserialize(base64_decode(trim($line)), ['allowed_classes' => false]);
        switch ($message[0]) {
            case 'hook': $hooks[$message[2]] = $message[3]; send($s, ['return', true]); break;
            case 'wp': send($s, ['return', null]); break;
            case 'log': fwrite(STDERR, "sandbox log: {$message[1]}\n"); break;
            default: return $message;
        }
    }
    throw new RuntimeException('tab closed the connection');
}

function vm(int $pid, string $field): float
{
    preg_match("/$field:\\s+(\\d+)/", (string) @file_get_contents("/proc/$pid/status"), $m);
    return (int) ($m[1] ?? 0) / 1024;
}

function request(string $socket, int $calls): array
{
    $t0 = hrtime(true);
    $s = @stream_socket_client("unix://$socket", $code, $error, 5);
    if (!$s) throw new RuntimeException("connect: $error");
    stream_set_timeout($s, 30);
    $hooks = [];
    send($s, ['boot', ['get' => [], 'post' => [], 'server' => []]]);
    $ready = reply($s, $hooks);
    $readyNs = hrtime(true) - $t0;
    if ($ready[0] !== 'ready' || !isset($hooks['securecore_bench_hook'], $hooks['securecore_bench_calls'])) {
        throw new RuntimeException('did not boot: ' . json_encode($ready));
    }
    $t = hrtime(true);
    for ($i = 0; $i < $calls; $i++) {
        send($s, ['call', $hooks['securecore_bench_hook'], [$i]]);
        $r = reply($s, $hooks);
        if ($r[0] !== 'return' || $r[1] !== $i) throw new RuntimeException('bad hook reply: ' . json_encode($r));
    }
    $hookUs = (hrtime(true) - $t) / $calls / 1000;
    send($s, ['call', $hooks['securecore_bench_calls'], [null, $calls]]);
    $r = reply($s, $hooks);
    if ($r[0] !== 'return' || !is_float($r[1])) throw new RuntimeException('bad calls reply: ' . json_encode($r));
    send($s, ['end']);
    fclose($s);
    return ['connect_to_ready_ms' => $readyNs / 1e6, 'hook_call_us' => $hookUs, 'forwarded_call_us' => $r[1]];
}

function stats(array $rows): array
{
    $out = [];
    foreach (array_keys($rows[0]) as $key) {
        $values = array_column($rows, $key);
        sort($values);
        $n = count($values);
        $out[$key] = ['p50' => round($values[intdiv($n - 1, 2)], 2), 'p95' => round($values[(int) ceil(0.95 * $n) - 1], 2)];
    }
    return $out;
}

$process = null;
try {
    $started = hrtime(true);
    $process = proc_open([$binary, 'serve', '--socket', $socket, $plugin, 'securecore-bench.php'], [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['pipe', 'w']], $pipes, null, []);
    if (!is_resource($process)) throw new RuntimeException('could not start the tab');
    $pid = proc_get_status($process)['pid'];
    $first = null;
    for ($i = 0; $i < 200 && $first === null; $i++) {
        try { $first = request($socket, 1); } catch (RuntimeException $e) { usleep(25000); }
    }
    if ($first === null) throw new RuntimeException('tab never served: ' . stream_get_contents($pipes[2]));
    $startMs = (hrtime(true) - $started) / 1e6;
    for ($i = 0; $i < 5; $i++) request($socket, $calls); // warm-up
    $rows = [];
    for ($i = 0; $i < $requests; $i++) $rows[] = request($socket, $calls);
    echo json_encode([
        'requests' => $requests, 'calls' => $calls,
        'tab_start_to_first_request_ms' => round($startMs, 1),
        'per_request' => stats($rows),
        'tab_rss_mb' => round(vm($pid, 'VmRSS'), 1),
        'tab_peak_rss_mb' => round(vm($pid, 'VmHWM'), 1),
    ], JSON_PRETTY_PRINT), "\n";
} catch (Throwable $error) {
    fwrite(STDERR, 'breakdown failed: ' . $error->getMessage() . "\n");
    exit(1);
} finally {
    if (is_resource($process)) {
        proc_terminate($process);
        proc_close($process);
    }
    @unlink($socket);
}
