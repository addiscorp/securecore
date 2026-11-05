<?php
// Measurement 1: where one sandbox's time goes, without WordPress or a web server.
// Plays core's side of the protocol (sandbox/setup.php) against the real binary.
//
//   php bench/breakdown.php [runs] [calls]      inside the php container (see bench/run.sh)
//
// Per run: start the binary, boot setup.php + the bench plugin, then time `calls` hook
// callbacks (core → sandbox) and `calls` forwarded function calls (sandbox → core).
// Prints JSON with median and p95 per step. Exits non-zero on any failure.
$runs = (int) ($argv[1] ?? 20);
$calls = (int) ($argv[2] ?? 1000);
$binary = '/usr/local/bin/securecore';
$plugin = '/var/www/html/wp-content/plugins/securecore-bench';
$functionsFile = '/var/www/html/wp-content/securecore-bench-functions.json';
$full = json_decode((string) @file_get_contents($functionsFile), true);
if (!is_array($full) || count($full) < 1000) {
    fwrite(STDERR, "missing $functionsFile (bench/run.sh writes it with wp-cli)\n");
    exit(1);
}
$full[] = 'securecore_bench_noop';

function send($in, array $message): void
{
    fwrite($in, base64_encode(serialize($message)) . "\n");
}

/** Read until the sandbox answers; serve its hook registrations and calls meanwhile. */
function reply($in, $out, array &$hooks, ?array &$timing): array
{
    while (($line = fgets($out)) !== false) {
        if ($line[0] === '#') {
            $event = json_decode(substr($line, 1), true);
            if (($event['event'] ?? '') === 'timing') $timing = $event;
            continue;
        }
        $message = unserialize(base64_decode(trim($line)), ['allowed_classes' => false]);
        switch ($message[0]) {
            case 'hook': $hooks[$message[2]] = $message[3]; send($in, ['return', true]); break;
            case 'wp': send($in, ['return', null]); break;
            case 'log': fwrite(STDERR, "sandbox log: {$message[1]}\n"); break;
            default: return $message;
        }
    }
    throw new RuntimeException('sandbox exited');
}

function rss(int $pid): array
{
    $status = (string) @file_get_contents("/proc/$pid/status");
    preg_match('/VmRSS:\s+(\d+)/', $status, $rss);
    preg_match('/VmHWM:\s+(\d+)/', $status, $hwm);
    return [(int) ($rss[1] ?? 0) / 1024, (int) ($hwm[1] ?? 0) / 1024];
}

function one(string $binary, string $plugin, array $functions, int $calls): array
{
    $spawn = microtime(true) * 1000;
    $process = proc_open([$binary, '--timings', $plugin, 'securecore-bench.php'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, []);
    if (!is_resource($process)) throw new RuntimeException('proc_open failed');
    [$in, $out, $err] = $pipes;
    stream_set_timeout($out, 30);
    $hooks = [];
    $timing = null;
    send($in, ['boot', ['functions' => $functions, 'get' => [], 'post' => [], 'server' => []]]);
    $ready = reply($in, $out, $hooks, $timing);
    $readyAt = microtime(true) * 1000;
    if ($ready[0] !== 'ready' || $timing === null || !isset($hooks['securecore_bench_hook'], $hooks['securecore_bench_calls'])) {
        throw new RuntimeException('sandbox did not boot: ' . json_encode($ready) . ' ' . stream_get_contents($err));
    }

    $t = hrtime(true);
    for ($i = 0; $i < $calls; $i++) {
        send($in, ['call', $hooks['securecore_bench_hook'], [$i]]);
        $r = reply($in, $out, $hooks, $timing);
        if ($r[0] !== 'return' || $r[1] !== $i) throw new RuntimeException('bad hook reply: ' . json_encode($r));
    }
    $hookUs = (hrtime(true) - $t) / $calls / 1000;

    $t = hrtime(true);
    send($in, ['call', $hooks['securecore_bench_calls'], [null, $calls]]);
    $r = reply($in, $out, $hooks, $timing);
    $forwardOuterUs = (hrtime(true) - $t) / $calls / 1000;
    if ($r[0] !== 'return' || !is_float($r[1])) throw new RuntimeException('bad calls reply: ' . json_encode($r));

    [$rssMb, $peakMb] = rss(proc_get_status($process)['pid']);
    send($in, ['end']);
    fclose($in);
    fclose($out);
    fclose($err);
    $code = proc_close($process);
    if ($code !== 0) throw new RuntimeException("sandbox exit code $code");

    return [
        'process_start_ms' => $timing['main'] - $spawn,
        'bun_load_ms' => $timing['load_ms'] - ($timing['main'] - $timing['origin']),
        'read_wasm_ms' => $timing['read_ms'],
        'compile_ms' => $timing['compile_ms'],
        'instantiate_ms' => $timing['instantiate_ms'],
        'php_boot_ms' => $readyAt - $timing['start'],
        'total_to_ready_ms' => $readyAt - $spawn,
        'hook_call_us' => $hookUs,
        'forwarded_call_us' => $r[1],
        'forwarded_call_outer_us' => $forwardOuterUs,
        'rss_mb' => $rssMb,
        'peak_rss_mb' => $peakMb,
    ];
}

function stats(array $rows): array
{
    $out = [];
    foreach (array_keys($rows[0]) as $key) {
        $values = array_column($rows, $key);
        sort($values);
        $n = count($values);
        $out[$key] = [
            'p50' => round($values[intdiv($n - 1, 2)], 2),
            'p95' => round($values[(int) ceil(0.95 * $n) - 1], 2),
            'min' => round($values[0], 2),
        ];
    }
    return $out;
}

try {
    one($binary, $plugin, $full, 10); // warm the page cache for the binary
    $result = ['runs' => $runs, 'calls' => $calls, 'functions' => count($full)];
    foreach (['all_core_functions' => $full, 'one_function' => ['securecore_bench_noop']] as $name => $functions) {
        $rows = [];
        for ($i = 0; $i < $runs; $i++) $rows[] = one($binary, $plugin, $functions, $calls);
        $result[$name] = stats($rows);
    }
    echo json_encode($result, JSON_PRETTY_PRINT), "\n";
} catch (Throwable $error) {
    fwrite(STDERR, 'breakdown failed: ' . $error->getMessage() . "\n");
    exit(1);
}
