<?php
// Test fixture for test/ext-microvm.sh (addiscorp/securecore#71): where this PHP runs and what
// it may do, one key=value per line. At the web root, so it is core and layer 2 never restricts
// it; what it can't do is layer 1's (the microVM's) doing. Copied into the test site only.
header('Content-Type: text/plain');
$root = __DIR__;
// A slow request (?sleep=N): keeps a php-fpm worker busy, so a graceful reload has to wait. A busy
// loop, not sleep(): php-fpm's stop signal would cut a sleep() short.
if (isset($_GET['sleep'])) {
    $until = microtime(true) + min(60, (int) $_GET['sleep']);
    while (microtime(true) < $until) {
        usleep(0);
    }
}
echo 'kernel=', php_uname('r'), "\n";
// The worker's effective uid, from the kernel (no posix extension needed).
echo 'euid=', preg_match('/^Uid:\s+\d+\s+(\d+)/m', (string) @file_get_contents('/proc/self/status'), $u) ? $u[1] : '?', "\n";
echo 'time=', time(), "\n";
$cmdline = (string) @file_get_contents('/proc/cmdline');
echo 'guest_init=', strpos($cmdline, 'init=/sbin/securecore-init') !== false ? 1 : 0, "\n";
// Network devices: the guest has loopback only.
echo 'netdev=', implode(',', array_map('basename', glob('/sys/class/net/*') ?: [])), "\n";
$upload = "$root/wp-content/uploads/sc-mvm.txt";
if (isset($_GET['write'])) {
    echo 'write_uploads=', @file_put_contents($upload, $_GET['write']) !== false ? 'OK' : 'BLOCKED', "\n";
}
echo 'read_uploads=', is_file($upload) ? trim((string) file_get_contents($upload)) : '', "\n";
echo 'write_root=', @file_put_contents("$root/sc-mvm-root.txt", 'x') !== false ? 'OK' : 'BLOCKED', "\n";
echo 'write_plugins=', @file_put_contents("$root/wp-content/plugins/sc-mvm.txt", 'x') !== false ? 'OK' : 'BLOCKED', "\n";
echo 'write_tmp=', @file_put_contents('/tmp/sc-mvm.txt', 'x') !== false ? 'OK' : 'BLOCKED', "\n";
// Who the host sees on the guest's connections: a forwarded port (4444) whose host socket answers
// with its peer's SO_PEERCRED (test/ext/microvm/peercred.py).
if (isset($_GET['peer'])) {
    $f = @stream_socket_client('tcp://127.0.0.1:4444', $en, $es, 3);
    echo 'peer=', $f ? trim((string) fgets($f)) : "FAILED $en $es", "\n";
}
// The folder sync (#72): changes to uploads, as WordPress makes them. Paths are relative to
// uploads; the test checks the host's copy.
$up = "$root/wp-content/uploads";
if (isset($_GET['put'])) {
    // ?put=<rel>&size=<bytes>[&seed=<s>]: a file of pseudo-random bytes; its sha256 is printed.
    $size = (int) ($_GET['size'] ?? 0);
    $block = hash('sha512', (string) ($_GET['seed'] ?? 'x'), true);
    $block = str_repeat($block, 1024);
    $path = "$up/" . $_GET['put'];
    @mkdir(dirname($path), 0755, true);
    $t = microtime(true);
    $f = fopen($path, 'wb');
    $ctx = hash_init('sha256');
    for ($left = $size; $left > 0; $left -= strlen($chunk)) {
        $chunk = substr($block, 0, min($left, strlen($block)));
        fwrite($f, $chunk);
        hash_update($ctx, $chunk);
    }
    fclose($f);
    echo 'put_sha=', hash_final($ctx), "\n";
    echo 'put_ms=', round((microtime(true) - $t) * 1000, 1), "\n";
}
if (isset($_GET['mv'])) {
    @mkdir(dirname("$up/" . $_GET['to']), 0755, true);
    echo 'mv=', rename("$up/" . $_GET['mv'], "$up/" . $_GET['to']) ? 'OK' : 'FAILED', "\n";
}
if (isset($_GET['rm'])) {
    // A file, or a folder with everything in it.
    $rm = function ($p) use (&$rm) {
        if (is_dir($p) && !is_link($p)) {
            foreach (scandir($p) as $n) {
                if ($n !== '.' && $n !== '..') {
                    $rm("$p/$n");
                }
            }
            return rmdir($p);
        }
        return unlink($p);
    };
    echo 'rm=', $rm("$up/" . $_GET['rm']) ? 'OK' : 'FAILED', "\n";
}
if (isset($_GET['chmod'])) {
    echo 'chmod=', chmod("$up/" . $_GET['chmod'], octdec($_GET['mode'])) ? 'OK' : 'FAILED', "\n";
}
// Fresh randomness: the kernel's (random_bytes) and a worker's userland generator (mt_rand).
echo 'random=', bin2hex(random_bytes(16)), "\n";
echo 'mt_rand=', mt_rand(), "\n";
