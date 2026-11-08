<?php
// Test fixture for test/ext-layer1.sh: listeners for probe.php's connects, started with
// `docker compose exec -d php php -n …`, so they run outside php-fpm and its sandbox. Each
// connection or datagram is appended to the log as "<listener> <first line>", so the test can
// check what actually arrived, not only what the probe says. Never shipped.
//   php -n listen.php <log>
$log = $argv[1];
$servers = [
    'tcp-25' => stream_socket_server('tcp://127.0.0.1:25', $e, $s),
    'tcp-443' => stream_socket_server('tcp://127.0.0.1:443', $e, $s),
    'udp-5353' => stream_socket_server('udp://127.0.0.1:5353', $e, $s, STREAM_SERVER_BIND),
];
@mkdir('/run/sc-l1');
@unlink('/run/sc-l1/listen.sock');
$servers['unix'] = stream_socket_server('unix:///run/sc-l1/listen.sock', $e, $s);
chmod('/run/sc-l1/listen.sock', 0777);
foreach ($servers as $name => $srv) {
    if ($srv === false) {
        fwrite(STDERR, "listen.php: $name: $s\n");
        exit(1);
    }
}
file_put_contents($log, "ready\n", FILE_APPEND);
while (true) {
    $read = array_values($servers);
    $w = $x = null;
    if (stream_select($read, $w, $x, null) === false) {
        exit(1);
    }
    foreach ($read as $srv) {
        $name = array_search($srv, $servers, true);
        if ($name === 'udp-5353') {
            $line = trim(stream_socket_recvfrom($srv, 64));
        } else {
            $c = stream_socket_accept($srv, 1);
            $line = $c ? trim((string) fgets($c)) : '';
            if ($c) {
                fclose($c);
            }
        }
        file_put_contents($log, "$name $line\n", FILE_APPEND);
    }
}
