<?php
// Test fixture for test/ext-layer1.sh: one php-fpm request tries each thing layer 1 decides and
// prints "<case>=OK" (it worked) or "<case>=BLOCKED <why>". It sits at the web root, so it is
// core: layer 2 never restricts it, and whatever is refused here is layer 1's (the kernel's)
// doing. The listeners it talks to are test/ext/layer1/listen.php, outside the sandbox.
// Copied into the test stack only; never shipped.
header('Content-Type: text/plain');
error_reporting(0);

$root = __DIR__;
function report(string $case, bool $ok, string $why = ''): void {
    echo $case, '=', $ok ? 'OK' : 'BLOCKED' . ($why === '' ? '' : " $why"), "\n";
}
function last_error(): string {
    $e = error_get_last();
    error_clear_last();
    return $e ? preg_replace('/\s+/', ' ', $e['message']) : '';
}
function connect(string $case, string $url): void {
    $s = stream_socket_client($url, $errno, $errstr, 3);
    report($case, $s !== false, "errno=$errno $errstr");
    if ($s) {
        // Only to the test's own listeners, which log what arrives.
        if (!str_contains($url, 'api.wordpress.org')) {
            fwrite($s, "$case\n");
        }
        fclose($s);
    }
}
function write(string $case, string $path): void {
    $ok = file_put_contents($path, "layer1 $case\n") !== false;
    report($case, $ok, last_error());
}

// The database, over TCP 3306 (the name resolved over TCP 53).
$db = mysqli_init();
$ok = @$db->real_connect(getenv('WORDPRESS_DB_HOST'), getenv('WORDPRESS_DB_USER'), getenv('WORDPRESS_DB_PASSWORD'), getenv('WORDPRESS_DB_NAME'), 3306);
report('db-3306', $ok && $db->query('select 1') !== false, mysqli_connect_error() ?? '');
report('dns-tcp', gethostbyname('db') !== 'db', 'db did not resolve');

// TCP by port: 443 is allowed; 25 and nginx's 80 are not; nor is binding anything but 9000.
connect('tcp-443-local', 'tcp://127.0.0.1:443');
connect('tcp-443-internet', 'tcp://api.wordpress.org:443');
connect('tcp-25', 'tcp://127.0.0.1:25');
connect('tcp-80-web', 'tcp://web:80');
$srv = stream_socket_server('tcp://127.0.0.1:8081', $errno, $errstr);
report('bind-8081', $srv !== false, "errno=$errno $errstr");

// UDP and unix sockets: closed with port rules.
$u = stream_socket_client('udp://127.0.0.1:5353', $errno, $errstr, 3);
$sent = $u !== false && fwrite($u, "udp\n") === 4;
report('udp-5353', $sent, "errno=$errno $errstr");
connect('unix-socket', 'unix:///run/sc-l1/listen.sock');

// Files: writes only in the listed folders, even from core; the denied path is unreadable.
write('write-uploads', "$root/wp-content/uploads/sc-l1.txt");
write('write-tmp', '/tmp/sc-l1.txt');
write('write-root', "$root/sc-l1-core-write.txt");
write('write-plugins', "$root/wp-content/plugins/sc-l1-write.txt");
$got = file_get_contents('/srv/backups/dump.sql');
report('read-denied', $got !== false, last_error());
report('read-wp-config', file_get_contents("$root/wp-config.php") !== false, last_error());

// A program php-fpm starts inherits the sandbox.
$out = shell_exec("sh -c 'echo child > $root/sc-l1-child.txt && echo wrote' 2>&1");
report('child-write-root', trim((string) $out) === 'wrote', trim((string) $out));
