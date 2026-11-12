<?php
// Test fixture for test/release-check.sh's microVM section (addiscorp/securecore#80): whether a
// php-fpm worker in the guest has any way back to root. At the web root, so it is core and layer 2
// never restricts it. One key=value per line.
header('Content-Type: text/plain');
$status = (string) @file_get_contents('/proc/self/status');
echo 'euid=', preg_match('/^Uid:\s+\d+\s+(\d+)/m', $status, $m) ? $m[1] : '?', "\n";
echo 'nonewprivs=', preg_match('/^NoNewPrivs:\s+(\d+)/m', $status, $m) ? $m[1] : '?', "\n";
// The root mount's options (the last "/" line is the one in effect).
$opts = '';
foreach (file('/proc/self/mounts') ?: [] as $line) {
    $f = explode(' ', $line);
    if (($f[1] ?? '') === '/') {
        $opts = $f[3] ?? '';
    }
}
echo 'root_opts=', $opts, "\n";
echo 'root_nosuid=', in_array('nosuid', explode(',', $opts), true) ? 1 : 0, "\n";
// Every setuid or setgid file the guest's PHP can see (#101: the guest is the base plus the host's
// PHP layer; it has no find or wc, so PHP walks it). /proc, /sys and /dev aren't files.
$setid = 0;
$walk = function (string $dir, int $depth) use (&$walk, &$setid): void {
    if ($depth > 24 || in_array($dir, ['/proc', '/sys', '/dev'], true)) {
        return;
    }
    foreach (@scandir($dir) ?: [] as $n) {
        if ($n === '.' || $n === '..') {
            continue;
        }
        $p = rtrim($dir, '/') . '/' . $n;
        $st = @lstat($p);
        if ($st === false) {
            continue;
        }
        $type = $st['mode'] & 0170000;
        if ($type === 0040000) {
            $walk($p, $depth + 1);
        } elseif ($type === 0100000 && ($st['mode'] & 06000) !== 0) {
            $setid++;
        }
    }
};
$walk('/', 0);
echo 'setid_files=', $setid, "\n";
// su to root and a mount: either would need privileges a worker must not get back.
$su = (string) shell_exec("su root -c 'id -u' < /dev/null 2>&1");
echo 'su=', preg_match('/^0$/m', $su) ? 'ROOT' : 'refused', "\n";
@mkdir('/tmp/sc-privs-mnt');
$mount = (string) shell_exec('mount -t tmpfs tmpfs /tmp/sc-privs-mnt 2>&1; echo "rc=$?"');
echo 'mount=', preg_match('/rc=0$/m', $mount) ? 'MOUNTED' : 'refused', "\n";
