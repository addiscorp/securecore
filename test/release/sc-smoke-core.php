<?php
// Test fixture for test/release-check.sh (addiscorp/securecore#53, E8): a script at the web root,
// so it is core and layer 2 never restricts it. It reports whether this PHP process runs inside
// layer 1's sandbox and tries one write layer 1 refuses (wp-includes is not in layer1.write) and
// one it allows (uploads). With the plain SAPI both writes work; started by securecore-fpm only
// the uploads one may. Copied into the release check's site only; never shipped.
header('Content-Type: text/plain');
$status = (string) @file_get_contents('/proc/self/status');
preg_match('/^NoNewPrivs:\s*(\d+)/m', $status, $nnp);
preg_match('/^Seccomp:\s*(\d+)/m', $status, $sec);
echo 'nonewprivs=', $nnp[1] ?? '?', "\n";
echo 'seccomp=', $sec[1] ?? '?', "\n";
$try = static function (string $case, string $path): void {
    @unlink($path);
    $ok = @file_put_contents($path, "layer1 smoke\n") !== false;
    @unlink($path);
    echo $case, '=', $ok ? 'OK' : 'BLOCKED', "\n";
};
$try('write-wp-includes', __DIR__ . '/wp-includes/sc-smoke-l1.txt');
$try('write-uploads', __DIR__ . '/wp-content/uploads/sc-smoke-l1.txt');
