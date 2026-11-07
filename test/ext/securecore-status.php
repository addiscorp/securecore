<?php
// Test fixture for test/ext-config.sh: what the extension in THIS php-fpm worker is enforcing,
// one key=value per line. Copied into the test stack's web root only; never shipped.
header('Content-Type: text/plain');
if (!function_exists('securecore_status')) {
    echo "loaded=0\n";
    return;
}
$s = securecore_status();
echo "loaded=1\n";
echo 'pid=', getmypid(), "\n";
foreach (['config', 'sha256', 'layer2_mode', 'layer2_app', 'reload_error'] as $k) {
    echo $k, '=', $s[$k] ?? '', "\n";
}
foreach (['off', 'restart_needed'] as $k) {
    echo $k, '=', $s[$k] ? 1 : 0, "\n";
}
echo 'reloads=', $s['reloads'], "\n";
foreach ($s['layers'] as $k => $v) {
    echo $k, '=', $v ? 1 : 0, "\n";
}
