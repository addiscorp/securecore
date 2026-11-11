<?php
// Test fixture for test/ext-microvm.sh (addiscorp/securecore#71): where this PHP runs and what
// it may do, one key=value per line. At the web root, so it is core and layer 2 never restricts
// it; what it can't do is layer 1's (the microVM's) doing. Copied into the test site only.
header('Content-Type: text/plain');
$root = __DIR__;
echo 'kernel=', php_uname('r'), "\n";
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
