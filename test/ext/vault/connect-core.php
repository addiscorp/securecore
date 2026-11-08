<?php
// A core (web-root) connect probe for test/ext-vault.sh: core code connecting to a foreign host
// with the DB placeholder. The caller is core, so only the host gate applies — and a foreign host
// is not the configured DB host, so the real password must not be substituted. Proves the host
// gate independently of the caller gate. ?fp=<port>.
require_once __DIR__ . '/wp-load.php';
header('Content-Type: text/plain');
$fp = (int) ($_GET['fp'] ?? 0);
echo "probe=connect-core\n";
@mysqli_connect('127.0.0.1', 'u', 'securecore-vault:DB_PASSWORD', '', $fp);
// Core connecting to the real DB with the placeholder still works (the swap is allowed).
$r = @mysqli_connect(DB_HOST, DB_USER, 'securecore-vault:DB_PASSWORD', DB_NAME, 3306);
echo 'core_connects_real_db=', ($r instanceof mysqli ? 'CONNECTED' : 'failed'), "\n";
