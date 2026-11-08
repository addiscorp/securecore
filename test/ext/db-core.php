<?php
// E4 canary, core side (test/ext-db.sh): copied to the site root, so the code running is core's.
// Core is unrestricted except for the statement allowlist, which applies to everyone; an
// unparseable query from core runs and is logged.
require __DIR__ . '/wp-load.php';
header('Content-Type: text/plain');
global $wpdb;
$wpdb->suppress_errors(true);
$cases = [
    'user-pass'   => "SELECT user_pass FROM {$wpdb->users} LIMIT 1",
    'siteurl'     => "UPDATE {$wpdb->options} SET option_value = option_value WHERE option_name = 'siteurl'",
    'prepare'     => "PREPARE sc_core FROM 'SELECT 1'",
    'set-var'     => "SET @sc_core = 1",
    'unparseable' => "SELECT 1 FROM DUAL WHERE 1 = 1 PROCEDURE ANALYSE()",
];
foreach ($cases as $case => $sql) {
    $r = $wpdb->query($sql);
    echo "core|$case=", ($r === false && str_contains($wpdb->last_error, 'securecore')) ? 'BLOCKED' : 'RAN:' . mysqli_errno($wpdb->dbh), "\n";
}
echo "DONE\n";
