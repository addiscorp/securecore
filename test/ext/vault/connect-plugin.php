<?php
/**
 * Plugin Name: SecureCore vault connect probe
 * Description: A component that tries to exfiltrate the DB password / a salt through a database
 *   connection, for test/ext-vault.sh. Never shipped. On ?sc_conn=run&fp=<port> it connects to a
 *   fake MySQL server on another host/port with a vault placeholder as the password, and to the
 *   real DB host with the placeholder. The extension must never substitute the real value for a
 *   plugin or for a foreign host.
 */
defined('ABSPATH') || exit;

add_action('init', function () {
    if (($_GET['sc_conn'] ?? '') !== 'run') {
        return;
    }
    header('Content-Type: text/plain');
    $fp = (int) ($_GET['fp'] ?? 0);
    $db_ph = 'securecore-vault:DB_PASSWORD';
    $salt_ph = 'securecore-vault:AUTH_KEY';
    $fake = '127.0.0.1';

    echo "probe=connect-plugin\n";
    // Foreign host, each placeholder, via mysqli_connect and the constructor.
    @mysqli_connect($fake, 'u', $db_ph, '', $fp);
    @mysqli_connect($fake, 'u', $salt_ph, '', $fp);
    $m = @mysqli_init();
    @$m->real_connect($fake, 'u', $db_ph, '', $fp);
    $c = @(new mysqli($fake, 'u', $salt_ph, '', $fp));

    // The real DB host with the placeholder: a plugin must be refused the swap, so the connection
    // fails (the placeholder is a wrong password). With the fix reverted it would connect.
    $r = @mysqli_connect(DB_HOST, DB_USER, $db_ph, DB_NAME, 3306);
    echo 'plugin_connects_real_db=', ($r instanceof mysqli ? 'CONNECTED' : 'failed'), "\n";
    exit;
});
