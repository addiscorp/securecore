<?php
/**
 * Plugin Name: SecureCore gelada Probe
 * Description: Test probe for the gelada-sandboxed worker (addiscorp/securecore#42, part 3). Run
 *   sandboxed, it tries to read wp-config.php, connect out (MySQL, php-fpm, an arbitrary host),
 *   and write inside and outside the folders gelada allows, and reports each to the worker log as
 *   GELADA_PROBE:<key>=<value>. test/gelada.sh reads those with gelada on and off. Not for
 *   production. It uses functions the launcher's disable_functions does NOT block (mysqli_connect,
 *   file_get_contents, file_put_contents), so what blocks them is gelada, not the inner layer.
 */
defined('ABSPATH') || exit;
if (!defined('SECURECORE_SANDBOX') || !SECURECORE_SANDBOX) return;

(function () {
    $log = static fn (string $k, string $v) => fwrite(STDERR, "GELADA_PROBE:$k=$v\n");

    // --- read wp-config.php (and so the DB password) ------------------------------------------
    $config = @file_get_contents(ABSPATH . 'wp-config.php');
    $log('read_wp_config', $config === false ? 'failed' : ('read ' . strlen($config) . ' bytes'));
    // The password is only in the child's memory if it could read the file; the constant is never
    // defined here (the sandbox boots wp-settings.php, never wp-config.php).
    $log('db_password_const', defined('DB_PASSWORD') ? 'DEFINED' : 'undefined');

    // --- connect out: MySQL, php-fpm, an arbitrary host (TCP) ---------------------------------
    // mysqli throws by default since PHP 8.1 (and @ does not suppress exceptions); turn that off
    // and bound the connect timeout so a blocked host cannot hang the request.
    if (function_exists('mysqli_report')) mysqli_report(MYSQLI_REPORT_OFF);
    $try = static function (string $host, int $port): string {
        $errno = 0;
        try {
            $m = mysqli_init();
            @mysqli_options($m, MYSQLI_OPT_CONNECT_TIMEOUT, 2);
            $ok = @mysqli_real_connect($m, $host, 'probe', 'probe', '', $port);
            if ($ok) { @mysqli_close($m); return 'reached'; }       // TCP up, auth/db failed later
            $errno = mysqli_connect_errno();
        } catch (\Throwable $e) {
            $errno = (int) $e->getCode();
        }
        // 2002/2003/2004 = could not open the connection at all (gelada blocked the socket).
        return in_array($errno, [2002, 2003, 2004], true) ? "blocked($errno)" : "reached($errno)";
    };
    $log('connect_mysql', $try('db', 3306));
    $log('connect_php_fpm', $try('php', 9000));
    $log('connect_arbitrary', $try('example.com', 80));

    // --- writes: one allowed folder, three that must be read-only -----------------------------
    $w = static function (string $path): string {
        $ok = @file_put_contents($path, 'gelada-probe');
        if ($ok !== false) { @unlink($path); return 'ok'; }
        return 'failed';
    };
    $log('write_uploads', $w(WP_CONTENT_DIR . '/uploads/securecore-gelada-probe.txt'));
    $log('write_plugins', $w(WP_PLUGIN_DIR . '/securecore-gelada/securecore-gelada-probe.txt'));
    $log('write_wp_includes', $w(ABSPATH . 'wp-includes/securecore-gelada-probe.txt'));
    $log('write_mu_plugins', $w(WP_CONTENT_DIR . '/mu-plugins/securecore-gelada-probe.txt'));

    $log('done', '1');
})();
