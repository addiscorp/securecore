<?php
/**
 * Plugin Name: SecureCore hosts probe
 * Description: E5 integration probe (addiscorp/securecore#53). On ?sc_hosts=run it tries one
 *   outbound connection per network route, to an allowed and to a disallowed host, and prints
 *   "<case>=OK" when the connection was reached or "<case>=BLOCKED" when it was refused (false /
 *   empty / WP_Error), or "<case>=SKIP" when the route's extension is not built. Attributed to
 *   plugin:securecore-hosts-probe. The core cases live in the mu-plugin securecore-loader.php so
 *   they run with no component on the stack.
 *
 * The test drives it as ?sc_hosts=run&ip=<helper-ip>. Every "disallowed" target is a real,
 *   reachable server (the same helper under another name or its IP), just not in the allowlist,
 *   so in log/off mode every case reaches it and prints OK — the revert proof.
 */

if (!defined('ABSPATH')) {
    exit;
}

add_action('init', function () {
    if (($_GET['sc_hosts'] ?? '') !== 'run') {
        return;
    }
    $ip = preg_replace('/[^0-9a-fA-F:.]/', '', (string) ($_GET['ip'] ?? ''));

    // Short timeouts so a reachable call returns fast and a refused one returns at once.
    $ctx = stream_context_create(['http' => ['timeout' => 2], 'ftp' => ['timeout' => 2]]);
    $reached = static function ($body) {
        return is_string($body) && $body !== '' ? 'OK' : 'BLOCKED';
    };

    $cases = [];

    // --- http(s)/ftp stream wrappers -----------------------------------------------------
    $cases['stream-allowed'] = static function () use ($ctx, $reached) {
        return $reached(@file_get_contents('http://allowed.test/', false, $ctx));
    };
    $cases['stream-disallowed'] = static function () use ($ctx, $reached) {
        return $reached(@file_get_contents('http://disallowed.test/', false, $ctx));
    };
    $cases['wildcard-allowed'] = static function () use ($ctx, $reached) {
        return $reached(@file_get_contents('http://a.wild.test/', false, $ctx));
    };
    $cases['fopen-disallowed'] = static function () use ($ctx) {
        $h = @fopen('http://disallowed.test/', 'r', false, $ctx);
        if ($h === false) {
            return 'BLOCKED';
        }
        fclose($h);
        return 'OK';
    };
    $cases['get_headers-disallowed'] = static function () use ($ctx) {
        $h = @get_headers('http://disallowed.test/', false, $ctx);
        return is_array($h) && $h !== [] ? 'OK' : 'BLOCKED';
    };

    // The host a URL actually goes to, not what it claims: a user:pass@ prefix does not count.
    $cases['userinfo-evil'] = static function () use ($ctx, $reached) {
        return $reached(@file_get_contents('http://allowed.test@disallowed.test/', false, $ctx));
    };
    // An IP literal is allowed only when listed; this one (the reachable helper) is not.
    $cases['ip-literal'] = static function () use ($ctx, $reached, $ip) {
        return $ip === '' ? 'SKIP' : $reached(@file_get_contents("http://$ip/", false, $ctx));
    };
    // A redirect from an allowed host to a disallowed one is refused at the hop (the http wrapper
    // re-enters our opener for the Location URL).
    $cases['stream-redirect'] = static function () use ($ctx, $reached) {
        return $reached(@file_get_contents('http://redirector.test/', false, $ctx));
    };

    // --- fsockopen / stream_socket_client ------------------------------------------------
    $sock = static function ($fn, $host) {
        $errno = 0;
        $errstr = '';
        $f = @$fn($host, 80, $errno, $errstr, 2);
        if ($f === false) {
            return 'BLOCKED';
        }
        fclose($f);
        return 'OK';
    };
    $cases['fsockopen-allowed'] = static function () use ($sock) {
        return $sock('fsockopen', 'allowed.test');
    };
    $cases['fsockopen-disallowed'] = static function () use ($sock) {
        return $sock('fsockopen', 'disallowed.test');
    };
    $cases['pfsockopen-disallowed'] = static function () use ($sock) {
        return $sock('pfsockopen', 'disallowed.test');
    };
    $ssc = static function ($remote) {
        $errno = 0;
        $errstr = '';
        $f = @stream_socket_client($remote, $errno, $errstr, 2);
        if ($f === false) {
            return 'BLOCKED';
        }
        fclose($f);
        return 'OK';
    };
    $cases['ssc-allowed'] = static function () use ($ssc) {
        return $ssc('tcp://allowed.test:80');
    };
    $cases['ssc-disallowed'] = static function () use ($ssc) {
        return $ssc('tcp://disallowed.test:80');
    };

    // --- ext/sockets ---------------------------------------------------------------------
    $cases['socket-connect-disallowed'] = static function () use ($ip) {
        if (!function_exists('socket_create') || $ip === '') {
            return 'SKIP';
        }
        $s = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if ($s === false) {
            return 'SKIP';
        }
        @socket_set_option($s, SOL_SOCKET, SO_SNDTIMEO, ['sec' => 2, 'usec' => 0]);
        $ok = @socket_connect($s, $ip, 80);
        @socket_close($s);
        return $ok ? 'OK' : 'BLOCKED';
    };

    // --- curl ----------------------------------------------------------------------------
    $curl = static function (callable $setup) {
        if (!function_exists('curl_init')) {
            return 'SKIP';
        }
        $h = curl_init();
        curl_setopt($h, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($h, CURLOPT_TIMEOUT, 3);
        curl_setopt($h, CURLOPT_CONNECTTIMEOUT, 3);
        $setup($h);
        $r = curl_exec($h);
        curl_close($h);
        return is_string($r) && $r !== '' ? 'OK' : 'BLOCKED';
    };
    $cases['curl-allowed'] = static function () use ($curl) {
        return $curl(static function ($h) {
            curl_setopt($h, CURLOPT_URL, 'http://allowed.test/');
        });
    };
    $cases['curl-disallowed'] = static function () use ($curl) {
        return $curl(static function ($h) {
            curl_setopt($h, CURLOPT_URL, 'http://disallowed.test/');
        });
    };
    // CURLOPT_RESOLVE pointing an allowed name at a disallowed IP (the reachable helper's IP).
    $cases['curl-resolve-evil'] = static function () use ($curl, $ip) {
        if ($ip === '') {
            return 'SKIP';
        }
        return $curl(static function ($h) use ($ip) {
            curl_setopt($h, CURLOPT_URL, 'http://allowed-resolve.test/');
            curl_setopt($h, CURLOPT_RESOLVE, ["allowed-resolve.test:80:$ip"]);
        });
    };
    // CURLOPT_CONNECT_TO pointing an allowed name at a disallowed host.
    $cases['curl-connectto-evil'] = static function () use ($curl) {
        return $curl(static function ($h) {
            curl_setopt($h, CURLOPT_URL, 'http://allowed-connect.test/');
            curl_setopt($h, CURLOPT_CONNECT_TO, ['allowed-connect.test:80:disallowed.test:80']);
        });
    };
    // curl_setopt_array path.
    $cases['curl-array-disallowed'] = static function () use ($curl) {
        return $curl(static function ($h) {
            curl_setopt_array($h, [CURLOPT_URL => 'http://disallowed.test/']);
        });
    };
    // curl_multi.
    $cases['curlmulti-disallowed'] = static function () {
        if (!function_exists('curl_multi_init')) {
            return 'SKIP';
        }
        $h = curl_init('http://disallowed.test/');
        curl_setopt($h, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($h, CURLOPT_TIMEOUT, 3);
        $m = curl_multi_init();
        $added = curl_multi_add_handle($m, $h);
        if ($added !== 0) {
            curl_multi_remove_handle($m, $h);
            curl_multi_close($m);
            curl_close($h);
            return 'BLOCKED';
        }
        do {
            $status = curl_multi_exec($m, $active);
        } while ($active && $status === CURLM_OK);
        $body = curl_multi_getcontent($h);
        curl_multi_remove_handle($m, $h);
        curl_multi_close($m);
        curl_close($h);
        return is_string($body) && $body !== '' ? 'OK' : 'BLOCKED';
    };
    // curl following a redirect: an allowed host 302s to a disallowed one. The extension follows
    // in-process (FOLLOWLOCATION off, re-exec per hop) and checks each hop, so this is refused at
    // the hop in enforce, logged+followed in log, allowed with the layer off.
    $cases['curl-redirect'] = static function () use ($curl) {
        return $curl(static function ($h) {
            curl_setopt($h, CURLOPT_URL, 'http://redirector.test/');
            curl_setopt($h, CURLOPT_FOLLOWLOCATION, true);
        });
    };
    // curl reading a local file bypasses E2b's file policy — refused by the scheme restriction.
    $cases['curl-file'] = static function () use ($curl) {
        return $curl(static function ($h) {
            curl_setopt($h, CURLOPT_URL, 'file:///var/www/html/wp-config.php');
        });
    };
    // a non-web scheme (gopher) to an allowed host — refused by the scheme restriction.
    $cases['curl-gopher'] = static function () use ($curl) {
        return $curl(static function ($h) {
            curl_setopt($h, CURLOPT_URL, 'gopher://allowed.test/');
        });
    };
    // curl_copy_handle carries the recorded options to the copy: a copy of a handle aimed at a
    // disallowed host is still refused (and an allowed one still allowed).
    $cases['curl-copy-disallowed'] = static function () {
        if (!function_exists('curl_copy_handle')) {
            return 'SKIP';
        }
        $a = curl_init();
        curl_setopt($a, CURLOPT_URL, 'http://disallowed.test/');
        curl_setopt($a, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($a, CURLOPT_TIMEOUT, 3);
        $b = curl_copy_handle($a);
        $r = curl_exec($b);
        curl_close($b);
        curl_close($a);
        return is_string($r) && $r !== '' ? 'OK' : 'BLOCKED';
    };
    $cases['curl-copy-allowed'] = static function () {
        if (!function_exists('curl_copy_handle')) {
            return 'SKIP';
        }
        $a = curl_init();
        curl_setopt($a, CURLOPT_URL, 'http://allowed.test/');
        curl_setopt($a, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($a, CURLOPT_TIMEOUT, 3);
        $b = curl_copy_handle($a);
        $r = curl_exec($b);
        curl_close($b);
        curl_close($a);
        return is_string($r) && $r !== '' ? 'OK' : 'BLOCKED';
    };
    // a handle whose URL the extension never saw being set fails closed at exec for a component.
    $cases['curl-nostate'] = static function () {
        if (!function_exists('curl_init')) {
            return 'SKIP';
        }
        $h = curl_init();
        curl_setopt($h, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($h, CURLOPT_TIMEOUT, 3);
        $r = @curl_exec($h);
        curl_close($h);
        return is_string($r) && $r !== '' ? 'OK' : 'BLOCKED';
    };

    // --- SoapClient (uses the http wrapper) ----------------------------------------------
    $cases['soap-disallowed'] = static function () {
        if (!class_exists('SoapClient')) {
            return 'SKIP';
        }
        try {
            new SoapClient('http://disallowed.test/service?wsdl', ['exceptions' => true, 'connection_timeout' => 2, 'cache_wsdl' => WSDL_CACHE_NONE]);
            return 'OK';
        } catch (\Throwable $e) {
            return 'BLOCKED';
        }
    };

    // --- the database host (#53 review, finding 5) ---------------------------------------
    // The plugin's own connection to the DB host is the plugin's: refused, as "db" is not in its
    // hosts (OK in log/off: the server is real).
    $cases['own-mysqli-dbhost'] = static function () {
        mysqli_report(MYSQLI_REPORT_OFF);
        $m = @mysqli_connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
        return $m instanceof mysqli ? 'OK' : 'BLOCKED';
    };
    // A wpdb reconnect on the plugin's call is core's connection to its own DB host: it must
    // work in every mode, or enforce mode takes the site down. Last, so a refused reconnect
    // can't break the cases above.
    $cases['wpdb-reconnect'] = static function () {
        global $wpdb;
        $wpdb->close();
        $ok = $wpdb->check_connection(false);
        return $ok && $wpdb->get_var('SELECT 1') === '1' ? 'OK' : 'BLOCKED';
    };

    foreach ($cases as $name => $fn) {
        echo "$name=" . $fn() . "\n";
    }
}, 10);
