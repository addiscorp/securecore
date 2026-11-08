<?php
/**
 * Plugin Name: SecureCore release smoke probe
 * Description: Test fixture for test/release-check.sh (addiscorp/securecore#53, E8). A mu-plugin,
 *   so it is a component (mu-plugin:sc-smoke) with no activation step. On ?sc_smoke=1 it tries
 *   one of each thing layer 2 decides for a component and prints "<case>=<result>" lines. Copied
 *   into the release check's site only; never shipped.
 */
defined('ABSPATH') || exit;

add_action('init', static function () {
    if (($_GET['sc_smoke'] ?? '') !== '1') {
        return;
    }
    header('Content-Type: text/plain');
    $ok = static fn(bool $did): string => $did ? 'OK' : 'BLOCKED';

    // Attribution: securecore_status() is core-only, so the extension must charge this call to
    // this mu-plugin (core calls it freely: securecore-status.php reports caller=core).
    try {
        $s = securecore_status();
        echo 'status=', $ok(isset($s['version'])), "\n";
    } catch (\Throwable $e) {
        echo "status=BLOCKED\n";
    }

    // One enforce refusal: a component may write uploads, never core's folders.
    $escape = WP_CONTENT_DIR . '/sc-smoke-escape.php';
    @unlink($escape);
    echo 'write-core=', $ok(@file_put_contents($escape, '<?php // smoke') !== false), "\n";
    @unlink($escape);
    $uploads = WP_CONTENT_DIR . '/uploads/sc-smoke.txt';
    echo 'write-uploads=', $ok(@file_put_contents($uploads, 'x') !== false), "\n";
    @unlink($uploads);

    // The vault: what PHP can see of the DB password and a key is the placeholder.
    echo 'db_password=', DB_PASSWORD, "\n";
    echo 'getenv=', (string) getenv('WORDPRESS_DB_PASSWORD'), "\n";
    echo 'auth_key=', AUTH_KEY, "\n";
    exit;
});
