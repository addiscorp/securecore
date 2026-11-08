<?php
/**
 * SecureCore core-probe (E5, addiscorp/securecore#53). A mu-plugin named securecore-loader.php is
 * attributed to *core* (securecore-attribution: SECURECORE_LOADER is core), so a connection made
 * from this file's own hook runs with no component on the stack — the way to exercise `core.hosts`.
 * It runs before the plugin's hook (priority 5), so its lines come first.
 *
 * core.hosts lists core-allowed.test but not allowed.test, so:
 *   - core-allowed    → OK  (core may reach its own host)
 *   - core-disallowed → BLOCKED in enforce (allowed.test is the component's host, not core's)
 */

if (!defined('ABSPATH')) {
    return;
}

add_action('init', function () {
    if (($_GET['sc_hosts'] ?? '') !== 'run') {
        return;
    }
    $ctx = stream_context_create(['http' => ['timeout' => 2]]);
    $reached = static function ($body) {
        return is_string($body) && $body !== '' ? 'OK' : 'BLOCKED';
    };
    echo 'core-allowed=' . $reached(@file_get_contents('http://core-allowed.test/', false, $ctx)) . "\n";
    echo 'core-disallowed=' . $reached(@file_get_contents('http://allowed.test/', false, $ctx)) . "\n";
}, 5);
