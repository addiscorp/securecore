<?php
/**
 * Plugin Name: SecureCore State
 * Description: Test plugin for request isolation. A hook with a static that records the id
 * from $_GET of every request it serves. With a fork per request each request sees only its
 * own id; without the fork the static leaks across requests. Definitions are guarded so the
 * no-fork worker can re-include the file without a redeclare fatal.
 * Version: 0.1.0
 */
defined('ABSPATH') || exit;

if (!function_exists('securecore_state_cb')) {
    function securecore_state_cb($value = null)
    {
        static $seen = [];
        $seen[] = $_GET['id'] ?? '?';
        return implode(',', $seen);
    }
}
add_filter('securecore_state', 'securecore_state_cb', 10, 1);
