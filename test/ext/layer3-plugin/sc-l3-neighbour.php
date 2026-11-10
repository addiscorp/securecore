<?php
/**
 * Plugin Name: SecureCore layer 3 neighbour
 * Description: Test fixture for test/ext-layer3.sh (addiscorp/securecore#53, E7), a plugin that is never isolated. It runs in the php-fpm worker, after the probe's filter, and reports the worker's pid and whether the isolated probe's code exists in the worker. On ?sc_l3_inc=1 it tries to include one of the probe's files. Never shipped.
 */

if (!defined('ABSPATH')) {
    exit;
}

add_filter('the_content', static function ($content) {
    $where = defined('SC_L3PROBE_LOADED') || function_exists('sc_l3probe_marker') ? 'probe-in-worker' : 'probe-not-in-worker';
    $inc = '';
    if (isset($_GET['sc_l3_inc'])) {
        $got = @include WP_PLUGIN_DIR . '/sc-l3probe/inc.php';
        $inc = ' inc=' . ($got === 'sc-l3-inc-loaded' ? 'loaded' : 'refused');
    }
    return $content . '<p class="sc-l3-neighbour">neighbour pid=' . getmypid() . ' ' . $where . $inc . '</p>';
}, 20);
