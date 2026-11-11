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

// ?sc_l3_mark=<v>: after the content, a write on the worker's connection (its own option, through
// core's update_option): it lands only if no transaction is left open on that connection (#94).
add_filter('the_content', static function ($content) {
    if (isset($_GET['sc_l3_mark'])) {
        update_option('sc_l3_neighbour_mark', sanitize_key($_GET['sc_l3_mark']), false);
    }
    // ?sc_l3_peak=1: the worker's peak memory so far (the result cap's test).
    if (isset($_GET['sc_l3_peak'])) {
        $content .= "\n<pre>\npeak=" . memory_get_peak_usage() . "\n</pre>";
    }
    return $content;
}, 30);
