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
    // ?sc_l3_session=1: the worker connection's session state as core's next queries see it.
    if (isset($_GET['sc_l3_session'])) {
        global $wpdb;
        $s = $wpdb->get_row('SELECT @@sql_select_limit AS l, @@completion_type AS c, @@transaction_read_only AS r, @@autocommit AS a, @@time_zone AS z, @@sql_mode AS m', ARRAY_A);
        // Its own table (test/ext-layer3.sh puts six rows in it): LIMIT 5 is 5 rows unless a
        // session sql_select_limit cut it.
        $n = count((array) $wpdb->get_col("SELECT id FROM {$wpdb->prefix}sc_l3_neighbour_data LIMIT 5"));
        $content .= "\n<pre>\nsession=" . esc_html(implode('|', (array) $s)) . "\ncore_rows=$n\n</pre>";
    }
    return $content;
}, 30);

// A `query` filter that throws on one marker query (an exception in the worker while it runs an
// isolated plugin's query), and ?sc_l3_throw=1 catching it around the shortcodes so the page
// goes on.
add_filter('query', static function ($q) {
    if (is_string($q) && str_contains($q, 'sc_l3db_throw_marker')) {
        throw new RuntimeException('sc-l3-neighbour: thrown from a query filter');
    }
    return $q;
});
if (isset($_GET['sc_l3_throw'])) {
    remove_filter('the_content', 'do_shortcode', 11);
    add_filter('the_content', static function ($content) {
        try {
            return do_shortcode($content);
        } catch (\Throwable $e) {
            return $content . "\n<pre>\ncaught=" . get_class($e) . "\n</pre>";
        }
    }, 11);
}
