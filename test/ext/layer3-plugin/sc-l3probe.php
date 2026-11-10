<?php
/**
 * Plugin Name: SecureCore layer 3 probe
 * Description: Test fixture for test/ext-layer3.sh (addiscorp/securecore#53, E7), the plugin the test isolates. It adds content through a filter and shortcodes, and has benign probe shortcodes for layer 3's limits: a write outside its folder, a read of a denied file, a network connect, a too-long loop and too much memory. Every output carries the pid it ran in. Never shipped.
 */

if (!defined('ABSPATH')) {
    exit;
}

// Proof of where this file ran: the neighbour fixture (never isolated) reports whether these
// exist in the php-fpm worker.
define('SC_L3PROBE_LOADED', getmypid());
function sc_l3probe_marker(): string
{
    return 'sc-l3probe';
}

add_filter('the_content', static function ($content) {
    return $content . '<p class="sc-l3-filter">l3 filter pid=' . getmypid() . '</p>';
});

add_shortcode('sc_l3', static function ($atts) {
    $a = shortcode_atts(['say' => 'hi'], $atts);
    return '<span class="sc-l3-short">said ' . esc_html($a['say']) . ' pid=' . getmypid()
        . ' blogname=' . esc_html((string) get_option('blogname')) . '</span>';
});

// Too long: spins for 8 s of wall clock (well past the test's timeoutMs).
add_shortcode('sc_l3_loop', static function () {
    $until = microtime(true) + 8;
    while (microtime(true) < $until) {
    }
    return 'loop-finished';
});

// Too much memory: 512 MiB in one string.
add_shortcode('sc_l3_memory', static function () {
    $s = str_repeat('x', 512 * 1024 * 1024);
    return 'memory-ok ' . strlen($s);
});

// One line per case: <case>=OK (it did what it asks) or <case>=BLOCKED.
add_shortcode('sc_l3_probe', static function () {
    $ok = static fn(bool $did): string => $did ? 'OK' : 'BLOCKED';
    $r = [];
    $own = WP_CONTENT_DIR . '/uploads/sc-l3probe';          // layer3.write for this plugin
    $r['write-own'] = $ok(@file_put_contents($own . '/w.txt', 'x') === 1);
    $r['write-uploads'] = $ok(@file_put_contents(WP_CONTENT_DIR . '/uploads/sc-l3-up.txt', 'x') === 1);
    $r['write-plugin-dir'] = $ok(@file_put_contents(__DIR__ . '/w.txt', 'x') === 1);
    $r['read-config'] = $ok(is_string(@file_get_contents(ABSPATH . 'wp-config.php')));
    $r['read-securecore-json'] = $ok(is_string(@file_get_contents(ABSPATH . 'securecore.json')));
    $s = @fsockopen('db', 3306, $errno, $errstr, 2);
    $r['net-db'] = $ok($s !== false);
    $lines = '';
    foreach ($r as $case => $verdict) {
        $lines .= "\n$case=$verdict";
    }
    return '<pre class="sc-l3-probe">pid=' . getmypid() . $lines . "\n</pre>";
});
