<?php
/**
 * Plugin Name: SecureCore attribution fixture
 * Description: Test fixture for test/ext-attribution.sh (addiscorp/securecore#53, E2a). Opens files in known ways on ?sc_attr=<case>, so the test can check which component each attribution rule charges. Never shipped.
 */

if (!defined('ABSPATH')) {
    exit;
}

add_action('init', static function () {
    $case = $_GET['sc_attr'] ?? '';
    if ($case === '') {
        return;
    }
    $dir = WP_CONTENT_DIR . '/uploads/sc-attr';
    header('Content-Type: text/plain');
    switch ($case) {
        case 'direct': // the plugin opens the file itself
            echo file_get_contents($dir . '/direct.txt');
            break;
        case 'core-api': // the plugin asks core, and core opens the file
            echo get_file_data($dir . '/core-api.txt', ['Name' => 'Name'])['Name'];
            break;
        case 'include': // the plugin includes its own file
            require_once __DIR__ . '/inc/own.php';
            echo securecore_attr_own();
            break;
        case 'write': // the plugin writes, two ways
            file_put_contents($dir . '/written.txt', 'written');
            $f = fopen($dir . '/fopen-w.txt', 'wb');
            fwrite($f, 'w');
            fclose($f);
            echo 'written';
            break;
        case 'filter': // the plugin runs a filter; a mu-plugin's callback opens the file
            echo apply_filters('securecore_attr_mu', '');
            break;
        case 'status': // who securecore_status() says is calling
            echo securecore_status()['caller'];
            break;
        case 'status-via-core': // the same, reached through core's apply_filters()
            add_filter('securecore_attr_status', 'securecore_status', 10, 0);
            echo apply_filters('securecore_attr_status', null)['caller'];
            break;
        default:
            echo 'unknown case';
    }
    exit;
});
