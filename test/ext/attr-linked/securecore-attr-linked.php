<?php
/**
 * Plugin Name: SecureCore attribution symlinked fixture
 * Description: Test fixture for test/ext-attribution.sh (E2a). Installed as a symlink into the plugins folder, pointing outside it; PHP reports its files by their real path, and the component map must still name it. Never shipped.
 */

if (!defined('ABSPATH')) {
    exit;
}

add_action('init', static function () {
    if (($_GET['sc_attr'] ?? '') !== 'linked') {
        return;
    }
    header('Content-Type: text/plain');
    echo file_get_contents(WP_CONTENT_DIR . '/uploads/sc-attr/linked.txt');
    exit;
});
