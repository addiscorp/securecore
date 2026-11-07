<?php
/**
 * Plugin Name: SecureCore attribution mu fixture
 * Description: Test fixture for test/ext-attribution.sh (E2a): a mu-plugin whose filter callback opens a file, called from the fixture plugin through core's apply_filters(). Never shipped.
 */

add_filter('securecore_attr_mu', static function ($value) {
    return $value . file_get_contents(WP_CONTENT_DIR . '/uploads/sc-attr/mu.txt');
});
