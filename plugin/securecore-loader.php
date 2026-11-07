<?php
/**
 * Plugin Name: SecureCore loader
 * Description: Loads SecureCore before other plugins while the SecureCore plugin is active, so sandboxed plugins never load in core. Installed by install.sh.
 *
 * Copy to wp-content/mu-plugins/. It does nothing unless wp-content/plugins/securecore is
 * present and the SecureCore plugin is active.
 */
defined('ABSPATH') || exit;

(function () {
    $main = 'securecore/securecore.php';
    $file = WP_PLUGIN_DIR . '/securecore/securecore-core.php';
    if (!is_file($file)) return;
    $active = (array) get_option('active_plugins', []);
    if (is_multisite()) $active = array_merge($active, array_keys((array) get_site_option('active_sitewide_plugins', [])));
    if (in_array($main, $active, true)) require_once $file;
})();
