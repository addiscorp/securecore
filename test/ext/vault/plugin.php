<?php
/**
 * Plugin Name: SecureCore vault probe
 * Description: A component (plugin) that tries every route to the secrets, for test/ext-vault.sh.
 *   Never shipped. On ?sc_vault=run it prints the shared probe routine's output and exits, so the
 *   reads run in plugin context (attributed to this plugin).
 */
defined('ABSPATH') || exit;

add_action('init', function () {
    if (($_GET['sc_vault'] ?? '') !== 'run') {
        return;
    }
    require_once '/var/www/html/sc-vault-routine.php';
    header('Content-Type: text/plain');
    echo "probe=plugin\n";
    echo sc_vault_probe();
    exit;
});
