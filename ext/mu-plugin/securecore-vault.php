<?php
/**
 * Plugin Name: SecureCore vault
 * Description: Defines WordPress's salted pluggables (wp_salt, wp_hash) over the SecureCore
 *   extension's native vault, so the HMAC keys never exist as a value PHP can read. Installed in
 *   wp-content/mu-plugins so it loads before pluggable.php, whose own definitions are then
 *   skipped (function_exists). Does nothing unless the securecore extension is loaded with a
 *   vault configured (addiscorp/securecore#53, E3).
 *
 * This file is part of SecureCore; attribution counts it as core, not a component.
 */
defined('ABSPATH') || exit;

// Only take over the salted functions when the extension's vault is actually in force. With no
// extension (or no vault), leave WordPress's own pluggable definitions to load as normal.
if (!function_exists('securecore_vault_hash') || !function_exists('securecore_status')) {
    return;
}
$sc = securecore_status();
if (empty($sc['vault'])) {
    return;
}

if (!function_exists('wp_salt')) {
    /**
     * The salt for a scheme. Never the real key: the extension returns a scheme-specific token,
     * and the real HMACs go through wp_hash() below. A plugin that calls wp_salt() therefore
     * cannot recover the key.
     */
    function wp_salt($scheme = 'auth') {
        return securecore_vault_salt($scheme);
    }
}

if (!function_exists('wp_hash')) {
    /**
     * hash_hmac($algo, $data, wp_salt($scheme)) computed natively over the real keys inside the
     * extension — byte-identical to stock WordPress for the standard key/salt constants, with the
     * key never becoming a PHP value. Keeps login cookies, nonces and password-reset keys working.
     */
    function wp_hash($data, $scheme = 'auth', $algo = 'md5') {
        return securecore_vault_hash((string) $data, $scheme, $algo);
    }
}
