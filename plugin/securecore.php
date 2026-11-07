<?php
/**
 * Plugin Name: SecureCore
 * Description: Runs the plugins you choose in a separate sandbox process. WordPress core stays on this PHP; every call between a sandboxed plugin and WordPress is checked against that plugin's manifest. Settings → SecureCore.
 * Version: 0.1.0
 * Requires PHP: 8.1
 * License: GPL-2.0-or-later
 *
 * The work is done by securecore-core.php, which the mu-plugin loader includes early (before
 * other plugins load) while this plugin is active. Deactivating this plugin turns
 * SecureCore off: plugins load normally again.
 *
 * The main class lives in securecore-core.php, not SecureCore.php: a name that differs from this
 * file only in case would collide with it when the release zip is staged on a case-insensitive
 * filesystem (macOS default TMPDIR), where one silently overwrites the other (#51).
 */
defined('ABSPATH') || exit;

require_once __DIR__ . '/securecore-core.php';
