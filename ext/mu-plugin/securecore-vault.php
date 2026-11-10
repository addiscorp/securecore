<?php
/**
 * Plugin Name: SecureCore vault
 * Description: No longer needed; does nothing. The SecureCore extension now defines WordPress's
 *   salted pluggables (wp_salt, wp_hash) itself, natively, at module startup when layer 2 is for
 *   WordPress and the vault holds the keys and salts (addiscorp/securecore#53, E3). Defined here,
 *   in PHP, they failed open: without this file, or with an earlier mu-plugin defining wp_salt
 *   first, WordPress keyed its HMACs with the public placeholders. This file is kept, empty, so
 *   an install that still copies it is harmless; it can be deleted.
 *
 * This file is part of SecureCore; attribution counts it as core, not a component.
 */
defined('ABSPATH') || exit;
