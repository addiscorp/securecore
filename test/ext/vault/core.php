<?php
// The core probe for test/ext-vault.sh (never shipped): a web-root script (core, not a
// component) that runs the same routes as the plugin probe, so we prove core can't see the
// secret either. It boots WordPress and calls the shared routine with no component on the stack.
require_once __DIR__ . '/wp-load.php';
require_once __DIR__ . '/sc-vault-routine.php';
header('Content-Type: text/plain');
echo "probe=core\n";
echo sc_vault_probe();
