<?php
// Generate a plugin's manifest from its code: the WordPress functions and hooks it uses.
// Run where WordPress's PHP runs (it needs the list of PHP built-ins to tell a WordPress
// function from a native one). SecureCore's admin screen calls the same logic (see
// SecureCore\generate_manifest); this CLI is for regenerating the committed test manifests.
//   php sandbox/gen-manifest.php <plugin-file> <plugins-dir>
namespace SecureCore;

require __DIR__ . '/scan.php';

$main = $argv[1] ?? '';
$pluginsDir = $argv[2] ?? '';
$path = "$pluginsDir/$main";
$dir = str_contains($main, '/') ? dirname($path) : $path;
$scan = scan_plugin(is_dir($dir) ? $dir : $path);

// Grant only names that are not PHP built-ins: WordPress functions, pluggable functions
// (not yet defined but never native), and other plugins' functions. Never fsockopen, exec,
// curl_* or the like — those must fail in the sandbox, not be forwarded to core.
$internal = array_flip(get_defined_functions()['internal']);
$functions = array_values(array_filter($scan['called'], fn ($n) => !isset($internal[$n])));
sort($functions);
sort($scan['hooks']);

echo json_encode([
    'plugin' => $main,
    'hooks' => $scan['hooks'],
    'functions' => $functions,
] + ($scan['dynamic'] ? ['dynamic_hooks' => true] : []), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
