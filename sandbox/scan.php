<?php
// What a plugin's code uses, from one token_get_all pass over its PHP files. Shared by the
// worker (which functions need stand-ins) and core (the generated manifest), so the two can
// never disagree.
//   called      functions called by name: name(...) not preceded by ->, ::, new or function
//   defined     functions the plugin declares itself
//   hooks       literal tags passed to add_action / add_filter
//   dynamic     true if some add_action / add_filter tag is not a literal ("admin_post_$x")
//   db_options  option names the plugin writes: the first (or, for register_setting and the
//               *_network_option calls, the second) literal argument to add_option/update_option/
//               register_setting/… — the options the gateway treats as "the plugin's own" and so
//               keeps in a bulk options read (addiscorp/securecore#42, part 2)
//   db_tables   table base names from `$wpdb->prefix . 'name'` concatenations — the plugin's own
//               tables (informational; the gateway allows every non-core table anyway)
// Dynamic calls (call_user_func('x'), $f()) are not seen; a dynamically named option is a gateway
// "miss" (the plugin's own option that it reads back comes through on an explicit read, just not a
// bulk one), logged by the gateway, not fatal.
namespace SecureCore;

function scan_plugin(string $path): array
{
    $files = is_file($path) ? [$path] : [];
    if (is_dir($path)) {
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) if ($file->getExtension() === 'php') $files[] = $file->getPathname();
    }
    // The functions whose option-name argument marks an option as the plugin's own, and which
    // argument (0-based) carries that name.
    $optionWriters = [
        'add_option' => 0, 'update_option' => 0, 'delete_option' => 0,
        'add_site_option' => 0, 'update_site_option' => 0, 'delete_site_option' => 0,
        'register_setting' => 1, 'unregister_setting' => 1,
        'add_network_option' => 1, 'update_network_option' => 1, 'delete_network_option' => 1,
    ];
    $called = $defined = $hooks = $dbOptions = $dbTables = [];
    $dynamic = false;
    foreach ($files as $file) {
        $tokens = array_values(array_filter(
            token_get_all((string) file_get_contents($file)),
            fn ($t) => !is_array($t) || !in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
        ));
        foreach ($tokens as $i => $token) {
            // $wpdb->prefix . 'name' / $wpdb->base_prefix . 'name' → the plugin's own table.
            if (is_array($token) && $token[0] === T_VARIABLE && strtolower($token[1]) === '$wpdb'
                && ($tokens[$i + 1][0] ?? null) === T_OBJECT_OPERATOR
                && is_array($tokens[$i + 2] ?? null) && $tokens[$i + 2][0] === T_STRING
                && in_array(strtolower($tokens[$i + 2][1]), ['prefix', 'base_prefix'], true)
                && ($tokens[$i + 3] ?? null) === '.'
                && is_array($tokens[$i + 4] ?? null) && $tokens[$i + 4][0] === T_CONSTANT_ENCAPSED_STRING) {
                $name = substr($tokens[$i + 4][1], 1, -1);
                if (preg_match('/^[a-z0-9_]+$/i', $name)) $dbTables[$name] = true;
            }

            if (!is_array($token) || !in_array($token[0], [T_STRING, T_NAME_FULLY_QUALIFIED], true)) continue;
            $name = strtolower(ltrim($token[1], '\\'));
            $prev = is_array($tokens[$i - 1] ?? null) ? $tokens[$i - 1][0] : ($tokens[$i - 1] ?? null);
            if ($prev === T_FUNCTION) { $defined[$name] = true; continue; }
            if (($tokens[$i + 1] ?? null) !== '(') continue;
            if (in_array($prev, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_NEW], true)) continue;
            $called[$name] = true;
            if ($name === 'add_action' || $name === 'add_filter') {
                $arg = $tokens[$i + 2] ?? null;
                $after = $tokens[$i + 3] ?? null;
                if (is_array($arg) && $arg[0] === T_CONSTANT_ENCAPSED_STRING && $after === ',') $hooks[substr($arg[1], 1, -1)] = true;
                else $dynamic = true;
            }
            if (isset($optionWriters[$name])) {
                $opt = nth_string_arg($tokens, $i + 1, $optionWriters[$name]);
                if ($opt !== null && preg_match('/^[a-z0-9_-]+$/i', $opt)) $dbOptions[$opt] = true;
            }
        }
    }
    $names = fn (array $set) => array_values(array_filter(array_keys($set), fn ($n) => preg_match('/^[a-z_][a-z0-9_]*$/', $n)));
    return [
        'called' => $names(array_diff_key($called, $defined)),
        'defined' => $names($defined),
        'hooks' => array_keys($hooks),
        'dynamic' => $dynamic,
        'db_options' => array_keys($dbOptions),
        'db_tables' => array_keys($dbTables),
    ];
}

/**
 * The content of the $n-th (0-based) argument of a call, when that argument is a single string
 * literal; otherwise null. $open is the index of the call's '(' in the filtered token list. Walks
 * at paren depth 1, splitting on top-level commas, so a literal inside a nested call or array is
 * not mistaken for a top-level argument.
 */
function nth_string_arg(array $tokens, int $open, int $n): ?string
{
    $depth = 0;
    $arg = 0;
    $count = count($tokens);
    for ($i = $open; $i < $count; $i++) {
        $t = $tokens[$i];
        if ($t === '(') { $depth++; continue; }
        if ($t === ')') { if (--$depth === 0) return null; continue; }
        if ($depth !== 1) continue;
        if ($t === ',') { $arg++; continue; }
        if ($arg === $n) {
            // The argument is a single string literal only if the next top-level token ends it.
            if (is_array($t) && $t[0] === T_CONSTANT_ENCAPSED_STRING) {
                $next = $tokens[$i + 1] ?? null;
                if ($next === ',' || $next === ')') return substr($t[1], 1, -1);
            }
            return null;
        }
    }
    return null;
}
