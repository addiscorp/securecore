<?php
// What a plugin's code uses, from one token_get_all pass over its PHP files. Shared by the
// worker (which functions need stand-ins) and core (the generated manifest), so the two can
// never disagree.
//   called   functions called by name: name(...) not preceded by ->, ::, new or function
//   defined  functions the plugin declares itself
//   hooks    literal tags passed to add_action / add_filter
//   dynamic  true if some add_action / add_filter tag is not a literal ("admin_post_$x")
// Dynamic calls (call_user_func('x'), $f()) are not seen.
namespace SecureCore;

function scan_plugin(string $path): array
{
    $files = is_file($path) ? [$path] : [];
    if (is_dir($path)) {
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) if ($file->getExtension() === 'php') $files[] = $file->getPathname();
    }
    $called = $defined = $hooks = [];
    $dynamic = false;
    foreach ($files as $file) {
        $tokens = array_values(array_filter(
            token_get_all((string) file_get_contents($file)),
            fn ($t) => !is_array($t) || !in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
        ));
        foreach ($tokens as $i => $token) {
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
        }
    }
    $names = fn (array $set) => array_values(array_filter(array_keys($set), fn ($n) => preg_match('/^[a-z_][a-z0-9_]*$/', $n)));
    return [
        'called' => $names(array_diff_key($called, $defined)),
        'defined' => $names($defined),
        'hooks' => array_keys($hooks),
        'dynamic' => $dynamic,
    ];
}
