<?php
// Build the reference index: what WordPress core defines (functions, classes, constants,
// globals, hooks it fires), the same for WooCommerce, and PHP's own symbols.
//
// Usage: php index.php <wordpress-dir> <woocommerce-dir> <out.json>
declare(strict_types=1);

require __DIR__ . '/lib.php';

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar;
use PhpParser\Node\Stmt;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;

[$_, $wpDir, $wooDir, $outPath] = $argv + [null, null, null, null];
if (!$outPath) {
    fwrite(STDERR, "usage: php index.php <wordpress-dir> <woocommerce-dir> <out.json>\n");
    exit(2);
}

final class DeclIndex extends NodeVisitorAbstract
{
    private const BOOT_FILES = ['wp-settings.php', 'wp-load.php', 'wp-blog-header.php', 'wp-includes/version.php',
        'wp-includes/vars.php', 'wp-includes/ms-settings.php', 'wp-admin/admin.php', 'wp-admin/admin-header.php',
        'wp-admin/menu.php', 'wp-admin/includes/admin.php'];
    public array $functions = [];   // lower name => file
    public array $classes = [];     // lower name => [name, file, kind, abstract]
    public array $constants = [];   // name => file
    public array $globals = [];     // name => count of files
    public array $pageGlobals = []; // name => first file (top-level variable of a non-bootstrap core file)
    public array $hooks = [];       // literal tag => file
    public array $hookPatterns = []; // regex => shown tag
    public array $hookPrefixes = [];
    private string $rel = '';
    private array $classStack = [];
    private int $fnDepth = 0;
    private array $seenGlobal = [];

    public function file(string $rel): void
    {
        $this->rel = $rel;
        $this->seenGlobal = [];
    }

    public function enterNode(Node $n)
    {
        if ($n instanceof Stmt\Function_) {
            $name = $n->namespacedName?->toString() ?? $n->name->toString();
            // noop.php re-declares __(), add_action() … as no-ops for load-scripts.php; the
            // real definitions are elsewhere in core.
            if ($this->rel !== 'wp-admin/includes/noop.php') {
                $this->functions[strtolower($name)] ??= $this->rel;
            }
            $this->fnDepth++;
        } elseif ($n instanceof Stmt\ClassMethod || $n instanceof Expr\Closure || $n instanceof Expr\ArrowFunction) {
            $this->fnDepth++;
        } elseif ($n instanceof Stmt\ClassLike && $n->name) {
            $name = $n->namespacedName?->toString() ?? $n->name->toString();
            $kind = strtolower(substr(strrchr('\\' . get_class($n), '\\'), 1));
            $this->classes[strtolower($name)] ??= [
                'name' => $name, 'file' => $this->rel, 'kind' => rtrim($kind, '_'),
                'abstract' => $n instanceof Stmt\Class_ && $n->isAbstract(),
            ];
            $this->classStack[] = $name;
        } elseif ($n instanceof Expr\FuncCall && $n->name instanceof Node\Name) {
            $fn = strtolower($n->name->toString());
            $a0 = $n->args[0] ?? null;
            if ($fn === 'define' && $a0 instanceof Node\Arg && $a0->value instanceof Scalar\String_) {
                $this->constants[$a0->value->value] ??= $this->rel;
            }
            if (in_array($fn, ['do_action', 'apply_filters', 'do_action_ref_array', 'apply_filters_ref_array',
                'do_action_deprecated', 'apply_filters_deprecated'], true) && $a0 instanceof Node\Arg) {
                $tag = render($a0->value, new Ctx('{CORE}', $this->rel));
                if (is_dynamic($tag)) {
                    $this->hookPatterns[tag_regex($tag)] = shown($tag);
                    $p = literal_prefix($tag);
                    if ($p !== '') {
                        $this->hookPrefixes[$p] = true;
                    }
                } else {
                    $this->hooks[$tag] ??= $this->rel;
                }
            }
        } elseif ($n instanceof Stmt\Const_ && !$this->classStack) {
            foreach ($n->consts as $c) {
                $this->constants[$c->namespacedName?->toString() ?? $c->name->toString()] ??= $this->rel;
            }
        } elseif ($n instanceof Stmt\Global_) {
            foreach ($n->vars as $v) {
                if ($v instanceof Expr\Variable && is_string($v->name)) {
                    $this->global($v->name);
                }
            }
        } elseif ($n instanceof Expr\ArrayDimFetch && $n->var instanceof Expr\Variable && $n->var->name === 'GLOBALS'
            && $n->dim instanceof Scalar\String_) {
            $this->global($n->dim->value);
        } elseif ($n instanceof Expr\Assign && $this->fnDepth === 0 && !$this->classStack
            && $n->var instanceof Expr\Variable && is_string($n->var->name)) {
            // Top-level assignments in the bootstrap files run at global scope on every
            // request ($wp_version, $pagenow, …), so they are globals too. Top-level
            // variables of other core files (wp-admin page scripts) are globals only while
            // that page runs: kept apart as page-scope globals.
            if (in_array($this->rel, self::BOOT_FILES, true)) {
                $this->global($n->var->name);
            } else {
                $this->pageGlobals[$n->var->name] ??= $this->rel;
            }
        }
        return null;
    }

    private function global(string $name): void
    {
        if (in_array($name, ['GLOBALS', '_GET', '_POST', '_REQUEST', '_SERVER', '_COOKIE', '_FILES', '_ENV', '_SESSION', 'this'], true)) {
            return;
        }
        if (!isset($this->seenGlobal[$name])) {
            $this->seenGlobal[$name] = true;
            $this->globals[$name] = ($this->globals[$name] ?? 0) + 1;
        }
    }

    public function leaveNode(Node $n)
    {
        if ($n instanceof Stmt\Function_ || $n instanceof Stmt\ClassMethod || $n instanceof Expr\Closure || $n instanceof Expr\ArrowFunction) {
            $this->fnDepth--;
        } elseif ($n instanceof Stmt\ClassLike && $n->name) {
            array_pop($this->classStack);
        }
        return null;
    }
}

function index_tree(string $root, bool $skipWpContent = false): array
{
    $v = new DeclIndex();
    $t = new NodeTraverser();
    $t->addVisitor($v);
    $errors = 0;
    $files = php_files($root);
    if ($skipWpContent) {
        // The WordPress zip ships wp-content/plugins/akismet, hello.php and the default
        // themes: not core.
        $files = array_values(array_filter($files, fn($f) => !str_starts_with($f, 'wp-content/')));
    }
    foreach ($files as $rel) {
        $p = parse_file("$root/$rel");
        $errors += $p->errors ? 1 : 0;
        $v->file($rel);
        $t->traverse($p->stmts);
    }
    ksort($v->functions);
    ksort($v->classes);
    ksort($v->constants);
    arsort($v->globals);
    ksort($v->hooks);
    return [
        'files' => count($files), 'file_list' => $files, 'parse_error_files' => $errors,
        'functions' => $v->functions, 'classes' => $v->classes, 'constants' => $v->constants,
        'globals' => $v->globals, 'page_globals' => array_diff_key($v->pageGlobals, $v->globals), 'hooks' => $v->hooks, 'hook_patterns' => $v->hookPatterns,
        'hook_prefixes' => array_keys($v->hookPrefixes),
    ];
}

$wp = index_tree($wpDir, true);
// wp-config.php constants: the sample's, plus the documented ones a site may add.
$cfgSample = (string) file_get_contents("$wpDir/wp-config-sample.php");
preg_match_all("/define\\(\\s*'([A-Z_]+)'/", $cfgSample, $m);
$wpVersion = '';
if (preg_match('/^\$wp_version\s*=\s*\'([^\']+)\'/m', (string) file_get_contents("$wpDir/wp-includes/version.php"), $vm)) {
    $wpVersion = $vm[1];
}
$woo = index_tree($wooDir);
$wooVersion = '';
if (preg_match('/^\s*\*\s*Version:\s*(\S+)/mi', (string) file_get_contents("$wooDir/woocommerce.php"), $vm)) {
    $wooVersion = $vm[1];
}

// PHP's own symbols in this container, plus function-name prefixes of common extensions
// the php:8.3-cli image doesn't load (gd, mysqli, intl, zip, imagick, …).
$phpFns = array_map('strtolower', get_defined_functions()['internal']);
$phpClasses = array_map('strtolower', array_merge(get_declared_classes(), get_declared_interfaces(), get_declared_traits()));
$phpConsts = array_keys(get_defined_constants());

json_out($outPath, [
    'wordpress_version' => $wpVersion,
    'woocommerce_version' => $wooVersion,
    'php_version' => PHP_VERSION,
    'php_extensions' => get_loaded_extensions(),
    'wp' => $wp,
    'wp_config_sample_constants' => $m[1],
    'pluggable' => array_keys(array_filter($wp['functions'], fn($f) => $f === 'wp-includes/pluggable.php')),
    'woo' => $woo,
    'php' => ['functions' => $phpFns, 'classes' => $phpClasses, 'constants' => $phpConsts],
]);
fprintf(STDERR, "index: WordPress %s: %d functions, %d classes, %d constants, %d globals, %d literal hooks (+%d dynamic); WooCommerce %s: %d functions, %d classes\n",
    $wpVersion, count($wp['functions']), count($wp['classes']), count($wp['constants']), count($wp['globals']),
    count($wp['hooks']), count($wp['hook_patterns']), $wooVersion, count($woo['functions']), count($woo['classes']));
