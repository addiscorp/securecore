<?php
// Shared pieces of the plugin survey (issue #40): parsing, and the resolver that turns
// path / hook-name / SQL expressions into strings with explicit placeholders for the
// parts static analysis cannot know.
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use PhpParser\Error;
use PhpParser\ErrorHandler;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\ParserFactory;

const T0 = "\x01";
const T1 = "\x02";

/** A placeholder for a part of a string the analysis cannot resolve. */
function dyn(string $label): string
{
    return T0 . str_replace([T0, T1], '', $label) . T1;
}

function is_dynamic(string $s): bool
{
    return str_contains($s, T0);
}

/** Human-readable form: placeholders become {label}. */
function shown(string $s): string
{
    return strtr($s, [T0 => '{', T1 => '}']);
}

/** Literal text before the first placeholder. */
function literal_prefix(string $s): string
{
    $p = strpos($s, T0);
    return $p === false ? $s : substr($s, 0, $p);
}

final class Parsed
{
    /** @param Node[] $stmts */
    public function __construct(public array $stmts, public int $errors, public string $firstError, public string $code) {}
}

function parse_file(string $path): Parsed
{
    static $parser = null;
    $parser ??= (new ParserFactory())->createForNewestSupportedVersion();
    $code = (string) @file_get_contents($path);
    $handler = new ErrorHandler\Collecting();
    try {
        $stmts = $parser->parse($code, $handler) ?? [];
    } catch (Error $e) {
        return new Parsed([], 1, $e->getMessage(), $code);
    }
    $errs = $handler->getErrors();
    $t = new NodeTraverser();
    $t->addVisitor(new NameResolver($handler, ['preserveOriginalNames' => true]));
    $stmts = $t->traverse($stmts);
    return new Parsed($stmts, count($errs), $errs ? $errs[0]->getMessage() : '', $code);
}

/** All .php files under $root, as paths relative to it, sorted. */
function php_files(string $root): array
{
    $out = [];
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );
    foreach ($it as $f) {
        // Skip macOS AppleDouble files (._x.php, __MACOSX/) that some zips carry: not PHP.
        if ($f->isFile() && strtolower($f->getExtension()) === 'php' && !str_starts_with($f->getFilename(), '._')
            && !str_contains($f->getPathname(), '/__MACOSX/')) {
            $out[] = substr($f->getPathname(), strlen($root) + 1);
        }
    }
    sort($out);
    return $out;
}

/** Bundled third-party code, reported separately from the plugin's own code. */
function is_vendor_path(string $rel): bool
{
    foreach (explode('/', $rel) as $seg) {
        if (preg_match('/^(vendor|vendors|vendor[-_]prefixed|jetpack[-_]vendor|third[-_]?party|node_modules|bower_components)$/i', $seg)) {
            return true;
        }
    }
    return false;
}

/** Function / constant name as PHP resolves it: [namespaced candidate or null, global fallback]. */
function name_candidates(Node\Name $n): array
{
    if ($n instanceof Node\Name\FullyQualified) {
        return [null, $n->toString()];
    }
    $ns = $n->getAttribute('namespacedName');
    if ($n->isQualified()) {
        // Ns\foo() relative to the current namespace: no global fallback.
        return [null, $ns ? $ns->toString() : $n->toString()];
    }
    return [$ns ? $ns->toString() : null, $n->toString()];
}

/** Context for resolving an expression in one file. */
final class Ctx
{
    public ?string $class = null;
    /** @var array<string,string> plugin constants resolved so far (name => value) */
    public array $consts = [];
    /** @var array<string,string> "class::CONST" => value */
    public array $classConsts = [];

    public function __construct(public string $root, public string $rel) {}
}

// Where WordPress's well-known path constants point, relative to ABSPATH. These are the
// defaults; a site can move wp-content, which this survey ignores.
const ROOTS = [
    'ABSPATH' => '{ABSPATH}/',
    'WP_CONTENT_DIR' => '{ABSPATH}/wp-content',
    'WP_PLUGIN_DIR' => '{ABSPATH}/wp-content/plugins',
    'WPMU_PLUGIN_DIR' => '{ABSPATH}/wp-content/mu-plugins',
    'WP_LANG_DIR' => '{ABSPATH}/wp-content/languages',
    'WPINC' => 'wp-includes',
    'PLUGINDIR' => 'wp-content/plugins',
    'MUPLUGINDIR' => 'wp-content/mu-plugins',
    'DIRECTORY_SEPARATOR' => '/',
    'WP_TEMP_DIR' => '{TMP}',
];

const WPDB_TABLES = ['posts', 'postmeta', 'comments', 'commentmeta', 'terms', 'termmeta', 'term_taxonomy',
    'term_relationships', 'options', 'links', 'users', 'usermeta', 'blogs', 'blogmeta', 'signups', 'site',
    'sitemeta', 'registration_log'];

function is_wpdb_expr(Node $e): bool
{
    if ($e instanceof Expr\Variable && $e->name === 'wpdb') {
        return true;
    }
    if (($e instanceof Expr\PropertyFetch || $e instanceof Expr\NullsafePropertyFetch || $e instanceof Expr\StaticPropertyFetch)
        && $e->name instanceof Node\Identifier && in_array(strtolower($e->name->toString()), ['wpdb', 'db', '_wpdb'], true)) {
        return true;
    }
    if ($e instanceof Expr\ArrayDimFetch && $e->var instanceof Expr\Variable && $e->var->name === 'GLOBALS'
        && $e->dim instanceof Scalar\String_ && $e->dim->value === 'wpdb') {
        return true;
    }
    return false;
}

function path_dirname(string $s, int $levels = 1): string
{
    for ($i = 0; $i < $levels; $i++) {
        $s = rtrim($s, '/');
        $p = strrpos($s, '/');
        if ($p === false || is_dynamic(substr($s, $p))) {
            return dyn('dirname(…)');
        }
        $s = substr($s, 0, $p);
    }
    return $s;
}

function render(?Node $e, Ctx $c, int $depth = 0): string
{
    if ($e === null) {
        return dyn('null');
    }
    if ($depth > 25) {
        return dyn('deep');
    }
    $r = fn(?Node $x) => render($x, $c, $depth + 1);
    $plugin = $c->root;

    if ($e instanceof Node\Arg) {
        return $r($e->value);
    }
    if ($e instanceof Scalar\String_) {
        return $e->value;
    }
    if ($e instanceof Scalar\Int_ || $e instanceof Scalar\Float_) {
        return (string) $e->value;
    }
    if ($e instanceof Scalar\InterpolatedString) {
        $s = '';
        foreach ($e->parts as $p) {
            $s .= $p instanceof Node\InterpolatedStringPart ? $p->value : $r($p);
        }
        return $s;
    }
    if ($e instanceof Expr\BinaryOp\Concat) {
        return $r($e->left) . $r($e->right);
    }
    if ($e instanceof Scalar\MagicConst\Dir) {
        $d = dirname($c->rel);
        return $d === '.' ? $plugin : "$plugin/$d";
    }
    if ($e instanceof Scalar\MagicConst\File) {
        return "$plugin/{$c->rel}";
    }
    if ($e instanceof Scalar\MagicConst\Class_) {
        return $c->class ?? dyn('__CLASS__');
    }
    if ($e instanceof Expr\ConstFetch) {
        [$ns, $global] = name_candidates($e->name);
        foreach (array_filter([$ns, $global]) as $name) {
            if (isset(ROOTS[$name])) {
                return ROOTS[$name];
            }
            if (isset($c->consts[$name])) {
                return $c->consts[$name];
            }
        }
        return dyn('C:' . $global);
    }
    if ($e instanceof Expr\ClassConstFetch && $e->name instanceof Node\Identifier && $e->class instanceof Node\Name) {
        $cls = $e->class->toString();
        if (in_array(strtolower($cls), ['self', 'static'], true)) {
            $cls = $c->class ?? $cls;
        }
        if (strtolower($e->name->toString()) === 'class') {
            return ltrim($cls, '\\');
        }
        $key = ltrim($cls, '\\') . '::' . $e->name->toString();
        return $c->classConsts[$key] ?? dyn('K:' . $key);
    }
    if ($e instanceof Expr\FuncCall && $e->name instanceof Node\Name) {
        $fn = strtolower($e->name->getLast());
        $a = $e->args;
        $arg = fn(int $i) => isset($a[$i]) && $a[$i] instanceof Node\Arg ? $a[$i]->value : null;
        switch ($fn) {
            case 'dirname':
                $lv = $arg(1) instanceof Scalar\Int_ ? $arg(1)->value : 1;
                return path_dirname($r($arg(0)), $lv);
            case 'plugin_dir_path':
                return path_dirname($r($arg(0))) . '/';
            case 'trailingslashit':
                return rtrim($r($arg(0)), '/') . '/';
            case 'untrailingslashit':
                return rtrim($r($arg(0)), '/');
            case 'realpath':
            case 'wp_normalize_path':
            case 'strval':
                return $r($arg(0));
            case 'path_join':
                return $r($arg(0)) . '/' . $r($arg(1));
            case 'get_home_path':
                return '{ABSPATH}/';
            case 'get_temp_dir':
            case 'sys_get_temp_dir':
                return '{TMP}/';
            case 'get_template_directory':
            case 'get_stylesheet_directory':
                return '{THEME}';
            case 'plugin_basename':
                $p = $r($arg(0));
                $pre = '{ABSPATH}/wp-content/plugins/';
                return (!is_dynamic($p) && str_starts_with($p, $pre)) ? substr($p, strlen($pre)) : dyn('plugin_basename(…)');
            case 'sprintf':
                if ($arg(0) instanceof Scalar\String_) {
                    $i = 1;
                    return preg_replace_callback('/%(?:\d+\$)?[sd]/', function () use (&$i, $arg, $r) {
                        return $r($arg($i++));
                    }, $arg(0)->value);
                }
                return dyn('sprintf(…)');
            case 'get_option':
            case 'get_site_option':
                return dyn($fn . '(' . ($arg(0) instanceof Scalar\String_ ? "'" . $arg(0)->value . "'" : '…') . ')');
        }
        return dyn($e->name->toString() . '()');
    }
    if ($e instanceof Expr\ArrayDimFetch) {
        $dim = $e->dim instanceof Scalar\String_ ? $e->dim->value : null;
        if ($e->var instanceof Expr\FuncCall && $e->var->name instanceof Node\Name
            && strtolower($e->var->name->getLast()) === 'wp_upload_dir') {
            if ($dim === 'basedir' || $dim === 'path') {
                return '{UPLOADS}';
            }
            return dyn("wp_upload_dir()[$dim]");
        }
        $base = $e->var instanceof Expr\Variable && is_string($e->var->name) ? '$' . $e->var->name : '…';
        return dyn($base . '[' . ($dim ?? '…') . ']');
    }
    if ($e instanceof Expr\Variable) {
        return dyn('$' . (is_string($e->name) ? $e->name : '$…'));
    }
    if ($e instanceof Expr\PropertyFetch || $e instanceof Expr\NullsafePropertyFetch) {
        $prop = $e->name instanceof Node\Identifier ? $e->name->toString() : '…';
        if (is_wpdb_expr($e->var)) {
            if (in_array($prop, ['prefix', 'base_prefix'], true)) {
                return '{prefix}';
            }
            if (in_array($prop, WPDB_TABLES, true)) {
                return '{prefix}' . $prop;
            }
            return dyn('$wpdb->' . $prop);
        }
        return dyn('->' . $prop);
    }
    if ($e instanceof Expr\MethodCall || $e instanceof Expr\NullsafeMethodCall) {
        $m = $e->name instanceof Node\Identifier ? strtolower($e->name->toString()) : '…';
        if ($m === 'get_blog_prefix' && is_wpdb_expr($e->var)) {
            return '{prefix}';
        }
        return match ($m) {
            'abspath' => '{ABSPATH}/',
            'wp_content_dir' => '{ABSPATH}/wp-content/',
            'wp_plugins_dir' => '{ABSPATH}/wp-content/plugins/',
            default => dyn('->' . $m . '()'),
        };
    }
    if ($e instanceof Expr\StaticCall && $e->name instanceof Node\Identifier) {
        return dyn(($e->class instanceof Node\Name ? $e->class->getLast() : '…') . '::' . $e->name->toString() . '()');
    }
    if ($e instanceof Expr\Cast\String_) {
        return $r($e->expr);
    }
    return dyn(substr(strrchr('\\' . get_class($e), '\\'), 1));
}

/** Collapse //, /./ and x/.. ; {ABSPATH} is a floor that .. cannot leave. */
function normalize_path(string $s): string
{
    if (is_dynamic($s) || preg_match('#^[a-z][a-z0-9.+-]*://#i', $s)) {
        return $s; // stream wrappers (php://temp, compress.zlib://…) stay as they are
    }
    $s = preg_replace('#/+#', '/', $s);
    $abs = str_starts_with($s, '{ABSPATH}');
    $parts = explode('/', $s);
    $out = [];
    foreach ($parts as $i => $p) {
        if ($p === '.' || ($p === '' && $i > 0 && $i < count($parts) - 1)) {
            continue;
        }
        if ($p === '..' && $out && end($out) !== '..' && end($out) !== '{ABSPATH}' && end($out) !== '') {
            array_pop($out);
            continue;
        }
        $out[] = $p;
    }
    $r = implode('/', $out);
    return $abs || !str_contains($r, '{ABSPATH}') ? $r : $r;
}

/**
 * Where a resolved (or partly resolved) file path points.
 * Returns [class, how] with how = resolved | partial | dynamic | heuristic.
 */
function classify_path(string $p, string $slug): array
{
    $how = is_dynamic($p) ? 'partial' : 'resolved';
    $lit = normalize_path(literal_prefix($p));
    $full = shown($p);
    if (preg_match('#^[a-z][a-z0-9.+-]*://#i', $lit)) {
        return ['stream', $how];
    }
    if (str_ends_with($full, '.htaccess')) {
        // The site's own .htaccess (rewrite rules for every request) vs a deny-all file a
        // plugin drops into its own log / upload / cache folder.
        if ($full === '{ABSPATH}/.htaccess' || preg_match('/^\{(\$home_path|get_home_path\(\)|\$htaccess_file|\$home|\$root\w*|\$path|\$htaccess\w*)\}\/?\.htaccess$/i', $full)) {
            return ['.htaccess (site root)', $how === 'resolved' ? 'resolved' : 'heuristic'];
        }
        if ($how === 'resolved') {
            return ['.htaccess (in a subfolder)', $how];
        }
        return ['.htaccess (folder unknown)', $how];
    }
    $special = [
        'wp-config.php' => 'wp-config.php',
        'advanced-cache.php' => 'drop-in',
        'object-cache.php' => 'drop-in',
        'db-error.php' => 'drop-in',
        'sunrise.php' => 'drop-in',
        'maintenance.php' => 'drop-in',
        '.user.ini' => 'php config',
        'php.ini' => 'php config',
        'web.config' => 'server config',
        'nginx.conf' => 'server config',
    ];
    foreach ($special as $needle => $cls) {
        if (str_ends_with(strtolower($full), strtolower($needle))) {
            return [$cls, $how];
        }
    }
    if (preg_match('#wp-content/db\.php$#', $full) || preg_match('#\{C:WP_CONTENT_DIR\}/db\.php$#', $full)) {
        return ['drop-in', $how];
    }
    if (str_contains($full, 'mu-plugins')) {
        return ['mu-plugins', $how];
    }
    if ($lit === '' || $lit === '/') {
        // Nothing literal in front: look at the placeholder for a hint.
        if (preg_match('/^\{[^}]*upload[^}]*\}/i', $full)) {
            return ['uploads', 'heuristic'];
        }
        return ['dynamic', 'dynamic'];
    }
    $own = "{ABSPATH}/wp-content/plugins/$slug";
    if ($lit === $own || str_starts_with($lit, "$own/")) {
        return ['own folder', $how];
    }
    if (str_starts_with($lit, '{ABSPATH}/wp-content/plugins')) {
        return ['plugins folder', $how];
    }
    if (str_starts_with($lit, '{ABSPATH}/wp-content/languages')) {
        return ['wp-content/languages', $how];
    }
    if (str_starts_with($lit, '{ABSPATH}/wp-content')) {
        return ['wp-content', $how];
    }
    if (str_starts_with($lit, '{UPLOADS}')) {
        return ['uploads', $how];
    }
    if (str_starts_with($lit, '{TMP}')) {
        return ['temp', $how];
    }
    if (str_starts_with($lit, '{THEME}')) {
        return ['theme', $how];
    }
    if (str_starts_with($lit, '{ABSPATH}/wp-admin') || str_starts_with($lit, '{ABSPATH}/wp-includes')
        || str_starts_with($lit, 'wp-includes') || str_starts_with($lit, 'wp-admin')) {
        return ['core', $how];
    }
    if (preg_match('#^\{ABSPATH\}/(wp-[a-z-]+\.php|xmlrpc\.php|index\.php)$#', $lit)) {
        return ['core', $how];
    }
    if (str_starts_with($lit, '{ABSPATH}')) {
        return ['site root', $how];
    }
    if (str_starts_with($lit, 'php://') || str_starts_with($lit, 'http')) {
        return ['stream', $how];
    }
    return ['other', $how];
}

/** Path relative to ABSPATH for a resolved core path, e.g. wp-admin/includes/plugin.php. */
function core_rel(string $p): ?string
{
    $p = normalize_path($p);
    if (str_starts_with($p, '{ABSPATH}/')) {
        return substr($p, strlen('{ABSPATH}/'));
    }
    if (str_starts_with($p, 'wp-includes/') || str_starts_with($p, 'wp-admin/')) {
        return $p;
    }
    return null;
}

/** Turn a rendered hook tag into a regex matching every tag it can produce. */
function tag_regex(string $tag): string
{
    $parts = preg_split('/' . T0 . '[^' . T1 . ']*' . T1 . '/', $tag);
    return '/^' . implode('.+', array_map(fn($p) => preg_quote($p, '/'), $parts)) . '$/';
}

function json_out(string $path, mixed $data, bool $pretty = true): void
{
    file_put_contents($path, json_encode($data, ($pretty ? JSON_PRETTY_PRINT : 0) | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n");
}
