<?php
// Analyze one plugin: what it needs from WordPress and what it touches (issue #40).
//
// Usage: php analyze.php <plugin-dir> <slug> <index.json> <out.json>
//
// Two passes over every .php file: pass 1 resolves the plugin's own constants
// (define('X_PATH', plugin_dir_path(__FILE__)) …) so include paths built from them can be
// classified; pass 2 records every use. Everything the resolver cannot know stays a
// {placeholder} and is counted as dynamic, never guessed.
declare(strict_types=1);

require __DIR__ . '/lib.php';

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar;
use PhpParser\Node\Stmt;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;

[$_, $pluginDir, $slug, $indexPath, $outPath] = $argv + [null, null, null, null, null];
if (!$outPath) {
    fwrite(STDERR, "usage: php analyze.php <plugin-dir> <slug> <index.json> <out.json>\n");
    exit(2);
}
$pluginDir = rtrim($pluginDir, '/');
$I = json_decode((string) file_get_contents($indexPath), true, 512, JSON_THROW_ON_ERROR);
$ROOT = "{ABSPATH}/wp-content/plugins/$slug";
$t0 = microtime(true);

const SECRET_CONSTANTS = ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST', 'AUTH_KEY', 'SECURE_AUTH_KEY',
    'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'];
const SECRET_WPDB_PROPS = ['dbpassword', 'dbuser', 'dbhost', 'dbname', 'dbh'];
// Core functions whose result depends on the keys and salts in wp-config.php.
const SALTED_FUNCTIONS = ['wp_salt', 'wp_hash', 'wp_create_nonce', 'wp_verify_nonce', 'wp_nonce_field', 'wp_nonce_url',
    'check_admin_referer', 'check_ajax_referer', 'wp_generate_auth_cookie', 'wp_validate_auth_cookie',
    'wp_set_auth_cookie', 'wp_parse_auth_cookie', 'wp_hash_password', 'wp_check_password', 'wp_generate_password'];
const HOOK_ADD = ['add_action', 'add_filter'];
const HOOK_OTHER = ['remove_action', 'remove_filter', 'has_action', 'has_filter', 'remove_all_actions', 'remove_all_filters', 'did_action', 'doing_action'];
const HOOK_FIRE = ['do_action', 'apply_filters', 'do_action_ref_array', 'apply_filters_ref_array', 'do_action_deprecated', 'apply_filters_deprecated'];
const EXEC_FUNCTIONS = ['exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', 'pcntl_exec', 'pcntl_fork'];
const NET_FUNCTIONS = ['wp_remote_get', 'wp_remote_post', 'wp_remote_head', 'wp_remote_request', 'wp_safe_remote_get',
    'wp_safe_remote_post', 'wp_safe_remote_head', 'wp_safe_remote_request', 'download_url', 'curl_init', 'curl_exec',
    'curl_multi_exec', 'fsockopen', 'pfsockopen', 'stream_socket_client', 'socket_create', 'socket_connect',
    'wp_mail', 'mail', 'ftp_connect', 'ftp_ssl_connect', 'ssh2_connect', 'dns_get_record', 'gethostbyname'];
const DIRECT_DB = ['mysqli_connect', 'mysqli_real_connect', 'mysql_connect', 'mysql_pconnect', 'pg_connect'];
// [path argument index, also counts as a write?] for filesystem functions.
const FS_FUNCTIONS = [
    'file_put_contents' => 0, 'mkdir' => 0, 'wp_mkdir_p' => 0, 'rename' => 1, 'copy' => 1, 'unlink' => 0,
    'rmdir' => 0, 'touch' => 0, 'chmod' => 0, 'chown' => 0, 'symlink' => 1, 'link' => 1, 'move_uploaded_file' => 1,
    'tempnam' => 0, 'insert_with_markers' => 0, 'unzip_file' => 1, 'copy_dir' => 1, 'wp_delete_file' => 0,
    'fopen' => 0, 'file_get_contents' => 0, 'file' => 0, 'readfile' => 0, 'parse_ini_file' => 0, 'is_writable' => 0,
];
const FS_READ_ONLY = ['file_get_contents', 'file', 'readfile', 'parse_ini_file', 'is_writable'];
const WPFS_METHODS = ['put_contents' => 0, 'mkdir' => 0, 'delete' => 0, 'move' => 1, 'copy' => 1, 'touch' => 0, 'chmod' => 0, 'rmdir' => 0];
const STORE_FUNCTIONS = ['update_option' => 1, 'add_option' => 1, 'set_transient' => 1, 'set_site_transient' => 1,
    'update_site_option' => 1, 'add_site_option' => 1, 'update_post_meta' => 2, 'add_post_meta' => 2,
    'update_user_meta' => 2, 'add_user_meta' => 2, 'update_term_meta' => 2, 'update_metadata' => 3,
    'wp_cache_set' => 1, 'wp_cache_add' => 1];
const CALLBACK_ARGS = ['add_action' => [1], 'add_filter' => [1], 'remove_action' => [1], 'remove_filter' => [1],
    'has_filter' => [1], 'has_action' => [1], 'array_map' => [0], 'array_filter' => [1], 'array_walk' => [1],
    'array_walk_recursive' => [1], 'usort' => [1], 'uasort' => [1], 'uksort' => [1], 'call_user_func' => [0],
    'call_user_func_array' => [0], 'register_activation_hook' => [1], 'register_deactivation_hook' => [1],
    'register_uninstall_hook' => [1], 'add_shortcode' => [1], 'is_callable' => [0], 'spl_autoload_register' => [0],
    'register_shutdown_function' => [0], 'set_error_handler' => [0], 'set_exception_handler' => [0],
    'add_menu_page' => [4], 'add_submenu_page' => [5], 'add_options_page' => [4], 'add_management_page' => [4],
    'add_theme_page' => [4], 'add_meta_box' => [2], 'wp_add_dashboard_widget' => [2], 'add_settings_field' => [2],
    'add_settings_section' => [2], 'preg_replace_callback' => [1], 'wp_schedule_single_event' => [], 'array_reduce' => [1]];
const SPECIAL_FILES = ['wp-config.php', '.htaccess', 'advanced-cache.php', 'object-cache.php', 'db.php', 'db-error.php',
    'sunrise.php', 'maintenance.php', '.maintenance', 'mu-plugins', '.user.ini', 'php.ini', 'web.config', 'wp-load.php',
    'wp-blog-header.php', 'wp-settings.php', 'WP_CACHE'];
// Calls that do nothing observable when a file is opened directly.
const PURE_TOP_CALLS = ['dirname', 'basename', 'define', 'defined', 'function_exists', 'class_exists', 'interface_exists',
    'trait_exists', 'enum_exists', 'version_compare', 'phpversion', 'is_array', 'is_string', 'is_int', 'is_numeric', 'is_bool',
    'in_array', 'array_merge', 'array_keys', 'array_values', 'array_map', 'array_filter', 'count', 'sprintf', 'implode', 'explode',
    'str_replace', 'strtolower', 'strtoupper', 'trim', 'rtrim', 'ltrim', 'substr', 'strlen', 'strpos', 'str_contains', 'constant',
    'array_key_exists', 'isset', 'empty', 'json_decode', 'max', 'min', 'intval', 'floatval', 'boolval', 'strval', 'realpath',
    'class_alias', 'spl_autoload_register', 'trigger_error', 'extension_loaded', 'ini_get', 'is_callable', 'method_exists'];
const BOOTSTRAP_FILES =['wp-load.php', 'wp-config.php', 'wp-blog-header.php', 'wp-admin/admin.php', 'wp-settings.php'];

// ---------------------------------------------------------------- pass 1: constants

final class ConstCollector extends NodeVisitorAbstract
{
    public array $defs = [];   // list of [name, expr, rel, class]
    private array $cls = [];
    public string $rel = '';

    public function enterNode(Node $n)
    {
        if ($n instanceof Stmt\ClassLike && $n->name) {
            $this->cls[] = $n->namespacedName?->toString() ?? $n->name->toString();
        } elseif ($n instanceof Expr\FuncCall && $n->name instanceof Node\Name && strtolower($n->name->toString()) === 'define'
            && ($n->args[0] ?? null) instanceof Node\Arg && $n->args[0]->value instanceof Scalar\String_
            && ($n->args[1] ?? null) instanceof Node\Arg) {
            $this->defs[] = [$n->args[0]->value->value, $n->args[1]->value, $this->rel, end($this->cls) ?: null];
        } elseif ($n instanceof Stmt\Const_ && !$this->cls) {
            foreach ($n->consts as $c) {
                $this->defs[] = [$c->namespacedName?->toString() ?? $c->name->toString(), $c->value, $this->rel, null];
            }
        } elseif ($n instanceof Stmt\ClassConst && $this->cls) {
            foreach ($n->consts as $c) {
                $this->defs[] = [end($this->cls) . '::' . $c->name->toString(), $c->value, $this->rel, end($this->cls)];
            }
        }
        return null;
    }

    public function leaveNode(Node $n)
    {
        if ($n instanceof Stmt\ClassLike && $n->name) {
            array_pop($this->cls);
        }
        return null;
    }
}

$files = php_files($pluginDir);
$cc = new ConstCollector();
$tr = new NodeTraverser();
$tr->addVisitor($cc);
foreach ($files as $rel) {
    $code = (string) @file_get_contents("$pluginDir/$rel");
    if (!str_contains($code, 'define') && !str_contains($code, 'const ')) {
        continue;
    }
    $cc->rel = $rel;
    $tr->traverse(parse_file("$pluginDir/$rel")->stmts);
}
$consts = [];
$classConsts = [];
for ($round = 0; $round < 6; $round++) {
    $changed = false;
    foreach ($cc->defs as [$name, $expr, $rel, $cls]) {
        $isClass = str_contains($name, '::');
        if ($isClass ? isset($classConsts[$name]) : isset($consts[$name])) {
            continue;
        }
        $ctx = new Ctx($ROOT, $rel);
        $ctx->class = $cls;
        $ctx->consts = $consts;
        $ctx->classConsts = $classConsts;
        $v = render($expr, $ctx);
        if (!is_dynamic($v) && !str_starts_with(substr(strrchr('\\' . get_class($expr), '\\'), 1), 'Array')) {
            if ($isClass) {
                $classConsts[$name] = $v;
            } else {
                $consts[$name] = $v;
            }
            $changed = true;
        }
    }
    if (!$changed) {
        break;
    }
}
$definedConstNames = [];
foreach ($cc->defs as [$name]) {
    if (!str_contains($name, '::')) {
        $definedConstNames[$name] = true;
    }
}
unset($cc, $tr);

// ---------------------------------------------------------------- pass 2: uses

final class Usage extends NodeVisitorAbstract
{
    public array $R = ['own' => [], 'vendor' => []];
    public array $definedFns = [];     // lower FQ name => true (top-level / namespaced functions only)
    public array $methodNames = [];    // lower method name => first location
    public array $definedClasses = []; // lower FQ => name
    public array $totals = [];
    public string $rel = '';
    public string $scope = 'own';
    public array $lines = [];
    public array $entry = [];
    private array $cls = [];
    private array $frames = [];
    public Ctx $ctx;

    public function __construct(public string $root, public string $slug, public array $consts, public array $classConsts) {}

    public function file(string $rel, string $code): void
    {
        $this->rel = $rel;
        $this->scope = is_vendor_path($rel) ? 'vendor' : 'own';
        $this->lines = explode("\n", $code);
        $this->cls = [];
        $this->frames = [['name' => '(file)', 'new' => [], 'mentions' => [], 'writes' => [], 'globals' => []]];
        $this->ctx = $this->newCtx();
    }

    private function newCtx(): Ctx
    {
        $c = new Ctx($this->root, $this->rel);
        $c->class = end($this->cls) ?: null;
        $c->consts = $this->consts;
        $c->classConsts = $this->classConsts;
        return $c;
    }

    private function at(Node $n): string
    {
        return $this->rel . ':' . $n->getStartLine();
    }

    private function line(Node $n): string
    {
        return trim(substr(trim($this->lines[$n->getStartLine() - 1] ?? ''), 0, 200));
    }

    private function where(): string
    {
        $f = end($this->frames)['name'];
        $c = end($this->cls);
        return $c && $f !== '(file)' ? "$c::$f" : $f;
    }

    /** Count $key in $R[scope][$cat] and keep a few sample locations. */
    private function hit(string $cat, string $key, Node $n, int $samples = 3, array $extra = []): void
    {
        $b = &$this->R[$this->scope][$cat][$key];
        $b['n'] = ($b['n'] ?? 0) + 1;
        if (count($b['at'] ?? []) < $samples) {
            $b['at'][] = $this->at($n);
        }
        foreach ($extra as $k => $v) {
            $b[$k] = $v;
        }
    }

    private function rec(string $cat, array $row): void
    {
        $this->R[$this->scope][$cat][] = $row;
    }

    private function tot(string $k, int $by = 1): void
    {
        $this->totals[$this->scope][$k] = ($this->totals[$this->scope][$k] ?? 0) + $by;
    }

    private function frame(): array
    {
        return end($this->frames);
    }

    public function enterNode(Node $n)
    {
        // ---- scope tracking and declarations
        if ($n instanceof Stmt\ClassLike) {
            if ($n->name) {
                $name = $n->namespacedName?->toString() ?? $n->name->toString();
                $this->definedClasses[strtolower($name)] = $name;
                $this->cls[] = $name;
            } else {
                $this->cls[] = '(anonymous class)';
            }
            $this->ctx = $this->newCtx();
            if ($n instanceof Stmt\Class_ || $n instanceof Expr\New_) {
                if ($n->extends ?? null) {
                    $this->hit('class_extends', ltrim($n->extends->toString(), '\\'), $n);
                }
                foreach ($n->implements ?? [] as $i) {
                    $this->hit('class_implements', ltrim($i->toString(), '\\'), $n);
                }
            } elseif ($n instanceof Stmt\Interface_) {
                foreach ($n->extends as $i) {
                    $this->hit('class_implements', ltrim($i->toString(), '\\'), $n);
                }
            }
        }
        if ($n instanceof Stmt\Function_) {
            $name = $n->namespacedName?->toString() ?? $n->name->toString();
            $this->definedFns[strtolower($name)] = true;
            $this->frames[] = ['name' => $n->name->toString(), 'new' => [], 'mentions' => [], 'writes' => [], 'globals' => []];
        } elseif ($n instanceof Stmt\ClassMethod) {
            $this->methodNames[strtolower($n->name->toString())] ??= $this->at($n);
            $this->frames[] = ['name' => $n->name->toString(), 'new' => [], 'mentions' => [], 'writes' => [], 'globals' => []];
        } elseif ($n instanceof Expr\Closure || $n instanceof Expr\ArrowFunction) {
            $this->frames[] = ['name' => end($this->frames)['name'] . '{closure}', 'new' => [], 'mentions' => [], 'writes' => [], 'globals' => []];
        }
        if ($n instanceof Stmt\TraitUse) {
            foreach ($n->traits as $t) {
                $this->hit('class_uses_trait', ltrim($t->toString(), '\\'), $n);
            }
        }

        // ---- function calls
        if ($n instanceof Expr\FuncCall) {
            if (!$n->name instanceof Node\Name) {
                $this->tot('fn_calls_dynamic');
                $this->hit('risky', 'variable function call $f()', $n, 5);
                return null;
            }
            $this->tot('fn_calls');
            [$ns, $global] = name_candidates($n->name);
            $this->hit('calls', ($ns ?? '') . '|' . $global, $n, 2);
            $this->call(strtolower($n->name->getLast()), $n, $ns === null && !($n->name instanceof Node\Name\FullyQualified) && str_contains($global, '\\'));
        } elseif ($n instanceof Expr\MethodCall || $n instanceof Expr\NullsafeMethodCall) {
            if (!$n->name instanceof Node\Identifier) {
                $this->tot('method_calls_dynamic');
            } else {
                $this->tot('method_calls');
                $this->method(strtolower($n->name->toString()), $n);
            }
        } elseif ($n instanceof Expr\StaticCall) {
            if (!$n->name instanceof Node\Identifier || !$n->class instanceof Node\Name) {
                $this->tot('static_calls_dynamic');
            } else {
                $this->tot('static_calls');
                $c = $n->class->toString();
                if (!in_array(strtolower($c), ['self', 'static', 'parent'], true)) {
                    $this->hit('class_static', ltrim($c, '\\'), $n);
                }
            }
        } elseif ($n instanceof Expr\New_) {
            if ($n->class instanceof Node\Name) {
                $this->tot('new');
                $c = $n->class->toString();
                if (!in_array(strtolower($c), ['self', 'static', 'parent'], true)) {
                    $this->hit('class_new', ltrim($c, '\\'), $n);
                    if (in_array(strtolower(ltrim($c, '\\')), ['mysqli', 'pdo'], true)) {
                        $this->rec('direct_db', ['at' => $this->at($n), 'what' => "new $c", 'in' => $this->where(), 'line' => $this->line($n)]);
                    }
                }
            } elseif (!$n->class instanceof Stmt\Class_) {
                $this->tot('new_dynamic');
                $this->hit('risky', 'new $class (dynamic class name)', $n, 5);
            }
        } elseif ($n instanceof Expr\Instanceof_ && $n->class instanceof Node\Name) {
            $this->hit('class_instanceof', ltrim($n->class->toString(), '\\'), $n, 1);
        } elseif ($n instanceof Stmt\Catch_) {
            foreach ($n->types as $t) {
                $this->hit('class_catch', ltrim($t->toString(), '\\'), $n, 1);
            }
        }

        // ---- constants
        if ($n instanceof Expr\ConstFetch) {
            [$ns, $global] = name_candidates($n->name);
            if (!in_array(strtolower($global), ['true', 'false', 'null'], true)) {
                $this->hit('constants', ($ns ?? '') . '|' . $global, $n, 2);
                if (in_array($global, SECRET_CONSTANTS, true)) {
                    $this->rec('secrets', ['at' => $this->at($n), 'what' => $global, 'in' => $this->where(), 'line' => $this->line($n)]);
                }
            }
        }

        // ---- globals
        if ($n instanceof Stmt\Global_) {
            foreach ($n->vars as $v) {
                if ($v instanceof Expr\Variable && is_string($v->name)) {
                    $this->hit('globals', $v->name, $n, 2);
                    $this->frames[count($this->frames) - 1]['globals'][$v->name] = true;
                } else {
                    $this->tot('globals_dynamic');
                }
            }
        } elseif ($n instanceof Expr\ArrayDimFetch && $n->var instanceof Expr\Variable && $n->var->name === 'GLOBALS') {
            if ($n->dim instanceof Scalar\String_) {
                $this->hit('globals', $n->dim->value, $n, 2);
            } else {
                $this->tot('globals_dynamic');
                $this->hit('risky', '$GLOBALS[$dynamic]', $n, 3);
            }
        } elseif ($n instanceof Expr\Variable && !is_string($n->name)) {
            $this->hit('risky', 'variable variable $$x', $n, 3);
        }
        if ($n instanceof Expr\Assign || $n instanceof Expr\AssignRef || $n instanceof Expr\AssignOp) {
            $v = $n->var;
            if ($v instanceof Expr\Variable && is_string($v->name) && isset($this->frame()['globals'][$v->name])) {
                $this->hit('globals_written', $v->name, $n, 2);
            } elseif ($v instanceof Expr\ArrayDimFetch && $v->var instanceof Expr\Variable && $v->var->name === 'GLOBALS'
                && $v->dim instanceof Scalar\String_) {
                $this->hit('globals_written', $v->dim->value, $n, 2);
            }
            if ($n instanceof Expr\Assign && $v instanceof Expr\Variable && is_string($v->name) && $n->expr instanceof Expr\New_) {
                $this->frames[count($this->frames) - 1]['new'][$v->name] = true;
            }
        }

        // ---- wpdb secrets
        if (($n instanceof Expr\PropertyFetch || $n instanceof Expr\NullsafePropertyFetch) && $n->name instanceof Node\Identifier
            && in_array(strtolower($n->name->toString()), SECRET_WPDB_PROPS, true) && is_wpdb_expr($n->var)) {
            $this->rec('secrets', ['at' => $this->at($n), 'what' => '$wpdb->' . $n->name->toString(), 'in' => $this->where(), 'line' => $this->line($n)]);
        }

        // ---- includes
        if ($n instanceof Expr\Include_) {
            $kind = [1 => 'include', 2 => 'include_once', 3 => 'require', 4 => 'require_once'][$n->type];
            $p = render($n->expr, $this->ctx);
            $np = normalize_path($p);
            [$class, $how] = classify_path($np, $this->slug);
            $this->tot('includes');
            $this->tot("includes_$how");
            $row = ['at' => $this->at($n), 'kind' => $kind, 'path' => shown($np), 'class' => $class, 'how' => $how];
            if ($class === 'core' && $how === 'resolved') {
                $row['core_file'] = core_rel($np);
            }
            foreach (BOOTSTRAP_FILES as $b) {
                if (str_ends_with(shown($np), $b)) {
                    $row['bootstrap'] = $b;
                    if ($b === 'wp-config.php' || $b === 'wp-load.php') {
                        $this->rec('secrets', ['at' => $this->at($n), 'what' => "$kind $b", 'in' => $this->where(), 'line' => $this->line($n)]);
                    }
                }
            }
            $this->rec('includes', $row);
        }

        // ---- risky
        if ($n instanceof Expr\Eval_) {
            $this->hit('risky', 'eval', $n, 5);
            $inner = (new PhpParser\NodeFinder())->findFirst([$n->expr], fn($x) => $x instanceof Expr\FuncCall && $x->name instanceof Node\Name
                && in_array(strtolower($x->name->getLast()), ['base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13', 'hex2bin'], true));
            if ($inner) {
                $this->hit('risky', 'eval(base64_decode/gzinflate…)', $n, 5);
            }
            $this->rec('eval', ['at' => $this->at($n), 'in' => $this->where(), 'line' => $this->line($n)]);
        } elseif ($n instanceof Expr\ShellExec) {
            $this->hit('risky', 'shell: `backticks`', $n, 5);
            $this->rec('exec', ['at' => $this->at($n), 'what' => 'backticks', 'in' => $this->where(), 'line' => $this->line($n)]);
        }

        // ---- strings: hosts, special files, SQL
        if ($n instanceof Scalar\String_ || $n instanceof Node\InterpolatedStringPart) {
            $s = $n->value;
            if (strlen($s) < 4000) {
                if (preg_match_all('~https?://([a-z0-9][a-z0-9.-]*\.[a-z]{2,})~i', $s, $m)) {
                    foreach (array_unique(array_map('strtolower', $m[1])) as $h) {
                        $this->hit('hosts', $h, $n, 1);
                    }
                }
                foreach (SPECIAL_FILES as $sf) {
                    if (stripos($s, $sf) !== false && !($sf === 'db.php' && !preg_match('#(^|/|\\\\)db\.php$#', $s))) {
                        $this->hit('mentions', $sf, $n, 3);
                        $this->frames[count($this->frames) - 1]['mentions'][$sf] = true;
                    }
                }
            }
        }
        if ($this->isTopString($n)) {
            $this->sql($n);
        }
        return null;
    }

    /** The outermost node of a string expression (a literal, interpolation or concatenation). */
    private function isTopString(Node $n): bool
    {
        if (!($n instanceof Scalar\String_ || $n instanceof Scalar\InterpolatedString || $n instanceof Expr\BinaryOp\Concat)) {
            return false;
        }
        $p = $n->getAttribute('_parent_concat', false);
        return !$p;
    }

    private function sql(Node $n): void
    {
        // Mark children so only the outermost concatenation is rendered.
        if ($n instanceof Expr\BinaryOp\Concat) {
            $stack = [$n->left, $n->right];
            while ($stack) {
                $x = array_pop($stack);
                $x->setAttribute('_parent_concat', true);
                if ($x instanceof Expr\BinaryOp\Concat) {
                    $stack[] = $x->left;
                    $stack[] = $x->right;
                }
            }
        }
        $s = render($n, $this->ctx);
        if (strlen($s) > 20000 || !preg_match('/\b(SELECT\b[\s\S]+?\bFROM|INSERT\s+(IGNORE\s+)?INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE|REPLACE\s+INTO|TRUNCATE\s+TABLE|(?:OPTIMIZE|ANALYZE|REPAIR|CHECK)\s+TABLE|SHOW\s+TABLES|SHOW\s+(FULL\s+)?COLUMNS)\b/i', $s)) {
            return;
        }
        $this->tot('sql_strings');
        if (preg_match_all('/\b(FROM|JOIN|INTO|UPDATE|TABLE(?:\s+IF\s+(?:NOT\s+)?EXISTS)?)\s+`?((?:\{prefix\}|' . T0 . '[^' . T1 . ']*' . T1 . '|[A-Za-z0-9_$.])+)`?/i', $s, $m, PREG_SET_ORDER)) {
            foreach ($m as $mm) {
                $kw = strtoupper(preg_replace('/\s.*/s', '', $mm[1]));
                $t = $mm[2];
                // SQL keywords and words from error messages ("create table for … failed").
                if (in_array(strtolower(rtrim($t, '.')), ['select', 'the', 'a', 'an', 'set', 'where', 'information_schema', 'if', 'for', 'failed',
                    'returned', 'schema', 'exists', 'not', 'statement', 'query', 'when', 'with', 'and', 'or', 'on', 'in', 'is', 'to', 'of',
                    'this', 'that', 'which', 'was', 'has', 'been', 'be', 'error', 'already', 'named', 'called', 'using', 'table', 'tables',
                    'your', 'its', 'their', 'dual', 'values', 'as', 'from', 'into', 'join'], true) || is_numeric($t)) {
                    continue;
                }
                $this->hit('sql_tables', shown($t), $n, 2);
                if (preg_match('/^CREATE/i', substr($s, max(0, strpos($s, $mm[0]) - 20), 30)) || ($kw === 'TABLE' && preg_match('/CREATE\s+TABLE(\s+IF\s+NOT\s+EXISTS)?\s+`?' . preg_quote($t, '/') . '/i', $s))) {
                    $this->hit('tables_created', shown($t), $n, 2);
                }
            }
        }
    }

    private function argExpr(Node $call, int $i): ?Node
    {
        $a = $call->args[$i] ?? null;
        return $a instanceof Node\Arg ? $a->value : null;
    }

    private function isObjectExpr(?Node $e): bool
    {
        return $e instanceof Expr\New_ || ($e instanceof Expr\Variable && ($e->name === 'this' || (is_string($e->name) && isset($this->frame()['new'][$e->name]))));
    }

    private function call(string $fn, Expr\FuncCall $n, bool $_q): void
    {
        $a0 = $this->argExpr($n, 0);

        // String callbacks: a core function named as a string is invisible to a call scan (#36).
        foreach (CALLBACK_ARGS[$fn] ?? [] as $i) {
            $cb = $this->argExpr($n, $i);
            if ($cb instanceof Scalar\String_ && preg_match('/^\\\\?[A-Za-z_][A-Za-z0-9_\\\\]*$/', $cb->value)) {
                $this->hit('string_callbacks', ltrim($cb->value, '\\') . "\t" . $fn, $n, 2);
            }
        }

        if (in_array($fn, HOOK_ADD, true) || in_array($fn, HOOK_OTHER, true) || in_array($fn, HOOK_FIRE, true)) {
            if ($a0 === null) {
                return;
            }
            $tag = render($a0, $this->ctx);
            $kind = in_array($fn, HOOK_FIRE, true) ? 'fire' : (in_array($fn, HOOK_ADD, true) ? 'add' : 'other');
            $this->tot("hooks_$kind");
            if (is_dynamic($tag)) {
                $this->tot("hooks_{$kind}_dynamic");
                $this->hit("hooks_{$kind}_dynamic", shown($tag), $n, 2);
            } else {
                $this->hit("hooks_$kind", $tag, $n, 1);
                if (!$a0 instanceof Scalar\String_) {
                    // Resolved here by folding constants/__FILE__, but not a literal in the
                    // source: a token scan (the current manifest generator) can't see it (#35).
                    $this->tot("hooks_{$kind}_folded");
                    $this->hit("hooks_{$kind}_folded", $tag, $n, 1);
                }
            }
            if ($kind === 'fire') {
                foreach (array_slice($n->args, 1) as $arg) {
                    if ($arg instanceof Node\Arg && $this->isObjectExpr($arg->value)) {
                        $this->hit('objects_crossing', "$fn(…, object)", $n, 3);
                        break;
                    }
                }
            }
            return;
        }
        if (in_array($fn, ['register_activation_hook', 'register_deactivation_hook', 'register_uninstall_hook'], true)) {
            $this->hit('lifecycle_hooks', $fn, $n, 2);
            return;
        }
        if ($fn === 'call_user_func' || $fn === 'call_user_func_array' || $fn === 'forward_static_call' || $fn === 'forward_static_call_array') {
            $this->tot('cuf');
            if (!$this->literalCallable($a0)) {
                $this->tot('cuf_dynamic');
                $this->hit('risky', 'call_user_func with a non-literal callable', $n, 5);
            }
            return;
        }
        if (in_array($fn, EXEC_FUNCTIONS, true)) {
            $this->hit('risky', "exec: $fn()", $n, 5);
            $this->rec('exec', ['at' => $this->at($n), 'what' => $fn, 'in' => $this->where(), 'line' => $this->line($n)]);
            return;
        }
        if (in_array($fn, ['unserialize', 'create_function', 'assert', 'extract', 'parse_str'], true)) {
            if ($fn === 'unserialize') {
                $opt = $this->argExpr($n, 1);
                $safe = $opt instanceof Expr\Array_ && (new PhpParser\NodeFinder())->findFirst([$opt], fn($x) => $x instanceof Scalar\String_ && $x->value === 'allowed_classes');
                $this->hit('risky', $safe ? 'unserialize (allowed_classes set)' : 'unserialize (any class)', $n, 5);
            } elseif ($fn === 'assert') {
                if ($a0 instanceof Scalar\String_ || $a0 instanceof Expr\Variable) {
                    $this->hit('risky', 'assert(string)', $n, 3);
                }
            } elseif ($fn === 'parse_str') {
                if (count($n->args) < 2) {
                    $this->hit('risky', 'parse_str into local scope', $n, 3);
                }
            } else {
                $this->hit('risky', "$fn()", $n, 5);
            }
            return;
        }
        if (in_array($fn, ['preg_replace', 'preg_filter'], true) && $a0 instanceof Scalar\String_
            && preg_match('/^(.).*\1([a-zA-Z]*)$/s', $a0->value, $mm) && str_contains($mm[2], 'e')) {
            $this->hit('risky', 'preg_replace /e', $n, 3);
        }
        if (in_array($fn, NET_FUNCTIONS, true)) {
            $this->hit('network', $fn, $n, 2);
            if ($a0 !== null && str_starts_with($fn, 'wp_') || in_array($fn, ['download_url', 'fsockopen', 'stream_socket_client'], true)) {
                $u = render($a0, $this->ctx);
                if (preg_match('~^(?:[a-z]+://)?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})~i', $u, $mm)) {
                    $this->hit('network_hosts', strtolower($mm[1]), $n, 1);
                } else {
                    $this->tot('network_url_dynamic');
                }
                $this->tot('network_url_calls');
            }
            return;
        }
        if (in_array($fn, DIRECT_DB, true)) {
            $this->rec('direct_db', ['at' => $this->at($n), 'what' => $fn, 'in' => $this->where(), 'line' => $this->line($n)]);
            return;
        }
        if ($fn === 'dbdelta' || $fn === 'maybe_create_table') {
            $this->hit('db_calls', $fn, $n, 3);
            return;
        }
        if (in_array($fn, SALTED_FUNCTIONS, true)) {
            $this->hit('salted', $fn, $n, 2);
        }
        if ($fn === 'constant' && $a0 instanceof Scalar\String_) {
            $this->hit('constants', '|' . $a0->value, $n, 2);
            if (in_array($a0->value, SECRET_CONSTANTS, true)) {
                $this->rec('secrets', ['at' => $this->at($n), 'what' => "constant('{$a0->value}')", 'in' => $this->where(), 'line' => $this->line($n)]);
            }
        }
        if ($fn === 'defined' && $a0 instanceof Scalar\String_) {
            $this->hit('defined_checks', $a0->value, $n, 1);
        }
        if ($fn === 'wp_upload_dir') {
            $this->hit('uploads', 'wp_upload_dir()', $n, 2);
        }
        if (in_array($fn, ['save_mod_rewrite_rules', 'flush_rewrite_rules', 'iis7_save_url_rewrite_rules'], true)) {
            $this->hit('rewrite', $fn, $n, 3);
            if ($fn === 'save_mod_rewrite_rules' || ($fn === 'flush_rewrite_rules' && !($a0 instanceof Expr\ConstFetch && strtolower($a0->name->toString()) === 'false'))) {
                $this->fsRow($fn, '{ABSPATH}/.htaccess', $n, true, 'core writes .htaccess when rewrite rules are flushed hard', '.htaccess via core (rewrite flush)');
            }
        }
        if (isset(STORE_FUNCTIONS[$fn]) && $this->isObjectExpr($this->argExpr($n, STORE_FUNCTIONS[$fn]))) {
            $this->hit('objects_crossing', "$fn(…, object)", $n, 3);
        }
        if ($fn === 'spl_autoload_register') {
            $this->hit('autoloaders', 'spl_autoload_register', $n, 3);
        }
        if (isset(FS_FUNCTIONS[$fn])) {
            $p = $this->argExpr($n, FS_FUNCTIONS[$fn]);
            if ($p === null) {
                return;
            }
            $write = !in_array($fn, FS_READ_ONLY, true);
            if ($fn === 'fopen') {
                $mode = $this->argExpr($n, 1);
                $write = !($mode instanceof Scalar\String_) || preg_match('/[waxc+]/', $mode->value) === 1;
            }
            $this->fsRow($fn, render($p, $this->ctx), $n, $write);
        }
    }

    private function fsRow(string $fn, string $path, Node $n, bool $write, string $note = '', ?string $forceClass = null): void
    {
        $np = normalize_path($path);
        [$class, $how] = classify_path($np, $this->slug);
        $class = $forceClass ?? $class;
        $row = ['at' => $this->at($n), 'fn' => $fn, 'path' => shown($np), 'class' => $class, 'how' => $how, 'in' => $this->where()];
        if ($note) {
            $row['note'] = $note;
        }
        if ($write) {
            $this->tot('fs_writes');
            $this->rec('fs_writes', $row);
            $this->frames[count($this->frames) - 1]['writes'][] = $row;
        } else {
            $this->rec('fs_reads', $row);
        }
        // Reading wp-config.php is reading the secrets (writes are in the writes table;
        // is_writable() is only a permission check).
        if (str_contains($row['path'], 'wp-config.php') && !$write && $fn !== 'is_writable') {
            $this->rec('secrets', ['at' => $this->at($n), 'what' => "$fn(wp-config.php)", 'in' => $this->where(), 'line' => $this->line($n)]);
        }
    }

    private function method(string $m, Node $n): void
    {
        if (is_wpdb_expr($n->var)) {
            $this->hit('wpdb_methods', $m, $n, 2);
            if (in_array($m, ['insert', 'update', 'delete', 'replace'], true)) {
                $t = $this->argExpr($n, 0);
                if ($t) {
                    $this->hit('sql_tables', shown(render($t, $this->ctx)), $n, 2);
                }
            }
            return;
        }
        if (isset(WPFS_METHODS[$m])) {
            $var = $n->var;
            $vn = $var instanceof Expr\Variable && is_string($var->name) ? $var->name
                : (($var instanceof Expr\PropertyFetch && $var->name instanceof Node\Identifier) ? $var->name->toString() : '');
            if ($m === 'put_contents' || stripos($vn, 'filesystem') !== false || $vn === 'wp_filesystem' || $vn === 'fs') {
                $p = $this->argExpr($n, WPFS_METHODS[$m]);
                if ($p) {
                    $this->fsRow('$wp_filesystem->' . $m, render($p, $this->ctx), $n, true);
                }
            }
        }
        if ($m === 'extractto') {
            $p = $this->argExpr($n, 0);
            if ($p) {
                $this->fsRow('->extractTo', render($p, $this->ctx), $n, true);
            }
        }
    }

    private function literalCallable(?Node $e): bool
    {
        if ($e instanceof Scalar\String_ || $e instanceof Expr\Closure || $e instanceof Expr\ArrowFunction) {
            return true;
        }
        if ($e instanceof Expr\Array_ && count($e->items) === 2 && $e->items[1]?->value instanceof Scalar\String_) {
            return true;
        }
        return false;
    }

    public function leaveNode(Node $n)
    {
        if ($n instanceof Stmt\ClassLike) {
            array_pop($this->cls);
            $this->ctx = $this->newCtx();
        }
        if ($n instanceof Stmt\Function_ || $n instanceof Stmt\ClassMethod || $n instanceof Expr\Closure || $n instanceof Expr\ArrowFunction) {
            $this->closeFrame(array_pop($this->frames));
        }
        return null;
    }

    public function finishFile(): void
    {
        $this->closeFrame($this->frames[0]);
    }

    public function closeFrame(array $f): void
    {
        // A function that both names a special file and writes somewhere probably writes that file.
        if ($f['mentions'] && $f['writes']) {
            foreach (['wp-config.php', '.htaccess', 'advanced-cache.php', 'object-cache.php', 'db.php', 'mu-plugins', '.user.ini', 'php.ini', 'WP_CACHE', 'maintenance.php', '.maintenance'] as $sf) {
                if (isset($f['mentions'][$sf])) {
                    $this->rec('likely_writes', ['special' => $sf, 'in' => $this->where() === '(file)' ? $f['name'] : (end($this->cls) ? end($this->cls) . '::' : '') . $f['name'],
                        'writes' => array_slice(array_map(fn($w) => $w['fn'] . ' ' . $w['path'] . ' @' . $w['at'], $f['writes']), 0, 3)]);
                }
            }
        }
    }

    /** Can this file do something when opened by URL, and does it guard against that? */
    public function entryPoint(array $stmts, array $includes): array
    {
        $flat = [];
        foreach ($stmts as $s) {
            if ($s instanceof Stmt\Namespace_) {
                array_push($flat, ...$s->stmts);
            } else {
                $flat[] = $s;
            }
        }
        $guard = false;
        $effects = false;
        $finder = new PhpParser\NodeFinder();
        foreach ($flat as $s) {
            if ($s instanceof Stmt\Use_ || $s instanceof Stmt\GroupUse || $s instanceof Stmt\Declare_ || $s instanceof Stmt\ClassLike
                || $s instanceof Stmt\Function_ || $s instanceof Stmt\Const_ || $s instanceof Stmt\Nop
                || ($s instanceof Stmt\InlineHTML && trim($s->value) === '')) {
                continue;
            }
            $hasExit = $finder->findFirst([$s], fn($x) => $x instanceof Expr\Exit_ || $x instanceof Stmt\Return_ || $x instanceof Expr\Throw_) !== null;
            $hasCheck = $finder->findFirst([$s], fn($x) => $x instanceof Expr\FuncCall && $x->name instanceof Node\Name
                && in_array(strtolower($x->name->toString()), ['defined', 'function_exists', 'class_exists'], true)) !== null;
            if (!$effects && $hasExit && $hasCheck) {
                $guard = true;
                break;
            }
            if ($s instanceof Stmt\Return_) {
                break; // a file that returns a value (config array) does nothing on its own
            }
            if ($s instanceof Stmt\If_ && $hasCheck && !$finder->findFirst($s->stmts, fn($x) => $x instanceof Expr\FuncCall || $x instanceof Stmt\Echo_ || $x instanceof Expr\Include_ || $x instanceof Expr\MethodCall || $x instanceof Expr\StaticCall)) {
                continue; // if (!function_exists('x')) { function x() {} }
            }
            $effects = true;
        }
        $boot = array_values(array_unique(array_filter(array_map(fn($r) => $r['bootstrap'] ?? null, $includes))));
        $code = implode("\n", $this->lines);
        $mentionsLoad = (bool) preg_match('/[\'"][^\'"]*wp-load\.php[\'"]/', $code);
        // What the top-level code calls (outside functions and classes), in order: the first
        // WordPress function decides whether opening the file directly just fatals.
        $calls = [];
        $includesTop = false;
        if ($effects && !$guard) {
            $top = array_filter($flat, fn($s) => !($s instanceof Stmt\ClassLike || $s instanceof Stmt\Function_));
            foreach ($finder->find($top, fn($x) => $x instanceof Expr\FuncCall || $x instanceof Expr\Include_ || $x instanceof Stmt\Echo_) as $x) {
                if ($x instanceof Expr\FuncCall && $x->name instanceof Node\Name) {
                    $calls[] = strtolower($x->name->getLast());
                } elseif ($x instanceof Expr\Include_) {
                    $includesTop = true;
                    $calls[] = '(include)';
                }
            }
        }
        return ['guard' => $guard, 'effects' => $effects, 'bootstraps' => $boot, 'mentions_wp_load' => $mentionsLoad,
            'top_calls' => array_values(array_unique($calls)), 'top_includes' => $includesTop];
    }
}

$phpFnTop = array_flip($I['php']['functions']);
$u = new Usage($ROOT, $slug, $consts, $classConsts);
$tr = new NodeTraverser();
$tr->addVisitor($u);
$parseErrors = [];
$entry = ['own' => [], 'vendor' => []];
$bytes = ['own' => 0, 'vendor' => 0];
$fileCount = ['own' => 0, 'vendor' => 0];
foreach ($files as $rel) {
    $p = parse_file("$pluginDir/$rel");
    if ($p->errors) {
        $parseErrors[] = "$rel: {$p->firstError}";
    }
    $u->file($rel, $p->code);
    $before = count($u->R[$u->scope]['includes'] ?? []);
    $tr->traverse($p->stmts);
    $u->finishFile();
    $fileIncludes = array_slice($u->R[$u->scope]['includes'] ?? [], $before);
    $e = $u->entryPoint($p->stmts, $fileIncludes);
    $bytes[$u->scope] += strlen($p->code);
    $fileCount[$u->scope]++;
    if ($e['bootstraps'] || $e['mentions_wp_load'] || ($e['effects'] && !$e['guard'])) {
        $kind = $e['bootstraps'] ? 'bootstraps WordPress' : 'names wp-load.php';
        if (!$e['bootstraps'] && (!$e['mentions_wp_load'] || ($e['effects'] && !$e['guard']))) {
            $wpCall = null;
            $other = false;
            foreach ($e['top_calls'] as $c) {
                if (isset($I['wp']['functions'][$c]) && !isset($phpFnTop[$c])) {
                    $wpCall = $c;
                    break;
                }
                if (!in_array($c, PURE_TOP_CALLS, true)) {
                    $other = true;
                }
            }
            $kind = $wpCall !== null && !$other ? 'fatal without WordPress' : ($other ? 'runs without WordPress' : ($e['mentions_wp_load'] ? 'names wp-load.php' : 'inert'));
            $e['first_wp_call'] = $wpCall;
            if (preg_match('#(^|/)(vendor|vendor[-_]prefixed|jetpack[-_]vendor)/(composer/|autoload[^/]*\.php$)|(^|/)autoload[^/]*\.php$#', $rel)) {
                $kind = 'autoloader';
            }
        }
        $entry[$u->scope][] = ['file' => $rel, 'kind' => $kind] + $e;
    }
}

// ---------------------------------------------------------------- classify

$coreFn = $I['wp']['functions'];
$coreCls = $I['wp']['classes'];
$coreConst = $I['wp']['constants'];
foreach ($I['wp_config_sample_constants'] as $c) {
    $coreConst[$c] ??= 'wp-config.php';
}
$coreGlobals = $I['wp']['globals'];
$isWoo = $slug === 'woocommerce';
$wooFn = $isWoo ? [] : $I['woo']['functions'];
$wooCls = $isWoo ? [] : $I['woo']['classes'];
$wooConst = $isWoo ? [] : $I['woo']['constants'];
$phpFn = array_flip($I['php']['functions']);
$phpCls = array_flip($I['php']['classes']);
$phpConst = array_flip($I['php']['constants']);
$extPrefix = '/^(mysqli_|mysql_|image|imagick|gd_|getimagesize|exif_|grapheme_|idn_to_|intl|numfmt_|normalizer_|locale_|collator_|msgfmt_|transliterator_|zip_|bc|gmp_|apcu?_|memcache|redis|xdebug_|opcache_|newrelic_|ftp_|ssh2_|gnupg_|mcrypt_|igbinary_|msgpack_|imap_|ldap_|pcntl_|posix_|wincache_|litespeed_|ioncube_|sg_|ini_|fastcgi_|apache_|getallheaders|uopz_|tideways_|blackfire|xhprof_|geoip_|yaml_|gzdeflate|zend_|sodium_|mb_|iconv)/';
$extClasses = ['ziparchive', 'imagick', 'imagickpixel', 'imagickdraw', 'mysqli', 'mysqli_result', 'mysqli_stmt', 'intldateformatter', 'numberformatter', 'normalizer', 'collator', 'redis', 'memcached', 'memcache', 'gmp', 'locale', 'messageformatter', 'transliterator', 'resourcebundle', 'intlchar', 'spoofchecker', 'uconverter', 'intlbreakiterator', 'gdimage', 'redisexception', 'imagickexception', 'pdo'];

$definedFns = $u->definedFns;
$definedCls = $u->definedClasses;

function classify_fn(string $name, array $sets): string
{
    [$coreFn, $wooFn, $phpFn, $definedFns, $extPrefix] = $sets;
    $l = strtolower(ltrim($name, '\\'));
    // PHP's own first: core polyfills some (mb_strlen, str_contains … in compat.php).
    if (isset($phpFn[$l])) {
        return 'php';
    }
    if (isset($coreFn[$l])) {
        return 'wp';
    }
    if (isset($wooFn[$l])) {
        return 'woo';
    }
    if (preg_match($extPrefix, $l)) {
        return 'php';
    }
    if (isset($definedFns[$l])) {
        return 'own';
    }
    return 'unknown';
}

$fnSets = [$coreFn, $wooFn, $phpFn, $definedFns, $extPrefix];
$coreFileSet = array_flip($I['wp']['file_list']);
$out = ['own' => [], 'vendor' => []];
foreach (['own', 'vendor'] as $scope) {
    $R = $u->R[$scope];
    // functions
    $fns = ['wp' => [], 'woo' => [], 'php' => [], 'own' => [], 'unknown' => []];
    foreach ($R['calls'] ?? [] as $key => $b) {
        [$ns, $global] = explode('|', $key, 2);
        if ($ns !== '' && isset($definedFns[strtolower($ns)])) {
            $name = $ns;
            $cls = 'own';
        } else {
            $name = ltrim($global, '\\');
            $cls = classify_fn($name, $fnSets);
        }
        $k = $cls === 'wp' || $cls === 'woo' || $cls === 'php' ? strtolower($name) : $name;
        $fns[$cls][$k]['n'] = ($fns[$cls][$k]['n'] ?? 0) + $b['n'];
        $fns[$cls][$k]['at'] = array_slice(array_merge($fns[$cls][$k]['at'] ?? [], $b['at']), 0, 2);
    }
    foreach ($fns as &$f) {
        uasort($f, fn($a, $b) => $b['n'] <=> $a['n']);
    }
    unset($f);
    // constants
    $cs = ['wp' => [], 'woo' => [], 'php' => [], 'own' => [], 'unknown' => []];
    foreach ($R['constants'] ?? [] as $key => $b) {
        [$ns, $global] = explode('|', $key, 2);
        $name = ($ns !== '' && isset($definedConstNames[$ns])) ? $ns : ltrim($global, '\\');
        $short = str_contains($name, '\\') ? substr(strrchr($name, '\\'), 1) : $name;
        // PHP's own first: core defines a few PHP constants for old PHP versions.
        $cls = isset($phpConst[$name]) ? 'php' : (isset($coreConst[$name]) ? 'wp' : (isset($wooConst[$name]) ? 'woo'
            : (isset($definedConstNames[$name]) ? 'own' : 'unknown')));
        $cs[$cls][$name]['n'] = ($cs[$cls][$name]['n'] ?? 0) + $b['n'];
        $cs[$cls][$name]['at'] = array_slice(array_merge($cs[$cls][$name]['at'] ?? [], $b['at']), 0, 2);
    }
    foreach ($R['defined_checks'] ?? [] as $name => $b) {
        if (isset($coreConst[$name])) {
            $cs['wp_checked'][$name] = $b;
        }
    }
    // classes
    $classes = [];
    foreach (['extends' => 'class_extends', 'implements' => 'class_implements', 'new' => 'class_new',
        'static' => 'class_static', 'instanceof' => 'class_instanceof', 'catch' => 'class_catch', 'trait' => 'class_uses_trait'] as $how => $cat) {
        foreach ($R[$cat] ?? [] as $name => $b) {
            $l = strtolower($name);
            // A class the plugin declares itself is its own, even when core ships one with the
            // same name (bundled copies of sodium_compat, PHPMailer, Requests, …).
            $cls = isset($phpCls[$l]) || in_array($l, $extClasses, true) ? 'php' : (isset($definedCls[$l]) ? 'own'
                : (isset($coreCls[$l]) ? 'wp' : (isset($wooCls[$l]) ? 'woo' : 'unknown')));
            $classes[$cls][$how][$name] = $b;
        }
    }
    // globals
    $globals = [];
    foreach ($R['globals'] ?? [] as $name => $b) {
        $cls = isset($coreGlobals[$name]) ? 'wp' : (isset($I['wp']['page_globals'][$name]) ? 'wp_page_scope' : 'other');
        $globals[$cls][$name] = $b + ['written' => isset($R['globals_written'][$name])];
    }
    // hooks
    $hooks = ['add_core' => [], 'add_woo' => [], 'add_other' => []];
    foreach ($R['hooks_add'] ?? [] as $tag => $b) {
        $cls = 'add_other';
        if (isset($I['wp']['hooks'][$tag])) {
            $cls = 'add_core';
        } elseif (!$isWoo && isset($I['woo']['hooks'][$tag])) {
            $cls = 'add_woo';
        } else {
            foreach ($I['wp']['hook_patterns'] as $re => $_) {
                if (@preg_match($re, $tag)) {
                    $cls = 'add_core';
                    $b['core_pattern'] = $_;
                    break;
                }
            }
        }
        $hooks[$cls][$tag] = $b;
    }
    $hooks['add_folded'] = $R['hooks_add_folded'] ?? [];
    $hooks['add_dynamic'] = $R['hooks_add_dynamic'] ?? [];
    $hooks['fire_dynamic'] = $R['hooks_fire_dynamic'] ?? [];
    $hooks['fire_literal_count'] = count($R['hooks_fire'] ?? []);
    $hooks['other_dynamic'] = $R['hooks_other_dynamic'] ?? [];
    // string callbacks naming core functions (#36)
    $scb = [];
    foreach ($R['string_callbacks'] ?? [] as $key => $b) {
        [$name, $via] = explode("\t", $key);
        $cls = classify_fn($name, $fnSets);
        $scb[$cls][$name . ' via ' . $via] = $b;
    }
    // includes summary
    $inc = $R['includes'] ?? [];
    $coreFiles = [];
    $notInCore = [];
    foreach ($inc as $i => $r) {
        if (isset($r['core_file'])) {
            if (isset($coreFileSet[$r['core_file']])) {
                $coreFiles[$r['core_file']][] = $r['at'];
            } else {
                // Resolves under ABSPATH but WordPress has no such file (WordPress.com-only
                // paths, plugin typos such as WPINC . 'http.php').
                $notInCore[$r['core_file']][] = $r['at'];
                $inc[$i]['class'] = 'ABSPATH (not a core file)';
            }
        }
    }
    ksort($coreFiles);
    $out[$scope] = [
        'files' => $fileCount[$scope],
        'bytes' => $bytes[$scope],
        'functions' => $fns,
        'constants' => $cs,
        'classes' => $classes,
        'globals' => $globals,
        'hooks' => $hooks,
        'lifecycle_hooks' => $R['lifecycle_hooks'] ?? [],
        'string_callbacks' => $scb,
        'includes' => [
            'core_files' => $coreFiles,
            'abspath_not_core' => $notInCore,
            'by_class' => array_count_values(array_map(fn($r) => $r['class'] . ' (' . $r['how'] . ')', $inc)),
            'non_own' => array_values(array_filter($inc, fn($r) => !($r['class'] === 'own folder' && $r['how'] === 'resolved'))),
        ],
        'wpdb_methods' => $R['wpdb_methods'] ?? [],
        'db_calls' => $R['db_calls'] ?? [],
        'sql_tables' => $R['sql_tables'] ?? [],
        'tables_created' => $R['tables_created'] ?? [],
        'direct_db' => $R['direct_db'] ?? [],
        'fs_writes' => $R['fs_writes'] ?? [],
        'fs_reads_outside_own' => array_values(array_filter($R['fs_reads'] ?? [], fn($r) => $r['class'] !== 'own folder')),
        'likely_writes' => $R['likely_writes'] ?? [],
        'mentions' => $R['mentions'] ?? [],
        'network' => $R['network'] ?? [],
        'network_hosts' => $R['network_hosts'] ?? [],
        'hosts' => $R['hosts'] ?? [],
        'risky' => $R['risky'] ?? [],
        'exec' => $R['exec'] ?? [],
        'eval' => $R['eval'] ?? [],
        'secrets' => $R['secrets'] ?? [],
        'salted' => $R['salted'] ?? [],
        'uploads' => $R['uploads'] ?? [],
        'rewrite' => $R['rewrite'] ?? [],
        'objects_crossing' => $R['objects_crossing'] ?? [],
        'autoloaders' => $R['autoloaders'] ?? [],
        'entry_points' => $entry[$scope],
        'totals' => $u->totals[$scope] ?? [],
    ];
}

// Keep the files small: for the plugin's own symbols and PHP's, counts only (locations are
// kept for everything WordPress / WooCommerce, which is what the survey is about).
$countsOnly = fn(array $m) => array_map(fn($b) => $b['n'], $m);
foreach (['own', 'vendor'] as $scope) {
    foreach (['php', 'own'] as $k) {
        $out[$scope]['functions'][$k] = $countsOnly($out[$scope]['functions'][$k]);
        $out[$scope]['constants'][$k] = $countsOnly($out[$scope]['constants'][$k]);
        foreach ($out[$scope]['classes'][$k] ?? [] as $how => $m) {
            $out[$scope]['classes'][$k][$how] = $countsOnly($m);
        }
    }
    $out[$scope]['hooks']['add_other'] = $countsOnly($out[$scope]['hooks']['add_other']);
    $out[$scope]['hosts'] = $countsOnly($out[$scope]['hosts']);
    $out[$scope]['string_callbacks']['own'] = $countsOnly($out[$scope]['string_callbacks']['own'] ?? []);
    $out[$scope]['string_callbacks']['php'] = $countsOnly($out[$scope]['string_callbacks']['php'] ?? []);
}

// #30: core functions the plugin calls that share a name with one of its methods.
$calledCore = array_unique(array_merge(array_keys($out['own']['functions']['wp']), array_keys($out['vendor']['functions']['wp'])));
$shadow = [];
foreach ($calledCore as $f) {
    if (isset($u->methodNames[$f])) {
        $shadow[$f] = $u->methodNames[$f];
    }
}
ksort($shadow);
// Plugin defines a function core also defines (pluggables like wp_mail, or polyfills).
$redefines = [];
foreach ($definedFns as $f => $_) {
    if (isset($coreFn[$f])) {
        $redefines[$f] = $coreFn[$f];
    }
}

// Bundled code and PHP version.
$mainHeader = [];
foreach (glob("$pluginDir/*.php") as $f) {
    $head = (string) file_get_contents($f, false, null, 0, 8192);
    if (preg_match('/^[ \t\/*#@]*Plugin Name:\s*(.+)$/mi', $head)) {
        foreach (['Plugin Name', 'Version', 'Requires PHP', 'Requires at least', 'Requires Plugins'] as $h) {
            if (preg_match('/^[ \t\/*#@]*' . preg_quote($h, '/') . ':\s*(.+)$/mi', $head, $m)) {
                $mainHeader[$h] = trim($m[1]);
            }
        }
        $mainHeader['file'] = basename($f);
        break;
    }
}
$composer = [];
foreach (['composer.json'] as $cf) {
    if (is_file("$pluginDir/$cf")) {
        $j = json_decode((string) file_get_contents("$pluginDir/$cf"), true) ?: [];
        $composer['php'] = $j['require']['php'] ?? null;
    }
}
$packages = [];
foreach (array_merge(glob("$pluginDir/vendor/composer/installed.json") ?: [], glob("$pluginDir/*/vendor/composer/installed.json") ?: [], glob("$pluginDir/*/*/vendor/composer/installed.json") ?: []) as $ij) {
    $j = json_decode((string) file_get_contents($ij), true) ?: [];
    foreach ($j['packages'] ?? $j as $pk) {
        if (isset($pk['name'])) {
            $packages[$pk['name']] = $pk['version'] ?? '';
        }
    }
}
ksort($packages);
$vendorDirs = [];
foreach ($files as $rel) {
    if (preg_match('#^(.*?(?:^|/)(?:vendor|vendor[-_]prefixed|jetpack[-_]vendor|third[-_]?party|node_modules))/#i', $rel, $m)) {
        $vendorDirs[$m[1]] = ($vendorDirs[$m[1]] ?? 0) + 1;
    }
}

json_out($outPath, [
    'slug' => $slug,
    'header' => $mainHeader,
    'php_files' => count($files),
    'parse_error_files' => $parseErrors,
    'own' => $out['own'],
    'vendor' => $out['vendor'],
    'method_named_like_called_core_function' => $shadow,
    'redefines_core_functions' => $redefines,
    'plugin_constants_resolved' => count($consts),
    'plugin_constants_defined' => count($definedConstNames),
    'bundled' => [
        'composer_php' => $composer['php'] ?? null,
        'vendor_dirs' => $vendorDirs,
        'composer_packages' => $packages,
        'has_vendor_autoload' => (bool) (glob("$pluginDir/vendor/autoload.php") ?: glob("$pluginDir/*/vendor/autoload.php")),
    ],
    'seconds' => round(microtime(true) - $t0, 1),
], false); // compact: the 56 files are ~8 MB this way, twice that pretty-printed (`jq .` to read one)
fprintf(STDERR, "%s: %d files, %.1fs, %d parse-error files\n", $slug, count($files), microtime(true) - $t0, count($parseErrors));
