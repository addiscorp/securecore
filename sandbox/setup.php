<?php
// Runs inside the wasm sandbox before the plugin's main file.
//
// The plugin sees a WordPress API, but every WordPress function here is a stand-in that
// sends the call to core (SecureCore.php) and waits for the answer. Core checks each call
// against the plugin's manifest. The plugin's own callbacks stay here, numbered; core
// holds a stub per callback and calls back in when the hook fires.
//
// Line protocol, one message per line: base64(serialize(array)).
//   sandbox → core: ['wp', fn, args, output]  ['hook', fn, tag, id, priority, accepted]
//                   ['ready', output]  ['return', value, output]  ['throw', message, output]
//                   ['log', message]  ['prepared']
//   tab → sandbox:  ['prepare', ['main' => file]]   (before a request arrives)
//   core → sandbox: ['boot', context]  ['call', id, args]  ['return', value]
//                   ['throw', message]  ['end']
// Messages go out on STDERR: p8 keeps writes to STDOUT buffered until exit, STDERR writes
// through. The engine maps the sandbox's fd 2 to the message channel.
namespace SecureCore;

const OUT = STDERR;

function send(array $message): void
{
    fwrite(OUT, base64_encode(serialize($message)) . "\n");
}

function receive(): array
{
    $line = fgets(STDIN);
    if ($line === false) exit(0);
    $message = unserialize(base64_decode(trim($line)), ['allowed_classes' => false]);
    if (!is_array($message)) exit(1);
    return $message;
}

final class Callbacks
{
    /** @var array<int, callable> */
    public static array $table = [];

    public static function add(callable $callback): int
    {
        self::$table[] = $callback;
        return array_key_last(self::$table);
    }
}

// Closures and [object, method] pairs cannot cross. They stay here and cross as a number.
function export_value(mixed $value): mixed
{
    if ($value instanceof \Closure || (is_array($value) && count($value) === 2 && isset($value[0], $value[1]) && is_object($value[0]) && is_string($value[1]))) {
        return ['__securecore_callback' => Callbacks::add($value)];
    }
    if (is_array($value)) return array_map(export_value(...), $value);
    return $value;
}

// Output the plugin printed since the last message. Sent with every message so core can
// print it in the right place.
function take_output(): string
{
    $output = ob_get_clean();
    ob_start();
    return $output === false ? '' : $output;
}

// Wait for the reply to our own request, answering core's calls into us meanwhile.
function wait(): mixed
{
    for (;;) {
        $message = receive();
        switch ($message[0]) {
            case 'return':
                return $message[1];
            case 'throw':
                throw new \RuntimeException($message[1]);
            case 'call':
                serve($message[1], $message[2]);
                break;
            case 'end':
                exit(0);
        }
    }
}

function serve(int $id, array $args): void
{
    take_output();
    try {
        $value = (Callbacks::$table[$id])(...$args);
        send(['return', export_value($value), take_output()]);
    } catch (\Throwable $error) {
        send(['throw', $error->getMessage(), take_output()]);
    }
}

function wp(string $function, array $args): mixed
{
    send(['wp', $function, export_value($args), take_output()]);
    return wait();
}

function hook(string $function, string $tag, mixed $callback, int $priority, int $accepted): bool
{
    if (!is_callable($callback)) return false;
    send(['hook', $function, $tag, Callbacks::add($callback), $priority, $accepted]);
    return (bool) wait();
}

set_error_handler(function (int $level, string $message, string $file, int $line): bool {
    send(['log', "php: $message ($file:$line)"]);
    return true;
});

/**
 * The functions the plugin calls that it does not define and PHP does not have: those are
 * the WordPress functions it uses. One token_get_all pass over the plugin's files (the
 * start of the manifest analyzer). Dynamic calls (call_user_func('x'), $f()) are not seen.
 */
function called_functions(string $dir): array
{
    $called = $defined = [];
    $files = [];
    $walk = function (string $dir) use (&$walk, &$files) {
        foreach (scandir($dir) ?: [] as $name) {
            if ($name === '.' || $name === '..') continue;
            $path = "$dir/$name";
            if (is_dir($path)) $walk($path);
            elseif (str_ends_with($name, '.php')) $files[] = $path;
        }
    };
    $walk($dir);
    $skip = [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT];
    foreach ($files as $file) {
        $tokens = array_values(array_filter(
            token_get_all((string) file_get_contents($file)),
            fn ($t) => !is_array($t) || !in_array($t[0], $skip, true),
        ));
        foreach ($tokens as $i => $token) {
            if (!is_array($token) || !in_array($token[0], [T_STRING, T_NAME_FULLY_QUALIFIED], true)) continue;
            $name = strtolower(ltrim($token[1], '\\'));
            $prev = $tokens[$i - 1] ?? null;
            $prevId = is_array($prev) ? $prev[0] : $prev;
            if ($prevId === T_FUNCTION) { $defined[$name] = true; continue; }
            if (($tokens[$i + 1] ?? null) !== '(') continue;
            if (in_array($prevId, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_NEW], true)) continue;
            $called[$name] = true;
        }
    }
    return array_values(array_filter(
        array_keys(array_diff_key($called, $defined)),
        fn (string $name) => preg_match('/^[a-z_][a-z0-9_]*$/', $name) && !function_exists($name),
    ));
}

// --- prepare: off the request path ------------------------------------------------------
// The tab boots an instance up to here before any request arrives.
$prepare = receive();
if ($prepare[0] !== 'prepare') exit(1);
$main = '/plugin/' . $prepare[1]['main'];

// Plugins check ABSPATH before doing anything. It points at a folder that does not exist.
define('ABSPATH', '/wordpress/');
define('WPINC', 'wp-includes');
define('SECURECORE_SANDBOX', true);

// Registering a hook keeps the callback here and tells core its number.
eval(<<<'PHP'
function add_filter($tag, $callback, $priority = 10, $accepted = 1) { return \SecureCore\hook('add_filter', $tag, $callback, $priority, $accepted); }
function add_action($tag, $callback, $priority = 10, $accepted = 1) { return \SecureCore\hook('add_action', $tag, $callback, $priority, $accepted); }
PHP);

// A stand-in for each WordPress function the plugin calls. Core decides: a granted one
// runs, any other is refused and logged.
eval(implode("\n", array_map(
    fn (string $name) => "function $name(...\$a) { return \\SecureCore\\wp('$name', \$a); }",
    called_functions('/plugin'),
)));
send(['prepared']);

// --- boot: one request ------------------------------------------------------------------
$boot = receive();
if ($boot[0] !== 'boot') exit(1);
$context = $boot[1];
$_GET = $context['get'];
$_POST = $context['post'];
$_REQUEST = array_merge($_GET, $_POST);
$_SERVER = array_merge($_SERVER, $context['server']);

ob_start();
try {
    require $main;
} catch (\Throwable $error) {
    send(['log', 'plugin failed to load: ' . $error->getMessage()]);
}
send(['ready', take_output()]);
wait();
