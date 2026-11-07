<?php
// Runs inside the wasm sandbox before the plugin's main file.
//
// The plugin sees a WordPress API, but every WordPress function here is a stand-in that
// sends the call to core (securecore-core.php) and waits for the answer. Core checks each call
// against the plugin's manifest. The plugin's own callbacks stay here, numbered; core
// holds a stub per callback and calls back in when the hook fires.
//
// Line protocol, one message per line: base64(serialize(array)).
//   sandbox → core: ['wp', fn, args, output]  ['hook', fn, tag, id, priority, accepted]
//                   ['ready', output]  ['return', value, output]  ['throw', message, output]
//                   ['log', message]
//   core → sandbox: ['boot', context]  ['call', id, args]  ['return', value]
//                   ['throw', message]  ['end']
// Messages go out on STDERR: p8 keeps writes to STDOUT buffered until exit, STDERR writes
// through. The securecore binary maps the sandbox's fd 2 to its own stdout.
namespace SecureCore;

require_once __DIR__ . '/scan.php';

// The line to core. Default: in on STDIN, out on STDERR (the wasm one-shot path; p8 keeps
// STDOUT buffered until exit). worker.php points both at the request's socket.
final class Conn
{
    /** @var resource */
    public static $in;
    /** @var resource */
    public static $out;
}
Conn::$in ??= STDIN;
Conn::$out ??= STDERR;

function send(array $message): void
{
    fwrite(Conn::$out, base64_encode(serialize($message)) . "\n");
}

function receive(): array
{
    $line = fgets(Conn::$in);
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

// The WordPress functions a plugin uses: the functions it calls but neither defines nor
// PHP has. One token_get_all pass over its files (the start of the manifest analyzer).
// Dynamic calls (call_user_func('x'), $f()) are not seen.
function called_functions(string $pluginPath): array
{
    // Stand-ins forward a call to core, which allows it only if the manifest grants it. We
    // forward only WordPress functions: a name the plugin calls that it does not define
    // (!function_exists) and that is not a PHP native. The natives to skip are exactly the
    // ones the launcher disabled (fsockopen, exec, curl_*, …) — ini_get tells us which — so
    // a dangerous native call fails in the sandbox instead of being forwarded to core.
    // PHP builtins still available (strlen, …) are function_exists, so they drop out too.
    $disabled = array_flip(array_filter(array_map('trim', explode(',', (string) ini_get('disable_functions')))));
    return array_values(array_filter(
        scan_plugin($pluginPath)['called'],
        fn (string $name) => !function_exists($name) && !isset($disabled[$name]),
    ));
}

// Serve one request: define the stand-ins, run the plugin, then the hook loop. In the
// worker this is the child after fork; the connection is already the request's socket.
// $standins is the list from called_functions(), computed once per plugin in the parent.
function serve_child(array $context, array $standins): void
{
    if (!defined('ABSPATH')) {
        // Plugins check ABSPATH before anything. It points at a folder that does not exist.
        define('ABSPATH', '/wordpress/');
        define('WPINC', 'wp-includes');
        define('SECURECORE_SANDBOX', true);
    }
    $_GET = $context['get'];
    $_POST = $context['post'];
    $_REQUEST = array_merge($_GET, $_POST);
    $_SERVER = array_merge($_SERVER, $context['server']);

    if (!function_exists('add_action')) {
        // Registering a hook keeps the callback here and tells core its number.
        eval(<<<'PHP'
function add_filter($tag, $callback, $priority = 10, $accepted = 1) { return \SecureCore\hook('add_filter', $tag, $callback, $priority, $accepted); }
function add_action($tag, $callback, $priority = 10, $accepted = 1) { return \SecureCore\hook('add_action', $tag, $callback, $priority, $accepted); }
PHP);
        // add_action/add_filter are defined just above; drop them and anything else that
        // now exists, so a stand-in never redeclares a real function.
        eval(implode("\n", array_map(
            fn (string $name) => "function $name(...\$a) { return \\SecureCore\\wp('$name', \$a); }",
            array_filter($standins, fn (string $name) => !function_exists($name)),
        )));
    }

    ob_start();
    $t = hrtime(true);
    try {
        require $context['main'];
    } catch (\Throwable $error) {
        send(['log', 'plugin failed to load: ' . $error->getMessage()]);
    }
    // The cost of including the plugin (with the opcache hit): read by bench/worker-breakdown.
    fwrite(Conn::$out, '#' . json_encode(['event' => 'timing', 'include_ms' => (hrtime(true) - $t) / 1e6]) . "\n");
    send(['ready', take_output()]);
    // Serve core's callbacks (hooks firing) until the request ends. Returns, so a no-fork
    // worker can reuse the process for the next request (and leak its state).
    for (;;) {
        $message = receive();
        if ($message[0] === 'call') serve($message[1], $message[2]);
        elseif ($message[0] === 'end') return;
    }
}

// Default path (wasm one-shot): one request on STDIN/STDERR, plugin at argv[1], stand-ins
// scanned from its folder. worker.php defines SECURECORE_WORKER and drives serve_child.
if (!defined('SECURECORE_WORKER')) {
    $boot = receive();
    if ($boot[0] !== 'boot') exit(1);
    $main = $boot[1]['main'] ?? ($argv[1] ?? '');
    serve_child(['main' => $main] + $boot[1], called_functions(dirname($main)));
}
