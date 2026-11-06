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
//                   ['log', message]
//   core → sandbox: ['boot', context]  ['call', id, args]  ['return', value]
//                   ['throw', message]  ['end']
// Messages go out on STDERR: p8 keeps writes to STDOUT buffered until exit, STDERR writes
// through. The securecore binary maps the sandbox's fd 2 to its own stdout.
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

// --- boot -------------------------------------------------------------------------------
$boot = receive();
if ($boot[0] !== 'boot') exit(1);
$context = $boot[1];

// Plugins check ABSPATH before doing anything. It points at a folder that does not exist.
define('ABSPATH', '/wordpress/');
define('WPINC', 'wp-includes');
define('SECURECORE_SANDBOX', true);

$_GET = $context['get'];
$_POST = $context['post'];
$_REQUEST = array_merge($_GET, $_POST);
$_SERVER = array_merge($_SERVER, $context['server']);

// Registering a hook keeps the callback here and tells core its number.
eval(<<<'PHP'
function add_filter($tag, $callback, $priority = 10, $accepted = 1) { return \SecureCore\hook('add_filter', $tag, $callback, $priority, $accepted); }
function add_action($tag, $callback, $priority = 10, $accepted = 1) { return \SecureCore\hook('add_action', $tag, $callback, $priority, $accepted); }
PHP);

$names = [];
foreach ($context['functions'] as $name) {
    if (preg_match('/^[a-z_][a-z0-9_]*$/i', $name) && !function_exists($name)) $names[] = $name;
}
eval(implode("\n", array_map(
    fn (string $name) => "function $name(...\$a) { return \\SecureCore\\wp('$name', \$a); }",
    $names,
)));

ob_start();
try {
    require $argv[1];
} catch (\Throwable $error) {
    send(['log', 'plugin failed to load: ' . $error->getMessage()]);
}
send(['ready', take_output()]);
wait();
