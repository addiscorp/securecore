<?php
// Request isolation: two requests to the same plugin must not see each other's state.
// Runs inside the php container (it reaches the worker socket). Plays core: boots the
// state plugin with a given ?id, fires its securecore_state hook, returns what the hook saw.
//
//   php isolation.php <socket>            fork worker: each request sees only its own id
//   php isolation.php <socket> leak       expects the leak (for the no-fork worker)
//
// Exits non-zero if the result isn't what the mode expects.
$socket = $argv[1] ?? '/run/securecore/worker.sock';
$expectLeak = ($argv[2] ?? '') === 'leak';

function request(string $socket, string $id): string
{
    $s = @stream_socket_client("unix://$socket", $errno, $errstr, 5);
    if (!$s) throw new RuntimeException("connect: $errstr");
    stream_set_timeout($s, 5);
    $send = fn (array $m) => fwrite($s, base64_encode(serialize($m)) . "\n");
    $recv = function () use ($s) {
        $line = fgets($s);
        if ($line === false) throw new RuntimeException('worker closed the connection');
        return $line[0] === '#' ? ['#'] : unserialize(base64_decode(trim($line)), ['allowed_classes' => false]);
    };
    $send(['boot', ['plugin' => 'securecore-state/securecore-state.php', 'get' => ['id' => $id], 'post' => [], 'server' => []]]);
    $hookId = null;
    for (;;) {
        $m = $recv();
        if ($m[0] === 'hook' && $m[2] === 'securecore_state') { $hookId = $m[3]; $send(['return', true]); }
        elseif ($m[0] === 'hook' || $m[0] === 'wp') { $send(['return', null]); }
        elseif ($m[0] === 'ready') break;
    }
    if ($hookId === null) throw new RuntimeException('plugin did not register securecore_state');
    $send(['call', $hookId, [null]]);
    for (;;) {
        $m = $recv();
        if ($m[0] === 'return') { $result = $m[1]; break; }
        if ($m[0] === 'throw') throw new RuntimeException('hook threw: ' . $m[1]);
    }
    $send(['end']);
    fclose($s);
    return (string) $result;
}

$a = request($socket, 'A');
$b = request($socket, 'B');
fwrite(STDERR, "request A saw: $a\nrequest B saw: $b\n");

$isolated = $a === 'A' && $b === 'B';
$leaked = $a === 'A' && $b === 'A,B';
if ($expectLeak) {
    if ($leaked) { fwrite(STDERR, "as expected, state leaked without the fork\n"); exit(0); }
    fwrite(STDERR, "expected a leak without the fork, but B saw '$b'\n");
    exit(1);
}
if ($isolated) { fwrite(STDERR, "isolated: each request saw only its own id\n"); exit(0); }
fwrite(STDERR, "NOT isolated: B should see 'B', saw '$b'\n");
exit(1);
