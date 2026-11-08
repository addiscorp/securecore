<?php
// A minimal fake MySQL server for test/ext-vault.sh (never shipped). It speaks just enough of the
// protocol to make a connecting mysqli client reveal its password in the CLEAR: it sends a
// HandshakeV10, then an AuthSwitchRequest to `mysql_clear_password`, and writes every byte the
// client then sends to a file. The test connects a probe to it with a vault placeholder as the
// password and asserts the real DB password / salt never arrives — which it only can if the
// extension wrongly substituted the real value for a foreign host or a non-core caller.
//
//   php fakemysql.php <port> <outfile>
// Listens on 0.0.0.0:<port>, serves connections until SIGTERM, appending each client's post-switch
// auth bytes to <outfile>.
error_reporting(E_ALL & ~E_WARNING);
[$port, $outfile] = [(int) ($argv[1] ?? 0), $argv[2] ?? '/tmp/fakemysql.bin'];

$srv = stream_socket_server("tcp://0.0.0.0:$port", $errno, $errstr);
if (!$srv) {
    fwrite(STDERR, "fakemysql: cannot listen on $port: $errstr\n");
    exit(1);
}
@file_put_contents($outfile, '');
fwrite(STDERR, "fakemysql: listening on $port\n");

function pkt(string $payload, int $seq): string {
    $len = strlen($payload);
    return chr($len & 0xff) . chr(($len >> 8) & 0xff) . chr(($len >> 16) & 0xff) . chr($seq & 0xff) . $payload;
}

function handshake(): string {
    $caps = 0x00000200 | 0x00008000 | 0x00080000; // PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH
    $scramble = str_repeat("\x01", 20);
    $p = "\x0a";                       // protocol v10
    $p .= "5.7.40-fake\x00";           // server version
    $p .= pack('V', 1);                // connection id
    $p .= substr($scramble, 0, 8) . "\x00"; // auth-plugin-data-part-1 + filler
    $p .= pack('v', $caps & 0xffff);   // capability flags (lower)
    $p .= "\x21";                      // charset
    $p .= pack('v', 0x0002);           // status flags
    $p .= pack('v', ($caps >> 16) & 0xffff); // capability flags (upper)
    $p .= chr(21);                     // length of auth-plugin-data
    $p .= str_repeat("\x00", 10);      // reserved
    $p .= substr($scramble, 8) . "\x00"; // auth-plugin-data-part-2 (13 bytes incl NUL)
    $p .= "mysql_native_password\x00"; // auth plugin name
    return pkt($p, 0);
}

function read_packet($conn): ?string {
    $hdr = '';
    while (strlen($hdr) < 4) {
        $b = fread($conn, 4 - strlen($hdr));
        if ($b === '' || $b === false) return null;
        $hdr .= $b;
    }
    $len = ord($hdr[0]) | (ord($hdr[1]) << 8) | (ord($hdr[2]) << 16);
    $body = '';
    while (strlen($body) < $len) {
        $b = fread($conn, $len - strlen($body));
        if ($b === '' || $b === false) break;
        $body .= $b;
    }
    return $body;
}

while (true) {
    $conn = @stream_socket_accept($srv, -1);
    if (!$conn) continue;
    fwrite($conn, handshake());
    read_packet($conn);                                   // the client's HandshakeResponse41
    fwrite($conn, pkt("\xfe" . "mysql_clear_password\x00", 2)); // AuthSwitchRequest → cleartext
    $clear = read_packet($conn);                          // the client's cleartext password (+NUL)
    if ($clear !== null && $clear !== '') {
        file_put_contents($outfile, $clear . "\n", FILE_APPEND);
    }
    // Deny with an error packet so the client gives up cleanly.
    fwrite($conn, pkt("\xff" . pack('v', 1045) . "#28000" . "fakemysql denies", 3));
    fclose($conn);
}
