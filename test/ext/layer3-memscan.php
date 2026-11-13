<?php
// Test helper for test/ext-layer3.sh (addiscorp/securecore#94): reads another process's
// environment and memory (its readable mappings that aren't files: heap, stack and anonymous
// memory, where PHP and the extension keep their values) and counts each needle in them. Run as
// root with CAP_SYS_PTRACE in the php container (`docker compose exec --privileged`), never on a
// developer machine. Prints key=value lines:
//   environ=<entries> bytes=<memory read> found_<i>=<count of needle i>
//   php -- <pid> <needle>... < test/ext/layer3-memscan.php
$pid = (int) ($argv[1] ?? 0);
$needles = array_slice($argv, 2);
if ($pid <= 0 || $needles === []) {
    fwrite(STDERR, "usage: php -- <pid> <needle>...\n");
    exit(2);
}
$env = @file_get_contents("/proc/$pid/environ");
echo 'environ=', is_string($env) ? count(array_filter(explode("\0", $env), 'strlen')) : 'unreadable', "\n";
$found = array_fill(0, count($needles), 0);
$maps = @file("/proc/$pid/maps", FILE_IGNORE_NEW_LINES);
$mem = @fopen("/proc/$pid/mem", 'rb');
$bytes = 0;
if (is_array($maps) && $mem) {
    stream_set_read_buffer($mem, 0);
    // Each chunk overlaps the last by the longest needle, so a needle across a boundary counts.
    $overlap = max(array_map('strlen', $needles)) - 1;
    foreach ($maps as $line) {
        $f = preg_split('/\s+/', $line, 6);
        $path = $f[5] ?? '';
        if (($f[1][0] ?? '') !== 'r' || ($path !== '' && $path[0] === '/') || in_array($path, ['[vvar]', '[vsyscall]', '[vdso]', '[vvar_vclock]'], true)) {
            continue;
        }
        [$lo, $hi] = array_map('hexdec', explode('-', $f[0]));
        $tail = '';
        // fread() on /proc returns what one read() gave (often 8 KiB): advance by what came.
        for ($at = $lo; $at < $hi; $at += strlen($chunk)) {
            if (fseek($mem, $at) !== 0) break;
            $chunk = @fread($mem, min(1 << 20, $hi - $at));
            if (!is_string($chunk) || $chunk === '') break;
            $bytes += strlen($chunk);
            $hay = $tail . $chunk;
            foreach ($needles as $i => $n) {
                // Counted in the new bytes only (an occurrence wholly inside $tail was counted).
                $off = 0;
                while (($p = strpos($hay, $n, $off)) !== false) {
                    if ($p + strlen($n) > strlen($tail)) $found[$i]++;
                    $off = $p + 1;
                }
            }
            $tail = $overlap > 0 ? substr($hay, -$overlap) : '';
        }
    }
}
echo 'bytes=', $bytes, "\n";
foreach ($found as $i => $c) {
    echo "found_$i=$c\n";
}
