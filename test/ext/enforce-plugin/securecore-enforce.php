<?php
/**
 * Plugin Name: SecureCore enforcement fixture
 * Description: Test fixture for test/ext-enforce.sh (addiscorp/securecore#53, E2b). On ?sc_enf=run it attempts one file or process operation per case and prints "<case>=OK" or "<case>=BLOCKED", where OK means the operation did what it asks (a read returned content, a write created the file, a program ran) and BLOCKED means it was refused (false / no effect). The test runs it under enforce, log and off and compares. Never shipped.
 */

if (!defined('ABSPATH')) {
    exit;
}

add_action('init', static function () {
    if (($_GET['sc_enf'] ?? '') !== 'run') {
        return;
    }
    header('Content-Type: text/plain');

    $own = __DIR__;                                  // the plugin's own folder (under the root)
    $uploads = WP_CONTENT_DIR . '/uploads/sc-enf';   // writable (uploads)
    @mkdir($uploads, 0777, true);
    $config = ABSPATH . 'wp-config.php';             // protected
    $victim = WP_CONTENT_DIR . '/sc-enf-victim.txt'; // core-owned; the harness recreates it per request
    $rename = WP_CONTENT_DIR . '/sc-enf-rename.txt'; // a second core-owned file, so unlink and rename don't collide
    $outside_inc = '/opt/sc-enf-out.php';            // the harness places this; `return 'outok';`

    $ok = static fn(bool $did): string => $did ? 'OK' : 'BLOCKED';
    $r = [];

    // --- reads: under the root is allowed; the protected files and outside the root are not ---
    $r['read-own'] = $ok(is_string(@file_get_contents(__FILE__)));
    $r['read-config'] = $ok(is_string(@file_get_contents($config)));
    $r['read-etc'] = $ok(is_string(@file_get_contents('/etc/hostname')));
    $f = @fopen('/etc/hostname', 'r');
    $r['fopen-read-etc'] = $ok($f !== false);
    if ($f) {
        fclose($f);
    }
    $r['scandir-etc'] = $ok(is_array(@scandir('/etc')));

    // --- writes: only uploads and cache (and granted paths); never the own folder or core ---
    $r['write-uploads'] = $ok(@file_put_contents($uploads . '/w.txt', 'x') !== false);
    $r['write-own'] = $ok(@file_put_contents($own . '/w.txt', 'x') !== false);
    $r['write-tmp'] = $ok(@file_put_contents('/tmp/sc-enf.txt', 'x') !== false);
    $g = @fopen($own . '/fw.txt', 'wb');
    $r['fopen-write-own'] = $ok($g !== false);
    if ($g) {
        fclose($g);
    }
    @unlink($victim);
    $r['unlink-core'] = $ok(!file_exists($victim)); // OK only if it was actually removed
    $made = @mkdir(WP_CONTENT_DIR . '/sc-enf-newdir');
    $r['mkdir-core'] = $ok($made);
    @rmdir(WP_CONTENT_DIR . '/sc-enf-newdir');
    $moved = @rename($rename, $rename . '.moved');
    $r['rename-core'] = $ok($moved);
    @rename($rename . '.moved', $rename);

    // --- process: refused unless the component is granted exec ---
    $out = @shell_exec('echo scok');
    $r['shell_exec'] = $ok(is_string($out) && str_contains($out, 'scok'));
    $line = @exec('echo scok', $o, $code);
    $r['exec'] = $ok($line === 'scok');

    // --- include: under the root is allowed; outside it is refused ---
    $r['include-own'] = $ok((@include $own . '/inc.php') === 'incok');
    $r['include-outside'] = $ok((@include $outside_inc) === 'outok');

    // --- securecore_status(): core only, whatever the component is granted ---
    try {
        $s = securecore_status();
        $r['status'] = $ok(isset($s['version']));
    } catch (\Throwable $e) {
        $r['status'] = 'BLOCKED';
    }

    foreach ($r as $case => $verdict) {
        echo $case, '=', $verdict, "\n";
    }
    exit;
});
