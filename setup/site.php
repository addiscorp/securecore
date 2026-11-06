<?php
// Steps 3–4 of install.sh, in PHP: WordPress (find it, or download a version picked from
// wordpress.org's list, checked against wordpress.org's sha1) and the database (SQLite
// through the SQLite Database Integration plugin, or MySQL/MariaDB), then wp-config.php and
// the site itself. install.sh runs this with the PHP that will serve the site, so the
// database extension it needs (pdo_sqlite or mysqli) is there.
//
//   php site.php --root <dir> [--wordpress latest|<version>] [--db sqlite|mysql://user:pass@host[:port]/name]
//                [--url http://localhost:8080] [--title …] [--admin-user …] [--admin-password …]
//                [--admin-email …] [--yes]
//
// Questions are asked on /dev/tty (it works under `curl | sh`); with --yes, or with no
// terminal, the defaults are used. A site that already has wp-config.php is left alone.
// Prints `SECURECORE_ADMIN_PASSWORD=<…>` when it generated the password, for install.sh.

const UA = 'securecore-installer';

$opt = ['root' => '', 'wordpress' => '', 'db' => 'sqlite', 'url' => 'http://localhost:8080', 'title' => '',
    'admin-user' => '', 'admin-password' => '', 'admin-email' => '', 'yes' => false];
for ($i = 1; $i < $argc; $i++) {
    $a = $argv[$i];
    if ($a === '--yes') { $opt['yes'] = true; continue; }
    if (!str_starts_with($a, '--')) fail("unexpected argument $a");
    [$k, $v] = str_contains($a, '=') ? explode('=', substr($a, 2), 2) : [substr($a, 2), $argv[++$i] ?? ''];
    if (!array_key_exists($k, $opt)) fail("unknown option --$k");
    $opt[$k] = $v;
}
$root = rtrim($opt['root'], '/');
if ($root === '' || !is_dir($root)) fail('--root must be an existing folder');

function say(string $s): void { fwrite(STDOUT, $s . "\n"); }
function fail(string $s): never { fwrite(STDERR, "securecore: error: $s\n"); exit(1); }

/** Ask on the terminal; the default when there is none, or with --yes. */
function ask(string $question, string $default, bool $secret = false): string
{
    global $opt;
    if ($opt['yes']) return $default;
    $tty = @fopen('/dev/tty', 'r+');
    if (!$tty) return $default;
    fwrite($tty, $question . ($default !== '' && !$secret ? " [$default]" : '') . ': ');
    $line = fgets($tty);
    fclose($tty);
    $line = $line === false ? '' : trim($line);
    return $line === '' ? $default : $line;
}

function http_get(string $url, ?string $to = null): string
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_FOLLOWLOCATION => true, CURLOPT_FAILONERROR => true, CURLOPT_USERAGENT => UA,
        CURLOPT_CONNECTTIMEOUT => 20, CURLOPT_TIMEOUT => 600]);
    $fh = null;
    if ($to !== null) { $fh = fopen($to, 'wb'); curl_setopt($ch, CURLOPT_FILE, $fh); }
    else curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $body = curl_exec($ch);
    $err = curl_error($ch);
    if ($fh) fclose($fh);
    if ($body === false) fail("could not download $url: $err");
    return $to === null ? (string) $body : '';
}

function unzip_to(string $zip, string $dir): void
{
    $z = new ZipArchive();
    if ($z->open($zip) !== true || !$z->extractTo($dir)) fail("cannot unpack $zip");
    $z->close();
}

/** Copy a tree, never overwriting a file that already exists. */
function copy_tree(string $from, string $to): void
{
    @mkdir($to, 0755, true);
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($from, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $item) {
        $dest = $to . '/' . substr($item->getPathname(), strlen($from) + 1);
        if ($item->isDir()) { @mkdir($dest, 0755, true); continue; }
        if (!file_exists($dest)) copy($item->getPathname(), $dest);
    }
}

function rm_tree(string $dir): void
{
    if (!is_dir($dir)) return;
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }
    rmdir($dir);
}

if (is_file("$root/wp-config.php")) {
    say("WordPress is already set up in $root (wp-config.php exists); leaving the site as it is.");
    exit(0);
}
$tmp = "$root/.securecore/tmp/site-" . getmypid();
@mkdir($tmp, 0755, true);
register_shutdown_function(fn () => rm_tree($tmp));

// --- 3. WordPress ----------------------------------------------------------------------------
if (is_file("$root/wp-load.php")) {
    include "$root/wp-includes/version.php";
    say("Found WordPress $wp_version in $root.");
} else {
    $versions = [];
    foreach ((array) json_decode(http_get('https://api.wordpress.org/core/stable-check/1.0/'), true) as $v => $status) {
        if ($status !== 'insecure') $versions[] = (string) $v;
    }
    usort($versions, fn ($a, $b) => version_compare($b, $a));
    if (!$versions) fail('could not read the WordPress version list from api.wordpress.org');
    $pick = $opt['wordpress'] !== '' ? $opt['wordpress'] : ask(
        'WordPress version (newest first: ' . implode(', ', array_slice($versions, 0, 6)) . ')', $versions[0]);
    if ($pick === 'latest') $pick = $versions[0];
    if (!preg_match('/^\d+\.\d+(\.\d+)?$/', $pick)) fail("not a WordPress version: $pick");
    $zip = "https://wordpress.org/wordpress-$pick.zip";
    say("Downloading WordPress $pick from $zip");
    http_get($zip, "$tmp/wordpress.zip");
    // wordpress.org publishes .sha1 and .md5 next to each release (its .sha256 URL just serves
    // the zip again), so sha1 is the strongest check it offers.
    $want = substr(trim(http_get("$zip.sha1")), 0, 40);
    $got = hash_file('sha1', "$tmp/wordpress.zip");
    if (!preg_match('/^[0-9a-f]{40}$/', $want) || $want !== $got) fail("wordpress-$pick.zip failed its checksum (wordpress.org's sha1 is $want, got $got)");
    say("WordPress $pick: sha1 $got (matches wordpress.org).");
    unzip_to("$tmp/wordpress.zip", $tmp);
    copy_tree("$tmp/wordpress", $root);
}

// --- 4. database, wp-config.php, the site ------------------------------------------------------
$db = $opt['db'];
$config = (string) file_get_contents("$root/wp-config-sample.php");
if ($db === 'sqlite') {
    if (!extension_loaded('pdo_sqlite')) fail('this PHP has no pdo_sqlite, which the SQLite database needs');
    $plugin = "$root/wp-content/plugins/sqlite-database-integration";
    if (!is_dir($plugin)) {
        say('Downloading the SQLite Database Integration plugin (wordpress.org)');
        $info = json_decode(http_get('https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=sqlite-database-integration&request[fields][versions]=0'), true);
        $url = (string) ($info['download_link'] ?? 'https://downloads.wordpress.org/plugin/sqlite-database-integration.zip');
        http_get($url, "$tmp/sqlite.zip");
        unzip_to("$tmp/sqlite.zip", "$root/wp-content/plugins");
        say('SQLite Database Integration ' . ($info['version'] ?? '') . " from $url");
    }
    // The db.php drop-in, from the plugin's own template.
    $dropin = (string) file_get_contents("$plugin/db.copy");
    $dropin = str_replace(['{SQLITE_IMPLEMENTATION_FOLDER_PATH}', '{SQLITE_PLUGIN}'],
        [$plugin, 'sqlite-database-integration/load.php'], $dropin);
    file_put_contents("$root/wp-content/db.php", $dropin);
    $name = 'wordpress'; $user = ''; $pass = ''; $host = 'localhost';
    $dbLabel = "SQLite (wp-content/database/.ht.sqlite, through the SQLite Database Integration plugin)";
} elseif (preg_match('#^mysql://([^:@/]*)(?::([^@/]*))?@([^/:]+)(?::(\d+))?/([^/?]+)$#', $db, $m)) {
    if (!extension_loaded('mysqli')) fail('this PHP has no mysqli, which WordPress needs for MySQL');
    [$user, $pass, $host, $port, $name] = [urldecode($m[1]), urldecode($m[2]), $m[3], $m[4] ?: '3306', urldecode($m[5])];
    mysqli_report(MYSQLI_REPORT_OFF);
    $link = @mysqli_connect($host, $user, $pass, '', (int) $port);
    if (!$link) fail("cannot connect to MySQL at $host:$port as $user: " . mysqli_connect_error());
    if (!mysqli_query($link, 'CREATE DATABASE IF NOT EXISTS `' . str_replace('`', '', $name) . '`')) fail("cannot create database $name: " . mysqli_error($link));
    mysqli_close($link);
    $host = $port === '3306' ? $host : "$host:$port";
    $dbLabel = "MySQL database $name on $host";
} else {
    fail("--db must be sqlite or mysql://user:pass@host[:port]/name, not $db");
}
$config = str_replace(["'database_name_here'", "'username_here'", "'password_here'", "'localhost'"],
    [var_export($name, true), var_export($user, true), var_export($pass, true), var_export($host, true)], $config);
$config = preg_replace_callback("/'put your unique phrase here'/",
    fn () => var_export(rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '='), true), $config);
file_put_contents("$root/wp-config.php", $config);
say("Wrote $root/wp-config.php ($dbLabel).");

$title = $opt['title'] !== '' ? $opt['title'] : ask('Site title', 'My WordPress site');
$adminUser = $opt['admin-user'] !== '' ? $opt['admin-user'] : ask('Admin user', 'admin');
$adminEmail = $opt['admin-email'] !== '' ? $opt['admin-email'] : ask('Admin email', 'admin@example.com');
$generated = false;
$adminPass = $opt['admin-password'] !== '' ? $opt['admin-password'] : ask('Admin password (Enter to generate one)', '', true);
if ($adminPass === '') { $adminPass = rtrim(strtr(base64_encode(random_bytes(12)), '+/', 'Ab'), '='); $generated = true; }

// Install the site, the way the web installer does.
$parts = parse_url($opt['url']);
$_SERVER['HTTP_HOST'] = ($parts['host'] ?? 'localhost') . (isset($parts['port']) ? ':' . $parts['port'] : '');
$_SERVER['SERVER_NAME'] = $parts['host'] ?? 'localhost';
$_SERVER['REQUEST_URI'] = '/';
$_SERVER['HTTPS'] = ($parts['scheme'] ?? 'http') === 'https' ? 'on' : '';
define('WP_INSTALLING', true);
require "$root/wp-load.php";
require_once ABSPATH . 'wp-admin/includes/upgrade.php';
if (is_blog_installed()) {
    say('The database already holds a WordPress site; not installing over it.');
} else {
    $result = wp_install($title, $adminUser, $adminEmail, true, '', wp_slash($adminPass));
    if (empty($result['user_id'])) fail('WordPress could not be installed');
    update_option('siteurl', rtrim($opt['url'], '/'));
    update_option('home', rtrim($opt['url'], '/'));
    say("Installed WordPress at {$opt['url']}: \"$title\", admin user $adminUser.");
}
// SecureCore is active from the start; install.sh puts its files in place next.
update_option('active_plugins', array_values(array_unique(array_merge((array) get_option('active_plugins', []), ['securecore/securecore.php']))));
if ($generated) say("SECURECORE_ADMIN_PASSWORD=$adminPass");
