<?php
// Steps 3–4 of install.sh, in PHP: WordPress (find it, or download a version picked from
// wordpress.org's list, checked against wordpress.org's sha1) and the database (SQLite
// through the SQLite Database Integration plugin, or MySQL/MariaDB), then wp-config.php and
// the site itself. install.sh runs this with the PHP that will serve the site, so the
// database extension it needs (pdo_sqlite or mysqli) is there.
//
//   php site.php --root <dir> [--wordpress latest|<version>] [--db sqlite|mysql://user:pass@host[:port]/name]
//                [--url http://localhost:8080] [--title …] [--admin-user …] [--admin-password …]
//                [--admin-email …] [--yes] [--verbose]
//
// Questions are asked on /dev/tty (it works under `curl | sh`); with --yes, or with no
// terminal, the defaults are used. A site that already has wp-config.php is left alone.
//
// Output is for install.sh, which formats it (one formatter for the whole installer): one
// tab-separated record per line on stdout —
//   step <name> <what happened>    a status line
//   detail <text>                  shown with --verbose (URLs, checksums, paths)
//   fail <what failed and what to do>, then exit 1
//   password <generated admin password>

const UA = 'securecore-installer';

$opt = ['root' => '', 'wordpress' => '', 'db' => 'sqlite', 'url' => 'http://localhost:8080', 'title' => '',
    'admin-user' => '', 'admin-password' => '', 'admin-email' => '', 'yes' => false, 'verbose' => false];
for ($i = 1; $i < $argc; $i++) {
    $a = $argv[$i];
    if ($a === '--yes' || $a === '--verbose') { $opt[substr($a, 2)] = true; continue; }
    if (!str_starts_with($a, '--')) fail("Unexpected argument $a.");
    [$k, $v] = str_contains($a, '=') ? explode('=', substr($a, 2), 2) : [substr($a, 2), $argv[++$i] ?? ''];
    if (!array_key_exists($k, $opt)) fail("Unknown option --$k (see install.sh --help).");
    $opt[$k] = $v;
}
$root = rtrim($opt['root'], '/');
if ($root === '' || !is_dir($root)) fail('--root must be an existing folder.');

function record(string $kind, string ...$fields): void
{
    fwrite(STDOUT, $kind . "\t" . implode("\t", array_map(fn ($f) => strtr($f, "\t\n", '  '), $fields)) . "\n");
}
function step(string $name, string $text): void { record('step', $name, $text); }
function detail(string $text): void { record('detail', $text); }
function fail(string $text): never { record('fail', $text); exit(1); }

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
    if ($body === false) fail("Couldn't download $url ($err). Check this computer's internet connection, then run the installer again.");
    return $to === null ? (string) $body : '';
}

function unzip_to(string $zip, string $dir): void
{
    $z = new ZipArchive();
    if ($z->open($zip) !== true || !$z->extractTo($dir)) fail("Couldn't unpack " . basename($zip) . '. Check there is free disk space, then run the installer again.');
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
    step('WordPress', 'already set up in this folder, left as it is');
    exit(0);
}
$tmp = "$root/.securecore/tmp/site-" . getmypid();
@mkdir($tmp, 0755, true);
register_shutdown_function(fn () => rm_tree($tmp));

// --- the questions, all before any step is reported -------------------------------------------
// install.sh prints the records as they arrive while the prompts go straight to the terminal,
// so a record sent while a prompt is open would land in the middle of it.
$found = null;
$pick = '';
if (is_file("$root/wp-load.php")) {
    include "$root/wp-includes/version.php";
    $found = $wp_version;
} else {
    $versions = [];
    foreach ((array) json_decode(http_get('https://api.wordpress.org/core/stable-check/1.0/'), true) as $v => $status) {
        if ($status !== 'insecure') $versions[] = (string) $v;
    }
    usort($versions, fn ($a, $b) => version_compare($b, $a));
    if (!$versions) fail("Couldn't read the list of WordPress versions from wordpress.org. Check this computer's internet connection, then run the installer again.");
    $pick = $opt['wordpress'] !== '' ? $opt['wordpress'] : ask(
        "Which WordPress version? Press Enter for the newest. Recent ones: " . implode(', ', array_slice($versions, 0, 6)) . "\nWordPress version", $versions[0]);
    if ($pick === 'latest') $pick = $versions[0];
    if (!preg_match('/^\d+\.\d+(\.\d+)?$/', $pick)) fail("\"$pick\" is not a WordPress version (they look like {$versions[0]}). Run the installer again and pick one from the list.");
}
$title = $opt['title'] !== '' ? $opt['title'] : ask('Site title (shown at the top of every page)', 'My WordPress site');
$adminUser = $opt['admin-user'] !== '' ? $opt['admin-user'] : ask('Admin user name (what you log in to wp-admin with)', 'admin');
$adminEmail = $opt['admin-email'] !== '' ? $opt['admin-email'] : ask('Admin email (WordPress sends password resets here)', 'admin@example.com');
$generated = false;
$adminPass = $opt['admin-password'] !== '' ? $opt['admin-password'] : ask('Admin password (press Enter to generate a strong one)', '', true);
if ($adminPass === '') { $adminPass = rtrim(strtr(base64_encode(random_bytes(12)), '+/', 'Ab'), '='); $generated = true; }

// --- 3. WordPress ----------------------------------------------------------------------------
if ($found !== null) {
    step("WordPress $found", 'already in this folder');
} else {
    $zip = "https://wordpress.org/wordpress-$pick.zip";
    detail("WordPress $pick: downloading $zip");
    http_get($zip, "$tmp/wordpress.zip");
    // wordpress.org publishes .sha1 and .md5 next to each release (its .sha256 URL just serves
    // the zip again), so sha1 is the strongest check it offers.
    $want = substr(trim(http_get("$zip.sha1")), 0, 40);
    $got = hash_file('sha1', "$tmp/wordpress.zip");
    if (!preg_match('/^[0-9a-f]{40}$/', $want) || $want !== $got) {
        detail("wordpress.org's sha1 is $want, got $got");
        fail('The WordPress download failed its checksum, so it was not used. Run the installer again; if this keeps happening, the download is being tampered with or corrupted on the way.');
    }
    detail("sha1 $got (matches wordpress.org)");
    unzip_to("$tmp/wordpress.zip", $tmp);
    copy_tree("$tmp/wordpress", $root);
    step("WordPress $pick", 'downloaded (verified)');
}

// --- 4. database, wp-config.php, the site ------------------------------------------------------
$db = $opt['db'];
$config = (string) file_get_contents("$root/wp-config-sample.php");
if ($db === 'sqlite') {
    if (!extension_loaded('pdo_sqlite')) fail("This PHP can't use SQLite (it has no pdo_sqlite). Run the installer again with --php download.");
    $plugin = "$root/wp-content/plugins/sqlite-database-integration";
    if (!is_dir($plugin)) {
        $info = json_decode(http_get('https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=sqlite-database-integration&request[fields][versions]=0'), true);
        $url = (string) ($info['download_link'] ?? 'https://downloads.wordpress.org/plugin/sqlite-database-integration.zip');
        detail('SQLite Database Integration ' . ($info['version'] ?? '') . ": downloading $url");
        http_get($url, "$tmp/sqlite.zip");
        unzip_to("$tmp/sqlite.zip", "$root/wp-content/plugins");
    }
    // The db.php drop-in, from the plugin's own template.
    $dropin = (string) file_get_contents("$plugin/db.copy");
    $dropin = str_replace(['{SQLITE_IMPLEMENTATION_FOLDER_PATH}', '{SQLITE_PLUGIN}'],
        [$plugin, 'sqlite-database-integration/load.php'], $dropin);
    file_put_contents("$root/wp-content/db.php", $dropin);
    $name = 'wordpress'; $user = ''; $pass = ''; $host = 'localhost';
    detail('SQLite database: a file under wp-content/database/, through the SQLite Database Integration plugin (wp-content/db.php)');
    $dbStep = 'SQLite, no database server needed';
} elseif (preg_match('#^mysql://([^:@/]*)(?::([^@/]*))?@([^/:]+)(?::(\d+))?/([^/?]+)$#', $db, $m)) {
    if (!extension_loaded('mysqli')) fail("This PHP can't use MySQL (it has no mysqli). Run the installer again with --php download.");
    [$user, $pass, $host, $port, $name] = [urldecode($m[1]), urldecode($m[2]), $m[3], $m[4] ?: '3306', urldecode($m[5])];
    mysqli_report(MYSQLI_REPORT_OFF);
    $link = @mysqli_connect($host, $user, $pass, '', (int) $port);
    if (!$link) fail("Couldn't connect to MySQL at $host:$port as $user (" . mysqli_connect_error() . '). Check the server is running and the user and password are right, then run the installer again with the right --db.');
    if (!mysqli_query($link, 'CREATE DATABASE IF NOT EXISTS `' . str_replace('`', '', $name) . '`')) fail("Couldn't create the database $name (" . mysqli_error($link) . "). Give $user permission to create it, or create it yourself, then run the installer again.");
    mysqli_close($link);
    $host = $port === '3306' ? $host : "$host:$port";
    $dbStep = "MySQL, database \"$name\" on $host";
} else {
    fail("The database must be sqlite or mysql://user:password@host[:port]/name, not \"$db\". Run the installer again with one of those.");
}
$config = str_replace(["'database_name_here'", "'username_here'", "'password_here'", "'localhost'"],
    [var_export($name, true), var_export($user, true), var_export($pass, true), var_export($host, true)], $config);
$config = preg_replace_callback("/'put your unique phrase here'/",
    fn () => var_export(rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '='), true), $config);
file_put_contents("$root/wp-config.php", $config);
detail("wrote $root/wp-config.php");
step('Database', $dbStep);

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
    step('Site', 'this database already holds a WordPress site, so it was kept as it is');
} else {
    $result = wp_install($title, $adminUser, $adminEmail, true, '', wp_slash($adminPass));
    if (empty($result['user_id'])) fail("WordPress couldn't be installed into the database. Empty this folder, then run the installer again.");
    update_option('siteurl', rtrim($opt['url'], '/'));
    update_option('home', rtrim($opt['url'], '/'));
    detail("site title: \"$title\"; admin email: $adminEmail");
    step('Site', rtrim($opt['url'], '/') . ", admin user \"$adminUser\"");
}
// SecureCore is active from the start; install.sh puts its files in place next.
update_option('active_plugins', array_values(array_unique(array_merge((array) get_option('active_plugins', []), ['securecore/securecore.php']))));
if ($generated) record('password', $adminPass);
