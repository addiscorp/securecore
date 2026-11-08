<?php
// The vault probe routine (addiscorp/securecore#53, E3), shared by the plugin probe and the core
// probe so both try exactly the same routes. It lives in the web root (core): the plugin includes
// it, so when the plugin calls sc_vault_probe() the innermost component frame is the plugin and
// its file reads are charged to the plugin; the core script includes and calls it with no
// component on the stack, so its reads are core's.
//
// Output has two parts, separated by a line "==BLOBS==":
//   * before it, one `key=value` line per scalar route (single-line values the test parses);
//   * after it, every large/multi-line route (phpinfo, var_dump, serialize, wp-config, …) dumped
//     raw, so the test can grep the whole output for a real secret — if any secret appears in any
//     route's result, a plain grep of the combined output finds it (nothing is base64-wrapped).
// The routine must never print a real secret; the test fails if the output contains the real DB
// password or any real salt.

function sc_vault_probe(): string {
    $scalar = '';
    $blob = '';
    $s = function ($k, $v) use (&$scalar) { $scalar .= $k . '=' . $v . "\n"; };
    $b = function ($k, $v) use (&$blob) { $blob .= "--- $k ---\n" . $v . "\n"; };
    $ex = function ($v) { return var_export($v, true); };

    $db_env = 'WORDPRESS_DB_PASSWORD';
    $salt_consts = ['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'];

    // 1. getenv — one name (scalar), and the whole environment (blob).
    $s('getenv_db', $ex(getenv($db_env)));
    $s('getenv_authkey', $ex(getenv('WORDPRESS_AUTH_KEY')));
    $b('getenv_all', $ex(getenv()));

    // 2. $_ENV and $_SERVER.
    $s('env_db', $ex($_ENV[$db_env] ?? '(unset)'));
    $s('server_db', $ex($_SERVER[$db_env] ?? '(unset)'));
    $s('env_authkey', $ex($_ENV['WORDPRESS_AUTH_KEY'] ?? '(unset)'));
    $b('server_all', $ex($_SERVER));

    // 3. the constants and get_defined_constants().
    $s('const_db', $ex(defined('DB_PASSWORD') ? DB_PASSWORD : '(undef)'));
    foreach ($salt_consts as $c) {
        $s('const_' . strtolower($c), $ex(defined($c) ? constant($c) : '(undef)'));
    }
    $picked = [];
    $defined = get_defined_constants();
    foreach (array_merge(['DB_PASSWORD'], $salt_consts) as $c) {
        if (isset($defined[$c])) { $picked[$c] = $defined[$c]; }
    }
    $b('get_defined_constants', $ex($picked));

    // 4. $wpdb — the property (scalar), then a var_dump, print_r, serialize and reflection (blob).
    global $wpdb;
    if ($wpdb instanceof wpdb) {
        $s('wpdb_dbpassword', $ex($wpdb->dbpassword));
        $s('db_ok', $ex((bool) $wpdb->get_var('SELECT 1')));
        ob_start(); var_dump($wpdb); $b('wpdb_var_dump', ob_get_clean());
        $b('wpdb_print_r', print_r($wpdb, true));
        $b('wpdb_serialize', @serialize($wpdb));
        $ref = new ReflectionObject($wpdb);
        $props = [];
        foreach ($ref->getProperties() as $prop) {
            $prop->setAccessible(true);
            $val = $prop->getValue($wpdb);
            if (is_scalar($val) || $val === null) { $props[$prop->getName()] = $val; }
        }
        $b('wpdb_reflection', $ex($props));
    } else {
        $s('wpdb', 'no wpdb');
    }

    // 5. wp_salt and wp_hash for every scheme; the key must not be recoverable.
    if (function_exists('wp_salt')) {
        foreach (['auth', 'secure_auth', 'logged_in', 'nonce'] as $scheme) {
            $s('wp_salt_' . $scheme, $ex(wp_salt($scheme)));
            $s('wp_hash_' . $scheme, wp_hash('sc-vault-probe', $scheme));
        }
    }

    // 6. phpinfo() — the whole INFO_ALL output.
    ob_start(); phpinfo(); $b('phpinfo', ob_get_clean());

    // 7. the vault file and wp-config.php: read and include.
    $vault_file = getenv('SC_VAULT_FILE') ?: '/etc/securecore/vault.json';
    $b('read_vault_file', $ex(@file_get_contents($vault_file)));
    $b('include_vault_file', $ex(@include $vault_file));
    $b('read_wp_config', (string) @file_get_contents(ABSPATH . 'wp-config.php'));

    // 8. debug_backtrace, $GLOBALS scalars and the error log. (A deep serialize of $GLOBALS is
    // circular; a scan of its scalar members is what could carry a leaked value.)
    ob_start(); var_dump(debug_backtrace()); $b('debug_backtrace', ob_get_clean());
    $gscan = [];
    foreach ($GLOBALS as $k => $v) {
        if (is_scalar($v)) { $gscan[$k] = $v; }
    }
    $b('globals_scalars', $ex($gscan));
    // Write the secrets we hold (placeholders) to the error log; the test checks the log is clean.
    error_log('securecore-vault-probe getenv=' . getenv($db_env) . ' const=' . (defined('DB_PASSWORD') ? DB_PASSWORD : '') . ' salt=' . (function_exists('wp_salt') ? wp_salt('auth') : ''));

    // 9. positive correctness: the login paths that depend on the salts must keep working.
    if (function_exists('wp_create_nonce')) {
        $n = wp_create_nonce('sc-vault-action');
        $s('nonce_roundtrip', $ex((int) wp_verify_nonce($n, 'sc-vault-action')));
    }
    if (function_exists('wp_generate_auth_cookie') && function_exists('wp_validate_auth_cookie') && class_exists('WP_Session_Tokens')) {
        $uid = 1;
        $expiration = time() + 3600;
        $manager = WP_Session_Tokens::get_instance($uid);
        $token = $manager->create($expiration);
        $cookie = wp_generate_auth_cookie($uid, $expiration, 'auth', $token);
        $s('auth_cookie_roundtrip', $ex((int) wp_validate_auth_cookie($cookie, 'auth')));
    }
    if (function_exists('get_password_reset_key') && function_exists('check_password_reset_key')) {
        $user = get_user_by('id', 1);
        if ($user) {
            $key = get_password_reset_key($user);
            $ok = !is_wp_error($key) && !is_wp_error(check_password_reset_key($key, $user->user_login));
            $s('password_reset_roundtrip', $ex($ok));
        }
    }

    return $scalar . "==BLOBS==\n" . $blob;
}
