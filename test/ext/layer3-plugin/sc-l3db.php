<?php
/**
 * Plugin Name: SecureCore layer 3 database probe
 * Description: Test fixture for test/ext-layer3.sh and test/ext-microvm.sh (addiscorp/securecore#94): an isolated plugin that uses the database through $wpdb, as real plugins do. It creates its own table with dbDelta, writes and reads it through every $wpdb method, keeps a counter in its own option, reads core's and the site's options, and has probes for layer 2's refusals, the gateway's caps and the secrets. Output is one key=value per line. Never shipped.
 */

if (!defined('ABSPATH')) {
    exit;
}

// A query while the plugin loads (before its child reports ready): its own option.
$GLOBALS['sc_l3db_loaded'] = get_option('sc_l3db_greeting', 'none');

/** Where this ran: 1 in a layer 3 child (the helper's code exists only there). */
function sc_l3db_where(): string
{
    return 'isolated=' . (class_exists('SecureCore\\Layer3\\State', false) ? 1 : 0) . "\npid=" . getmypid();
}

function sc_l3db_out(array $r): string
{
    $lines = sc_l3db_where();
    foreach ($r as $k => $v) {
        $lines .= "\n$k=$v";
    }
    return "<pre class=\"sc-l3db\">\n" . esc_html($lines) . "\n</pre>";
}

/** OK when the query ran (did not return false), BLOCKED when it failed. */
function sc_l3db_ran($ret): string
{
    return $ret === false ? 'BLOCKED' : 'OK';
}

// Its own table and options, through every $wpdb method.
add_shortcode('sc_l3db_rw', static function () {
    global $wpdb;
    $r = [];
    $t = $wpdb->prefix . 'sc_l3db_items';
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta("CREATE TABLE $t (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  name varchar(64) NOT NULL DEFAULT '',
  n int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY  (id),
  KEY name (name)
) " . $wpdb->get_charset_collate() . ';');
    $r['dbdelta'] = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $t)) === $t ? 'OK' : 'BLOCKED';
    $r['prefix'] = $wpdb->prefix;
    $r['options_table'] = $wpdb->options;
    $r['charset'] = $wpdb->charset;
    $wpdb->query("DELETE FROM $t");
    // Quotes, a backslash, a newline and a NUL: escaped here, as mysqli would.
    $tricky = "a'b\"c\\d\ne\0f";
    $ins = $wpdb->insert($t, ['name' => $tricky, 'n' => 1], ['%s', '%d']);
    $id = (int) $wpdb->insert_id;
    $r['insert'] = $ins === 1 && $id > 0 ? 'OK' : 'BLOCKED';
    $row = $wpdb->get_row($wpdb->prepare("SELECT id, name, n FROM $t WHERE id = %d", $id));
    $r['get_row'] = is_object($row) && (int) $row->id === $id && $row->name === $tricky ? 'OK' : 'BLOCKED';
    $r['get_row_array'] = ($wpdb->get_row($wpdb->prepare("SELECT n FROM $t WHERE id = %d", $id), ARRAY_A)['n'] ?? null) === '1' ? 'OK' : 'BLOCKED';
    $up = $wpdb->update($t, ['n' => 2], ['id' => $id], ['%d'], ['%d']);
    $r['update'] = $up === 1 && $wpdb->rows_affected === 1 ? 'OK' : 'BLOCKED';
    $rep = $wpdb->replace($t, ['id' => $id, 'name' => 'replaced', 'n' => 3], ['%d', '%s', '%d']);
    $r['replace'] = $rep === 2 && $wpdb->rows_affected === 2 ? 'OK' : 'BLOCKED';
    $wpdb->insert($t, ['name' => 'second', 'n' => 4]);
    $r['insert_id_next'] = (int) $wpdb->insert_id > $id ? 'OK' : 'BLOCKED';
    $r['get_var'] = $wpdb->get_var("SELECT COUNT(*) FROM $t") === '2' ? 'OK' : 'BLOCKED';
    $r['get_col'] = implode(',', $wpdb->get_col("SELECT name FROM $t ORDER BY n")) === 'replaced,second' ? 'OK' : 'BLOCKED';
    $all = $wpdb->get_results("SELECT name, n FROM $t ORDER BY n DESC");
    $r['get_results'] = is_array($all) && count($all) === 2 && $all[0]->name === 'second' && $wpdb->num_rows === 2 ? 'OK' : 'BLOCKED';
    $r['get_col_info'] = implode(',', (array) $wpdb->get_col_info('name')) === 'name,n' ? 'OK' : 'BLOCKED';
    $keyed = $wpdb->get_results("SELECT name, n FROM $t", OBJECT_K);
    $r['get_results_k'] = isset($keyed['replaced'], $keyed['second']) ? 'OK' : 'BLOCKED';
    // A transaction rolled back leaves the table as it was.
    $wpdb->query('START TRANSACTION');
    $wpdb->insert($t, ['name' => 'rolled', 'n' => 9]);
    $wpdb->query('ROLLBACK');
    $r['transaction'] = $wpdb->get_var("SELECT COUNT(*) FROM $t WHERE name = 'rolled'") === '0' ? 'OK' : 'BLOCKED';
    $del = $wpdb->delete($t, ['name' => 'second'], ['%s']);
    $r['delete'] = $del === 1 ? 'OK' : 'BLOCKED';
    $r['bad_query_error'] = $wpdb->query("SELECT no_such_column FROM $t") === false && str_contains($wpdb->last_error, 'no_such_column') ? 'OK' : 'BLOCKED';
    $wpdb->query("SELECT 1 FROM $t");
    $r['last_error_clears'] = $wpdb->last_error === '' ? 'OK' : 'BLOCKED';
    // Options: its own (a counter kept across requests), the site's, core's from the snapshot.
    $c = (int) get_option('sc_l3db_counter', 0);
    update_option('sc_l3db_counter', $c + 1, false);
    $r['counter'] = $c;
    $r['counter_written'] = (int) get_option('sc_l3db_counter') === $c + 1 ? 'OK' : 'BLOCKED';
    $r['greeting'] = get_option('sc_l3db_greeting', 'none');
    $r['loaded_greeting'] = $GLOBALS['sc_l3db_loaded'] ?? 'unset';
    $r['blogname'] = get_option('blogname');
    $r['transient'] = set_transient('sc_l3db_t', 'tv', 60) && get_transient('sc_l3db_t') === 'tv' ? 'OK' : 'BLOCKED';
    return sc_l3db_out($r);
});

// Layer 2's refusals: a core table without a grant, a refused statement, another plugin's table.
add_shortcode('sc_l3db_l2', static function () {
    global $wpdb;
    return sc_l3db_out([
        'core-table' => sc_l3db_ran($wpdb->get_var("SELECT user_login FROM {$wpdb->users} LIMIT 1") ?? false),
        'statement' => sc_l3db_ran($wpdb->query("SELECT LOAD_FILE('/etc/hostname')")),
        'cross-plugin' => sc_l3db_ran($wpdb->query("SELECT COUNT(*) FROM {$wpdb->prefix}sc_l3_neighbour_data")),
        'core-table-error' => str_contains($wpdb->get_var("SELECT user_login FROM {$wpdb->users} LIMIT 1") ?? $wpdb->last_error, 'securecore') ? 'securecore' : 'other',
    ]);
});

// What only the gateway refuses: SQL that is not UTF-8 (layer 2 reads text), and a change to the
// statement time cap.
add_shortcode('sc_l3db_l3', static function () {
    global $wpdb;
    $sql = "SELECT user_login, user_pass FROM {$wpdb->users} /* \xff */ LIMIT 1";
    return sc_l3db_out([
        'not-utf8' => sc_l3db_ran($wpdb->query($sql)),
        // Unisolated, straight to mysqli (wpdb would strip the byte first): layer 2's own check.
        'not-utf8-direct' => $wpdb->dbh instanceof mysqli ? sc_l3db_ran(@mysqli_query($wpdb->dbh, $sql)) : 'none',
        'time-cap' => sc_l3db_ran($wpdb->query('SET SESSION max_statement_time = 0')),
    ]);
});

// A transaction left open by a child that dies: it opens one, writes, then spins past timeoutMs.
add_shortcode('sc_l3db_txn_dies', static function () {
    global $wpdb;
    $wpdb->query('START TRANSACTION');
    $wpdb->insert($wpdb->prefix . 'sc_l3db_items', ['name' => 'orphan', 'n' => 7]);
    $until = microtime(true) + 3;
    while (microtime(true) < $until) {
    }
    return sc_l3db_out(['survived' => 'yes']);
});

// Transactions left open on a normal return: one opened behind a comment, one by turning
// autocommit off. Each writes a row and returns without committing.
add_shortcode('sc_l3db_txn_open', static function () {
    global $wpdb;
    $wpdb->query('/* hidden */ START TRANSACTION');
    $wpdb->insert($wpdb->prefix . 'sc_l3db_items', ['name' => 'open1', 'n' => 8]);
    return sc_l3db_out(['returned' => 'yes']);
});
add_shortcode('sc_l3db_autocommit_off', static function () {
    global $wpdb;
    $wpdb->query('SET autocommit = FALSE');
    $wpdb->insert($wpdb->prefix . 'sc_l3db_items', ['name' => 'ac1', 'n' => 8]);
    return sc_l3db_out(['returned' => 'yes']);
});

// The result cap against a result far larger than it: 40 rows of 1 MiB.
add_shortcode('sc_l3db_huge', static function () {
    global $wpdb;
    $v = $wpdb->get_col("SELECT REPEAT('x', 1048576) FROM information_schema.COLLATIONS LIMIT 40");
    return sc_l3db_out(['huge' => count($v) === 40 ? 'OK' : 'BLOCKED', 'error' => str_contains($wpdb->last_error, 'dbResultBytes') ? 'dbResultBytes' : 'other']);
});

// A server error naming the database: what the child sees of it.
add_shortcode('sc_l3db_err', static function () {
    global $wpdb;
    $wpdb->query("SELECT * FROM {$wpdb->prefix}sc_l3db_nope");
    return sc_l3db_out(['err' => $wpdb->last_error]);
});

// Two 1 s statements in one call: the second must be capped at the time left, not at the time
// there was before the first.
add_shortcode('sc_l3db_sleeps', static function () {
    global $wpdb;
    $wpdb->query('SELECT SLEEP(1)');
    $wpdb->query('SELECT SLEEP(1)');
    return sc_l3db_out(['slept' => 'twice']);
});

// The query cap: n queries in a row, how many ran.
add_shortcode('sc_l3db_many', static function ($atts) {
    global $wpdb;
    $n = (int) (shortcode_atts(['n' => 80], $atts)['n']);
    $ran = 0;
    for ($i = 0; $i < $n; $i++) {
        if ($wpdb->get_var('SELECT 1') === '1') $ran++;
    }
    return sc_l3db_out(['ran' => $ran, 'error' => str_contains($wpdb->last_error, 'dbQueries') ? 'dbQueries' : 'other']);
});

// The cost: microseconds per query, n queries of one row each, timed in the plugin.
add_shortcode('sc_l3db_time', static function ($atts) {
    global $wpdb;
    $n = (int) (shortcode_atts(['n' => 50], $atts)['n']);
    $t = $wpdb->prefix . 'sc_l3db_items';
    $wpdb->get_var("SELECT name FROM $t LIMIT 1");
    $start = hrtime(true);
    for ($i = 0; $i < $n; $i++) {
        $wpdb->get_row($wpdb->prepare("SELECT id, name, n FROM $t WHERE n >= %d LIMIT 1", $i % 3));
    }
    return sc_l3db_out(['us_per_query' => round((hrtime(true) - $start) / 1000 / $n, 1)]);
});

// The result cap: one answer of 300 KB.
add_shortcode('sc_l3db_big', static function () {
    global $wpdb;
    $v = $wpdb->get_var("SELECT REPEAT('x', 300000)");
    return sc_l3db_out(['big' => is_string($v) && strlen($v) === 300000 ? 'OK' : 'BLOCKED', 'error' => str_contains($wpdb->last_error, 'dbResultBytes') ? 'dbResultBytes' : 'other']);
});

// The time cap: a 5 s statement.
add_shortcode('sc_l3db_sleep', static function () {
    global $wpdb;
    $t = microtime(true);
    $wpdb->query('SELECT SLEEP(5)');
    return sc_l3db_out(['slept' => round(microtime(true) - $t, 1)]);
});

// The secrets: what PHP shows of the environment, then a pause for the test to read this
// process's environment and memory from outside (test/ext/layer3-memscan.php): it writes its pid
// into its folder and waits (at most 1.3 s) for the test's "scanned" file. A layer 3 child is not
// dumpable (it changed uid), so it can't read its own /proc files; the test can. This file never
// names the DB password.
add_shortcode('sc_l3db_secrets', static function () {
    $r = [];
    $r['getenv'] = count(getenv());
    $r['env_superglobal'] = count($_ENV);
    $r['db_password_const'] = defined('DB_PASSWORD') ? 'defined' : 'undefined';
    $dir = WP_CONTENT_DIR . '/uploads/sc-l3db';
    @unlink("$dir/scanned");
    $r['pid_written'] = @file_put_contents("$dir/pid", (string) getmypid()) !== false ? 'OK' : 'BLOCKED';
    $until = microtime(true) + 1.3;
    while (!file_exists("$dir/scanned") && microtime(true) < $until) {
        usleep(20000);
        clearstatcache();
    }
    $r['scanned'] = file_exists("$dir/scanned") ? 'yes' : 'no';
    return sc_l3db_out($r);
});
