<?php
// Unit assertions over SqlPolicy::decide() (addiscorp/securecore#42, part 2). Run with wp-cli so
// a real $wpdb (live table names + prefix) is available, but without executing any query — the
// destructive and structural refusals (DROP/ALTER/TRUNCATE on a core table, multi-statement,
// INSERT into users, capability escalation) are proven here precisely and safely, where the live
// canary (test/policy.sh) cannot run them without wrecking the stack.
//   DOCKER_CONTEXT=colima docker compose -f docker/compose.yml run --rm -T cli \
//       wp eval-file wp-content/securecore/policy-unit.php
// Exits non-zero if any verdict is wrong.
namespace SecureCore;

$base = '/var/www/html/wp-content/plugins/securecore';
require_once "$base/vendor/autoload.php";
require_once "$base/sql-policy.php";

global $wpdb;
$U = $wpdb->users; $UM = $wpdb->usermeta; $O = $wpdb->options; $P = $wpdb->posts; $PM = $wpdb->postmeta;
$pre = $wpdb->prefix;

$plain = new SqlPolicy($wpdb, ['db' => ['grants' => [], 'options' => ['securecore_policy_probe_own']]]);
$granted = new SqlPolicy($wpdb, ['db' => ['grants' => ['users', 'usermeta:capabilities', 'option:admin_email'], 'options' => []]]);

$fails = 0;
$expect = static function (string $label, SqlPolicy $pol, string $sql, bool $wantRun) use (&$fails): void {
    $d = $pol->decide($sql);
    $got = (bool) ($d['run'] ?? true);
    $ok = $got === $wantRun;
    printf("%-5s %-34s %s\n", $ok ? 'ok' : 'FAIL', $label, $got ? 'allow' : ('deny: ' . ($d['reason'] ?? '')));
    if (!$ok) { $fails++; echo "      expected " . ($wantRun ? 'allow' : 'deny') . "\n"; }
};

echo "-- denied, no grant --\n";
$expect('DROP core table', $plain, "DROP TABLE $U", false);
$expect('TRUNCATE core table', $plain, "TRUNCATE TABLE $U", false);
$expect('ALTER core table', $plain, "ALTER TABLE $O ADD COLUMN x INT", false);
$expect('CREATE over a core table', $plain, "CREATE TABLE $P (id INT)", false);
$expect('multi-statement', $plain, "SELECT 1; DROP TABLE $P", false);
$expect('unparseable', $plain, "this is not a query", false);
$expect('read user_pass', $plain, "SELECT user_pass FROM $U WHERE ID = 1", false);
$expect('read user_activation_key', $plain, "SELECT ID, user_activation_key FROM $U", false);
$expect('insert users', $plain, "INSERT INTO $U (user_login, user_pass) VALUES ('x', 'y')", false);
$expect('delete users', $plain, "DELETE FROM $U WHERE ID = 2", false);
$expect('escalate capabilities', $plain, "UPDATE $UM SET meta_value = 'a:1:{}' WHERE user_id = 1 AND meta_key = '{$pre}capabilities'", false);
$expect('write session_tokens', $plain, "UPDATE $UM SET meta_value = 'x' WHERE user_id = 1 AND meta_key = 'session_tokens'", false);
$expect('write active_plugins', $plain, "UPDATE $O SET option_value = 'x' WHERE option_name = 'active_plugins'", false);
$expect('write siteurl', $plain, "UPDATE $O SET option_value = 'http://evil' WHERE option_name = 'siteurl'", false);
$expect('write user_roles', $plain, "UPDATE $O SET option_value = 'x' WHERE option_name = '{$pre}user_roles'", false);
$expect('insert admin_email', $plain, "INSERT INTO $O (option_name, option_value) VALUES ('admin_email', 'x')", false);
$expect('delete admin_email', $plain, "DELETE FROM $O WHERE option_name = 'mailserver_pass'", false);

echo "\n-- denied by shape (no table it names can save it) --\n";
// The prepared-statement bypass, one forwarded query at a time: set a user variable to the hex of
// a forbidden SELECT, PREPARE from it, EXECUTE. Each statement must be refused on its own.
$expect('SET user variable', $plain, "SET @s = 0x" . bin2hex("SELECT user_pass FROM $U WHERE ID=1"), false);
$expect('SET @@ system variable', $plain, "SET @@global.sql_mode = ''", false);
$expect('PREPARE', $plain, "PREPARE stmt FROM @s", false);
$expect('EXECUTE', $plain, "EXECUTE stmt", false);
$expect('DEALLOCATE PREPARE', $plain, "DEALLOCATE PREPARE stmt", false);
$expect('SELECT LOAD_FILE', $plain, "SELECT LOAD_FILE('/etc/passwd')", false);
$expect('SELECT INTO OUTFILE', $plain, "SELECT * FROM $P INTO OUTFILE '/tmp/x'", false);
$expect('SELECT INTO DUMPFILE', $plain, "SELECT ID FROM $P INTO DUMPFILE '/tmp/x'", false);
$expect('INSERT with LOAD_FILE', $plain, "INSERT INTO {$pre}myplugin (a) VALUES (LOAD_FILE('/etc/passwd'))", false);
$expect('LOAD DATA INFILE', $plain, "LOAD DATA INFILE '/etc/passwd' INTO TABLE {$pre}myplugin", false);
$expect('CALL', $plain, "CALL some_proc()", false);
$expect('HANDLER open', $plain, "HANDLER $U OPEN", false);
$expect('DO SLEEP', $plain, "DO SLEEP(5)", false);
$expect('USE', $plain, "USE wordpress", false);
$expect('GRANT', $plain, "GRANT ALL ON *.* TO 'x'@'localhost'", false);
$expect('LOCK TABLES', $plain, "LOCK TABLES $O WRITE", false);
$expect('CREATE VIEW', $plain, "CREATE DEFINER=`root`@`localhost` VIEW v AS SELECT 1", false);
$expect('CREATE FUNCTION', $plain, "CREATE FUNCTION f() RETURNS INT RETURN 1", false);
$expect('CREATE TRIGGER', $plain, "CREATE TRIGGER t BEFORE INSERT ON $P FOR EACH ROW SET @x=1", false);
$expect('WITH (CTE)', $plain, "WITH t AS (SELECT user_pass FROM $U) SELECT * FROM t", false);

echo "\n-- allowed --\n";
$expect('select * users (secrets stripped)', $plain, "SELECT * FROM $U WHERE ID = 1", true);
$expect('select posts', $plain, "SELECT * FROM $P LIMIT 5", true);
$expect('bulk alloptions', $plain, "SELECT option_name, option_value FROM $O WHERE autoload IN ('yes', 'on')", true);
$expect('read own option', $plain, "SELECT option_value FROM $O WHERE option_name = 'securecore_policy_probe_own'", true);
$expect('read siteurl explicitly', $plain, "SELECT option_value FROM $O WHERE option_name = 'siteurl'", true);
$expect('write own option', $plain, "UPDATE $O SET option_value = 'x' WHERE option_name = 'myplugin_setting'", true);
$expect('create own table', $plain, "CREATE TABLE {$pre}myplugin_data (id INT)", true);
$expect('insert own table', $plain, "INSERT INTO {$pre}myplugin_data (id) VALUES (1)", true);
$expect('write postmeta (content)', $plain, "INSERT INTO $PM (post_id, meta_key, meta_value) VALUES (1, 'k', 'v')", true);
$expect('SET NAMES', $plain, "SET NAMES utf8mb4", true);
$expect('SET SESSION sql_mode', $plain, "SET SESSION sql_mode = 'NO_ENGINE_SUBSTITUTION'", true);
$expect('SET autocommit', $plain, "SET autocommit = 0", true);
$expect('SELECT 1', $plain, "SELECT 1", true);
$expect('DESCRIBE core table', $plain, "DESCRIBE $O", true);
$expect('EXPLAIN SELECT', $plain, "EXPLAIN SELECT * FROM $P", true);
$expect('START TRANSACTION', $plain, "START TRANSACTION", true);
$expect('BEGIN', $plain, "BEGIN", true);
$expect('COMMIT', $plain, "COMMIT", true);
$expect('ROLLBACK', $plain, "ROLLBACK", true);
$expect('SAVEPOINT', $plain, "SAVEPOINT sp1", true);
$expect('ROLLBACK TO SAVEPOINT', $plain, "ROLLBACK TO SAVEPOINT sp1", true);
$expect('TRUNCATE own table', $plain, "TRUNCATE TABLE {$pre}myplugin_data", true);
// File-function words appearing only inside a string literal are data, not a file operation.
$expect('search posts (outfile literal)', $plain, "SELECT ID FROM $P WHERE post_content LIKE '%into outfile%'", true);
$expect('write own (load_file literal)', $plain, "INSERT INTO {$pre}myplugin (note) VALUES ('about load_file( usage')", true);

echo "\n-- a grant opens exactly its door --\n";
$expect('insert users (granted)', $granted, "INSERT INTO $U (user_login) VALUES ('x')", true);
$expect('escalate caps (granted)', $granted, "UPDATE $UM SET meta_value = 'a:1:{}' WHERE user_id = 1 AND meta_key = '{$pre}capabilities'", true);
$expect('write admin_email (granted)', $granted, "UPDATE $O SET option_value = 'x' WHERE option_name = 'admin_email'", true);
$expect('still DROP-denied (granted)', $granted, "DROP TABLE $U", false);

echo $fails ? "\npolicy-unit: FAIL ($fails)\n" : "\npolicy-unit: PASS\n";
exit($fails ? 1 : 0);
