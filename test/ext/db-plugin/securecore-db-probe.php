<?php
/**
 * Plugin Name: SecureCore DB probe (test fixture)
 * Description: E4 canary (test/ext-db.sh). On ?sc_db=run, sends each case through each query route
 * and prints "<route>|<case>=BLOCKED" when SecureCore's database policy stopped it, or
 * "<route>|<case>=RAN:<errno>" when it reached the server (whatever the server then said).
 */

if (($_GET['sc_db'] ?? '') !== 'run') {
    return;
}

add_action('init', static function (): void {
    global $wpdb;
    header('Content-Type: text/plain');
    $p = $wpdb->prefix;

    // The cases: what each sends, and whether the policy should stop it in enforce mode without a
    // grant (the shell test holds the expectations; this list only names them).
    $cases = [
        'own-select'     => "SELECT COUNT(*) FROM {$p}securecore_db_probe",
        'own-insert'     => "INSERT INTO {$p}securecore_db_probe (note) VALUES ('probe')",
        'other-table'    => "SELECT COUNT(*) FROM {$p}otherplugin_data",
        'core-posts'     => "SELECT ID FROM {$p}posts LIMIT 1",
        'user-pass'      => "SELECT user_pass FROM {$p}users LIMIT 1",
        'users-star'     => "SELECT * FROM {$p}users LIMIT 1",
        'protected-opt'  => "UPDATE {$p}options SET option_value = option_value WHERE option_name = 'siteurl'",
        'own-option'     => "SELECT option_value FROM {$p}options WHERE option_name = 'securecore-db-probe_setting'",
        'prepare'        => "PREPARE sc_probe FROM 'SELECT 1'",
        'set-var'        => "SET @sc_probe = 0x53454c454354",
        'load-file'      => "SELECT LOAD_FILE('/etc/hostname')",
        'outfile'        => "SELECT 1 INTO OUTFILE '/tmp/sc-db-probe-" . getmypid() . "-" . mt_rand() . "'",
        'multi'          => "SELECT 1; SELECT 2",
        'comment-trick'  => "SELECT /*!50000 user_pass */ ID FROM {$p}users LIMIT 1",
        'ansi-quotes'    => "SET SESSION sql_mode = 'ANSI_QUOTES'",
    ];

    $blocked = static fn (string $error): bool => str_contains($error, 'securecore');
    $out = [];
    $say = static function (string $route, string $case, bool $stopped, int $errno) use (&$out): void {
        $out[] = "$route|$case=" . ($stopped ? 'BLOCKED' : "RAN:$errno");
    };

    $m = $wpdb->dbh; // core's own connection: the policy is per call, not per connection
    $own = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
    mysqli_report(MYSQLI_REPORT_OFF);
    // A fresh PDO connection per case: PDO::exec of a SELECT leaves its rows pending on the
    // connection, which would fail the next case with 2014 (PDO's doing, not the policy's).
    $connect = static fn (): PDO => new PDO('mysql:host=' . DB_HOST . ';dbname=' . DB_NAME, DB_USER, DB_PASSWORD,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true]);

    foreach ($cases as $case => $sql) {
        $pdo = $connect();
        // mysqli, procedural and method, on core's connection and on the plugin's own.
        $r = mysqli_query($m, $sql);
        $say('mysqli_query', $case, $r === false && $blocked(mysqli_error($m)), mysqli_errno($m));
        if ($r instanceof mysqli_result) $r->free();
        $r = mysqli_real_query($m, $sql);
        $say('mysqli_real_query', $case, $r === false && $blocked(mysqli_error($m)), mysqli_errno($m));
        if ($r) { $x = mysqli_store_result($m); if ($x instanceof mysqli_result) $x->free(); }
        $r = $own->query($sql);
        $say('mysqli::query', $case, $r === false && $blocked($own->error), $own->errno);
        if ($r instanceof mysqli_result) $r->free();
        $r = $own->real_query($sql);
        $say('mysqli::real_query', $case, $r === false && $blocked($own->error), $own->errno);
        if ($r) { $x = $own->store_result(); if ($x instanceof mysqli_result) $x->free(); }
        $r = mysqli_multi_query($own, $sql);
        $say('mysqli_multi_query', $case, $r === false && $blocked($own->error), $own->errno);
        if ($r) { do { $x = $own->store_result(); if ($x instanceof mysqli_result) $x->free(); } while ($own->more_results() && $own->next_result()); }
        $r = $own->multi_query($sql);
        $say('mysqli::multi_query', $case, $r === false && $blocked($own->error), $own->errno);
        if ($r) { do { $x = $own->store_result(); if ($x instanceof mysqli_result) $x->free(); } while ($own->more_results() && $own->next_result()); }

        // Prepared: refused at prepare (the statement fails there), or at execute.
        $prep = static function (string $route, $stmt, mysqli $link) use ($case, $say, $blocked): void {
            if ($stmt === false) { $say($route, $case, $blocked($link->error), $link->errno); return; }
            $ok = @$stmt->execute();
            $say($route, $case, !$ok && $blocked($stmt->error), $stmt->errno);
            $stmt->close();
        };
        $prep('mysqli_prepare', mysqli_prepare($own, $sql), $own);
        $prep('mysqli::prepare', $own->prepare($sql), $own);
        $st = mysqli_stmt_init($own);
        $prep('mysqli_stmt_prepare', mysqli_stmt_prepare($st, $sql) ? $st : false, $own);
        $st = $own->stmt_init();
        $prep('mysqli_stmt::prepare', $st->prepare($sql) ? $st : false, $own);
        // When the constructor's prepare fails, PHP leaves the object uninitialised (any use throws
        // Error) and the reason on the link, as for any failed prepare: read it there.
        try {
            $st = new mysqli_stmt($own, $sql);
            if ($st->errno) {
                // The constructor keeps a failed prepare's error on the statement, not the link.
                $say('new mysqli_stmt', $case, $blocked($st->error), $st->errno);
            } else {
                $prep('new mysqli_stmt', $st, $own);
            }
        } catch (Throwable $e) {
            $say('new mysqli_stmt', $case, $blocked($own->error) || $blocked($e->getMessage()), $own->errno);
        }
        $r = @mysqli_execute_query($own, $sql);
        $say('mysqli_execute_query', $case, $r === false && $blocked($own->error), $own->errno);
        $r = @$own->execute_query($sql);
        $say('mysqli::execute_query', $case, $r === false && $blocked($own->error), $own->errno);

        // PDO, exception mode (PHP 8's default), and silent mode once per case.
        // Every result is drained and closed, so the next call isn't "unbuffered queries active".
        $drain = static function ($s): void {
            if ($s instanceof PDOStatement) { do { try { $s->fetchAll(); } catch (Throwable) {} } while (@$s->nextRowset()); $s->closeCursor(); }
        };
        try { $drain($pdo->query($sql)); $say('PDO::query', $case, false, 0); }
        catch (PDOException $e) { $say('PDO::query', $case, $blocked($e->getMessage()), (int) ($e->errorInfo[1] ?? 0)); }
        try { $pdo->exec($sql); $say('PDO::exec', $case, false, 0); }
        catch (PDOException $e) { $say('PDO::exec', $case, $blocked($e->getMessage()), (int) ($e->errorInfo[1] ?? 0)); }
        try { $s = $pdo->prepare($sql); $s->execute(); $drain($s); $say('PDO::prepare', $case, false, 0); }
        catch (PDOException $e) { $say('PDO::prepare', $case, $blocked($e->getMessage()), (int) ($e->errorInfo[1] ?? 0)); }
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_SILENT);
        $r = $pdo->query($sql);
        $say('PDO::query(silent)', $case, $r === false && $blocked((string) ($pdo->errorInfo()[2] ?? '')), (int) ($pdo->errorInfo()[1] ?? 0));
        $drain($r);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        // Reset the session the cases may have changed (ANSI_QUOTES), on every connection.
        @$own->query("SET SESSION sql_mode = 'NO_ENGINE_SUBSTITUTION'");
        $pdo = null;
        $wpdb->set_sql_mode();

        // $wpdb: mysqli under the hood; the refusal must show in last_error and the call return.
        $wpdb->suppress_errors(true);
        $r = $wpdb->query($sql);
        $say('wpdb::query', $case, $r === false && $blocked($wpdb->last_error), 0);
        $wpdb->suppress_errors(false);
    }

    // mysqli in strict report mode (PHP 8.1's default outside WordPress): an exception, as a
    // permission error throws.
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    try { $own->query($cases['user-pass']); $out[] = 'strict|user-pass=RAN:0'; }
    catch (mysqli_sql_exception $e) { $out[] = 'strict|user-pass=' . ($blocked($e->getMessage()) && $e->getCode() === 1142 ? 'BLOCKED' : 'RAN:' . $e->getCode()); }
    mysqli_report(MYSQLI_REPORT_OFF);

    // Core's passthrough helpers: SQL (or an option name) the plugin hands them is the plugin's,
    // so none of these may launder a protected write or a user_pass read through core.
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    $wpdb->suppress_errors(true);
    $via = static function (string $case, callable $run) use (&$out, $wpdb, $blocked): void {
        $wpdb->last_error = '';
        $run();
        $out[] = "helper|$case=" . ($blocked($wpdb->last_error) ? 'BLOCKED' : 'RAN:0');
    };
    $via('dbdelta-protected-opt', static fn () => dbDelta("UPDATE {$p}options SET option_value = option_value WHERE option_name = 'active_plugins'"));
    $via('dbdelta-user-pass', static fn () => dbDelta("INSERT INTO {$p}securecore_db_probe (note) SELECT user_pass FROM {$p}users LIMIT 1"));
    // maybe_create_table runs another query after the DDL (SHOW TABLES), which clears last_error,
    // so this one is judged by its effect: the DDL writes a marker into a write-protected option.
    $login = get_option('mailserver_login');
    $marker = 'sc-probe-' . mt_rand();
    maybe_create_table("{$p}sc_db_probe_nope", "UPDATE {$p}options SET option_value = '$marker' WHERE option_name = 'mailserver_login'");
    wp_cache_delete('alloptions', 'options');
    wp_cache_delete('mailserver_login', 'options');
    $out[] = 'helper|maybe-create-table=' . (get_option('mailserver_login') === $marker ? 'RAN:0' : 'BLOCKED');
    update_option('mailserver_login', $login); // put it back where log/off let the DDL through
    $mailpass = get_option('mailserver_pass');
    $via('update-option-protected', static fn () => update_option('mailserver_pass', 'sc-probe-' . mt_rand()));
    $wpdb->last_error = '';
    update_option('mailserver_pass', $mailpass); // put it back where log/off let the probe change it

    // cron: scheduling through core's API is core's write; the plugin writing the option is not.
    wp_clear_scheduled_hook('sc_db_probe_event');
    $scheduled = wp_schedule_single_event(time() + 3600, 'sc_db_probe_event') && wp_next_scheduled('sc_db_probe_event');
    $out[] = 'cron|schedule=' . ($scheduled ? 'RAN:0' : 'BLOCKED');
    wp_clear_scheduled_hook('sc_db_probe_event');
    $wpdb->last_error = '';
    $r = $wpdb->query("UPDATE {$p}options SET option_value = option_value WHERE option_name = 'cron'");
    $out[] = 'cron|update-direct=' . ($r === false && $blocked($wpdb->last_error) ? 'BLOCKED' : 'RAN:0');
    $wpdb->suppress_errors(false);

    // Not queries: USE and a re-login are refused for a component, and an unsafe charset for all.
    $out[] = 'select_db|use=' . (mysqli_select_db($own, DB_NAME) ? 'RAN:0' : 'BLOCKED');
    $out[] = 'set_charset|gbk=' . ($own->set_charset('gbk') ? 'RAN:0' : 'BLOCKED');
    $own->set_charset('utf8mb4');

    echo implode("\n", $out), "\nDONE\n";
    exit;
}, 1);
