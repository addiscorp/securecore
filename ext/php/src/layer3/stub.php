<?php
// SecureCore layer 3 (addiscorp/securecore#53, E7): what the php-fpm worker runs in place of an
// isolated plugin's main file. The extension compiles it (with the plugin's slug and file
// filled in) when wp-settings.php includes the plugin, so not one line of the plugin runs here.
// It asks the helper for a child that loads the plugin, and mirrors what the plugin registered
// there (hooks and shortcodes) as callbacks that forward each call to the child.
//
// The database gateway (#94): while the plugin loads or a call runs, the child may send queries
// instead of its answer. Each one comes back here as an array; $run takes its text from the
// extension and runs it on this worker's $wpdb, where layer 2 checks it as the plugin's own
// (the extension charges this file's frames to the plugin while it runs), and the answer goes
// back to the child. The call's remaining time caps each statement on the server.
//
// If the child can't be had, or a call fails (timeout, memory, a crash), the page goes on: a
// filter passes its value through unchanged, a shortcode renders empty, an action does nothing.
(static function (string $slug, string $file): void {
    // Objects and resources don't cross yet (they become null): see ext/README.md, "not yet".
    $plain = static function ($v, int $depth = 0) use (&$plain) {
        if (is_object($v) || is_resource($v) || $depth > 32) return null;
        if (is_array($v)) {
            foreach ($v as $k => $x) $v[$k] = $plain($x, $depth + 1);
        }
        return $v;
    };
    $mariadb = static function (): bool {
        global $wpdb;
        return stripos((string) $wpdb->db_server_info(), 'mariadb') !== false;
    };
    // The server's error for the child: its code and its text, with the connection's database
    // name, user and host taken out (`'db.table'`, `'user'@'host'`), so the child learns no part
    // of the credentials from an error.
    $clean = static function (string $error, int $errno): string {
        global $wpdb;
        if ($error === '' || str_starts_with($error, 'securecore: ')) return $error;
        $error = (string) preg_replace("/'[^']*'@'[^']*'/", "'<user>'@'<host>'", $error);
        $db = defined('DB_NAME') ? (string) DB_NAME : (string) ($wpdb->dbname ?? '');
        if ($db !== '') {
            // Where the server names it: 'db.table', `db`.table, 'db'.
            $error = str_replace(["'$db.", "`$db`.", "'$db'", "`$db`"], ["'", '', "'<db>'", '`<db>`'], $error);
        }
        return $errno > 0 ? "[$errno] $error" : $error;
    };
    // One query from the child, on this worker's connection, PHP-serialized as wpdb::query()
    // would leave it. It runs as $wpdb's own query does (the worker's `query` filters, then
    // mysqli_query() on $wpdb's connection, which layer 2 checks with the same route and text),
    // but unbuffered (MYSQLI_USE_RESULT): rows are read one at a time and copied only up to
    // $limit bytes (layer3.limits.dbResultBytes). Past it the rest is drained unread and the
    // answer is a refusal, so a result far over the cap never sits in the worker's memory.
    $run = static function (int $limit) use ($slug, $clean): string {
        global $wpdb;
        $sql = \securecore_layer3_db_begin($slug);
        if (!is_string($sql)) {
            return serialize(['ret' => false, 'error' => 'securecore: layer3 had no query to run']);
        }
        $sql = (string) apply_filters('query', $sql);
        $dbh = $wpdb->dbh ?? null;
        if (!$dbh instanceof \mysqli && $wpdb->check_connection(false)) $dbh = $wpdb->dbh ?? null;
        if ($sql === '' || !$dbh instanceof \mysqli) {
            return serialize(['ret' => false, 'error' => $sql === '' ? '' : 'securecore: layer3: the worker has no database connection']);
        }
        $ret = false;
        $error = '';
        $errno = 0;
        $keys = [];
        $cols = [];
        $rows = [];
        $a = [];
        try {
            $res = mysqli_query($dbh, $sql, MYSQLI_USE_RESULT);
        } catch (\Throwable $e) {
            $res = false;
        }
        if ($res === false) {
            $errno = (int) mysqli_errno($dbh);
            $error = (string) mysqli_error($dbh);
        } elseif ($res instanceof \mysqli_result) {
            $cols = array_map(static fn ($f) => $f->name, mysqli_fetch_fields($res) ?: []);
            $bytes = 0;
            while (($row = mysqli_fetch_assoc($res)) !== null && $row !== false) {
                if ($keys === []) $keys = array_keys($row);
                // What serialize() writes for each value, near enough (its text and ~16 bytes).
                foreach ($row as $x) $bytes += strlen((string) $x) + 16;
                if ($limit > 0 && $bytes > $limit) {
                    $rows = [];
                    mysqli_free_result($res);
                    error_log("securecore: layer3 plugin:$slug database answer refused: over the dbResultBytes cap of $limit");
                    return serialize(['ret' => false, 'error' => "securecore: layer3 refused this answer (over the dbResultBytes cap of $limit)"]);
                }
                $rows[] = array_values($row);
            }
            if (mysqli_errno($dbh)) {
                $errno = (int) mysqli_errno($dbh);
                $error = (string) mysqli_error($dbh);
            }
            mysqli_free_result($res);
            $ret = $error === '' ? count($rows) : false;
        } elseif (preg_match('/^\s*(create|alter|truncate|drop)\s/i', $sql)) {
            $ret = true;
        } elseif (preg_match('/^\s*(insert|delete|update|replace)\s/i', $sql)) {
            // As wpdb::query() sets them: rows_affected for a write, insert_id for an INSERT/REPLACE.
            $ret = (int) mysqli_affected_rows($dbh);
            $a['affected'] = $ret;
            if (preg_match('/^\s*(insert|replace)\s/i', $sql)) $a['insert_id'] = (int) mysqli_insert_id($dbh);
        } else {
            $ret = 0;
        }
        if ($error !== '' && preg_match('/^\s*(insert|replace)\s/i', $sql)) $a['insert_id'] = 0;
        $a += [
            'ret' => $ret,
            'error' => $clean($error, $errno),
            'keys' => $keys,
            'rows' => $rows,
            'cols' => $cols,
            'num_rows' => count($rows),
        ];
        return serialize($a);
    };
    // The statement time cap: the time left before the call's deadline, set before a query
    // whenever the last setting is more than 50 ms old (so a statement never runs more than 50 ms
    // past the deadline on the server), then the session's own value again (read once per
    // request). MariaDB's max_statement_time covers every statement; MySQL's max_execution_time
    // only SELECTs (addiscorp/securecore#99).
    $before = null;
    $cap = static function (?int $ms) use (&$before, $mariadb): void {
        global $wpdb;
        $var = $mariadb() ? 'max_statement_time' : 'max_execution_time';
        $before ??= (string) $wpdb->get_var("SELECT @@SESSION.$var");
        if ($ms === null) {
            $value = is_numeric($before) ? $before : '0';
        } else {
            $value = $var === 'max_statement_time' ? sprintf('%.3F', $ms / 1000) : (string) $ms;
        }
        $wpdb->query("SET SESSION $var = $value");
    };
    // The connection's transaction state, as the server reports it (never read from the SQL
    // text): [autocommit on, a transaction open].
    $state = static function () use ($mariadb): array {
        global $wpdb;
        $open = $mariadb()
            ? '@@in_transaction'
            : '(SELECT COUNT(*) FROM information_schema.innodb_trx WHERE trx_mysql_thread_id = CONNECTION_ID())';
        $r = $wpdb->get_row("SELECT @@autocommit, $open", ARRAY_N);
        return [(int) ($r[0] ?? 1) === 1, (int) ($r[1] ?? 0) > 0];
    };
    // Waits out the child's queries: the answer (a string), or null. However the exchange ended
    // (an answer, a timeout, a crash), a transaction the plugin opened, or autocommit it turned
    // off, is rolled back and restored, so core's later writes in the request never join it.
    $pump = static function ($answer) use ($slug, $run, $cap, $state) {
        global $wpdb;
        $was = null;
        $set_at = null;
        while (is_array($answer)) {
            $was ??= $state();
            if ($set_at === null || microtime(true) - $set_at > 0.05) {
                $cap(max(1, (int) ($answer['ms'] ?? 1)));
                $set_at = microtime(true);
            }
            $answer = \securecore_layer3_db_reply($slug, $run((int) ($answer['bytes'] ?? 0)));
        }
        if ($was !== null) {
            $cap(null);
            [$autocommit, $open] = $state();
            if (($open && !$was[1]) || (!$autocommit && $was[0])) {
                $wpdb->query('ROLLBACK');
                if (!$autocommit && $was[0]) $wpdb->query('SET autocommit = 1');
                error_log("securecore: layer3 plugin:$slug left " . ($open ? 'a transaction open' : 'autocommit off')
                    . " on the worker's connection: rolled back" . (!$autocommit && $was[0] ? ', autocommit restored' : ''));
            }
        }
        return $answer;
    };
    $register = null;
    $register = static function (array $regs) use ($slug, $plain, $pump, &$register): void {
        foreach ($regs as $r) {
            if (!is_array($r) || !isset($r['kind'], $r['name'], $r['id'])) continue;
            $id = (int) $r['id'];
            $kind = (string) $r['kind'];
            $forward = static function (...$args) use ($slug, $id, $kind, $plain, $pump, &$register) {
                $answer = $pump(\securecore_layer3_call($slug, $id, serialize($plain($args))));
                $a = is_string($answer) ? unserialize($answer, ['allowed_classes' => false]) : null;
                if (!is_array($a)) {
                    return $kind === 'shortcode' ? '' : ($args[0] ?? null);
                }
                if (!empty($a['reg']) && is_array($a['reg'])) $register($a['reg']);
                if (is_string($a['out'] ?? null) && $a['out'] !== '') echo $a['out'];
                if (!empty($a['error'])) {
                    return $kind === 'shortcode' ? '' : ($args[0] ?? null);
                }
                return $a['ret'] ?? null;
            };
            if ($kind === 'shortcode') {
                add_shortcode((string) $r['name'], $forward);
            } else {
                add_filter((string) $r['name'], $forward, (int) ($r['priority'] ?? 10), (int) ($r['args'] ?? 1));
            }
        }
    };
    global $wpdb;
    $prefix = (string) ($GLOBALS['table_prefix'] ?? 'wp_');
    // The helper boots from WordPress's own options only (#47): the list is the extension's.
    $names = \securecore_layer3_snapshot_names(ABSPATH, $prefix, (string) get_option('stylesheet'));
    $snapshot = serialize(array_intersect_key(wp_load_alloptions(), array_flip($names)));
    // What the child's $wpdb reports without a connection; never a credential.
    $facts = [(string) $wpdb->charset, (string) $wpdb->collate, (string) $wpdb->db_version(), (string) $wpdb->db_server_info()];
    $ready = $pump(\securecore_layer3_open($slug, $file, ABSPATH, $prefix, $snapshot, $facts));
    $a = is_string($ready) ? unserialize($ready, ['allowed_classes' => false]) : null;
    if (!is_array($a)) return;
    if (is_string($a['out'] ?? null) && $a['out'] !== '') echo $a['out'];
    if (is_array($a['reg'] ?? null)) $register($a['reg']);
})(__SC_SLUG__, __SC_FILE__);
