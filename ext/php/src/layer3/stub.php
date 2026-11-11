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
    // One query from the child, on this worker's connection: what $wpdb saw, PHP-serialized.
    $run = static function () use ($slug): string {
        global $wpdb;
        $sql = \securecore_layer3_db_begin($slug);
        if (!is_string($sql)) {
            return serialize(['ret' => false, 'error' => 'securecore: layer3 had no query to run']);
        }
        $ret = false;
        $cols = [];
        try {
            $ret = $wpdb->query($sql);
            $error = (string) $wpdb->last_error;
            if ($ret !== false && ($wpdb->result ?? null) instanceof \mysqli_result) {
                $cols = (array) $wpdb->get_col_info('name');
            }
        } catch (\Throwable $e) {
            $ret = false;
            $error = 'securecore: ' . get_class($e) . ': ' . $e->getMessage();
        }
        $keys = [];
        $rows = [];
        foreach (is_array($wpdb->last_result) ? $wpdb->last_result : [] as $row) {
            $v = is_object($row) ? get_object_vars($row) : [];
            if ($keys === []) $keys = array_keys($v);
            $rows[] = array_values($v);
        }
        $a = [
            'ret' => is_int($ret) || is_bool($ret) ? $ret : false,
            'error' => $error,
            'keys' => $keys,
            'rows' => $rows,
            'cols' => $cols,
            'num_rows' => count($rows),
        ];
        // As wpdb::query() sets them: rows_affected for a write, insert_id for an INSERT/REPLACE.
        if (preg_match('/^\s*(insert|delete|update|replace)\s/i', $sql)) $a['affected'] = (int) $wpdb->rows_affected;
        if (preg_match('/^\s*(insert|replace)\s/i', $sql)) $a['insert_id'] = (int) $wpdb->insert_id;
        return serialize($a);
    };
    // The statement time cap: the call's remaining milliseconds while it queries, then the
    // session's own value again (read once per request).
    $before = null;
    $cap = static function (?int $ms) use (&$before): void {
        global $wpdb;
        $var = stripos((string) $wpdb->db_server_info(), 'mariadb') !== false ? 'max_statement_time' : 'max_execution_time';
        $before ??= (string) $wpdb->get_var("SELECT @@SESSION.$var");
        if ($ms === null) {
            $value = is_numeric($before) ? $before : '0';
        } else {
            $value = $var === 'max_statement_time' ? sprintf('%.3F', $ms / 1000) : (string) $ms;
        }
        $wpdb->query("SET SESSION $var = $value");
    };
    // Waits out the child's queries: the answer (a string), or null.
    $pump = static function ($answer) use ($slug, $run, $cap) {
        global $wpdb;
        $capped = false;
        while (is_array($answer)) {
            if (!$capped) {
                $capped = true;
                $cap(max(1, (int) ($answer['ms'] ?? 1)));
            }
            $answer = \securecore_layer3_db_reply($slug, $run());
        }
        if ($capped) $cap(null);
        if (!is_string($answer) && \securecore_layer3_take_rollback($slug)) {
            $wpdb->query('ROLLBACK');
            error_log("securecore: layer3 plugin:$slug rolled back the transaction its child left open");
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
