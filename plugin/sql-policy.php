<?php
// The database gateway's SQL policy (addiscorp/securecore#42, part 2).
//
// Part 1's gateway ran whatever query a sandboxed plugin sent against core's real $wpdb. This
// closes that: every query the sandbox forwards is parsed with a maintained SQL parser
// (phpmyadmin/sql-parser, vendored into the plugin zip, pinned by exact version — APS 10) and
// checked against a per-plugin policy before it runs. The policy's job is core's sensitive data,
// not cross-plugin isolation (that is a later part); everything it does not protect stays free so
// plugins keep working.
//
// It is deny-by-default on statement SHAPE first, then on the data a statement touches. Only these
// statement types ever run; everything else is refused whatever table it names:
//   - SELECT, INSERT, UPDATE, DELETE, REPLACE;
//   - SHOW, DESCRIBE / DESC, EXPLAIN (schema/plan, no row data);
//   - the session SETs WordPress uses (SET NAMES, SET SESSION sql_mode, SET autocommit) — never a
//     user or system variable, i.e. no `SET @x = …` and no `SET @@…`;
//   - transaction control (START TRANSACTION, BEGIN, COMMIT, ROLLBACK [TO [SAVEPOINT]], SAVEPOINT,
//     RELEASE SAVEPOINT);
//   - CREATE / ALTER / DROP / TRUNCATE on tables that are NOT core's.
// Refused outright: PREPARE, EXECUTE, DEALLOCATE, HANDLER, DO, USE, CALL, LOAD DATA, LOCK / UNLOCK,
// CREATE PROCEDURE / FUNCTION / TRIGGER / EVENT / VIEW, GRANT, CTEs (WITH …), the table-maintenance
// statements, and anything the parser does not build a statement for. That is what stops the
// prepared-statement bypass — `SET @s = 0x<hex of a SELECT user_pass>`, then `PREPARE x FROM @s`,
// then `EXECUTE x`: the SET of a user variable, the PREPARE and the EXECUTE are each refused on
// their own, so a payload cannot be smuggled past the column checks below. Inside an allowed
// statement, LOAD_FILE(, INTO OUTFILE and INTO DUMPFILE are refused too (reading/writing files on
// the database server). The shape check uses the statement's class, not its text, so an alias or
// comment cannot rename it.
//
// What it then protects on the data (default deny; a plugin's manifest may grant the gated items):
//   - never readable, for anyone:  wp_users.user_pass, wp_users.user_activation_key,
//                                  wp_usermeta meta_key 'session_tokens';
//   - gated (manifest grant):      writes to wp_users; capability rows in wp_usermeta
//                                  ({prefix}capabilities, {prefix}user_level); the sensitive
//                                  options active_plugins, admin_email, users_can_register,
//                                  default_role, cron, mailserver_login, mailserver_pass (read
//                                  and write) and siteurl, home, {prefix}user_roles (write only —
//                                  see the note below);
//   - free:                        the plugin's own tables, options and meta; reads of core
//                                  content (posts, terms, postmeta, comments).
//
// A refused statement never runs; the gateway returns what a failed $wpdb query returns (false
// or an empty result, last_error "securecore: denied <reason>"), so a plugin degrades instead of
// crashing, and the denial is audited with the plugin and table.
//
// siteurl / home / {prefix}user_roles are in #42's denied list, but a sandboxed plugin reads them
// only because the sandbox's own WordPress needs them: siteurl/home for every URL it builds,
// user_roles for WP_Roles (so current_user_can() is not empty). Read-denying them regresses the
// front page and dashboard below part 1d's results, which #42 requires we hold. They are public,
// non-secret config, so this policy allows reading them and denies only writing them, and flags
// the divergence in the PR. Everything else in the denied list is read- and write-denied.
//
// Limit — one install per database. Core tables are recognised from THIS install's $wpdb (its
// prefix and table names). A second WordPress sharing the same MySQL database under a different
// prefix (otherprefix_users, otherprefix_options) is invisible to this policy: coreTablesIn() does
// not match it, so a sandboxed plugin may read and write those tables as if they were its own —
// otherprefix_users.user_pass counts as free. SecureCore assumes one install per database; a
// shared database is out of scope for this part (noted in docs/realwp-spike.md).
namespace SecureCore;

use PhpMyAdmin\SqlParser\Parser;

/**
 * A per-plugin decision engine over the SQL a sandboxed plugin forwards. Built once per request
 * from core's real $wpdb (for the live table names and prefix) and the plugin's manifest (for its
 * own options and any grants). decide() returns how the gateway should treat one query.
 */
final class SqlPolicy
{
    // Transaction-control statements: a tiny, payload-free vocabulary (no tables, no expressions).
    // Matched on the normalised text BEFORE the parser, because this parser version reports several
    // of them (COMMIT, ROLLBACK, SAVEPOINT, RELEASE SAVEPOINT, ROLLBACK TO SAVEPOINT) as errors, and
    // the error deny below would otherwise reject them. Anchored, with no `.*`, so it cannot match a
    // second statement smuggled in after one of these.
    private const TX_CONTROL = '~^(?:'
        . 'start\s+transaction(?:\s+(?:read\s+(?:only|write)|with\s+consistent\s+snapshot)(?:\s*,\s*(?:read\s+(?:only|write)|with\s+consistent\s+snapshot))*)?'
        . '|begin(?:\s+work)?'
        . '|commit(?:\s+work)?(?:\s+(?:and(?:\s+no)?\s+chain|(?:no\s+)?release))?'
        . '|rollback(?:\s+work)?(?:\s+to(?:\s+savepoint)?\s+`?\w+`?|\s+(?:and(?:\s+no)?\s+chain|(?:no\s+)?release))?'
        . '|savepoint\s+`?\w+`?'
        . '|release\s+savepoint\s+`?\w+`?'
        . ')$~i';

    // CREATE of a stored object rather than a table — refused whatever it names. Tolerates
    // OR REPLACE / ALGORITHM= / DEFINER= / SQL SECURITY / AGGREGATE / TEMPORARY before the keyword.
    private const CREATE_ROUTINE = '~^create\s+(?:or\s+replace\s+)?(?:algorithm\s*=\s*\S+\s+)?(?:definer\s*=\s*\S+\s+)?(?:sql\s+security\s+\S+\s+)?(?:aggregate\s+)?(?:temporary\s+)?(?:procedure|function|trigger|event|view)\b~i';

    private string $prefix;
    private string $usersTable;
    private string $usermetaTable;
    private string $optionsTable;
    /** @var array<string,true> every core table's full name, lower-cased */
    private array $coreTables;
    /** @var array<string,true> the usermeta capability keys, lower-cased */
    private array $capabilityKeys;
    private string $userRolesOption;

    /** @var array<string,true> options a plugin may never read without a grant */
    private array $readDenied;
    /** @var array<string,true> options a plugin may never write without a grant */
    private array $writeDenied;

    private bool $grantUsers = false;
    private bool $grantCapabilities = false;
    /** @var array<string,true> options the plugin's manifest grants (read and write) */
    private array $grantedOptions = [];
    /** @var array<string,true> the plugin's own option names, lower-cased */
    private array $ownOptions = [];

    public function __construct(\wpdb $wpdb, array $manifest)
    {
        $this->prefix = strtolower($wpdb->prefix);
        $this->usersTable = strtolower($wpdb->users);
        $this->usermetaTable = strtolower($wpdb->usermeta);
        $this->optionsTable = strtolower($wpdb->options);
        $this->userRolesOption = $this->prefix . 'user_roles';

        $tables = [];
        foreach ($wpdb->tables('all', true) as $full) {
            $tables[strtolower((string) $full)] = true;
        }
        // Belt and braces: the per-blog and global tables by property, in case tables() is thin.
        foreach (['users', 'usermeta', 'options', 'posts', 'postmeta', 'comments', 'commentmeta',
                  'terms', 'termmeta', 'term_taxonomy', 'term_relationships', 'links'] as $t) {
            if (isset($wpdb->$t)) $tables[strtolower((string) $wpdb->$t)] = true;
        }
        $this->coreTables = $tables;

        $this->capabilityKeys = [
            $this->prefix . 'capabilities' => true,
            $this->prefix . 'user_level' => true,
            strtolower($wpdb->base_prefix) . 'capabilities' => true,
            strtolower($wpdb->base_prefix) . 'user_level' => true,
        ];

        // active_plugins is forced empty in the sandbox already; it stays denied so a plugin can
        // neither read the real list nor rewrite it.
        $this->readDenied = array_fill_keys([
            'active_plugins', 'admin_email', 'users_can_register', 'default_role',
            'cron', 'mailserver_login', 'mailserver_pass',
        ], true);
        // Write-denied adds the three read-allowed-for-function options (see the file header).
        $this->writeDenied = $this->readDenied + array_fill_keys([
            'siteurl', 'home', $this->userRolesOption,
        ], true);

        $db = is_array($manifest['db'] ?? null) ? $manifest['db'] : [];
        foreach ((array) ($db['grants'] ?? []) as $grant) {
            $grant = strtolower((string) $grant);
            if ($grant === 'users') $this->grantUsers = true;
            elseif ($grant === 'usermeta:capabilities') $this->grantCapabilities = true;
            elseif (str_starts_with($grant, 'option:')) $this->grantedOptions[substr($grant, 7)] = true;
        }
        foreach ((array) ($db['options'] ?? []) as $name) {
            $this->ownOptions[strtolower((string) $name)] = true;
        }
    }

    /**
     * Decide one forwarded query. Returns:
     *   ['run' => false, 'reason' => string]                 refuse: do not run it
     *   ['run' => true, 'reason' => '', 'filters' => [...]]  run it, then apply these result filters
     * Filters (all optional): strip_user_secrets (bool), options ('allowlist'|'denied'),
     * usermeta (bool), keep_caps (bool).
     */
    public function decide(string $sql): array
    {
        $sql = trim($sql);
        if ($sql === '') return self::allow();

        // Normalise for shape matching: drop a trailing ';' and surrounding whitespace.
        $clean = preg_replace('/;\s*$/', '', rtrim($sql)) ?? rtrim($sql);
        $lower = strtolower($clean);

        // Transaction control first (several forms are flagged as parse errors by this parser).
        if (preg_match(self::TX_CONTROL, $lower)) return self::allow();

        try {
            $parser = new Parser($clean);
        } catch (\Throwable $e) {
            return self::deny('unparseable query');
        }
        if (!empty($parser->errors)) return self::deny('unparseable query');

        $n = count($parser->statements);
        // No statement the parser builds: PREPARE / EXECUTE / DEALLOCATE / HANDLER / DO / USE and
        // anything else it does not classify. Refused — this is the prepared-statement bypass.
        if ($n === 0) return self::deny('unsupported statement');
        if ($n > 1) return self::deny('multi-statement query');

        // Classify by the statement's class (its text cannot lie about what it is).
        $class = substr((string) strrchr('\\' . get_class($parser->statements[0]), '\\'), 1);

        // Reading or writing a file on the database server, inside any data statement. String
        // literals are stripped first so a query that merely mentions these as data (searching
        // post_content for "into outfile") is not refused.
        $code = preg_replace('~\'(?:\\\\.|[^\'\\\\])*\'|"(?:\\\\.|[^"\\\\])*"~', '', $lower) ?? $lower;
        if (preg_match('/\bload_file\s*\(/', $code) || preg_match('/\binto\s+(?:out|dump)file\b/', $code)) {
            return self::deny('uses a server file function (load_file / outfile / dumpfile)');
        }

        $touched = $this->coreTablesIn($lower);
        $usesUsers = isset($touched[$this->usersTable]);
        $usesUsermeta = isset($touched[$this->usermetaTable]);
        $usesOptions = isset($touched[$this->optionsTable]);

        switch ($class) {
            // Schema / plan (DESCRIBE wp_users, SHOW COLUMNS, EXPLAIN SELECT …): no row data.
            case 'ShowStatement':
            case 'ExplainStatement':
                return self::allow();

            // BEGIN / START TRANSACTION (COMMIT / ROLLBACK / SAVEPOINT handled above).
            case 'TransactionStatement':
                return self::allow();

            // Session SETs only. A user variable (SET @x = …) or a direct system variable
            // (SET @@…) is the first step of the PREPARE/EXECUTE bypass — refuse it.
            case 'SetStatement':
                if (strpos($lower, '@') !== false) return self::deny('SET of a user or system variable');
                return self::allow();

            case 'SelectStatement':
                if ($touched === []) return self::allow();
                return $this->decideSelect($sql, $lower, $usesUsers, $usesUsermeta, $usesOptions);

            case 'InsertStatement':
            case 'UpdateStatement':
            case 'DeleteStatement':
            case 'ReplaceStatement':
                if ($touched === []) return self::allow();   // the plugin's own / other content
                return $this->decideWrite($sql, $lower, $usesUsers, $usesUsermeta, $usesOptions);

            case 'CreateStatement':
                if (preg_match(self::CREATE_ROUTINE, $lower)) {
                    return self::deny('CREATE of a procedure / function / trigger / event / view');
                }
                return $touched === [] ? self::allow() : self::deny('CREATE on a core table');

            case 'AlterStatement':
            case 'DropStatement':
            case 'TruncateStatement':
            case 'RenameStatement':
                if ($touched === []) return self::allow();
                $verb = ['AlterStatement' => 'ALTER', 'DropStatement' => 'DROP',
                         'TruncateStatement' => 'TRUNCATE', 'RenameStatement' => 'RENAME'][$class];
                return self::deny("$verb on a core table");

            // CALL, LOAD DATA, LOCK / UNLOCK, CTE (WITH …), table maintenance, KILL, PURGE, … .
            default:
                return self::deny('unsupported statement type');
        }
    }

    /** SELECT on a core table: refuse protected reads, else allow with the result filters set. */
    private function decideSelect(string $sql, string $lower, bool $usesUsers, bool $usesUsermeta, bool $usesOptions): array
    {
        // A query that names a never-readable users column cannot be served safely by stripping it
        // from the result (it can filter or order by it); refuse it outright.
        if ($usesUsers && preg_match('/\b(user_pass|user_activation_key)\b/i', $sql)) {
            return self::deny('reads a protected wp_users column');
        }
        $filters = [];
        if ($usesUsers) $filters['strip_user_secrets'] = true;
        if ($usesUsermeta) {
            // A read that names a protected meta_key (get_user_meta's WHERE meta_key = …) must be
            // refused, not filtered: it often projects only meta_value, so there is no key column
            // left to strip. A broad per-user read (update_meta_cache, no meta_key in its WHERE)
            // projects meta_key, so its protected rows are stripped (below).
            foreach ($this->whereNames($sql, 'meta_key') as $key) {
                if ($this->usermetaRowDenied($key, $this->grantCapabilities)) {
                    return self::deny("reads the protected usermeta key '$key'");
                }
            }
            $filters['usermeta'] = true;
            $filters['keep_caps'] = $this->grantCapabilities;
        }
        if ($usesOptions) {
            // A read that names the options it wants (get_option's SELECT … WHERE option_name = …)
            // is refused if any named option is protected — like meta, it usually projects only
            // option_value, so there is no name column to strip. An unqualified read
            // (wp_load_alloptions' bulk autoload SELECT) is held to the core allowlist so it cannot
            // hand the sandbox every plugin's options.
            if (preg_match('/\boption_name\b\s*(?:=|in\b)/i', $lower)) {
                foreach ($this->whereNames($sql, 'option_name') as $name) {
                    if ($this->optionReadDenied($name)) return self::deny("reads the protected option '$name'");
                }
                $filters['options'] = 'denied';
            } else {
                $filters['options'] = 'allowlist';
            }
        }
        return self::allow($filters);
    }

    /** INSERT / UPDATE / DELETE / REPLACE on a core table: refuse protected writes, else allow. */
    private function decideWrite(string $sql, string $lower, bool $usesUsers, bool $usesUsermeta, bool $usesOptions): array
    {
        if ($usesUsers && !$this->grantUsers) {
            return self::deny('writes wp_users (not granted)');
        }
        if ($usesUsermeta && !$this->grantCapabilities) {
            foreach (array_merge(array_keys($this->capabilityKeys), ['session_tokens']) as $key) {
                if (stripos($sql, $key) !== false) return self::deny("writes the protected usermeta key '$key'");
            }
        }
        if ($usesOptions) {
            $bad = $this->deniedOptionWrite($sql, $lower);
            if ($bad !== null) return self::deny("writes the protected option '$bad'");
        }
        // Other core content (posts, terms, comments and their meta) and the plugin's own meta: free.
        return self::allow();
    }

    // --- result filters (run by the gateway after the query) -----------------------------------

    /** Keep only option rows a sandboxed plugin may see in an unqualified (bulk) read. */
    public function bulkOptionAllowed(string $name): bool
    {
        $name = strtolower($name);
        // A protected option is never handed over, even if the plugin writes an option by that
        // name (so a plugin cannot launder admin_email into "its own" by calling update_option).
        if ($this->optionReadDenied($name)) return false;
        return isset($this->ownOptions[$name]) || isset($this->grantedOptions[$name])
            || isset(snapshot_option_allowlist()[$name]);
    }

    /** True for an option a sandboxed plugin may not read when it names it explicitly. */
    public function optionReadDenied(string $name): bool
    {
        $name = strtolower($name);
        if (isset($this->grantedOptions[$name])) return false;
        return isset($this->readDenied[$name]);
    }

    /** True for a usermeta row (by meta_key) that must be stripped from a read. */
    public function usermetaRowDenied(string $metaKey, bool $keepCaps): bool
    {
        $metaKey = strtolower($metaKey);
        if ($metaKey === 'session_tokens') return true;          // never readable
        if ($keepCaps) return false;
        return isset($this->capabilityKeys[$metaKey]);
    }

    // --- internals ------------------------------------------------------------------------------

    /** @return array<string,true> the core tables whose names appear in $lower (lower-cased SQL) */
    private function coreTablesIn(string $lower): array
    {
        $hit = [];
        foreach ($this->coreTables as $table => $_) {
            // Word-bounded so wp_users does not match wp_usermeta or a plugin's wp_users_extra,
            // and backtick-tolerant.
            if (preg_match('/(?<![a-z0-9_])`?' . preg_quote($table, '/') . '`?(?![a-z0-9_])/', $lower)) {
                $hit[$table] = true;
            }
        }
        return $hit;
    }

    /**
     * The write-denied option a statement on the options table touches, or null. For UPDATE/DELETE
     * the name is the WHERE's option_name; for INSERT/REPLACE it is the option_name column's value.
     * A statement whose option name cannot be read but that mentions a denied name as a literal is
     * refused (safe over-approximation); one that names only allowed options is let through.
     */
    private function deniedOptionWrite(string $sql, string $lower): ?string
    {
        // UPDATE/DELETE ... WHERE option_name = 'x' | IN ('a','b')
        $names = $this->whereNames($sql, 'option_name');
        // INSERT/REPLACE INTO options (cols) VALUES (vals): pair option_name to its value.
        if ($names === [] && preg_match('/\(([^)]*)\)\s*values\s*\(/i', $sql, $cm)) {
            $cols = array_map(static fn ($c) => strtolower(trim($c, " `\t")), explode(',', $cm[1]));
            $idx = array_search('option_name', $cols, true);
            if ($idx !== false && preg_match('/\)\s*values\s*\((.*)\)/is', $sql, $vm)) {
                $vals = self::splitValues($vm[1]);
                if (isset($vals[$idx])) $names[] = $vals[$idx];
            }
        }
        foreach ($names as $name) {
            $name = strtolower($name);
            if (isset($this->writeDenied[$name]) && !isset($this->grantedOptions[$name])) return $name;
        }
        if ($names !== []) return null; // named only allowed options
        // Could not identify the option; refuse if a denied name appears as a literal at all.
        foreach ($this->writeDenied as $denied => $_) {
            if (isset($this->grantedOptions[$denied])) continue;
            if (preg_match('/[\'"]' . preg_quote($denied, '/') . '[\'"]/', $lower)) return $denied;
        }
        return null;
    }

    /**
     * The string literals a WHERE pins a column to: `<col> = 'x'` or `<col> IN ('a','b')`. Used to
     * read the option_name / meta_key a statement targets. (WordPress always passes these as
     * literals through $wpdb->prepare, so they are in the SQL by the time the gateway sees it.)
     *
     * @return list<string>
     */
    private function whereNames(string $sql, string $column): array
    {
        $out = [];
        if (preg_match('/\b' . preg_quote($column, '/') . '\b\s*(?:=|in\b)\s*\(?\s*((?:\'[^\']*\'|"[^"]*")(?:\s*,\s*(?:\'[^\']*\'|"[^"]*"))*)/i', $sql, $m)
            && preg_match_all('/\'([^\']*)\'|"([^"]*)"/', $m[1], $lits)) {
            foreach ($lits[0] as $i => $_) $out[] = $lits[1][$i] !== '' ? $lits[1][$i] : $lits[2][$i];
        }
        return $out;
    }

    /** Split a VALUES(...) body into its top-level comma-separated literals (quoted → unquoted). */
    private static function splitValues(string $body): array
    {
        $out = [];
        $buf = '';
        $quote = '';
        $len = strlen($body);
        for ($i = 0; $i < $len; $i++) {
            $ch = $body[$i];
            if ($quote !== '') {
                if ($ch === '\\' && $i + 1 < $len) { $buf .= $ch . $body[++$i]; continue; }
                if ($ch === $quote) { $quote = ''; continue; }
                $buf .= $ch;
                continue;
            }
            if ($ch === '\'' || $ch === '"') { $quote = $ch; continue; }
            if ($ch === ',') { $out[] = trim($buf); $buf = ''; continue; }
            $buf .= $ch;
        }
        $out[] = trim($buf);
        return $out;
    }

    private static function allow(array $filters = []): array
    {
        return ['run' => true, 'reason' => '', 'filters' => $filters];
    }

    private static function deny(string $reason): array
    {
        return ['run' => false, 'reason' => $reason];
    }
}
