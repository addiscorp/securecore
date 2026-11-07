<?php
// Boot the site's own WordPress inside the sandbox, with no plugins and no database of its
// own. Part 1 of the gelada-sandbox redesign (addiscorp/securecore#42).
//
// The sandbox reads the site's real WordPress files (ABSPATH), but it never sees
// wp-config.php and never holds a database password. We include wp-settings.php directly —
// not wp-config.php, not wp-load.php — after defining the few things wp-config normally
// provides (ABSPATH, the table prefix, a couple of debug constants) and after pre-seating a
// $wpdb that has no connection: every query it would run goes back to core over the request
// socket (the gateway in SecureCore.php). See sandbox/setup.php for the line protocol.
//
// A handful of salted pluggable functions (nonces, hashes, auth cookies, and wp_mail) are
// pre-defined here to forward to core, so they agree with core's secrets, which the sandbox
// does not have. pluggable.php is function_exists-guarded, so defining them first wins.
//
// This file runs in the child (sandbox/realwp.php drives it), after the request socket is
// connected, because booting WordPress needs the gateway live.
namespace SecureCore;

/**
 * A $wpdb subclass that holds no connection. Every query is sent to core over the socket,
 * which runs it against the real database and returns the rows and the metadata (insert_id,
 * num_rows, …). The higher-level readers (get_var/get_row/get_col/get_results) are the parent
 * class's; they call query() and read $this->last_result, which we fill from core's answer.
 * It is built as an anonymous class so its parent (\wpdb) is resolved only after
 * class-wpdb.php has been loaded, not when this file is parsed.
 *
 * Part 1 does not carry the per-row/column SQL policy (that is a later part of #42): core
 * runs whatever query the sandbox sends. So a sandboxed plugin can still reach any row core
 * can until the policy lands — see the PR's "what is not closed yet".
 */
function make_gateway_wpdb(string $prefix): \wpdb
{
    return new class($prefix) extends \wpdb {
        public function __construct(string $prefix)
        {
            // No parent constructor: that would try to connect. We are ready to "query",
            // which means forward. The placeholder escape string is generated lazily by the
            // parent class's add_placeholder_escape(), which needs no connection.
            $this->ready = true;
            $this->prefix = $prefix;
            $this->base_prefix = $prefix;
            $this->field_types = [];
        }

        public function query($query)
        {
            $this->flush();
            $this->last_query = $query;
            $answer = db_gateway('query', [(string) $query]);
            // last_result rows cross as plain arrays (stdClass cannot cross with
            // allowed_classes:false); rebuild the objects WordPress's readers expect.
            $this->last_result = array_map(static fn ($row) => (object) $row, $answer['last_result'] ?? []);
            $this->last_error = (string) ($answer['last_error'] ?? '');
            $this->insert_id = (int) ($answer['insert_id'] ?? 0);
            $this->rows_affected = (int) ($answer['rows_affected'] ?? 0);
            $this->num_rows = (int) ($answer['num_rows'] ?? 0);
            $this->num_queries++;
            return $answer['return'] ?? false;
        }

        // No connection, so escaping cannot use mysqli_real_escape_string. addslashes is the
        // same fallback the parent class uses when it has no dbh; good enough for the spike.
        public function _real_escape($data)
        {
            if (!is_scalar($data)) return '';
            return $this->add_placeholder_escape(addslashes((string) $data));
        }

        public function db_version()
        {
            return (string) db_gateway('db_version', []);
        }

        public function db_server_info()
        {
            return (string) db_gateway('db_server_info', []);
        }

        // The parent reads col info from the live mysqli result; we fetch it from core.
        public function get_col_info($info_type = 'name', $col_offset = -1)
        {
            return db_gateway('get_col_info', [$info_type, $col_offset]);
        }

        public function check_connection($allow_bail = true)
        {
            return true;
        }

        public function close()
        {
            return true;
        }
    };
}

/**
 * Boot WordPress. $root is the site's WordPress folder (ABSPATH); $prefix the table prefix.
 * Returns nothing — $GLOBALS are populated as in any WordPress request.
 *
 * $wpdb is the connectionless database to boot against. The per-request child passes none and
 * boots against the socket gateway (every query goes to core). The worker parent pre-booting
 * once (addiscorp/securecore#42, part 1b) passes a snapshot-backed $wpdb that serves the boot's
 * one options query from the on-disk snapshot, because the parent has no request socket.
 */
function boot_wordpress(string $root, string $prefix, ?\wpdb $wpdb = null): void
{
    if (!defined('ABSPATH')) {
        define('ABSPATH', rtrim($root, '/') . '/');
        // The sandbox never reads wp-config.php, so set the few constants wp-settings.php
        // needs before it reaches wp-initial-constants. No DB_* constants: there is no
        // database here.
        define('WP_DEBUG', false);
        define('WP_DEBUG_DISPLAY', false);
        define('WP_DEBUG_LOG', false);
        define('SECURECORE_SANDBOX', true);
    }
    $GLOBALS['table_prefix'] = $prefix;
    // WordPress runs with the web root as the working directory; match it, so core's own
    // relative file_exists() checks (e.g. register_block_type('core/...')) resolve inside
    // open_basedir instead of warning.
    @chdir(ABSPATH);

    define_pluggable_forwards();

    // Pre-seat the connectionless $wpdb so require_wp_db() in wp-settings.php finds it set
    // and returns early instead of building one that connects.
    require_once ABSPATH . 'wp-includes/class-wpdb.php';
    $GLOBALS['wpdb'] = $wpdb ?? make_gateway_wpdb($prefix);

    require ABSPATH . 'wp-settings.php';
}

/**
 * A $wpdb for the worker parent's one-time pre-boot (addiscorp/securecore#42, part 1b). The
 * parent has no request socket, so there is no gateway to answer queries; instead this $wpdb
 * serves the single query a no-plugin boot makes — wp_load_alloptions()'s autoloaded-options
 * SELECT — from the snapshot core wrote to disk, and treats anything else as empty (logged to
 * the worker log, so an unexpected boot query is visible). It never connects and never writes.
 * Built as an anonymous class so \wpdb is resolved only after class-wpdb.php is loaded.
 */
function make_snapshot_wpdb(string $prefix, array $options): \wpdb
{
    return new class($prefix, $options) extends \wpdb {
        /** @var array<string,string> option_name => raw option_value */
        private array $snapshot;

        public function __construct(string $prefix, array $options)
        {
            // No parent constructor (it would connect). wp-settings.php calls set_prefix()
            // on us, which fills in the table names; we only need to be "ready".
            $this->ready = true;
            $this->prefix = $prefix;
            $this->base_prefix = $prefix;
            $this->field_types = [];
            $this->snapshot = $options;
        }

        // wp_load_alloptions() runs "SELECT option_name, option_value ... WHERE autoload IN (...)";
        // serve it from the snapshot regardless of the exact autoload values (they vary by
        // WordPress version). Any other get_results during a no-plugin boot is unexpected.
        public function get_results($query = null, $output = OBJECT)
        {
            if (is_string($query) && stripos($query, 'option_name') !== false && stripos($query, 'autoload') !== false) {
                $rows = [];
                foreach ($this->snapshot as $name => $value) {
                    $rows[] = (object) ['option_name' => (string) $name, 'option_value' => $value];
                }
                return $rows;
            }
            $this->parent_boot_miss($query);
            return [];
        }

        public function query($query)
        {
            $this->parent_boot_miss($query);
            return false;
        }

        public function get_row($query = null, $output = OBJECT, $y = 0)
        {
            $this->parent_boot_miss($query);
            return null;
        }

        public function get_var($query = null, $x = 0, $y = 0)
        {
            $this->parent_boot_miss($query);
            return null;
        }

        public function get_col($query = null, $x = 0)
        {
            $this->parent_boot_miss($query);
            return [];
        }

        public function _real_escape($data)
        {
            if (!is_scalar($data)) return '';
            return $this->add_placeholder_escape(addslashes((string) $data));
        }

        public function db_version()
        {
            return '8.0.0';
        }

        public function db_server_info()
        {
            return '8.0.0';
        }

        public function check_connection($allow_bail = true)
        {
            return true;
        }

        public function close()
        {
            return true;
        }

        private function parent_boot_miss($query): void
        {
            // Truncated: a boot query may carry a large value (a theme's block-pattern cache),
            // and this only needs to stay visible, not fill the log.
            $sql = preg_replace('/\s+/', ' ', trim((string) $query));
            if (strlen($sql) > 200) $sql = substr($sql, 0, 200) . '…';
            fwrite(STDERR, gmdate('c') . ' securecore-worker preboot: query not served from snapshot (returned empty): ' . $sql . "\n");
        }
    };
}

/**
 * The ~15 salted pluggable functions, forwarded to core so they agree with core's secrets.
 * pluggable.php defines these only if they do not already exist, so defining them here first
 * takes over. Each forwards to core and returns core's answer. wp_mail goes too, so mail a
 * sandboxed plugin sends is sent by core (and, in the test stack, caught by core's catcher).
 */
function define_pluggable_forwards(): void
{
    // WordPress calls these from the global namespace, and pluggable.php defines them there
    // only if they do not already exist. So define the global functions first; each forwards
    // to core's real (salted) implementation through the gateway.
    foreach ([
        'wp_create_nonce', 'wp_verify_nonce', 'wp_hash', 'wp_salt', 'wp_mail',
        'wp_set_auth_cookie', 'wp_clear_auth_cookie', 'wp_parse_auth_cookie',
        'wp_generate_auth_cookie', 'wp_validate_auth_cookie',
    ] as $name) {
        if (!function_exists($name)) {
            eval("namespace { function $name(...\$args) { return \\SecureCore\\pluggable_gateway('$name', \$args); } }");
        }
    }
}
