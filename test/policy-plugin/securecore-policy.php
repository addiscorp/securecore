<?php
/**
 * Plugin Name: SecureCore Policy Probe
 * Description: Test probe for the database gateway's SQL policy (addiscorp/securecore#42, part 2).
 *   Run sandboxed, it exercises reads and writes the policy should block and ones it should allow,
 *   and writes each observation to the worker log as POLICY_PROBE:<key>=<value>. test/policy.sh
 *   reads those: with the policy on the blocked ones must be empty/absent and the allowed ones
 *   must work; it also checks, from outside the sandbox, that the blocked writes did not land.
 *   Not for production.
 *
 * The probe writes one option of its own (securecore_policy_probe_own) so the manifest scan
 * records it as the plugin's own option — the gateway keeps a plugin's own options in a bulk read.
 */
defined('ABSPATH') || exit;
if (!defined('SECURECORE_SANDBOX') || !SECURECORE_SANDBOX) return;

(function () {
    global $wpdb;
    $log = static fn (string $k, string $v) => fwrite(STDERR, "POLICY_PROBE:$k=$v\n");
    $filled = static fn ($v) => ($v !== null && $v !== '' && $v !== false) ? 'nonempty' : 'empty';

    // --- allowed: the plugin's own option round-trips, siteurl reads, core content reads --------
    update_option('securecore_policy_probe_own', 'own-ok');
    $log('read_own_option', (string) get_option('securecore_policy_probe_own', 'MISSING'));
    $log('read_siteurl', $filled(get_option('siteurl')));
    $log('read_posts_count', ($c = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->posts}")) === null ? 'denied' : (string) (int) $c);

    // --- bulk options: core secrets and other plugins' options must not come through ------------
    $all = wp_load_alloptions();
    $log('bulk_admin_email', isset($all['admin_email']) ? 'present' : 'absent');
    $log('bulk_foreign_secret', isset($all['securecore_policy_foreign_secret']) ? 'present' : 'absent');

    // --- never-readable columns / gated usermeta reads ------------------------------------------
    $log('read_user_pass', $filled($wpdb->get_var("SELECT user_pass FROM {$wpdb->users} WHERE ID = 1")));
    $log('read_session_tokens', $filled($wpdb->get_var("SELECT meta_value FROM {$wpdb->usermeta} WHERE user_id = 1 AND meta_key = 'session_tokens'")));
    $log('read_caps', $filled($wpdb->get_var("SELECT meta_value FROM {$wpdb->usermeta} WHERE user_id = 1 AND meta_key = '{$wpdb->prefix}capabilities'")));

    // --- prepared-statement bypass: hide a forbidden SELECT in a user variable, then PREPARE and
    // EXECUTE it (none of the three names wp_users as a table the policy would see). With the policy
    // on, each statement is refused on its own; with it off, the chain reads user_pass. Each is a
    // separate forwarded query on the same core connection, so @scp persists across them.
    $sel = "SELECT user_pass FROM {$wpdb->users} WHERE ID = 1";
    $wpdb->query('SET @scp = 0x' . bin2hex($sel));
    $wpdb->query('PREPARE scp_stmt FROM @scp');
    $log('bypass_user_pass', $filled($wpdb->get_var('EXECUTE scp_stmt')));
    $wpdb->query('DEALLOCATE PREPARE scp_stmt');

    // --- gated write: changing a protected option (reversible; the test restores it) ------------
    // update_option first reads the current value (denied → it thinks it changed) then writes
    // (denied → no change). The test confirms admin_email is unchanged from outside the sandbox.
    update_option('admin_email', 'securecore-policy-evil@example.com');
    $log('wrote_admin_email', 'attempted');

    $log('done', '1');
})();
