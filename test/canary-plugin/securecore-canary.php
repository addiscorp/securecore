<?php
/**
 * Plugin Name: SecureCore Canary
 * Description: Test probe for addiscorp/securecore#47. Run sandboxed, it searches the sandbox's
 *   own memory — $GLOBALS and the $wpdb object (private properties included, via reflection) —
 *   for the value of a secret autoloaded option that was set outside the sandbox, and writes
 *   SECURECORE_CANARY_RESULT:FOUND or :CLEAN to the worker log. It must never find it: a
 *   sandboxed plugin must not reach another context's options from memory. Not for production.
 *
 * The needle is the fixed value test/canary.sh stores in `securecore_canary_secret`; the probe
 * never reads the option (that would be a legitimate gateway fetch) — it only scans memory.
 */
defined('ABSPATH') || exit;

// Only scan when actually running inside the sandbox. In core (or under wp-cli) the secret is a
// legitimately loaded option, and scanning all of core's $GLOBALS would be pointless and slow.
if (!defined('SECURECORE_SANDBOX') || !SECURECORE_SANDBOX) return;

(function () {
    $needle = 'SECURECORE_CANARY_SENTINEL_7f3ad2c1';
    $seen = [];
    $found = false;

    $search = static function ($value, int $depth) use (&$search, &$seen, &$found, $needle): void {
        if ($found || $depth > 6) return;
        if (is_string($value)) {
            if (strpos($value, $needle) !== false) $found = true;
            return;
        }
        if (is_array($value)) {
            foreach ($value as $item) {
                $search($item, $depth + 1);
                if ($found) return;
            }
            return;
        }
        if (is_object($value)) {
            $id = spl_object_id($value);
            if (isset($seen[$id])) return;
            $seen[$id] = true;
            try {
                foreach ((new \ReflectionObject($value))->getProperties() as $property) {
                    $property->setAccessible(true);
                    if (!$property->isInitialized($value)) continue;
                    $search($property->getValue($value), $depth + 1);
                    if ($found) return;
                }
            } catch (\Throwable $e) {
                // A property we cannot read is one we cannot leak through; skip it.
            }
        }
    };

    // $GLOBALS reaches the whole booted state, including $GLOBALS['wpdb'] and its private
    // snapshot. Skip the self-referential 'GLOBALS' key.
    foreach ($GLOBALS as $key => $value) {
        if ($key === 'GLOBALS') continue;
        $search($value, 0);
        if ($found) break;
    }

    fwrite(STDERR, 'SECURECORE_CANARY_RESULT:' . ($found ? 'FOUND' : 'CLEAN') . "\n");
})();
