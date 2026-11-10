<?php
// SecureCore layer 3 (addiscorp/securecore#53, E7): what the php-fpm worker runs in place of an
// isolated plugin's main file. The extension compiles it (with the plugin's slug and file
// filled in) when wp-settings.php includes the plugin, so not one line of the plugin runs here.
// It asks the helper for a child that loads the plugin, and mirrors what the plugin registered
// there (hooks and shortcodes) as callbacks that forward each call to the child.
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
    $register = null;
    $register = static function (array $regs) use ($slug, $plain, &$register): void {
        foreach ($regs as $r) {
            if (!is_array($r) || !isset($r['kind'], $r['name'], $r['id'])) continue;
            $id = (int) $r['id'];
            $kind = (string) $r['kind'];
            $forward = static function (...$args) use ($slug, $id, $kind, $plain, &$register) {
                $answer = \securecore_layer3_call($slug, $id, serialize($plain($args)));
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
    $prefix = (string) ($GLOBALS['table_prefix'] ?? 'wp_');
    // The helper boots from WordPress's own options only (#47): the list is the extension's.
    $names = \securecore_layer3_snapshot_names(ABSPATH, $prefix, (string) get_option('stylesheet'));
    $snapshot = serialize(array_intersect_key(wp_load_alloptions(), array_flip($names)));
    $ready = \securecore_layer3_open($slug, $file, ABSPATH, $prefix, $snapshot);
    $a = is_string($ready) ? unserialize($ready, ['allowed_classes' => false]) : null;
    if (!is_array($a)) return;
    if (is_string($a['out'] ?? null) && $a['out'] !== '') echo $a['out'];
    if (is_array($a['reg'] ?? null)) $register($a['reg']);
})(__SC_SLUG__, __SC_FILE__);
