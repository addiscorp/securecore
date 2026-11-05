<?php
/**
 * Plugin Name: SecureCore Bench
 * Description: Benchmark plugin for SecureCore. Registers two hooks that only the bench scripts fire; on a normal page it does nothing.
 * Version: 0.1.0
 */
defined('ABSPATH') || exit;

// One hook callback that does nothing: the cost of core → sandbox → core.
add_action('securecore_bench_hook', 'securecore_bench_hook', 10, 1);
function securecore_bench_hook($value = null)
{
    return $value;
}

// Calls a WordPress function $n times and returns microseconds per call, measured in the
// sandbox: the cost of sandbox → core → sandbox.
add_filter('securecore_bench_calls', 'securecore_bench_calls', 10, 2);
function securecore_bench_calls($result, $n = 1000)
{
    $t = hrtime(true);
    for ($i = 0; $i < $n; $i++) securecore_bench_noop();
    return (hrtime(true) - $t) / $n / 1000;
}
