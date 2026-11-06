// Print the breakdown and tabs results as markdown: median across the 3 repeats of each
// repeat's p50 (and p95). Reads .tmp/bench/breakdown-*.json and tabs-*.json.
//   bun bench/summary.ts
import { readFileSync } from 'node:fs'

const dir = '.tmp/bench'
const read = (name: string) => [1, 2, 3].map((i) => JSON.parse(readFileSync(`${dir}/${name}-${i}.json`, 'utf8')))
const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[1]
const f = (x: number) => (Math.round(x * 10) / 10).toString()

const breakdown = read('breakdown')
const rows: [string, string, string][] = [
  ['process_start_ms', 'process start (exec → script runs)', 'ms'],
  ['bun_load_ms', 'bun: load the plugin files', 'ms'],
  ['read_wasm_ms', 'read php2.wasm (embedded, 24 MB)', 'ms'],
  ['compile_ms', 'WebAssembly.compile', 'ms'],
  ['instantiate_ms', 'WebAssembly.instantiate', 'ms'],
  ['php_boot_ms', 'p8 start + setup.php + plugin boot → ready', 'ms'],
  ['total_to_ready_ms', 'total: spawn → ready', 'ms'],
  ['hook_call_us', 'hook callback, core → sandbox → core', 'µs'],
  ['forwarded_call_us', 'forwarded function, sandbox → core → sandbox', 'µs'],
  ['rss_mb', 'RSS of one sandbox process, after the calls', 'MiB'],
  ['peak_rss_mb', 'peak RSS of one sandbox process (VmHWM)', 'MiB'],
]
const { runs, calls, functions } = breakdown[0]
console.log(`Breakdown: ${runs} sandboxes per repeat × 3 repeats; ${calls} calls each; median of the repeats' p50 (p95)\n`)
console.log(`| step | ${functions} stand-ins | 1 stand-in |\n|---|---|---|`)
for (const [key, label, unit] of rows) {
  const cell = (variant: string) => {
    const p50 = median(breakdown.map((b) => b[variant][key].p50))
    const p95 = median(breakdown.map((b) => b[variant][key].p95))
    return `${f(p50)} ${unit} (${f(p95)})`
  }
  console.log(`| ${label} | ${cell('all_core_functions')} | ${cell('one_function')} |`)
}

const tabs = read('tabs')
console.log(`\nTabs estimate: one process, compiled once, ${tabs[0].runs} boots per repeat × 3 repeats (after 3 warm-up boots); median of the repeats\n`)
console.log('| step | p50 | p95 |\n|---|---|---|')
console.log(`| compile, once per process | ${f(median(tabs.map((t) => t.compile_once_ms)))} ms | |`)
for (const [key, label] of [['instantiate_ms', 'instantiate a fresh instance'], ['boot_to_ready_ms', 'boot setup.php + plugin → ready'], ['restore_memory_copy_ms', 'copy a saved booted memory back']] as const) {
  console.log(`| ${label} | ${f(median(tabs.map((t) => t[key].p50)))} ms | ${f(median(tabs.map((t) => t[key].p95)))} ms |`)
}
console.log(`| linear memory at ready | ${f(median(tabs.map((t) => t.memory_at_ready_mb)))} MiB | |`)
console.log(`| process RSS at the end | ${f(median(tabs.map((t) => t.rss_mb)))} MiB | |`)
