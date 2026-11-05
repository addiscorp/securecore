// Print the breakdown results as markdown, one column per engine: median across the 3
// repeats of each repeat's p50 (p95). Reads .tmp/bench/breakdown-<engine>-*.json. The load
// results print themselves (.tmp/bench/load.md).
//   bun bench/summary.ts [engines]     (default p8)
import { readFileSync } from 'node:fs'

const engines = (process.argv[2] ?? 'p8').split(',')
const runs = Object.fromEntries(engines.map((e) => [e, [1, 2, 3].map((i) => JSON.parse(readFileSync(`.tmp/bench/breakdown-${e}-${i}.json`, 'utf8')))]))
const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[1]
const f = (x: number) => (Math.round(x * 10) / 10).toString()
const first = runs[engines[0]][0]

console.log(`One tab per engine: ${first.requests} requests per repeat × 3 repeats after 5 warm-up; ${first.calls} calls each; median of the repeats, p50 (p95)\n`)
console.log(`| step | ${engines.join(' | ')} |\n|---|${engines.map(() => '---').join('|')}|`)
for (const [key, label, unit] of [
  ['connect_to_ready_ms', 'request: connect + boot plugin → ready', 'ms'],
  ['hook_call_us', 'hook callback, core → sandbox → core', 'µs'],
  ['forwarded_call_us', 'forwarded function, sandbox → core → sandbox', 'µs'],
] as const) {
  const cells = engines.map((e) => `${f(median(runs[e].map((r) => r.per_request[key].p50)))} ${unit} (${f(median(runs[e].map((r) => r.per_request[key].p95)))})`)
  console.log(`| ${label} | ${cells.join(' | ')} |`)
}
console.log(`| tab start → first request served | ${engines.map((e) => `${f(median(runs[e].map((r) => r.tab_start_to_first_request_ms)))} ms`).join(' | ')} |`)
console.log(`| tab RSS, 4 slots (peak) | ${engines.map((e) => `${f(median(runs[e].map((r) => r.tab_rss_mb)))} MiB (${f(median(runs[e].map((r) => r.tab_peak_rss_mb)))})`).join(' | ')} |`)
