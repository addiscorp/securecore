// Print the breakdown results as markdown: median across the 3 repeats of each repeat's
// p50 (and p95). Reads .tmp/bench/breakdown-*.json. The load results print themselves
// (.tmp/bench/load.md).
//   bun bench/summary.ts
import { readFileSync } from 'node:fs'

const runs = [1, 2, 3].map((i) => JSON.parse(readFileSync(`.tmp/bench/breakdown-${i}.json`, 'utf8')))
const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[1]
const f = (x: number) => (Math.round(x * 10) / 10).toString()

console.log(`One tab: ${runs[0].requests} requests per repeat × 3 repeats after 5 warm-up; ${runs[0].calls} calls each; median of the repeats\n`)
console.log('| step | p50 | p95 |\n|---|---|---|')
for (const [key, label, unit] of [
  ['connect_to_ready_ms', 'request: connect + boot plugin → ready', 'ms'],
  ['hook_call_us', 'hook callback, core → sandbox → core', 'µs'],
  ['forwarded_call_us', 'forwarded function, sandbox → core → sandbox', 'µs'],
] as const) {
  console.log(`| ${label} | ${f(median(runs.map((r) => r.per_request[key].p50)))} ${unit} | ${f(median(runs.map((r) => r.per_request[key].p95)))} ${unit} |`)
}
console.log(`| tab start → first request served (once per tab) | ${f(median(runs.map((r) => r.tab_start_to_first_request_ms)))} ms | |`)
console.log(`| tab RSS (4 slots) | ${f(median(runs.map((r) => r.tab_rss_mb)))} MiB | peak ${f(median(runs.map((r) => r.tab_peak_rss_mb)))} MiB |`)
