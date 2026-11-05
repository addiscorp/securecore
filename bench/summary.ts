// Print the per-request split (bench/run.sh breakdown) as markdown: median across the 3
// repeats of each repeat's p50 (p95). The load results print themselves (.tmp/bench/load.md).
//   bun bench/summary.ts
import { readFileSync } from 'node:fs'

const runs = [1, 2, 3].map((i) => JSON.parse(readFileSync(`.tmp/bench/breakdown-${i}.json`, 'utf8')))
const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[1]
const f = (x: number) => (Math.round(x * 10) / 10).toString()

console.log(`Per-request cost split, fork worker: ${runs[0].requests} requests per repeat × 3 repeats after warm-up; ${runs[0].calls} forwarded calls; median of the repeats, p50 (p95)\n`)
console.log('| step | p50 | p95 |\n|---|---|---|')
for (const [key, label, unit, scale] of [
  ['fork_us', 'fork() a child from the warm worker', 'ms', 1000],
  ['include_us', 'include the plugin (opcache hit)', 'ms', 1000],
  ['first_call_us', 'first call: core → sandbox → core', 'µs', 1],
  ['forwarded_call_us', 'forwarded call: sandbox → core → sandbox', 'µs', 1],
] as const) {
  const p50 = median(runs.map((r) => r[key].p50)) / scale
  const p95 = median(runs.map((r) => r[key].p95)) / scale
  console.log(`| ${label} | ${f(p50)} ${unit} | ${f(p95)} ${unit} |`)
}
const perReq = median(runs.map((r) => r.fork_us.p50 + r.include_us.p50 + r.first_call_us.p50)) / 1000
console.log(`\nfork + include + first call ≈ ${f(perReq)} ms per request per sandboxed plugin.`)
