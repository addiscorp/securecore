// Measurements 2–4: page latency, throughput and memory on the running docker/ stack.
//
//   bun bench/load.ts [repeats]          (see bench/run.sh; needs docker/setup.sh first)
//
// The load tool (oha) runs in a container on the stack's Docker network, so requests go
// straight to nginx. Configurations:
//   off   SECURECORE_DISABLED, Hello Dolly + the bench plugin load as normal plugins
//   on1   SecureCore on, Hello Dolly sandboxed
//   on2   SecureCore on, Hello Dolly + the bench plugin sandboxed
// Every run is checked: all responses 200, else exit 1. Writes .tmp/bench/load.json and
// prints a markdown table.
import { mkdirSync, writeFileSync } from 'node:fs'

const repeats = Number(process.argv[2] ?? 3)
const OHA = 'ghcr.io/hatoo/oha@sha256:3ec3dbf549ea197793482d47a6324797411406bbf438c2fe8b91f244ec641a2f' // oha 1.16.0
const COMPOSE = ['docker', 'compose', '-f', 'docker/compose.yml']
const HOST = '127.0.0.1:8088'
const out = '.tmp/bench'
mkdirSync(out, { recursive: true })

function run(cmd: string[], quiet = true): string {
  const result = Bun.spawnSync(cmd, { stdout: 'pipe', stderr: 'pipe' })
  if (result.exitCode !== 0) {
    throw new Error(`${cmd.join(' ')} → exit ${result.exitCode}\n${result.stderr.toString()}`)
  }
  if (!quiet) process.stdout.write(result.stdout)
  return result.stdout.toString()
}
const wp = (...args: string[]) => run([...COMPOSE, 'run', '--rm', '-T', 'cli', 'wp', ...args])

function configure(config: 'off' | 'on1' | 'on2') {
  wp('plugin', 'deactivate', 'securecore-probe')
  if (config === 'off') wp('config', 'set', 'SECURECORE_DISABLED', 'true', '--raw')
  else {
    try { wp('config', 'delete', 'SECURECORE_DISABLED') } catch { /* not set */ }
  }
  wp('plugin', 'activate', 'hello')
  if (config === 'on1') wp('plugin', 'deactivate', 'securecore-bench')
  else wp('plugin', 'activate', 'securecore-bench')
  // Restarting php stops the tabs from the previous configuration, so each one is measured
  // (memory included) with only its own tabs; the warm-up requests start them again.
  run([...COMPOSE, 'restart', 'php'])
}

async function ready() {
  for (let i = 0; i < 60; i++) {
    const response = await fetch(`http://${HOST}/`).catch(() => null)
    if (response?.status === 200) return
    await Bun.sleep(500)
  }
  throw new Error('site did not come back after restarting php')
}

async function cookie(): Promise<string> {
  const response = await fetch(`http://${HOST}/wp-login.php`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: 'wordpress_test_cookie=WP%20Cookie%20check' },
    body: 'log=admin&pwd=securecore-demo&wp-submit=Log+In&testcookie=1',
  })
  const cookies = response.headers.getSetCookie().map((c) => c.split(';')[0]).filter((c) => c.startsWith('wordpress_'))
  if (response.status !== 302 || cookies.length < 2) throw new Error(`login failed: HTTP ${response.status}`)
  return cookies.join('; ')
}

type Oha = { metrics: { latency_ms: { p50: number; p95: number }; requests_per_sec: number }; statusCodeDistribution: Record<string, number> }

// Async, so the memory sampler keeps running while oha does.
async function oha(path: string, n: number, c: number, cookieHeader: string): Promise<{ p50: number; p95: number; rps: number }> {
  const args = ['docker', 'run', '--rm', '--network', 'securecore_default', OHA, '-n', String(n), '-c', String(c), '--no-tui', '--output-format', 'json', '-H', `Host: ${HOST}`]
  if (path.startsWith('/wp-admin')) args.push('-H', `Cookie: ${cookieHeader}`)
  args.push(`http://web${path}`)
  const proc = Bun.spawn(args, { stdout: 'pipe', stderr: 'pipe' })
  const [text, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited])
  if (code !== 0) throw new Error(`oha ${path} → exit ${code}\n${err}`)
  const result = JSON.parse(text) as Oha
  const codes = result.statusCodeDistribution
  if (Object.keys(codes).some((code) => code !== '200') || (codes['200'] ?? 0) !== n) {
    throw new Error(`${path}: not all ${n} responses were 200: ${JSON.stringify(codes)}`)
  }
  return { p50: result.metrics.latency_ms.p50, p95: result.metrics.latency_ms.p95, rps: result.metrics.requests_per_sec }
}

// Highest memory per container while `body` runs, sampled with docker stats.
async function peakMemory<T>(body: () => Promise<T>): Promise<{ result: T; peakMb: Record<string, number> }> {
  const peak: Record<string, number> = {}
  let running = true
  const sampler = (async () => {
    while (running) {
      const proc = Bun.spawn(['docker', 'stats', '--no-stream', '--format', '{{.Name}} {{.MemUsage}}'], { stdout: 'pipe' })
      const text = await new Response(proc.stdout).text()
      await proc.exited
      for (const line of text.trim().split('\n')) {
        const [name, usage] = line.split(' ')
        if (!name?.startsWith('securecore-')) continue
        const m = /^([\d.]+)(KiB|MiB|GiB)/.exec(usage ?? '')
        if (!m) continue
        const mb = Number(m[1]) * (m[2] === 'GiB' ? 1024 : m[2] === 'KiB' ? 1 / 1024 : 1)
        peak[name] = Math.max(peak[name] ?? 0, Math.round(mb))
      }
    }
  })()
  let result: T
  try {
    result = await body()
  } finally {
    running = false
    await sampler
  }
  return { result, peakMb: peak }
}

const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor((xs.length - 1) / 2)]
const r1 = (x: number) => Math.round(x * 10) / 10

const configs = ['off', 'on1', 'on2'] as const
const pages = ['/', '/wp-admin/'] as const
const concurrency = [1, 4, 8] as const
type Point = { p50: number[]; p95: number[]; rps: number[] }
const latency: Record<string, Point> = {}
const throughput: Record<string, Point> = {}
const memory: Record<string, Record<string, number>> = {}
const add = (table: Record<string, Point>, key: string, r: { p50: number; p95: number; rps: number }) => {
  table[key] ??= { p50: [], p95: [], rps: [] }
  table[key].p50.push(r.p50); table[key].p95.push(r.p95); table[key].rps.push(r.rps)
}

try {
  for (let rep = 0; rep < repeats; rep++) {
    for (const config of configs) {
      configure(config)
      await ready()
      const header = await cookie()
      for (const page of pages) {
        await oha(page, 10, 1, header) // warm-up
        add(latency, `${config} ${page}`, await oha(page, 100, 1, header))
      }
      for (const c of concurrency) {
        await oha('/', 2 * c, c, header) // warm-up
        const n = c === 1 ? 100 : 200
        const { result, peakMb } = await peakMemory(() => oha('/', n, c, header))
        add(throughput, `${config} c=${c}`, result)
        if (c === 8) for (const [name, mb] of Object.entries(peakMb)) {
          memory[config] ??= {}
          memory[config][name] = Math.max(memory[config][name] ?? 0, mb)
        }
      }
      console.error(`repeat ${rep + 1}/${repeats} ${config} done`)
    }
  }
} catch (error) {
  console.error('load failed:', error instanceof Error ? error.message : error)
  process.exit(1)
} finally {
  try { configure('on2'); wp('plugin', 'activate', 'securecore-probe') } catch { /* reported above */ }
}

writeFileSync(`${out}/load.json`, JSON.stringify({ repeats, latency, throughput, memory }, null, 2))
console.log(`Latency, concurrency 1, 100 requests per run, median of ${repeats} runs (ms)\n`)
console.log('| page | config | p50 | p95 |\n|---|---|---|---|')
for (const page of pages) for (const config of configs) {
  const p = latency[`${config} ${page}`]
  console.log(`| ${page} | ${config} | ${r1(median(p.p50))} | ${r1(median(p.p95))} |`)
}
console.log(`\nThroughput, front page, median of ${repeats} runs (requests/s; p50 ms)\n`)
console.log('| config | c=1 | c=4 | c=8 |\n|---|---|---|---|')
for (const config of configs) {
  const cells = concurrency.map((c) => {
    const p = throughput[`${config} c=${c}`]
    return `${r1(median(p.rps))} (${Math.round(median(p.p50))})`
  })
  console.log(`| ${config} | ${cells.join(' | ')} |`)
}
console.log('\nPeak memory during the c=8 runs (MiB, docker stats)\n')
console.log('| config | php (fpm + sandboxes) | web | db |\n|---|---|---|---|')
for (const config of configs) {
  const m = memory[config] ?? {}
  console.log(`| ${config} | ${m['securecore-php-1'] ?? '?'} | ${m['securecore-web-1'] ?? '?'} | ${m['securecore-db-1'] ?? '?'} |`)
}
