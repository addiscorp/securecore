// Part-1b measurements (addiscorp/securecore#42): the three sandbox worker models side by
// side on the running docker/ stack, three runs each, in one session.
//
//   bun bench/preboot.ts [repeats]        (default 3; needs docker/setup.sh first)
//
// Models (the worker is recreated between them; wp-config and the worker env are set to match):
//   stub     SECURECORE_REALWP off            — the #11 forward-stub worker
//   realwp   SECURECORE_REALWP on             — real WordPress, booted per request (part 1)
//   preboot  SECURECORE_REALWP + PREBOOT on   — real WordPress, booted once in the parent (1b)
// Plugin load per model: 1 plugin (Hello Dolly sandboxed) and 2 (Hello Dolly + the bench
// plugin). "off" (SECURECORE_DISABLED, both plugins loaded normally) is measured once.
//
// Reported per configuration, median with [min, max] over the runs: front-page and wp-admin
// p50, requests/s at concurrency 8, and the worker's PSS (summed over the master and its forks
// from /proc/<pid>/smaps_rollup — the honest shared-memory number). oha runs in a container on
// the stack's network, straight to nginx. Every response must be 200 or the run is retried
// once (a pre-boot worker re-boot, if one lands mid-run, shows as a non-200); writes
// .tmp/bench/preboot.json.
import { mkdirSync, writeFileSync } from 'node:fs'

const repeats = Number(process.argv[2] ?? 3)
const OHA = 'ghcr.io/hatoo/oha@sha256:3ec3dbf549ea197793482d47a6324797411406bbf438c2fe8b91f244ec641a2f' // oha 1.16.0
const COMPOSE = ['docker', 'compose', '-f', 'docker/compose.yml']
const HOST = '127.0.0.1:8088'
const out = '.tmp/bench'
mkdirSync(out, { recursive: true })

function run(cmd: string[], env?: Record<string, string>): string {
  const result = Bun.spawnSync(cmd, { stdout: 'pipe', stderr: 'pipe', env: env ? { ...process.env, ...env } : process.env })
  if (result.exitCode !== 0) throw new Error(`${cmd.join(' ')} → exit ${result.exitCode}\n${result.stderr.toString()}`)
  return result.stdout.toString()
}
const wp = (...args: string[]) => run([...COMPOSE, 'run', '--rm', '-T', 'cli', 'wp', ...args])
const wpTry = (...args: string[]) => { try { wp(...args) } catch { /* option/plugin already in the wanted state */ } }

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

async function httpStatus(path: string): Promise<number> {
  try {
    const res = await fetch(`http://${HOST}${path}`, { redirect: 'manual' })
    return res.status
  } catch { return 0 }
}

/** Wait until the front page serves 200 (core and worker agree on the model), or give up. */
async function waitHealthy(label: string): Promise<void> {
  for (let i = 0; i < 60; i++) {
    if ((await httpStatus('/')) === 200) return
    await sleep(500)
  }
  throw new Error(`stack not healthy after switching to ${label}`)
}

type Model = 'stub' | 'realwp' | 'preboot'

/** Point wp-config and the worker container at a model, and wait until it serves. */
async function setModel(model: Model): Promise<void> {
  if (model === 'stub') wpTry('config', 'delete', 'SECURECORE_REALWP')
  else wp('config', 'set', 'SECURECORE_REALWP', 'true', '--raw')

  if (model === 'preboot') {
    // The parent boots from core's on-disk options snapshot; make sure one exists (core writes
    // it on a request while the real-WordPress model is on and a plugin is sandboxed) before
    // the worker starts, so it comes up pre-booted rather than falling back to per-request.
    wpTry('config', 'delete', 'SECURECORE_DISABLED')
    wp('plugin', 'activate', 'hello')
    await httpStatus('/') // trigger the snapshot write
    await sleep(800)
  }
  const env = {
    SECURECORE_REALWP: model === 'stub' ? '' : '1',
    SECURECORE_PREBOOT: model === 'preboot' ? '1' : '',
  }
  run([...COMPOSE, 'up', '-d', '--force-recreate', 'worker'], env)
  await sleep(1500)
  await waitHealthy(model)
  if (model === 'preboot') {
    const log = run([...COMPOSE, 'logs', '--tail', '80', 'worker'])
    if (!log.includes('preboot: booted WordPress from snapshot')) {
      throw new Error('preboot worker did not report booting from the snapshot:\n' + log.split('\n').filter((l) => l.includes('preboot')).join('\n'))
    }
  }
}

/** Set the plugin load. 'off' disables SecureCore entirely; on1/on2 sandbox 1 or 2 plugins. */
function configure(config: 'off' | 'on1' | 'on2'): void {
  if (config === 'off') wp('config', 'set', 'SECURECORE_DISABLED', 'true', '--raw')
  else wpTry('config', 'delete', 'SECURECORE_DISABLED')
  wpTry('plugin', 'deactivate', 'securecore-probe')
  wp('plugin', 'activate', 'hello')
  if (config === 'on2') wp('plugin', 'activate', 'securecore-bench')
  else wpTry('plugin', 'deactivate', 'securecore-bench')
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

type Oha = { metrics: { latency_ms: { p50: number }; requests_per_sec: number }; statusCodeDistribution: Record<string, number> }

async function oha(path: string, n: number, c: number, cookieHeader: string): Promise<{ p50: number; rps: number }> {
  const args = ['docker', 'run', '--rm', '--network', 'securecore_default', OHA, '-n', String(n), '-c', String(c), '--no-tui', '--output-format', 'json', '-H', `Host: ${HOST}`]
  if (path.startsWith('/wp-admin')) args.push('-H', `Cookie: ${cookieHeader}`)
  args.push(`http://web${path}`)
  const proc = Bun.spawn(args, { stdout: 'pipe', stderr: 'pipe' })
  const [text, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited])
  if (code !== 0) throw new Error(`oha ${path} → exit ${code}\n${err}`)
  const result = JSON.parse(text) as Oha
  const codes = result.statusCodeDistribution
  if (Object.keys(codes).some((s) => s !== '200') || (codes['200'] ?? 0) !== n) {
    throw new Error(`${path}: not all ${n} responses were 200: ${JSON.stringify(codes)}`)
  }
  return { p50: result.metrics.latency_ms.p50, rps: result.metrics.requests_per_sec }
}

/** Peak summed worker PSS (MiB) while `body` runs; 0 when the worker is idle (off). */
async function workerPss<T>(body: () => Promise<T>): Promise<{ result: T; pss: number }> {
  let pss = 0
  let running = true
  const sampler = (async () => {
    while (running) {
      const w = Bun.spawn([...COMPOSE, 'exec', '-T', 'worker', 'sh', '-c',
        "awk '/^Pss:/{p+=$2}END{print p}' /proc/[0-9]*/smaps_rollup 2>/dev/null"], { stdout: 'pipe', stderr: 'ignore' })
      const text = await new Response(w.stdout).text()
      await w.exited
      const kb = Number(text.trim())
      if (kb) pss = Math.max(pss, Math.round(kb / 1024))
    }
  })()
  let result: T
  try { result = await body() } finally { running = false; await sampler }
  return { result, pss }
}

type Series = { front: number[]; admin: number[]; rps: number[]; pss: number[] }
const series: Record<string, Series> = {}
const push = (key: string, m: { front: number; admin: number; rps: number; pss: number }) => {
  series[key] ??= { front: [], admin: [], rps: [], pss: [] }
  series[key].front.push(m.front); series[key].admin.push(m.admin); series[key].rps.push(m.rps); series[key].pss.push(m.pss)
}

/** One measured run of the current configuration. Retried once by the caller on a non-200. */
async function measure(): Promise<{ front: number; admin: number; rps: number; pss: number }> {
  const header = await cookie()
  await oha('/', 20, 1, header)            // warm-up
  const front = (await oha('/', 100, 1, header)).p50
  await oha('/wp-admin/', 20, 1, header)   // warm-up
  const admin = (await oha('/wp-admin/', 100, 1, header)).p50
  await oha('/', 16, 8, header)            // warm-up
  const { result, pss } = await workerPss(() => oha('/', 200, 8, header))
  return { front, admin, rps: result.rps, pss }
}

// config key → [model, pluginConfig]; 'off' is model-independent (measured under stub).
const plan: Array<{ key: string; model: Model; pc: 'off' | 'on1' | 'on2' }> = [
  { key: 'off', model: 'stub', pc: 'off' },
  { key: 'stub 1p', model: 'stub', pc: 'on1' },
  { key: 'stub 2p', model: 'stub', pc: 'on2' },
  { key: 'realwp 1p', model: 'realwp', pc: 'on1' },
  { key: 'realwp 2p', model: 'realwp', pc: 'on2' },
  { key: 'preboot 1p', model: 'preboot', pc: 'on1' },
  { key: 'preboot 2p', model: 'preboot', pc: 'on2' },
]

const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor((xs.length - 1) / 2)]
const r1 = (x: number) => Math.round(x * 10) / 10
const cell = (xs: number[], round: (n: number) => number) =>
  `${round(median(xs))} [${round(Math.min(...xs))}, ${round(Math.max(...xs))}]`

try {
  wpTry('config', 'set', 'DISABLE_WP_CRON', 'true', '--raw') // steady autoloaded options during the runs
  let lastModel: Model | null = null
  for (const { key, model, pc } of plan) {
    if (model !== lastModel) { await setModel(model); lastModel = model }
    configure(pc)
    for (let rep = 0; rep < repeats; rep++) {
      let attempt = 0
      for (;;) {
        try { push(key, await measure()); break } catch (error) {
          if (++attempt >= 2) throw error
          console.error(`  ${key} run ${rep + 1}: retrying after ${error instanceof Error ? error.message.split('\n')[0] : error}`)
          await sleep(2500) // let a pre-boot re-boot settle
        }
      }
      console.error(`${key} run ${rep + 1}/${repeats} done`)
    }
  }
} catch (error) {
  console.error('preboot bench failed:', error instanceof Error ? error.message : error)
  process.exit(1)
} finally {
  try { wpTry('config', 'delete', 'DISABLE_WP_CRON'); configure('on2'); wpTry('plugin', 'activate', 'securecore-probe') } catch { /* reported above */ }
}

writeFileSync(`${out}/preboot.json`, JSON.stringify({ repeats, series }, null, 2))
console.log(`\nSandbox worker models, median [min, max] of ${repeats} runs\n`)
console.log('| config | front / p50 (ms) | /wp-admin/ p50 (ms) | req/s c=8 | worker PSS (MiB) |')
console.log('|---|---|---|---|---|')
for (const { key } of plan) {
  const s = series[key]
  if (!s) continue
  const pss = key === 'off' ? '—' : cell(s.pss, Math.round)
  console.log(`| ${key} | ${cell(s.front, r1)} | ${cell(s.admin, r1)} | ${cell(s.rps, r1)} | ${pss} |`)
}
