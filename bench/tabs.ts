// Measurement 5: what an always-on sandbox ("tab") would cost per request.
//
//   securecore-tabs <plugin-dir> <main-file> <functions.json> [runs]   (see bench/run.sh)
//
// One process, php2.wasm compiled once. Each run instantiates a fresh instance and boots
// setup.php + the plugin to 'ready', answering the plugin's hook registrations from a
// script. After the first boot it also times copying a saved copy of linear memory back
// into a live instance: the cost of "reset to a clean booted state" between requests.
// Prints JSON. Exits non-zero on failure.
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { ConsoleStdout, Directory, Fd, File, PreopenDirectory, WASI, WASIProcExit, wasi } from '@bjorn3/browser_wasi_shim'
import wasmPath from '../sandbox/php2.wasm' with { type: 'file' }
import setupPath from '../sandbox/setup.php' with { type: 'file' }

const [pluginDir, mainFile, functionsFile, runsArg] = process.argv.slice(2)
if (!pluginDir || !mainFile || !functionsFile) {
  console.error('usage: securecore-tabs <plugin-dir> <main-file> <functions.json> [runs]')
  process.exit(2)
}
const runs = Number(runsArg ?? 30)

// PHP serialize() for the few shapes the protocol needs here.
function ser(value: unknown): string {
  if (value === true || value === false) return `b:${value ? 1 : 0};`
  if (value === null) return 'N;'
  if (typeof value === 'number') return `i:${value};`
  if (typeof value === 'string') return `s:${Buffer.byteLength(value)}:"${value}";`
  if (Array.isArray(value)) return `a:${value.length}:{${value.map((v, i) => `i:${i};${ser(v)}`).join('')}}`
  const entries = Object.entries(value as Record<string, unknown>)
  return `a:${entries.length}:{${entries.map(([k, v]) => ser(k) + ser(v)).join('')}}`
}
const line = (message: unknown) => Buffer.from(Buffer.from(ser(message)).toString('base64') + '\n')
const functions = JSON.parse(readFileSync(functionsFile, 'utf8')) as string[]
const BOOT = line(['boot', { functions, get: [], post: [], server: [] }])
const OK = line(['return', true])
const END = line(['end'])

function load(dir: string): Directory {
  const entries: [string, File | Directory][] = []
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    const stat = statSync(path)
    if (stat.isDirectory()) entries.push([name, load(path)])
    else if (stat.isFile()) entries.push([name, new File(readFileSync(path), { readonly: true })])
  }
  return new Directory(entries)
}

// Plays core: answers each message the sandbox writes. At 'ready' it calls onReady, then ends.
class Script extends Fd {
  queue: Buffer[] = [BOOT]
  pending = ''
  constructor(private onReady: () => void) { super() }
  fd_fdstat_get() { return { ret: 0, fdstat: new wasi.Fdstat(wasi.FILETYPE_CHARACTER_DEVICE, 0) } }
  fd_read(size: number) {
    const next = this.queue.shift()
    if (!next) throw new Error('sandbox read with nothing queued')
    if (next.length > size) { this.queue.unshift(next.subarray(size)); return { ret: 0, data: new Uint8Array(next.subarray(0, size)) } }
    return { ret: 0, data: new Uint8Array(next) }
  }
  written(bytes: Uint8Array) {
    this.pending += Buffer.from(bytes).toString('utf8')
    let i
    while ((i = this.pending.indexOf('\n')) >= 0) {
      const message = Buffer.from(this.pending.slice(0, i), 'base64').toString('utf8')
      this.pending = this.pending.slice(i + 1)
      if (message.includes('s:4:"hook"')) this.queue.push(OK)
      else if (message.includes('s:5:"ready"')) { this.onReady(); this.queue.push(END) }
      else if (message.includes('s:3:"log"')) console.error('sandbox log:', message)
      else throw new Error(`unexpected message: ${message.slice(0, 80)}`)
    }
  }
}

const t0 = performance.now()
const module = await WebAssembly.compile(readFileSync(wasmPath))
const compileMs = performance.now() - t0
const setup = readFileSync(setupPath)
const plugin = load(pluginDir)

let snapshot: Uint8Array | null = null
let memory: WebAssembly.Memory | null = null

async function boot(): Promise<{ instantiate: number; boot: number }> {
  let readyAt = 0
  const script = new Script(() => {
    readyAt = performance.now()
    if (!snapshot && memory) snapshot = new Uint8Array(memory.buffer).slice()
  })
  const root = new Directory([
    ['sandbox', new Directory([['setup.php', new File(setup, { readonly: true })]])],
    ['plugin', plugin],
    ['tmp', new Directory([])],
  ])
  const runtime = new WASI(['php2', '-d', 'display_errors=0', '-d', 'log_errors=0', '/sandbox/setup.php', `/plugin/${mainFile}`], [], [
    script,
    new ConsoleStdout(() => {}),
    new ConsoleStdout((bytes) => script.written(bytes)),
    new PreopenDirectory('/', root.contents),
  ], { debug: false })
  const a = performance.now()
  const instance = await WebAssembly.instantiate(module, { wasi_snapshot_preview1: runtime.wasiImport })
  const b = performance.now()
  memory = instance.exports.memory as WebAssembly.Memory
  try {
    const status = runtime.start(instance as { exports: { memory: WebAssembly.Memory; _start: () => unknown } })
    if (status !== 0) throw new Error(`exit ${status}`)
  } catch (error) {
    if (!(error instanceof WASIProcExit) || error.code !== 0) throw error
  }
  if (!readyAt) throw new Error('never reached ready')
  return { instantiate: b - a, boot: readyAt - b }
}

const pct = (values: number[], p: number) => {
  const sorted = [...values].sort((x, y) => x - y)
  return Math.round(sorted[Math.max(0, Math.ceil(p * sorted.length) - 1)] * 100) / 100
}

try {
  const rows: { instantiate: number; boot: number }[] = []
  for (let i = 0; i < runs + 3; i++) {
    const row = await boot()
    if (i >= 3) rows.push(row) // the first three warm up the JIT
    // A finished instance's memory is only freed by GC; without this the process runs out
    // around 20 instances. A real tab would hold one instance per request in flight.
    Bun.gc(true)
  }
  // Restore: copy the saved booted memory back into the last instance's memory.
  if (!snapshot || !memory) throw new Error('no snapshot')
  const saved: Uint8Array = snapshot
  const live = new Uint8Array((memory as WebAssembly.Memory).buffer)
  const restores: number[] = []
  for (let i = 0; i < runs; i++) {
    const a = performance.now()
    live.set(saved.subarray(0, Math.min(saved.length, live.length)))
    restores.push(performance.now() - a)
  }
  const inst = rows.map((r) => r.instantiate)
  const boots = rows.map((r) => r.boot)
  console.log(JSON.stringify({
    runs, functions: functions.length, compile_once_ms: Math.round(compileMs * 100) / 100,
    instantiate_ms: { p50: pct(inst, 0.5), p95: pct(inst, 0.95) },
    boot_to_ready_ms: { p50: pct(boots, 0.5), p95: pct(boots, 0.95) },
    memory_at_ready_mb: Math.round(saved.length / 1048576 * 10) / 10,
    restore_memory_copy_ms: { p50: pct(restores, 0.5), p95: pct(restores, 0.95) },
    rss_mb: Math.round(process.memoryUsage().rss / 1048576),
  }, null, 2))
} catch (error) {
  console.error('tabs failed:', error instanceof Error ? error.message : error)
  process.exit(1)
}
