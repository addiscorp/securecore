// securecore: runs one WordPress plugin in a sandbox.
//
//   securecore serve --socket <path> [--pool N] [--engine p8|php-wasm|native] <plugin> <main>
//       A tab: stays up and serves requests from SecureCore.php over a unix socket, one
//       connection per request. N slots, each holding one prepared, fresh instance.
//       Engines: p8 (php2.wasm, default) and php-wasm (stock PHP 8.3, WordPress
//       Playground's build) run in worker threads; native runs the php CLI as a child
//       process: a lower bound for benchmarks, NOT a sandbox (the plugin sees the host).
//   securecore [--timings] <plugin-dir-or-file> <main-file>
//       One p8 instance on stdin/stdout, then exit.
//
// The sandbox sees only the plugin's folder, /sandbox/setup.php and an empty /tmp; see
// engine.ts.
import { existsSync, readFileSync, readSync, statSync, unlinkSync, writeFileSync, writeSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import type { Socket, Subprocess } from 'bun'
import { Fd, p8, pluginFiles, prepareLine, sandboxRoot, wasi } from './engine'
import wasmPath from './php2.wasm' with { type: 'file' }
import setupPath from './setup.php' with { type: 'file' }
// Built as a second entry point of the executable (package.json "build"); from source,
// next to this file.
const tabWorker = import.meta.url.includes('$bunfs') ? './tab.ts' : new URL('./tab.ts', import.meta.url).href

const log = (line: string) => writeSync(2, `${new Date().toISOString()} securecore[${process.pid}] ${line}\n`)
const argv = process.argv.slice(2)
const PREPARED = Buffer.from('a:1:{i:0;s:8:"prepared";}').toString('base64')

// --- one-shot ---------------------------------------------------------------------------
class Stdin extends Fd {
  local: Uint8Array[] = []
  fd_fdstat_get() { return { ret: 0, fdstat: new wasi.Fdstat(wasi.FILETYPE_CHARACTER_DEVICE, 0) } }
  fd_read(size: number) {
    const local = this.local.shift()
    if (local) return { ret: 0, data: local }
    const buf = Buffer.alloc(size)
    for (;;) {
      try {
        const n = readSync(0, buf, 0, size, null)
        return { ret: 0, data: new Uint8Array(buf.buffer, buf.byteOffset, n) }
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code
        if (code === 'EAGAIN') continue
        if (code === 'EOF') return { ret: 0, data: new Uint8Array() }
        throw error
      }
    }
  }
}

function oneShot(args: string[]): number {
  const mainAt = Date.now()
  const timings = args[0] === '--timings'
  if (timings) args.shift()
  const [pluginPath, main] = args
  if (!pluginPath || !main) {
    writeSync(2, 'usage: securecore [--timings] <plugin-dir-or-file> <main-file>\n')
    return 2
  }
  const files = pluginFiles(pluginPath)
  const t0 = performance.now()
  const bytes = readFileSync(wasmPath)
  const t1 = performance.now()
  const module = new WebAssembly.Module(bytes)
  const t2 = performance.now()
  const audit = (e: Record<string, unknown>) => writeSync(1, '#' + JSON.stringify(e) + '\n')
  if (timings) audit({ event: 'timing', origin: performance.timeOrigin, main: mainAt, start: Date.now(), load_ms: t0, read_ms: t1 - t0, compile_ms: t2 - t1, instantiate_ms: 0 })
  const stdin = new Stdin()
  stdin.local.push(prepareLine(`/plugin/${main}`, '/plugin'))
  return p8(module).run(sandboxRoot(files, readFileSync(setupPath)), stdin, (b) => { writeSync(1, b) }, audit) as number
}

// --- tab --------------------------------------------------------------------------------
const RING = 8 << 20

type Conn = { out: Buffer[]; early: Buffer[]; slot?: Slot }
type Slot = {
  worker?: Worker
  proc?: Subprocess<'pipe', 'ignore', 'pipe'>
  ctrl: Int32Array
  data: Uint8Array
  pending: Buffer[]
  conn?: Socket<Conn>
  idle: boolean
  killTimer?: ReturnType<typeof setTimeout>
}

async function serve(args: string[]): Promise<void> {
  let socketPath = ''
  let pool = 4
  let engine = 'p8'
  const rest: string[] = []
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--socket') socketPath = args[++i]
    else if (args[i] === '--pool') pool = Number(args[++i])
    else if (args[i] === '--engine') engine = args[++i]
    else rest.push(args[i])
  }
  const [pluginPath, main] = rest
  if (!socketPath || !pluginPath || !main) {
    writeSync(2, 'usage: securecore serve --socket <path> [--pool N] <plugin-dir-or-file> <main-file>\n')
    process.exit(2)
  }

  // Someone else already serves this socket: nothing to do. A stale file: remove it.
  if (existsSync(socketPath)) {
    const alive = await Bun.connect({ unix: socketPath, socket: { data() {} } }).then((s) => { s.end(); return true }, () => false)
    if (alive) { log(`${socketPath} already served`); process.exit(0) }
    unlinkSync(socketPath)
  }

  const slots: Slot[] = []
  const waiting: Socket<Conn>[] = []

  function feed(slot: Slot) {
    if (slot.proc) {
      for (const chunk of slot.pending) slot.proc.stdin.write(chunk)
      slot.proc.stdin.flush()
      slot.pending = []
      return
    }
    const { ctrl, data } = slot
    while (slot.pending.length) {
      const chunk = slot.pending[0]
      const written = Atomics.load(ctrl, 0)
      const free = data.length - (written - Atomics.load(ctrl, 1))
      if (free === 0) { Atomics.store(ctrl, 3, 1); return }
      const start = written % data.length
      const n = Math.min(free, chunk.length, data.length - start)
      data.set(chunk.subarray(0, n), start)
      Atomics.store(ctrl, 0, written + n)
      Atomics.notify(ctrl, 0)
      if (n === chunk.length) slot.pending.shift()
      else slot.pending[0] = chunk.subarray(n)
    }
    Atomics.store(ctrl, 3, 0)
  }

  function send(conn: Socket<Conn>, bytes: Buffer) {
    if (conn.data.out.length) { conn.data.out.push(bytes); return }
    const n = conn.write(bytes)
    if (n < bytes.length) conn.data.out.push(bytes.subarray(n))
  }

  function assign(slot: Slot) {
    const conn = waiting.shift()
    if (!conn) { slot.idle = true; return }
    slot.idle = false
    slot.conn = conn
    conn.data.slot = slot
    // Bytes that arrived while the connection waited for a slot.
    slot.pending.push(...conn.data.early)
    conn.data.early = []
    feed(slot)
  }

  function release(slot: Slot) {
    if (slot.killTimer) clearTimeout(slot.killTimer)
    slot.killTimer = undefined
    if (slot.conn) { slot.conn.data.slot = undefined; slot.conn.end() }
    slot.conn = undefined
    slot.pending = []
    for (let i = 0; i < 4; i++) Atomics.store(slot.ctrl, i, 0)
  }

  // Native engine: a php CLI child process per slot. Not a sandbox; benchmark lower bound.
  const nativeSetup = join(tmpdir(), `securecore-setup-${process.pid}.php`)
  if (engine === 'native') writeFileSync(nativeSetup, readFileSync(setupPath))
  const nativeScan = pluginPath
  const nativeMain = statSync(pluginPath).isDirectory() ? join(pluginPath, main) : join(dirname(pluginPath), main)

  // php-fpm starts tabs with an empty environment (no PATH), so look in the usual places.
  const phpCli = ['/usr/local/bin/php', '/usr/bin/php'].find((p) => existsSync(p)) ?? 'php'

  function startNative(index: number) {
    const proc = Bun.spawn([phpCli, '-d', 'display_errors=0', '-d', 'log_errors=0', nativeSetup], {
      stdin: 'pipe', stdout: 'ignore', stderr: 'pipe', env: {},
    })
    const slot: Slot = { proc, ctrl: new Int32Array(4), data: new Uint8Array(0), pending: [], idle: false }
    slots[index] = slot
    proc.stdin.write(prepareLine(nativeMain, nativeScan))
    proc.stdin.flush()
    ;(async () => {
      let prepared = false
      let buffer = ''
      for await (const chunk of proc.stderr) {
        if (prepared) { if (slot.conn) send(slot.conn, Buffer.from(chunk)); continue }
        buffer += Buffer.from(chunk).toString('utf8')
        let i
        while (!prepared && (i = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, i)
          buffer = buffer.slice(i + 1)
          if (line === PREPARED) {
            prepared = true
            assign(slot)
            if (buffer && slot.conn) send(slot.conn, Buffer.from(buffer))
          } else log(`slot ${index}: ${line}`)
        }
      }
      const status = await proc.exited
      release(slot)
      if (!prepared) { log(`slot ${index}: php exited ${status} before it was prepared`); setTimeout(() => startNative(index), 1000) }
      else startNative(index)
    })()
  }

  function start(index: number) {
    if (engine === 'native') return startNative(index)
    const ctrl = new SharedArrayBuffer(16)
    const data = new SharedArrayBuffer(RING)
    const worker = new Worker(tabWorker)
    const slot: Slot = { worker, ctrl: new Int32Array(ctrl), data: new Uint8Array(data), pending: [], idle: false }
    slots[index] = slot
    worker.onmessage = (event: MessageEvent) => {
      const m = event.data
      if (m.type === 'idle') assign(slot)
      else if (m.type === 'out') { if (slot.conn) send(slot.conn, Buffer.from(m.bytes)) }
      else if (m.type === 'drain') feed(slot)
      else if (m.type === 'log') log(`slot ${index}: ${m.line}`)
      else if (m.type === 'done') {
        if (!m.prepared) log(`slot ${index}: instance exited ${m.status} before it was prepared`)
        release(slot)
        if (!m.prepared) { worker.terminate(); setTimeout(() => start(index), 1000) }
      }
    }
    // A crash replaces only that slot, after a pause so a broken plugin cannot spin.
    worker.onerror = (error) => {
      log(`slot ${index} crashed: ${error.message}`)
      release(slot)
      worker.terminate()
      setTimeout(() => start(index), 1000)
    }
    worker.postMessage({ ctrl, data, plugin: pluginPath, main, engine })
  }

  // A slot whose instance does not finish after its request closed is stuck: replace it.
  function restart(index: number) {
    const slot = slots[index]
    release(slot)
    if (slot.proc) { slot.proc.kill(); return } // its exit handler starts the next one
    slot.worker?.terminate()
    start(index)
  }

  for (let i = 0; i < pool; i++) start(i)

  Bun.listen<Conn>({
    unix: socketPath,
    socket: {
      open(conn) {
        conn.data = { out: [], early: [] }
        const slot = slots.find((s) => s.idle)
        waiting.push(conn)
        if (slot) assign(slot)
      },
      data(conn, bytes) {
        const slot = conn.data.slot
        if (!slot) {
          // Not assigned yet: keep the bytes until a slot takes the connection.
          conn.data.early.push(Buffer.from(bytes))
          return
        }
        slot.pending.push(Buffer.from(bytes))
        feed(slot)
      },
      drain(conn) {
        while (conn.data.out.length) {
          const bytes = conn.data.out[0]
          const n = conn.write(bytes)
          if (n < bytes.length) { conn.data.out[0] = bytes.subarray(n); return }
          conn.data.out.shift()
        }
      },
      close(conn) {
        const i = waiting.indexOf(conn)
        if (i >= 0) waiting.splice(i, 1)
        const slot = conn.data.slot
        if (!slot) return
        if (slot.proc) slot.proc.stdin.end()
        Atomics.store(slot.ctrl, 2, 1)
        Atomics.notify(slot.ctrl, 0)
        const index = slots.indexOf(slot)
        slot.killTimer = setTimeout(() => { log(`slot ${index} still running 2 s after its request ended: restarting`); restart(index) }, 2000)
      },
    },
  })
  log(`serving ${pluginPath} on ${socketPath} with ${pool} ${engine} slots${engine === 'native' ? ' (NOT a sandbox)' : ''}`)
}

if (argv[0] === 'serve') await serve(argv.slice(1))
else process.exit(oneShot(argv))
