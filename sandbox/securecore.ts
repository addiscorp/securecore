// securecore: runs one WordPress plugin in a sandbox (engine: p8, php2.wasm).
//
//   securecore serve --socket <path> [--pool N] <plugin-dir-or-file> <main-file>
//       A tab: stays up and serves requests from SecureCore.php over a unix socket, one
//       connection per request. N worker slots, each holding one prepared, fresh instance.
//   securecore [--timings] <plugin-dir-or-file> <main-file>
//       One instance on stdin/stdout, then exit (bench/breakdown.php).
//
// The sandbox sees only the plugin's folder, /sandbox/setup.php and an empty /tmp; see
// engine.ts.
import { existsSync, readFileSync, readSync, unlinkSync, writeSync } from 'node:fs'
import type { Socket } from 'bun'
import { Fd, p8, pluginFiles, sandboxRoot, wasi } from './engine'
import wasmPath from './php2.wasm' with { type: 'file' }
import setupPath from './setup.php' with { type: 'file' }
// Built as a second entry point of the executable (package.json "build").
const tabWorker = './tab.ts'

const log = (line: string) => writeSync(2, `${new Date().toISOString()} securecore[${process.pid}] ${line}\n`)
const argv = process.argv.slice(2)

function prepareLine(main: string): Uint8Array {
  const ser = `a:2:{i:0;s:7:"prepare";i:1;a:1:{s:4:"main";s:${Buffer.byteLength(main)}:"${main}";}}`
  return new Uint8Array(Buffer.from(Buffer.from(ser).toString('base64') + '\n'))
}

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
  stdin.local.push(prepareLine(main))
  return p8(module).run(sandboxRoot(files, readFileSync(setupPath)), stdin, (b) => { writeSync(1, b) }, audit)
}

// --- tab --------------------------------------------------------------------------------
const RING = 8 << 20

type Conn = { out: Buffer[]; early: Buffer[]; slot?: Slot }
type Slot = {
  worker: Worker
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
  const rest: string[] = []
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--socket') socketPath = args[++i]
    else if (args[i] === '--pool') pool = Number(args[++i])
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

  function start(index: number) {
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
    worker.postMessage({ ctrl, data, plugin: pluginPath, main })
  }

  // A slot whose instance does not finish after its request closed is stuck: replace it.
  function restart(index: number) {
    const slot = slots[index]
    release(slot)
    slot.worker.terminate()
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
        Atomics.store(slot.ctrl, 2, 1)
        Atomics.notify(slot.ctrl, 0)
        const index = slots.indexOf(slot)
        slot.killTimer = setTimeout(() => { log(`slot ${index} still running 2 s after its request ended: restarting`); restart(index) }, 2000)
      },
    },
  })
  log(`serving ${pluginPath} on ${socketPath} with ${pool} slots`)
}

if (argv[0] === 'serve') await serve(argv.slice(1))
else process.exit(oneShot(argv))
