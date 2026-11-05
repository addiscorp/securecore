// One slot of a tab: a worker thread that runs one fresh instance per request.
//
// Loop: new instance → feed it 'prepare' (stand-ins, plugin scan) → tell the tab it is
// idle → PHP blocks reading the next message → the tab hands it a request's bytes through a
// shared ring → the instance serves that request and exits → repeat. An instance never sees
// a second request: each request starts from a clean, already-prepared state.
//
// Ring (SharedArrayBuffer): ctrl[0] bytes written by the tab, ctrl[1] bytes read here,
// ctrl[2] 1 = connection closed, ctrl[3] 1 = tab waits for space. Counters only grow.
import { readFileSync } from 'node:fs'
import { Fd, p8, pluginFiles, sandboxRoot, wasi } from './engine'
import wasmPath from './php2.wasm' with { type: 'file' }
import setupPath from './setup.php' with { type: 'file' }

declare const self: Worker

type Init = { ctrl: SharedArrayBuffer; data: SharedArrayBuffer; plugin: string; main: string }

const PREPARE_LINE = (main: string) => {
  const ser = `a:2:{i:0;s:7:"prepare";i:1;a:1:{s:4:"main";s:${Buffer.byteLength(main)}:"${main}";}}`
  return new Uint8Array(Buffer.from(Buffer.from(ser).toString('base64') + '\n'))
}
const PREPARED = Buffer.from('a:1:{i:0;s:8:"prepared";}').toString('base64')

class RingStdin extends Fd {
  local: Uint8Array[] = []
  constructor(private ctrl: Int32Array, private data: Uint8Array) { super() }
  fd_fdstat_get() { return { ret: 0, fdstat: new wasi.Fdstat(wasi.FILETYPE_CHARACTER_DEVICE, 0) } }
  fd_read(size: number) {
    const local = this.local.shift()
    if (local) {
      if (local.length > size) this.local.unshift(local.subarray(size))
      return { ret: 0, data: local.subarray(0, size) }
    }
    const { ctrl, data } = this
    for (;;) {
      const written = Atomics.load(ctrl, 0)
      const read = Atomics.load(ctrl, 1)
      if (written !== read) {
        const n = Math.min(size, written - read, data.length - (read % data.length))
        const start = read % data.length
        const out = data.slice(start, start + n)
        Atomics.store(ctrl, 1, read + n)
        if (Atomics.load(ctrl, 3)) self.postMessage({ type: 'drain' })
        return { ret: 0, data: out }
      }
      if (Atomics.load(ctrl, 2)) return { ret: 0, data: new Uint8Array() }
      Atomics.wait(ctrl, 0, written)
    }
  }
}

self.onmessage = (event: MessageEvent<Init>) => {
  const { plugin, main } = event.data
  const ctrl = new Int32Array(event.data.ctrl)
  const data = new Uint8Array(event.data.data)
  const engine = p8(new WebAssembly.Module(readFileSync(wasmPath)))
  const files = pluginFiles(plugin)
  const setup = readFileSync(setupPath)
  const prepare = PREPARE_LINE(main)
  for (;;) {
    const stdin = new RingStdin(ctrl, data)
    stdin.local.push(prepare)
    let pending = ''
    let prepared = false
    const message = (bytes: Uint8Array) => {
      if (prepared) { self.postMessage({ type: 'out', bytes }); return }
      // Until 'prepared', the messages are this slot's, not a request's.
      pending += Buffer.from(bytes).toString('utf8')
      let i
      while (!prepared && (i = pending.indexOf('\n')) >= 0) {
        const line = pending.slice(0, i)
        pending = pending.slice(i + 1)
        if (line === PREPARED) {
          prepared = true
          self.postMessage({ type: 'idle' })
          if (pending) self.postMessage({ type: 'out', bytes: Buffer.from(pending) })
        } else self.postMessage({ type: 'log', line })
      }
    }
    const audit = (e: Record<string, unknown>) => self.postMessage({ type: 'out', bytes: Buffer.from('#' + JSON.stringify(e) + '\n') })
    let status: number
    try {
      status = engine.run(sandboxRoot(files, setup), stdin, message, audit)
    } catch (error) {
      status = 1
      self.postMessage({ type: 'log', line: `instance failed: ${error instanceof Error ? error.message : String(error)}` })
    }
    self.postMessage({ type: 'done', status, prepared })
    if (!prepared) return // could not even prepare: let the tab see it and stop this slot
    Bun.gc(false)
  }
}
