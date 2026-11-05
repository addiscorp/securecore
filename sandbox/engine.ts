// What every sandbox shares, whatever runs the PHP: the file tree it may see, the audit of
// paths it tried outside that tree, and how one instance runs. The engine is a parameter;
// p8 (php2.wasm, wasm32-wasip1) or stock PHP 8.3 built by WordPress Playground (@php-wasm,
// Emscripten). The native engine (a php CLI process, not a sandbox) lives in securecore.ts.
//
// The sandbox sees only:
//   /sandbox/setup.php   (embedded)
//   /plugin/...          the plugin's own folder, read-only
//   /tmp                 empty, in memory, gone with the instance
// No environment variables, no wp-config.php, no network (WASI preview 1 has no sockets).
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { basename, join } from 'node:path'
import { ConsoleStdout, Directory, Fd, File, PreopenDirectory, WASI, WASIProcExit, wasi } from '@bjorn3/browser_wasi_shim'

export { Fd, wasi }

export type Engine = {
  name: string
  // Run one instance to completion. stdin is read by PHP's fgets(STDIN); `message` gets
  // every byte the sandbox writes on the message channel. Returns the exit status.
  run(root: Directory, stdin: Fd, message: (bytes: Uint8Array) => void, audit: (event: Record<string, unknown>) => void): number | Promise<number>
}

// The first message every instance gets, before a request: which file is the plugin and
// what to scan for the functions it calls (see setup.php).
export function prepareLine(main: string, scan: string): Uint8Array {
  const s = (v: string) => `s:${Buffer.byteLength(v)}:"${v}";`
  const ser = `a:2:{i:0;${s('prepare')}i:1;a:2:{${s('main')}${s(main)}${s('scan')}${s(scan)}}}`
  return new Uint8Array(Buffer.from(Buffer.from(ser).toString('base64') + '\n'))
}

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

// The plugin's files are read once per process. Each instance gets its own tree around
// them, so one request's /tmp never reaches the next.
export function pluginFiles(pluginPath: string): Directory {
  return statSync(pluginPath).isDirectory()
    ? load(pluginPath)
    : new Directory([[basename(pluginPath), new File(readFileSync(pluginPath), { readonly: true })]])
}

export function sandboxRoot(plugin: Directory, setup: Uint8Array): Directory {
  return new Directory([
    ['sandbox', new Directory([['setup.php', new File(setup, { readonly: true })]])],
    ['plugin', new Directory(plugin.contents)],
    ['tmp', new Directory([])],
  ])
}

const VISIBLE = ['plugin', 'sandbox', 'tmp']

// Logs a failed lookup outside the visible tree, once PHP has started reading messages
// (before that it is p8's own startup looking for php.ini).
class Root extends PreopenDirectory {
  started = false
  constructor(contents: Map<string, File | Directory>, private audit: (event: Record<string, unknown>) => void) {
    super('/', contents)
  }
  private check(ret: number, path: string, op: string) {
    if (ret !== 0 && this.started && !VISIBLE.some((dir) => path === dir || path.startsWith(dir + '/'))) {
      this.audit({ event: 'fs.deny', op, path: '/' + path })
    }
  }
  path_open(dirflags: number, path: string, oflags: number, base: bigint, inheriting: bigint, flags: number) {
    const result = super.path_open(dirflags, path, oflags, base, inheriting, flags)
    this.check(result.ret, path, 'open')
    return result
  }
  path_filestat_get(flags: number, path: string) {
    const result = super.path_filestat_get(flags, path)
    this.check(result.ret, path, 'stat')
    return result
  }
}

// Marks the tree as started on the first read, then delegates.
class Watched extends Fd {
  constructor(private inner: Fd, private root: Root) { super() }
  fd_fdstat_get() { return { ret: 0, fdstat: new wasi.Fdstat(wasi.FILETYPE_CHARACTER_DEVICE, 0) } }
  fd_filestat_get() { return { ret: 0, filestat: new wasi.Filestat(0n, wasi.FILETYPE_CHARACTER_DEVICE, 0n) } }
  fd_read(size: number) {
    this.root.started = true
    return this.inner.fd_read(size)
  }
}

export function p8(module: WebAssembly.Module): Engine {
  return {
    name: 'p8',
    run(root, stdin, message, audit) {
      const tree = new Root(root.contents, audit)
      // PHP's stdout (fd 1) is diagnostics only. Its stderr (fd 2) carries the messages:
      // p8 keeps stdout buffered until exit, stderr writes through. See setup.php.
      const runtime = new WASI(['php2', '-d', 'display_errors=0', '-d', 'log_errors=0', '-d', 'date.timezone=UTC', '/sandbox/setup.php'], [], [
        new Watched(stdin, tree),
        new ConsoleStdout(() => {}),
        new ConsoleStdout(message),
        tree,
      ], { debug: false })
      const instance = new WebAssembly.Instance(module, { wasi_snapshot_preview1: runtime.wasiImport })
      try {
        return runtime.start(instance as unknown as { exports: { memory: WebAssembly.Memory; _start: () => unknown } })
      } catch (error) {
        if (error instanceof WASIProcExit) return error.code
        throw error
      }
    },
  }
}

// --- stock PHP, WordPress Playground's build ---------------------------------------------
// The Emscripten loader from @php-wasm/node-8-3 (asyncify variant), driven directly: no
// @php-wasm/universal request handling. Same isolation as p8, made the Emscripten way:
//   files    MEMFS only (the loader mounts nothing from the host); we write the same tree
//   env      ENV = {} (Emscripten adds its fixed defaults: USER=web_user, HOME, PATH=/)
//   network  Emscripten sockets would open a WebSocket to the target; websocket.url throws,
//            so every connect fails and is logged
type Emscripten = {
  FS: {
    mkdirTree(path: string): void
    writeFile(path: string, data: Uint8Array): void
    open: (path: string, flags: unknown, mode?: unknown) => unknown
    streams: { stream_ops: Record<string, unknown> }[]
  }
  ccall(name: string, ret: string | null, types: string[], args: unknown[], opts?: { async: boolean }): unknown
}
type Loader = { init(runtime: string, module: Record<string, unknown>): Emscripten }

function write(FS: Emscripten['FS'], dir: Directory, path: string) {
  FS.mkdirTree(path)
  for (const [name, node] of dir.contents) {
    if (node instanceof Directory) write(FS, node, `${path}/${name}`)
    else if (node instanceof File) FS.writeFile(`${path}/${name}`, node.data)
  }
}

export function phpWasm(loader: Loader, module: WebAssembly.Module): Engine {
  return {
    name: 'php-wasm',
    async run(root, stdin, message, audit) {
      let started = false
      let initialized: () => void = () => {}
      const ready = new Promise<void>((resolve) => { initialized = resolve })
      const php = loader.init('NODE', {
        noInitialRun: true,
        ENV: {},
        locateFile: (path: string) => path,
        instantiateWasm(imports: WebAssembly.Imports, done: (i: WebAssembly.Instance, m: WebAssembly.Module) => void) {
          const instance = new WebAssembly.Instance(module, imports)
          done(instance, module)
          return instance.exports
        },
        // Replaced below by a read that returns what has arrived; see the stdin stream.
        stdin: () => null,
        // STDERR carries the messages (same as p8; see setup.php); STDOUT is dropped. The
        // php-wasm SAPI hands both over in chunks through these hooks.
        onStdout() {},
        onStderr(chunk: Uint8Array | string) {
          message(typeof chunk === 'string' ? new Uint8Array(Buffer.from(chunk)) : new Uint8Array(chunk))
        },
        print() {},
        printErr() {},
        websocket: {
          url: (...args: unknown[]) => {
            // Called as (socket, host, port).
            audit({ event: 'net.deny', target: args.slice(1).map(String).join(':') })
            throw new Error('no network in the sandbox')
          },
        },
        onRuntimeInitialized: () => initialized(),
      })
      await ready
      const FS = php.FS
      // fgets(STDIN) reads 8 KiB at a time; Emscripten's stdin device would wait for all of
      // it, byte by byte. Like a pipe, return what has arrived (blocking only when nothing
      // has), and 0 at end of input.
      let input = new Uint8Array()
      let at = 0
      FS.streams[0].stream_ops = {
        ...FS.streams[0].stream_ops,
        read(_stream: unknown, buffer: Uint8Array, offset: number, length: number) {
          started = true
          if (at >= input.length) {
            const { data } = stdin.fd_read(65536) as { data: Uint8Array }
            if (data.length === 0) return 0
            input = data
            at = 0
          }
          const n = Math.min(length, input.length - at)
          buffer.set(input.subarray(at, at + n), offset)
          at += n
          return n
        },
      }
      for (const [name, node] of root.contents) if (node instanceof Directory) write(FS, node, `/${name}`)
      // Same path audit as p8: a failed open outside the visible tree is logged.
      const open = FS.open
      FS.open = (path: string, flags: unknown, mode?: unknown) => {
        try {
          return open(path, flags, mode)
        } catch (error) {
          const p = String(path)
          if (started && !VISIBLE.some((dir) => p === `/${dir}` || p.startsWith(`/${dir}/`))) audit({ event: 'fs.deny', op: 'open', path: p })
          throw error
        }
      }
      for (const arg of ['php', '-d', 'display_errors=0', '-d', 'log_errors=0', '-d', 'date.timezone=UTC', '/sandbox/setup.php']) {
        php.ccall('wasm_add_cli_arg', null, ['string'], [arg])
      }
      try {
        const status = await php.ccall('run_cli', 'number', [], [], { async: true })
        return typeof status === 'number' ? status : 0
      } catch (error) {
        const status = (error as { status?: number }).status
        if (typeof status === 'number') return status
        throw error
      }
    },
  }
}
