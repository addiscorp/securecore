// What every sandbox shares, whatever runs the PHP: the file tree it may see, the audit of
// paths it tried outside that tree, and how one instance runs. The engine is a parameter;
// today the only one is p8 (php2.wasm, wasm32-wasip1).
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
  run(root: Directory, stdin: Fd, message: (bytes: Uint8Array) => void, audit: (event: Record<string, unknown>) => void): number
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
