// securecore: runs one WordPress plugin inside php2.wasm (p8, wasm32-wasip1).
//
//   securecore <plugin-dir-or-file> <main-file>   run the plugin behind sandbox/setup.php
//
// stdin and stdout are the line to SecureCore.php in core. The wasm sees only:
//   /sandbox/setup.php   (embedded)
//   /plugin/...          the plugin's own folder, read-only
//   /tmp                 empty, in memory, gone when the process exits
// No environment variables, no wp-config.php, no network (WASI preview 1 has no sockets).
import { readFileSync, readdirSync, readSync, statSync, writeSync } from 'node:fs'
import { basename, join } from 'node:path'
import { ConsoleStdout, Directory, Fd, File, PreopenDirectory, WASI, wasi } from '@bjorn3/browser_wasi_shim'
import wasmPath from './php2.wasm' with { type: 'file' }
import setupPath from './setup.php' with { type: 'file' }

// Audit events from the binary itself go to core on the same line, marked with '#'.
function audit(event: Record<string, unknown>) {
  writeSync(1, '#' + JSON.stringify(event) + '\n')
}

// Paths the sandbox may see. Anything else does not exist; trying it is logged once PHP
// has started reading from core (before that it is p8's own startup looking for php.ini).
const VISIBLE = ['plugin', 'sandbox', 'tmp']
let started = false
function check(ret: number, path: string, op: string) {
  if (ret !== 0 && started && !VISIBLE.some((dir) => path === dir || path.startsWith(dir + '/'))) {
    audit({ event: 'fs.deny', op, path: '/' + path })
  }
}
class Root extends PreopenDirectory {
  path_open(dirflags: number, path: string, oflags: number, base: bigint, inheriting: bigint, flags: number) {
    const result = super.path_open(dirflags, path, oflags, base, inheriting, flags)
    check(result.ret, path, 'open')
    return result
  }
  path_filestat_get(flags: number, path: string) {
    const result = super.path_filestat_get(flags, path)
    check(result.ret, path, 'stat')
    return result
  }
}

// Blocking reads from the real stdin: PHP's fgets(STDIN) waits for core's next message.
class Stdin extends Fd {
  fd_fdstat_get() {
    return { ret: 0, fdstat: new wasi.Fdstat(wasi.FILETYPE_CHARACTER_DEVICE, 0) }
  }
  fd_filestat_get() {
    return { ret: 0, filestat: new wasi.Filestat(0n, wasi.FILETYPE_CHARACTER_DEVICE, 0n) }
  }
  fd_read(size: number) {
    started = true
    const buf = Buffer.alloc(size)
    for (;;) {
      try {
        const n = readSync(0, buf, 0, size, null)
        return { ret: 0, data: new Uint8Array(buf.buffer, buf.byteOffset, n) }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EAGAIN') continue
        if ((error as NodeJS.ErrnoException).code === 'EOF') return { ret: 0, data: new Uint8Array() }
        throw error
      }
    }
  }
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

const argv = process.argv.slice(2)
const [pluginDir, mainFile] = argv
if (!pluginDir || !mainFile) {
  writeSync(2, 'usage: securecore <plugin-dir-or-file> <main-file>\n')
  process.exit(2)
}

// A single-file plugin (hello.php) is mounted alone; a plugin folder is mounted whole.
const plugin = statSync(pluginDir).isDirectory()
  ? load(pluginDir)
  : new Directory([[basename(pluginDir), new File(readFileSync(pluginDir), { readonly: true })]])

const root = new Directory([
  ['sandbox', new Directory([['setup.php', new File(readFileSync(setupPath), { readonly: true })]])],
  ['plugin', plugin],
  ['tmp', new Directory([])],
])

const module = await WebAssembly.compile(readFileSync(wasmPath))
const args = ['php2', '-d', 'display_errors=0', '-d', 'log_errors=0', '-d', 'date.timezone=UTC', '/sandbox/setup.php', `/plugin/${mainFile}`]
// The sandbox's stdout (fd 1) is diagnostics only and goes to our stderr. Its stderr (fd 2)
// carries the messages and goes to our stdout, the line core reads. See setup.php.
const runtime = new WASI(args, [], [
  new Stdin(),
  new ConsoleStdout((bytes) => { writeSync(2, bytes) }),
  new ConsoleStdout((bytes) => { writeSync(1, bytes) }),
  new Root('/', root.contents),
], { debug: false })
const instance = await WebAssembly.instantiate(module, { wasi_snapshot_preview1: runtime.wasiImport })
let status = 0
try {
  status = runtime.start(instance as { exports: { memory: WebAssembly.Memory; _start: () => unknown } })
} catch (error) {
  writeSync(2, `securecore: ${error instanceof Error ? error.message : String(error)}\n`)
  status = 1
}
process.exit(status)
