// Fetch php2.wasm (p8 built for wasm32-wasip1, the build addiscorp/p8-wordpress serves)
// into sandbox/ and check it against the pinned hash. Not committed: 24 MB.
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'

const URL = 'https://p8-wordpress.addis.gg/php2.wasm'
const SHA256 = '4609a584d96867cd82cb53962bc435f3526e973254e9d8ac9b761a0b946552cf'
const OUT = new globalThis.URL('../sandbox/php2.wasm', import.meta.url).pathname

const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex')

if (existsSync(OUT) && hash(readFileSync(OUT)) === SHA256) {
  console.log(`sandbox/php2.wasm is current (${SHA256.slice(0, 12)})`)
  process.exit(0)
}
const response = await fetch(URL)
if (!response.ok) throw new Error(`${URL}: HTTP ${response.status}`)
const bytes = new Uint8Array(await response.arrayBuffer())
const got = hash(bytes)
if (got !== SHA256) throw new Error(`${URL}: sha256 ${got}, expected ${SHA256}`)
writeFileSync(OUT, bytes)
console.log(`sandbox/php2.wasm ${bytes.length} bytes, sha256 ${SHA256.slice(0, 12)}`)
