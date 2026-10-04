#!/usr/bin/env node
/**
 * Skill provenance: which of our skill/knowledge files actually came from upstream?
 *
 * Written because "I think I wrote that" is not a licence statement. The author could not
 * remember whether two vendored skill collections were his own or copied, and guessing
 * either way is worse than checking: a false claim of authorship is a licence violation,
 * and a false claim of copying throws away work.
 *
 * Method: index every `SKILL.md` under a set of upstream checkouts by directory name, then
 * compare SHA-256 against every `SKILL.md` this project ships. A byte-identical pair is a
 * copy; a name that does not exist upstream cannot have been copied from there.
 *
 * What it cannot do: prove authorship of something that exists nowhere else. That is the
 * strongest evidence available without a git history, and it is what the notices cite.
 *
 * Usage:
 *   node scripts/skill-provenance.mjs [--upstream <dir> ...]
 *   node scripts/skill-provenance.mjs --upstream ~/src/dsh-redteam-model
 */

import { createHash } from 'node:crypto'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { basename, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..')

/** Default upstream checkouts to compare against; overridable with --upstream. */
const DEFAULT_UPSTREAMS = []
// No author-machine defaults: name your upstream checkouts explicitly, e.g.
//   node scripts/skill-provenance.mjs --upstream ~/src/dsh-redteam-model
// (scripts/provenance-content.mjs is the maintained content-wide comparator.)

const argv = process.argv.slice(2)
const upstreams = []
for (let index = 0; index < argv.length; index += 1) {
  if (argv[index] === '--upstream' && argv[index + 1] !== undefined) upstreams.push(argv[index + 1])
}
const candidates = upstreams.length > 0 ? upstreams : DEFAULT_UPSTREAMS
const present = candidates.filter((dir) => existsSync(dir))
if (present.length === 0) {
  process.stdout.write(`no upstream checkout found (looked for: ${candidates.join(', ')})\n`)
  process.stdout.write('pass --upstream <dir> to name one; without it this comparison cannot run.\n')
  process.exit(0)
}

/** Every SKILL.md under `dir`, keyed by its parent directory name. */
function index(dir) {
  const found = new Map()
  const walk = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue
      const full = join(path, entry.name)
      if (entry.isDirectory()) { walk(full); continue }
      if (entry.name !== 'SKILL.md') continue
      const key = basename(path)
      if (!found.has(key)) found.set(key, full)
    }
  }
  walk(dir)
  return found
}

const upstreamIndex = new Map()
for (const dir of present) {
  for (const [name, path] of index(dir)) if (!upstreamIndex.has(name)) upstreamIndex.set(name, { path, dir })
}

const ours = index(root)
const digest = (path) => createHash('sha256').update(readFileSync(path)).digest('hex')

const copied = []
const modified = []
const own = []
for (const [name, path] of [...ours.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
  const hit = upstreamIndex.get(name)
  if (hit === undefined) { own.push([name, path]); continue }
  if (digest(path) === digest(hit.path)) copied.push([name, path, hit.dir])
  else modified.push([name, path, hit.dir])
}

const line = (label, rows) => {
  console.log(`\n${label}: ${String(rows.length)}`)
  for (const [name, path, dir] of rows) {
    console.log(`  ${name.padEnd(40)} ${relative(root, path)}${dir === undefined ? '' : `  ← ${dir}`}`)
  }
}
console.log(`our SKILL.md count: ${String(ours.size)} | upstream checkouts: ${present.join(', ')}`)
console.log(`upstream SKILL.md names: ${String(upstreamIndex.size)}`)
line('COPIED byte-for-byte from an upstream (keep its licence notice)', copied)
line('MODIFIED from an upstream (state the changes)', modified)
line('not present upstream (strongest available evidence of first-party)', own)

console.log('\nsummary:')
console.log(`  copied=${String(copied.length)} modified=${String(modified.length)} own=${String(own.length)}`)
console.log('  Content under vendor/ or skills/ that lands in COPIED must carry the upstream')
console.log('  licence text; see THIRD-PARTY-NOTICES.md §1.5 for how that is documented.')
