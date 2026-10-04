#!/usr/bin/env node
/**
 * Content provenance: which files in this package are byte-identical to an upstream project?
 *
 * Why this replaced a name-based comparison
 * -----------------------------------------
 * The first version of this script indexed upstream files by their **directory name** and
 * compared `SKILL.md` against `SKILL.md`. The port renamed things on the way in
 * (`modes/x/skills/reverse-engineering/references/languages.md` became
 * `vendor/reverse-skills/reverse-engineering/languages.md`), so nothing matched and the script
 * reported "zero byte-identical files" for a tree that in fact contained 136 of them. A
 * provenance check that reports the comfortable answer is worse than none: it was quoted in the
 * licence notices as fact.
 *
 * This version compares **content hashes across the whole tree**, which is name-independent.
 * It answers one question honestly: is this file the same bytes as some file upstream?
 *
 * What it cannot do: decide *direction*. If two projects both contain a file, the comparison
 * says they are identical, not who wrote it first. When direction matters and no upstream clone
 * is available, keep both attributions (see THIRD-PARTY-NOTICES.md §1.4).
 *
 * Usage:
 *   node scripts/provenance-content.mjs                       # default upstreams below
 *   node scripts/provenance-content.mjs --upstream /path/to/upstream [...]
 *   node scripts/provenance-content.mjs --zone vendor/reverse-skills
 */

import { createHash } from 'node:crypto'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..')
const argv = process.argv.slice(2)
const upstreams = []
let zone
for (let index = 0; index < argv.length; index += 1) {
  if (argv[index] === '--upstream' && argv[index + 1] !== undefined) upstreams.push(argv[index + 1])
  if (argv[index] === '--zone' && argv[index + 1] !== undefined) zone = argv[index + 1]
}
const candidates = upstreams.length > 0 ? upstreams : []
// No author-machine defaults on purpose: pass --upstream <dir> so the comparison is explicit.
const present = candidates.filter((dir) => existsSync(dir))

/** SHA-256 by content, ignoring empty files and build/VCS noise. */
function index(dir) {
  const byHash = new Map()
  const walk = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'audit') continue
      const full = join(path, entry.name)
      if (entry.isDirectory()) { walk(full); continue }
      if (!entry.isFile()) continue
      const bytes = readFileSync(full)
      if (bytes.toString('utf8').trim() === '') continue
      const hash = createHash('sha256').update(bytes).digest('hex')
      if (!byHash.has(hash)) byHash.set(hash, relative(dir, full))
    }
  }
  walk(dir)
  return byHash
}

if (present.length === 0) {
  process.stdout.write(`no upstream checkout found (looked for: ${candidates.join(', ')})\n`)
  process.stdout.write('pass --upstream <dir>; without one this comparison cannot run.\n')
  process.exit(0)
}

const upstream = new Map()
for (const dir of present) {
  for (const [hash, path] of index(dir)) if (!upstream.has(hash)) upstream.set(hash, { path, dir })
}
process.stdout.write(`upstream files indexed: ${String(upstream.size)} (from ${present.join(', ')})\n\n`)

/** Zones to report on: each is a path in this package. */
const ZONES = zone === undefined
  ? ['vendor/redteam-skills', 'vendor/reverse-skills', 'skills', 'presets/redteam-modes', 'refs/power', 'persona', 'playbook']
  : [zone]

let totalCopied = 0
for (const zonePath of ZONES) {
  const dir = join(root, zonePath)
  if (!existsSync(dir)) { process.stdout.write(`${zonePath}: (absent)\n`); continue }
  const files = []
  const walk = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue
      const full = join(path, entry.name)
      if (entry.isDirectory()) { walk(full); continue }
      if (!entry.isFile()) continue
      if (readFileSync(full).toString('utf8').trim() === '') continue
      files.push(full)
    }
  }
  walk(dir)
  const copied = []
  for (const file of files) {
    const hash = createHash('sha256').update(readFileSync(file)).digest('hex')
    const hit = upstream.get(hash)
    if (hit !== undefined) copied.push([relative(root, file), hit])
  }
  totalCopied += copied.length
  const share = files.length === 0 ? '0' : ((copied.length / files.length) * 100).toFixed(0)
  process.stdout.write(`${zonePath}: ${String(copied.length)}/${String(files.length)} byte-identical to upstream (${share}%)\n`)
  const byExtension = new Map()
  for (const [path] of copied) {
    const match = /\.([a-z0-9]+)$/i.exec(path)
    const extension = match === null ? '(none)' : `.${match[1]}`
    byExtension.set(extension, (byExtension.get(extension) ?? 0) + 1)
  }
  if (copied.length > 0) {
    process.stdout.write(`  by type: ${[...byExtension.entries()].map(([k, v]) => `${k}=${String(v)}`).join(' ')}\n`)
    for (const [path, hit] of copied.slice(0, 3)) process.stdout.write(`  e.g. ${path}  ←  ${hit.path}\n`)
    // Executable content is worth calling out: a copied script is not the same kind of
    // redistribution as a copied paragraph.
    const scripts = copied.filter(([path]) => /\.(sh|ps1|py|js|mjs)$/i.test(path))
    if (scripts.length > 0) {
      process.stdout.write(`  NOTE: ${String(scripts.length)} of them are executables — check them, a copied script is redistributed code\n`)
      for (const [path] of scripts.slice(0, 5)) process.stdout.write(`      ${path}\n`)
    }
  }
}
process.stdout.write(`\nTotal byte-identical files across zones: ${String(totalCopied)}\n`)
process.stdout.write('Identical content does not establish direction: when no upstream clone exists, keep both attributions.\n')
