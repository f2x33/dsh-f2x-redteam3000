#!/usr/bin/env node
/**
 * Provenance coverage audit.
 *
 * A licence notice that covers *most* of what you ship is worse than none: it reads as
 * "checked", while the uncovered remainder is exactly where the unlicensed copy hides.
 * This walks everything `package.json#files` puts in the tarball and reports, per top
 * level path, how much of it is covered by a statement in THIRD-PARTY-NOTICES.md, so the
 * gaps are visible instead of assumed away.
 *
 * It cannot tell you whether a statement is TRUE — only whether a path is mentioned.
 * Truth is verified by reading the files; this stops the silent-omission failure mode.
 *
 * Usage: node scripts/provenance-audit.mjs
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..')
const notices = readFileSync(join(root, 'THIRD-PARTY-NOTICES.md'), 'utf8')
const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))

const count = (dir) => {
  let files = 0
  let bytes = 0
  const walk = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const full = join(path, entry.name)
      if (entry.isDirectory()) walk(full)
      else {
        files += 1
        bytes += statSync(full).size
      }
    }
  }
  walk(dir)
  return { files, bytes }
}

const rows = []
for (const entry of manifest.files ?? []) {
  const target = join(root, entry)
  const info = statSync(target, { throwIfNoEntry: false })
  if (info === undefined) {
    rows.push({ entry, files: 0, mb: 0, covered: false, note: 'declared but missing' })
    continue
  }
  const { files, bytes } = info.isDirectory() ? count(target) : { files: 1, bytes: info.size }
  // Coverage: the notice names this path, or names a subdirectory/file of it.
  const escaped = entry.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const covered = new RegExp(`(?:^|[\\s\`(/])${escaped}(?:$|[\\s\`)/])`, 'm').test(notices)
  rows.push({ entry, files, mb: bytes / 1048576, covered, note: '' })
}

const total = rows.reduce((sum, row) => sum + row.files, 0)
const uncovered = rows.filter((row) => !row.covered)
console.log(`${'path'.padEnd(24)}${'files'.padStart(7)}${'MB'.padStart(8)}  covered by notice`)
for (const row of rows.sort((a, b) => b.files - a.files)) {
  console.log(`${row.entry.padEnd(24)}${String(row.files).padStart(7)}${row.mb.toFixed(2).padStart(8)}  ${row.covered ? 'yes' : 'NO'}${row.note === '' ? '' : ` (${row.note})`}`)
}
console.log(`\ntotal files in the package: ${String(total)}`)
if (uncovered.length > 0) {
  console.log(`\nNOT covered by any statement in THIRD-PARTY-NOTICES.md (${String(uncovered.length)}):`)
  for (const row of uncovered) console.log(`  - ${row.entry} (${String(row.files)} files)`)
  process.exit(1)
}
console.log('every shipped path is named in THIRD-PARTY-NOTICES.md')
