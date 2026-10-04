#!/usr/bin/env node
/**
 * Inline the per-mode preset patches into the bundle patch.
 *
 * Why this exists
 * ---------------
 * `dsh plugin add <pkg>` applies the package's **own** patch layers and never
 * touches the operator's profile patch. The three modes must therefore ship inside
 * this bundle's patch, or a fresh install produces a plugin whose `f2x_*` tools
 * exist while the mode picker stays empty — with nothing on screen saying why.
 *
 * The natural way to express that is `dsh.bundle.patch` as an **array** of files
 * (DSH's loader explicitly supports it: `bundlePatchFiles()` accepts "one file for a
 * string `patch`, the listed files in order for an array"). The published
 * `dsh-plugin-guide` checker predates that support and crashes on an array
 * (`paths[1] must be of type string`), so this repository keeps `dsh.bundle.patch` a
 * single string and inlines the three files here instead.
 *
 * The per-mode files stay the authoring source: one ~250-line preset per file beats
 * an 800-line bundle patch. `tests/presets.test.ts` asserts the inlined region still
 * matches them, so the two cannot drift silently.
 *
 * Usage
 * -----
 *   node scripts/sync-presets.mjs           # rewrite the region
 *   node scripts/sync-presets.mjs --check   # exit 1 when it is already stale
 */

import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = join(fileURLToPath(new URL('.', import.meta.url)), '..')
const bundlePatch = join(packageRoot, 'cordis.patch.yml')

/** Directories scanned for preset patch files, in the order they are inlined. */
export const PRESET_DIRS = ['presets/dsh-0.2', 'presets/redteam-modes']

/**
 * Preset source files, in the order they are inlined.
 *
 * `presets/redteam-modes` holds modes ported from dsh-redteam-model; the directory is
 * absent until `scripts/port-redteam-modes.mjs` has run, which is why this is
 * discovered rather than hardcoded.
 */
export const PRESET_FILES = PRESET_DIRS.flatMap((dir) => {
  const abs = join(packageRoot, dir)
  if (!existsSync(abs)) return []
  return readdirSync(abs)
    .filter((entry) => entry.endsWith('.patch.yml'))
    .sort()
    .map((entry) => `${dir}/${entry}`)
})

/** Region markers. The sync script rewrites exactly what lies between them. */
export const BEGIN_MARKER =
  '# >>> f2x preset layers (generated from presets/dsh-0.2/*.patch.yml — run scripts/sync-presets.mjs) >>>'
export const END_MARKER = '# <<< f2x preset layers <<<'

/**
 * The `- insert:` item list of one per-mode patch file, re-indented for the bundle
 * patch's own top-level array.
 * @param relativePath - path of a `presets/dsh-0.2/*.patch.yml` file.
 * @returns the inner rows, without the file's leading comments or `- insert:` line.
 */
export function presetRows(relativePath) {
  const text = readFileSync(join(packageRoot, relativePath), 'utf8')
  const lines = text.split('\n')
  const start = lines.findIndex((line) => line.trim() === '- insert:')
  if (start < 0) throw new Error(`${relativePath}: no "- insert:" entry`)
  const body = lines.slice(start + 1)
  while (body.length > 0 && body[body.length - 1].trim() === '') body.pop()
  if (body.length === 0) throw new Error(`${relativePath}: "- insert:" entry is empty`)
  return body
}

/**
 * The exact text the region must hold.
 *
 * The rows are emitted under one `- insert:` entry of their own, so the bundle
 * patch ends up with two top-level patch entries: the plugin row and the presets.
 * A bare row list would not parse — every top-level item of a patch file must be a
 * patch entry.
 * @returns marker-delimited YAML, ending without a trailing newline.
 */
/**
 * Reject a duplicate preset row id across the whole set.
 *
 * Two patch files declaring the same row id do not merge — the later one wins and the
 * earlier preset simply never registers. The roster then lacks a mode with no error
 * anywhere, and any client still pointing at that id fails with
 * `agent-preset/not-found`. That is a silent, confusing failure, so it is refused here
 * rather than discovered later.
 */
function assertUniquePresetRowIds() {
  const seen = new Map()
  for (const file of PRESET_FILES) {
    for (const line of presetRows(file)) {
      // Only the direct children of `- insert:` — the preset rows. The plugin rows
      // nested inside a preset repeat freely across presets (`persona`, `tool-bash`, …)
      // and are scoped to their own preset.
      const match = /^ {4}- id: (\S+)\s*$/.exec(line)
      if (match === null) continue
      const previous = seen.get(match[1])
      if (previous !== undefined) {
        throw new Error(
          `duplicate preset row id "${match[1]}" in ${file} and ${previous} — ` +
            `the later declaration wins and the earlier preset never registers`,
        )
      }
      seen.set(match[1], file)
    }
  }
}

export function renderRegion() {
  assertUniquePresetRowIds()
  const parts = [BEGIN_MARKER, '- insert:']
  for (const file of PRESET_FILES) {
    parts.push(`    # from ${file}`)
    parts.push(...presetRows(file))
  }
  parts.push(END_MARKER)
  return parts.join('\n')
}

/** Replace the marked region in `cordis.patch.yml`. */
function rewrite({ check }) {
  const original = readFileSync(bundlePatch, 'utf8')
  const begin = original.indexOf(BEGIN_MARKER)
  const end = original.indexOf(END_MARKER)
  if (begin < 0 || end < 0) throw new Error(`cordis.patch.yml: region markers not found`)
  const next = original.slice(0, begin) + renderRegion() + original.slice(end + END_MARKER.length)
  if (next === original) {
    process.stdout.write('cordis.patch.yml: preset region already in sync\n')
    return 0
  }
  if (check) {
    process.stderr.write('cordis.patch.yml: preset region is STALE — run node scripts/sync-presets.mjs\n')
    return 1
  }
  writeFileSync(bundlePatch, next, 'utf8')
  process.stdout.write(`cordis.patch.yml: inlined ${String(PRESET_FILES.length)} preset layers\n`)
  return 0
}

// Only run when invoked directly; the test imports the exports above.
if (process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`) {
  process.exit(rewrite({ check: process.argv.includes('--check') }))
}
