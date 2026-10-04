#!/usr/bin/env node
/**
 * Verify that every agent preset this plugin ships actually mounts.
 *
 * Why this exists
 * ---------------
 * DSH marks a preset `broken` when *any* row in its `plugins:` list fails to
 * mount, and the Web UI's mode selector silently filters broken presets out
 * (`presetOptions()` drops `preset.broken !== undefined`). A preset whose row
 * omits a schema-required config key therefore disappears from the picker with
 * no visible error in the browser — the exact failure this plugin hit when
 * `tool-fs-search` (required `sampleOverCapGlobResults`) and `tool-todo`
 * (required `allowParallelInProgress`) were declared bare.
 *
 * The roster read below is the same call the UI makes, so a green run here means
 * the modes are selectable.
 *
 * Usage
 * -----
 *   node scripts/verify-presets.mjs [profile]
 *
 * Exits 0 when every `f2x-*` preset is healthy, 1 otherwise. Override the DSH
 * installation location with `DSH_INSTALL` when it is not the default.
 */

import { createRequire } from 'node:module'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { zstdDecompressSync } from 'node:zlib'
import { MODES as PORTED_MODES } from './port-redteam-modes.mjs'
import { PRESET_ID as DRILL_PRESET } from './port-redteam-mode-preset.mjs'

const DEFAULT_INSTALL = '/usr/lib/node_modules/@deepseek-ai/dsh'

/** Prefix of the presets this plugin authors directly. */
const OWN_PREFIX = 'f2x-'

/**
 * Whether a roster row is one of this plugin's presets.
 *
 * Two families: the directly authored `f2x-*` modes, and the modes ported from
 * dsh-redteam-model, which keep their upstream ids (`redteam`, `pentest`, …). Checking
 * only the prefix would leave the ten ported modes unguarded — and a preset whose rows
 * fail to mount is silently dropped from the UI picker, which is exactly the failure
 * this script exists to catch.
 */
function isOwnPreset(id) {
  return id.startsWith(OWN_PREFIX) || PORTED_MODES.includes(id) || id === DRILL_PRESET
}

/** Locate the DSH installation that provides `@deepseek-ai/dsh-app-boot`. */
function findInstall() {
  const candidates = [process.env.DSH_INSTALL, DEFAULT_INSTALL].filter(
    (entry) => typeof entry === 'string' && entry !== '',
  )
  for (const candidate of candidates) {
    if (existsSync(join(candidate, 'package.json'))) return candidate
  }
  throw new Error(
    `cannot find the DSH installation; set DSH_INSTALL to the directory holding @deepseek-ai/dsh (tried: ${candidates.join(', ')})`,
  )
}

const install = findInstall()
const require = createRequire(join(install, 'package.json'))
const profile = process.argv[2] ?? 'web'

const { loadLayeredEnv } = await import(require.resolve('@deepseek-ai/dsh-app-boot'))
const { runProfile } = await import(join(install, 'lib/profile-boot.js'))

// Port 0 lets the OS pick a free port, so verification never collides with a
// running `dsh web`.
const { ctx } = await runProfile({
  environment: loadLayeredEnv('dsh'),
  profile,
  patchFiles: [],
  args: ['--port', '0', '--no-open'],
})

let roster
try {
  roster = await ctx.agentPresets.list()
} catch (error) {
  console.error(`could not read the agent-preset roster: ${error?.message ?? error}`)
  process.exit(1)
}

const own = roster.filter((preset) => isOwnPreset(preset.id))
if (own.length === 0) {
  console.error(`none of this plugin's presets are registered in profile "${profile}" — is the patch applied?`)
  process.exit(1)
}

console.log(`profile "${profile}" — ${String(roster.length)} presets, ${String(own.length)} owned by this plugin:\n`)
for (const preset of roster) {
  const owned = isOwnPreset(preset.id)
  const state = preset.broken === undefined ? 'OK    ' : 'BROKEN'
  if (!owned && preset.broken === undefined) continue
  console.log(`  ${state} ${preset.id}${preset.name === undefined ? '' : ` — ${preset.name}`}`)
  if (preset.broken !== undefined) {
    for (const line of String(preset.broken).split('\n')) console.log(`           ${line}`)
  }
}

const broken = own.filter((preset) => preset.broken !== undefined)
console.log()
if (broken.length > 0) {
  console.error(`${String(broken.length)} of ${String(own.length)} preset(s) are broken and will NOT appear in the UI mode picker.`)
  process.exit(1)
}

/**
 * Preset ids that existing sessions recorded but the roster no longer offers.
 *
 * Removing a preset does not remove the references to it. A session records the preset
 * it was created with, and the browser separately remembers the operator's last choice;
 * either one going stale turns creating or opening a session into
 * `agent-preset/not-found: Unknown agent preset: <id>`, with nothing on screen pointing
 * at the cause. This scans the session store so a removal is caught here instead.
 *
 * The browser-side memory cannot be reached from the server, so a clean result here is
 * necessary but not sufficient — see the note printed below.
 */
function danglingSessionPresets(roster, sessionsRoot) {
  if (!existsSync(sessionsRoot)) return []
  const known = new Set(roster.map((preset) => preset.id))
  const dangling = new Map()
  let zstd
  for (const workspace of readdirSync(sessionsRoot)) {
    const workspacePath = join(sessionsRoot, workspace)
    let sessions
    try {
      sessions = readdirSync(workspacePath)
    } catch {
      continue
    }
    for (const session of sessions) {
      const log = join(workspacePath, session, 'session.v4.jsonl.zstd')
      if (!existsSync(log)) continue
      try {
        zstd ??= zstdDecompressSync
        const header = JSON.parse(
          zstd(readFileSync(log)).toString('utf8').split('\n')[0],
        )
        const id = header.agentPreset
        if (typeof id !== 'string' || id === '' || known.has(id)) continue
        dangling.set(id, [...(dangling.get(id) ?? []), session])
      } catch {
        // An unreadable or non-zstd log is not this check's business.
      }
    }
  }
  return [...dangling]
}

const sessionsRoot = join(process.env.DSH_HOME ?? join(homedir(), '.dsh'), 'sessions')
const dangling = danglingSessionPresets(roster, sessionsRoot)
if (dangling.length > 0) {
  console.error('sessions reference presets the roster no longer offers:')
  for (const [id, sessions] of dangling) {
    console.error(`  ${id} — ${String(sessions.length)} session(s), e.g. ${sessions[0]}`)
  }
  console.error('those sessions cannot be opened or forked; re-add the preset or repoint them.')
  process.exit(1)
}

console.log(`all ${String(own.length)} preset(s) mount cleanly and are selectable.`)
console.log('note: the browser also remembers the operator\'s last mode choice; after removing a')
console.log('      preset, pick a mode again in Settings or new sessions will fail with not-found.')
process.exit(0)
