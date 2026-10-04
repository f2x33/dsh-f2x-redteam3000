#!/usr/bin/env node
/**
 * Fail when a preset mounts fewer `redteam_*` tools than its own skills reference.
 *
 * Every mode except `rt-drill` mounts a subset of the 53 ledger tools
 * (`vendor/redteam-tools/lib/ledger.js`); this check re-derives, for every preset:
 *   · mounted  = tools the preset's plugin row actually registers
 *   · needed   = `redteam_*` names that appear in the SKILL.md files the mode can see
 * and fails when `needed` is not a subset of `mounted`.
 *
 * Usage: node scripts/check-tool-subsets.mjs
 */
import { readFileSync, existsSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = join(fileURLToPath(new URL('.', import.meta.url)), '..')
const TOOLS_ENTRY = join(packageRoot, 'vendor', 'redteam-tools', 'lib', 'index.js')
const LEDGER_ENTRY = join(packageRoot, 'vendor', 'redteam-tools', 'lib', 'ledger.js')

/** Every tool name the vendored package can register. */
function allToolNames() {
  const text = readFileSync(TOOLS_ENTRY, 'utf8')
  return new Set([...text.matchAll(/name: '(redteam_[a-z_]+)'/g)].map((m) => m[1]))
}

/** The subset `ledger.js` mounts. */
function ledgerToolNames() {
  if (!existsSync(LEDGER_ENTRY)) return new Set()
  const text = readFileSync(LEDGER_ENTRY, 'utf8')
  const block = /LEDGER_TOOLS = \[([\s\S]*?)\]/.exec(text)
  if (block === null) throw new Error('ledger.js: no LEDGER_TOOLS list')
  return new Set([...block[1].matchAll(/'(redteam_[a-z_]+)'/g)].map((m) => m[1]))
}

/** Every `*.patch.yml` preset source this package ships. */
function presetFiles() {
  const out = []
  for (const dir of ['presets/dsh-0.2', 'presets/redteam-modes']) {
    const abs = join(packageRoot, dir)
    if (!existsSync(abs)) continue
    for (const entry of readdirSync(abs)) {
      if (entry.endsWith('.patch.yml')) out.push(join(abs, entry))
    }
  }
  return out.sort()
}

/** SKILL.md files a mode sees: its own skills, shared skills, the package's, and vendored ones. */
function visibleSkillTexts(mode) {
  const roots = [
    join(packageRoot, 'presets', 'redteam-modes', mode, 'skills'),
    join(packageRoot, 'presets', 'redteam-modes', 'shared', 'skills'),
    join(packageRoot, 'skills'),
    join(packageRoot, 'vendor', 'redteam-skills'),
    join(packageRoot, 'vendor', 'reverse-skills'),
  ]
  const texts = []
  const walk = (dir) => {
    if (!existsSync(dir)) return
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const abs = join(dir, entry.name)
      if (entry.isDirectory()) walk(abs)
      else if (entry.name.endsWith('.md')) texts.push(readFileSync(abs, 'utf8'))
    }
  }
  for (const root of roots) walk(root)
  return texts
}

const all = allToolNames()
const ledger = ledgerToolNames()
let failures = 0

console.log(`tools: ${String(all.size)} available, ${String(ledger.size)} in the ledger subset\n`)

for (const file of presetFiles()) {
  const text = readFileSync(file, 'utf8')
  const mode = /^\s+id:\s*(\S+)\s*$/m.exec(text)?.[1] ?? '?'
  const mounted = text.includes('vendor/redteam-tools/lib/index.js')
    ? all
    : text.includes('vendor/redteam-tools/lib/ledger.js')
      ? ledger
      : new Set()
  const needed = new Set()
  for (const skill of visibleSkillTexts(mode)) {
    for (const name of all) if (skill.includes(name)) needed.add(name)
  }
  const missing = [...needed].filter((name) => !mounted.has(name))
  const ok = missing.length === 0
  if (!ok) failures += 1
  console.log(
    `${ok ? 'ok  ' : 'FAIL'} ${mode.padEnd(18)} mounted ${String(mounted.size).padStart(2)}` +
      ` | referenced ${String(needed.size).padStart(2)}` +
      (missing.length > 0 ? ` | MISSING: ${missing.join(', ')}` : ''),
  )
}

if (failures > 0) {
  console.error(`\n${String(failures)} preset(s) lost a tool their own skills reference.`)
  process.exit(1)
}
console.log('\nEvery referenced redteam_* tool is mounted by the preset that references it.')
