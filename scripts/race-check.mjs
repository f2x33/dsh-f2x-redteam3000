#!/usr/bin/env node
/**
 * Cross-process concurrency check for the engagement ledger.
 *
 * Why this exists as a shipped script
 * -----------------------------------
 * Two audit rounds reported lost records when several processes shared one `stateDir`
 * (28–30 of 60). The in-process promise chain does not help there: each process reads the file,
 * mutates its own copy, and renames — last writer wins. The fix is a lock file taken around the
 * whole read-modify-write. This script is the evidence that the fix holds, and the way to notice
 * if it stops holding.
 *
 * It spawns N writer processes against ONE state directory and counts both the expected records
 * and the ids: a duplicate id means two writers minted the same serial, which is the same bug
 * wearing a different hat.
 *
 * Usage:
 *   node scripts/race-check.mjs                 # 3 processes x 20 records
 *   node scripts/race-check.mjs 4 25            # processes, records each
 *   AUDIT_ENTRY=../../src/index.ts node scripts/race-check.mjs   # run against the sources
 */

import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, existsSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = fileURLToPath(new URL('.', import.meta.url))
const [processCount = '3', perProcess = '20'] = process.argv.slice(2)
const processes = Number(processCount)
const per = Number(perProcess)
const stateDir = mkdtempSync(join(tmpdir(), 'f2x-race-'))

/** The child: boot the real plugin, open one task, then write `per` audit records concurrently. */
// String.raw keeps the child's \n escapes intact: a plain template literal turns them into real
// newlines, which produced a child script that could not be parsed.
const childSource = String.raw`
try {
// Self-contained: no dependency on the audit/ directory (which is not shipped) and no
// assumption about where the peer packages live — they are resolved from this package first,
// then from the dsh installation, exactly as a deployment would find them.
const { createRequire } = await import('node:module')
const { join: j } = await import('node:path')
const { pathToFileURL } = await import('node:url')
const { existsSync } = await import('node:fs')
const pkgDir = j(pathToFileURL(process.env.F2X_PKG_ROOT ?? ${JSON.stringify(join(here, '..'))}).href.replace('file://', ''))
const dshInstall = process.env.DSH_INSTALL ?? '/usr/lib/node_modules/@deepseek-ai/dsh'
// Peer resolution order: this package's own node_modules, the dsh installation's, then the
// global node_modules next to it. An unpacked tarball has none of its own — which is why this
// tries several bases instead of assuming one.
const bases = [
  pkgDir,
  dshInstall,
  j(dshInstall, '..'),
  j(dshInstall, '..', '..'),
  '/usr/lib/node_modules',
  '/usr/local/lib/node_modules',
]
const loadPeer = async (name) => {
  const libJs = j('lib', 'index.js')
  for (const base of bases) {
    try {
      const viaRequire = createRequire(j(base, 'package.json')).resolve(name + '/package.json')
      const dir = j(viaRequire, '..')
      if (existsSync(j(dir, libJs))) return await import(pathToFileURL(j(dir, libJs)).href)
    } catch { /* try the next base */ }
    const direct = j(base, 'node_modules', name, libJs)
    if (existsSync(direct)) return await import(pathToFileURL(direct).href)
  }
  throw new Error('cannot resolve peer ' + name + ' from ' + bases.join(', '))
}
const mod = await import(pathToFileURL(j(pkgDir, 'lib', 'index.mjs')).href)
const { Context } = await loadPeer('@deepseek-ai/cordis')
const { ToolRuntime } = await loadPeer('@deepseek-ai/dsh-tools')
const { SkillRegistry } = await loadPeer('@deepseek-ai/dsh-skill')
const [stateDir, prefix, per] = process.argv.slice(2)
const ctx = new Context()
ctx.systemPrompt = { tools: () => () => {} }
ctx.tools = new ToolRuntime(ctx)
ctx.skills = new SkillRegistry(ctx)
ctx.logger = new Proxy({}, { get: () => () => {} })
mod.apply(ctx, { ...mod.Config({}), stateDir, registerSkillProvider: false, publishPowerSkillsGlobally: false, persistState: true, allowedTargets: ['10.0.0.0/8'] })
const call = async (name, args) => {
  const out = await ctx.tools.execute({ callId: prefix + '-' + name + '-' + Math.random().toString(36).slice(2), name, arguments: args, signal: AbortSignal.timeout(30000) })
  return (out.content ?? []).map((b) => (b.type === 'text' ? b.text : '')).join('\n')
}
await call('f2x_orchestrate_start', { brief: 'race', targets: ['10.10.0.5'] })
const jobs = []
for (let i = 0; i < Number(per); i += 1) {
  jobs.push(call('f2x_orchestrate_audit', { action: prefix + '-' + i, operation: 'register-read', target: '10.10.0.5:502' }))
}
const results = await Promise.all(jobs)
const refused = results.filter((text) => text.includes('Refused')).length
process.stdout.write('DONE ' + prefix + ' refused=' + refused + '\n')
} catch (error) {
  process.stderr.write('CHILD-ERROR ' + (error?.stack ?? String(error)) + '\n')
  process.exit(7)
}
`
const childPath = join(stateDir, 'writer.mjs')
writeFileSync(childPath, childSource)

const runWriter = (prefix) =>
  new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--experimental-strip-types', childPath, stateDir, prefix, String(per)], {
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let out = ''
    let err = ''
    child.stdout.on('data', (chunk) => { out += chunk })
    child.stderr.on('data', (chunk) => { err += chunk })
    child.on('exit', (code) => {
      if (code !== 0) {
        const log = join(tmpdir(), `f2x-race-child-${prefix}.log`)
        writeFileSync(log, err)
        reject(new Error(`${prefix} exited ${String(code)}; stderr at ${log}`))
        return
      }
      const refused = /refused=(\d+)/.exec(out)
      if (refused !== null && Number(refused[1]) > 0) reject(new Error(`${prefix}: ${refused[1]} writes were refused`))
      resolve(out)
    })
  })

const started = Date.now()
const prefixes = Array.from({ length: processes }, (_, index) => String.fromCodePoint(65 + index))
await Promise.all(prefixes.map((prefix) => runWriter(prefix)))
const stateFile = join(stateDir, 'state.json')
if (stateFile === undefined) {
  console.error('no state file was produced; writers reported:', stateFiles)
  process.exit(1)
}
const state = JSON.parse(readFileSync(stateFile, 'utf8'))
const audit = Object.values(state.audit ?? {})
const expected = processes * per
const lost = expected - audit.length
const ids = audit.map((entry) => entry.id)
const duplicates = ids.length - new Set(ids).size
const uniqueActions = new Set(audit.map((entry) => entry.action)).size

console.log(`${String(processes)} processes x ${String(per)} records against ${stateFile}`)
console.log(`  expected ${String(expected)}  recorded ${String(audit.length)}  lost ${String(lost)}  duplicate ids ${String(duplicates)}  distinct actions ${String(uniqueActions)}`)
console.log(`  wall clock ${((Date.now() - started) / 1000).toFixed(1)}s`)
if (lost > 0 || duplicates > 0) {
  console.error('  FAIL: the ledger lost or duplicated records under cross-process concurrency')
  process.exit(1)
}
console.log('  OK: every record survived, with unique ids')
