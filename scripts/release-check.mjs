#!/usr/bin/env node
/**
 * Publish gate.
 *
 * `npm publish` is irreversible for a version number, so the checks that catch a
 * half-filled manifest run *before* it, and they fail the process instead of printing
 * a warning nobody reads. Everything here has bitten a release somewhere:
 *
 *   1. `repository` / `author` / `homepage` still holding a TODO placeholder — the
 *      package page then links nowhere and nobody can reach the source.
 *   2. `lib/` older than `src/` — the classic silent defect: the tarball ships the
 *      previous build while the tests, which run from `src/`, stay green.
 *   3. A missing `dsh.bundle.patch` or an exports map without `./vendor/*` — the modes
 *      or the vendored tool row would not mount for a fresh install.
 *   4. A tarball that carries `node_modules/`, `src/`, or `tests/`.
 *
 * Usage:
 *   node scripts/release-check.mjs          # run the gate
 *   node scripts/release-check.mjs --pack   # also build and inspect the tarball
 */

import { execFileSync } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = join(fileURLToPath(new URL('.', import.meta.url)), '..')
const pack = process.argv.includes('--pack')
const failures = []
const notes = []

/** Fail the gate with a reason a reader can act on. */
function check(name, ok, detail) {
  if (ok) {
    notes.push(`  ok   ${name}${detail === undefined ? '' : ` — ${detail}`}`)
    return
  }
  failures.push(`  FAIL ${name}${detail === undefined ? '' : ` — ${detail}`}`)
}

const manifest = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'))

// 1. Manifest identity.
const todos = []
for (const key of ['author', 'homepage']) {
  if (typeof manifest[key] === 'string' && manifest[key].includes('TODO')) todos.push(key)
}
if (typeof manifest.repository?.url === 'string' && manifest.repository.url.includes('TODO')) todos.push('repository')
if (typeof manifest.bugs?.url === 'string' && manifest.bugs.url.includes('TODO')) todos.push('bugs')
check('publish metadata is filled in', todos.length === 0, todos.length === 0 ? 'author, repository, homepage, bugs' : `TODO in: ${todos.join(', ')}`)
check('version is set', typeof manifest.version === 'string' && /^\d+\.\d+\.\d+/.test(manifest.version), manifest.version)
check('license is a permissive OSI licence', ['Apache-2.0', 'MIT'].includes(manifest.license), manifest.license)
{
  // The shipped LICENSE must actually be the licence the manifest names.
  const licenceText = existsSync(join(packageRoot, 'LICENSE')) ? readFileSync(join(packageRoot, 'LICENSE'), 'utf8') : ''
  const matches = manifest.license === 'Apache-2.0'
    ? /Apache License[\s\S]{1,20}Version 2\.0/.test(licenceText)
    : /MIT License/.test(licenceText)
  check('LICENSE file matches package.json license', matches, matches ? `${manifest.license} text present` : `LICENSE does not look like ${manifest.license}`)
}

// 2. The build must not be older than its sources.
const newest = (dir) => {
  let stamp = 0
  const walk = (path) => {
    const info = statSync(path, { throwIfNoEntry: false })
    if (info === undefined) return
    if (info.isDirectory()) {
      for (const entry of readdirSync(path)) walk(join(path, entry))
      return
    }
    stamp = Math.max(stamp, info.mtimeMs)
  }
  if (existsSync(dir)) walk(dir)
  return stamp
}
const srcStamp = newest(join(packageRoot, 'src'))
const libStamp = newest(join(packageRoot, 'lib'))
check('lib/ is not older than src/', libStamp >= srcStamp, `src=${new Date(srcStamp).toISOString()} lib=${new Date(libStamp).toISOString()}`)

// 3. The row and export surface a fresh install needs.
check('dsh.bundle.patch is declared', typeof manifest.dsh?.bundle?.patch === 'string', manifest.dsh?.bundle?.patch)
for (const key of ['.', './client', './package.json', './vendor/*']) {
  check(`exports declares "${key}"`, manifest.exports?.[key] !== undefined, String(manifest.exports?.[key] ?? '(missing)'))
}

// 3b. The legal files are part of the artefact, not an afterthought: a security tool
// published without its usage terms and attribution is a liability for whoever installs it.
{
  const legal = ['LICENSE', 'NOTICE', 'DISCLAIMER.md', 'THIRD-PARTY-NOTICES.md']
  const missing = legal.filter((name) => !existsSync(join(packageRoot, name)))
  check('legal documents are present', missing.length === 0, missing.length === 0 ? legal.join(', ') : `missing: ${missing.join(', ')}`)
  const declared = new Set(manifest.files ?? [])
  const undeclared = legal.filter((name) => !declared.has(name))
  check('legal documents ship in the package', undeclared.length === 0, undeclared.length === 0 ? 'listed in package.json files' : `not in files: ${undeclared.join(', ')}`)
  // Copyleft content must not creep back in: it would relicence the whole package.
  const copyleft = []
  for (const dir of ['presets', 'vendor', 'skills']) {
    if (!existsSync(join(packageRoot, dir))) continue
    const walk = (path) => {
      for (const entry of readdirSync(path)) {
        const full = join(path, entry)
        if (statSync(full).isDirectory()) { walk(full); continue }
        if (entry !== 'LICENSE' && entry !== 'COPYING' && entry !== 'NOTICE') continue
        const text = readFileSync(full, 'utf8').slice(0, 400)
        if (/GNU (AFFERO )?GENERAL PUBLIC LICENSE|Commons Clause/i.test(text)) copyleft.push(full.slice(packageRoot.length + 1))
      }
    }
    walk(join(packageRoot, dir))
  }
  check('no copyleft licence text ships inside the package', copyleft.length === 0, copyleft.length === 0 ? 'checked presets/, vendor/, skills/' : copyleft.slice(0, 3).join(', '))
}

// 3c. Provenance coverage: every shipped path must be named in the notices, and the
// author attestation must be closed out. Both are the difference between "we wrote a
// licence file" and "we know what we are shipping".
{
  try {
    execFileSync('node', ['scripts/provenance-audit.mjs'], { cwd: packageRoot, stdio: 'pipe' })
    check('every shipped path is named in THIRD-PARTY-NOTICES.md', true, 'provenance-audit passed')
  } catch (error) {
    const output = String(error.stdout ?? '').trim().split('\n').slice(-6).join(' | ')
    check('every shipped path is named in THIRD-PARTY-NOTICES.md', false, output.slice(0, 300))
  }
  const notices = readFileSync(join(packageRoot, 'THIRD-PARTY-NOTICES.md'), 'utf8')
  // Only table rows count: the prose explaining the checkbox convention must not
  // register as an unfinished item.
  const openItems = notices.split('\n').filter((line) => line.startsWith('|') && line.includes('☐')).length
  const signed = /签名：\s*[^\s_]{2,}/.test(notices)
  check(
    'author attestation in THIRD-PARTY-NOTICES.md is closed out',
    openItems === 0 && signed,
    openItems === 0 ? (signed ? 'signed' : 'attestation block not signed') : `${String(openItems)} open item(s) still await the author`,
  )
}

// 3d. Syntax-check every JavaScript file that ships.
//
// This exists because it already happened: a text edit inside a vendored `core.js` replaced the
// contents of a template literal, the file stopped parsing, and every preset that mounts it died
// with "never started". Neither `vitest` (which reads src/), `selfcheck.mjs` (paths and docs) nor
// the tsc run noticed — the fault was only visible when a profile tried to boot. A shipped file
// that cannot be parsed is the cheapest possible failure to catch, so catch it here.
{
  const jsFiles = []
  const walk = (path) => {
    const info = statSync(path, { throwIfNoEntry: false })
    if (info === undefined) return
    if (info.isDirectory()) {
      for (const entry of readdirSync(path)) {
        if (entry === 'node_modules' || entry === '.git' || entry === 'audit') continue
        walk(join(path, entry))
      }
      return
    }
    if (/\.(mjs|js|cjs)$/.test(path)) jsFiles.push(path)
  }
  for (const entry of manifest.files ?? []) walk(join(packageRoot, entry))
  // A heuristic ("does this look like code?") was the first attempt and an audit walked past it:
  // a genuinely broken file could be sorted into the prose bucket and skipped. The list of files
  // that are NOT code is now explicit, so anything not on it MUST parse. A new broken file fails
  // this check; adding a file to the list is a deliberate, reviewable act.
  const KNOWN_NON_CODE = new Set([
    'presets/redteam-modes/binary-analysis/refs/mobile/android-reverse/engineering-skill-v2/skills/android-reverse-engineering/scripts/bypass_frida_svc_detect.js',
  ])
  const broken = []
  const notCode = []
  for (const file of jsFiles) {
    try {
      execFileSync('node', ['--check', file], { stdio: 'pipe' })
    } catch (error) {
      const detail = String(error.stderr ?? '').split('\n').slice(0, 3).join(' ').slice(0, 140)
      const rel = relative(packageRoot, file)
      if (KNOWN_NON_CODE.has(rel)) notCode.push(rel)
      else broken.push(`${rel}: ${detail}`)
    }
  }
  check(
    `every shipped JavaScript file parses (${String(jsFiles.length)} files)`,
    broken.length === 0,
    broken.length === 0 ? 'node --check passed' : broken.slice(0, 2).join(' | '),
  )
  if (notCode.length > 0) {
    notes.push(
      `  note ${String(notCode.length)} file(s) named .js are prose, not code (vendored): ${notCode.slice(0, 2).join(', ')}`,
    )
  }
}

// 3d-bis. The provenance numbers in THIRD-PARTY-NOTICES must match a fresh measurement.
//
// This check exists because the numbers drifted the moment upstream files were edited: the notice
// still said "24/24 byte-identical" after one of those files had been rewritten, and "1103/1118"
// after 22. A licence notice quoting stale counts is the same class of defect as one quoting a
// wrong wording, so the counts are re-derived here instead of trusted. Skipped (with a note) when
// no upstream checkout is available, because the measurement cannot be taken without one.
{
  const upstreams = (process.env.F2X_UPSTREAMS ?? '').split(':').filter((value) => value !== '')
  if (upstreams.length === 0) {
    notes.push('  note provenance counts not re-measured (set F2X_UPSTREAMS=path1:path2 to enable)')
  } else {
    try {
      const args = ['scripts/provenance-content.mjs']
      for (const upstream of upstreams) args.push('--upstream', upstream)
      const out = execFileSync('node', args, { cwd: packageRoot, encoding: 'utf8', stdio: 'pipe' })
      const measured = new Map()
      for (const line of out.split('\n')) {
        const match = /^([\w/.-]+): (\d+)\/(\d+) byte-identical/.exec(line)
        if (match !== null) measured.set(match[1], `${match[2]} / ${match[3]}`)
      }
      // Normalise away markdown emphasis and whitespace before comparing: the notice writes
      // `**23 / 24**`, the measurement writes `23/24`.
      const normalise = (value) => value.replace(/[*_`\s]/g, '')
      const notices = normalise(readFileSync(join(packageRoot, 'THIRD-PARTY-NOTICES.md'), 'utf8'))
      // Only zones whose counts this notice actually states are compared; every stated zone must
      // also be present in the measurement (so a renamed/removed zone does not go unnoticed).
      const stated = new Set(['vendor/redteam-skills', 'vendor/reverse-skills', 'presets/redteam-modes', 'skills', 'persona', 'playbook', 'refs/power'])
      const stale = []
      for (const [zone, counts] of measured) {
        if (!stated.has(zone)) continue
        if (!notices.includes(normalise(counts))) stale.push(`${zone} (measured ${counts})`)
      }
      for (const zone of stated) {
        if (!measured.has(zone)) stale.push(`${zone} (not re-measured)`)
      }
      check(
        'provenance counts in the notices match a fresh measurement',
        stale.length === 0,
        stale.length === 0 ? `${String(measured.size)} zones re-measured` : `stale: ${stale.slice(0, 3).join(', ')}`,
      )
    } catch (error) {
      check('provenance counts in the notices match a fresh measurement', false, String(error).slice(0, 160))
    }
  }
}

// 3e. Cross-process ledger concurrency.
//
// Two audit rounds reported lost records when processes shared a stateDir (29 of 60 measured here
// with the lock removed, matching their 28-30). The lock file closed it; this runs the probe so a
// future change that drops the lock fails the gate instead of silently corrupting the ledger.
{
  try {
    const out = execFileSync('node', ['scripts/race-check.mjs', '3', '10'], { cwd: packageRoot, encoding: 'utf8', stdio: 'pipe' })
    const line = out.split('\n').find((l) => l.includes('expected'))?.trim() ?? ''
    check('ledger survives cross-process writes', true, line)
  } catch (error) {
    const detail = String(`${error.stdout ?? ''}${error.stderr ?? ''}`).split('\n').filter(Boolean).slice(-2).join(' | ')
    check('ledger survives cross-process writes', false, detail.slice(0, 220))
  }
}

// 4. The bundle patch must actually insert the plugin row and the presets.
const patch = readFileSync(join(packageRoot, 'cordis.patch.yml'), 'utf8')
check('bundle patch inserts the plugin row', /- id: f2x-redteam3000\b/.test(patch))
check('bundle patch carries the twelve presets', (patch.match(/^\s*- id: f2x-preset-/gm) ?? []).length === 12, `${String((patch.match(/^\s*- id: f2x-preset-/gm) ?? []).length)} preset rows`)
check('preset region is in sync', (() => {
  try {
    execFileSync('node', ['scripts/sync-presets.mjs', '--check'], { cwd: packageRoot, stdio: 'pipe' })
    return true
  } catch {
    return false
  }
})(), 'node scripts/sync-presets.mjs --check')

// 5. Optional: build and look inside the artefact.
if (pack) {
  // Pack into a temp directory. `pnpm pack` with no destination writes the tarball into the
  // repository root, overwriting whatever was there — an audit that runs this check then finds
  // the artefact changed underneath it, and a stale tarball can silently be shipped.
  const staging = mkdtempSync(join(tmpdir(), 'f2x-pack-'))
  const tgz = join(staging, `${manifest.name}-${manifest.version}.tgz`)
  try {
    execFileSync('pnpm', ['pack', '--pack-destination', staging], { cwd: packageRoot, stdio: 'pipe' })
    const listing = execFileSync('tar', ['tzf', tgz], { encoding: 'utf8' }).split('\n').filter(Boolean)
    const forbidden = listing.filter((entry) => /package\/(node_modules|src|tests)\//.test(entry))
    check('tarball excludes node_modules/src/tests', forbidden.length === 0, forbidden.slice(0, 3).join(', '))
    check('tarball contains the built entry', listing.includes('package/lib/index.mjs'))
    check('tarball contains the bundle patch', listing.includes('package/cordis.patch.yml'))
    const size = statSync(tgz).size
    notes.push(`  info tarball: ${String(listing.length)} files / ${(size / 1048576).toFixed(1)} MB`)
  } catch (error) {
    check('pnpm pack and inspect the tarball', false, String(error).slice(0, 200))
  }
}

process.stdout.write(`${notes.join('\n')}\n`)
if (failures.length > 0) {
  process.stderr.write(`\nrelease gate FAILED (${String(failures.length)}):\n${failures.join('\n')}\n`)
  process.exit(1)
}
process.stdout.write(`\nrelease gate passed${pack ? '' : ' (run with --pack to also inspect the tarball)'}.\n`)
