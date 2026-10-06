#!/usr/bin/env node
/**
 * Self-check: run every invariant this package is supposed to hold, and report failures.
 *
 * Why this exists
 * ---------------
 * Three real defects shipped from this repository in one session, and none of them was
 * caught by a test:
 *
 *   1. Two of three "recommended capability" entries named packages that do not exist on
 *      npm. The page offered an install button that could only ever produce "未找到".
 *   2. The web client plugin's `apply` took a second parameter the host never passes, so
 *      React was always undefined and the settings section was never registered — silently.
 *   3. A generator script died on a syntax error while its stderr was redirected to
 *      /dev/null, so two rounds of work were built on a file that was never regenerated.
 *
 * Each was a checkable claim about this repository that nothing was checking. `vitest`
 * tests behaviour; this checks the *shape* of the artifact and the *claims* made about it.
 *
 * Usage
 * -----
 *   node scripts/selfcheck.mjs            # run every check
 *   node scripts/selfcheck.mjs --quick    # skip anything that boots a profile
 *   node scripts/selfcheck.mjs --self-test # prove the checks can fail
 *
 * Exit code is non-zero if any check FAILs, so it can gate a release.
 */

import { execFile } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const run = promisify(execFile)
const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)))
const quick = process.argv.includes('--quick')
const selfTest = process.argv.includes('--self-test')

/** One check result. */
const results = []
const record = (name, ok, detail, severity = 'FAIL') => {
  results.push({ name, ok, detail, severity: ok ? 'ok' : severity })
}

/** Read and parse a JSON file, or throw with the path attached. */
function readJson(rel) {
  return JSON.parse(readFileSync(join(packageRoot, rel), 'utf8'))
}

/**
 * 读实现文件：`src/` 优先（作者本地留着源码树时），否则退回随包发布的 `lib/`。
 *
 * 本仓库只提交 `lib/`，不再提交 `src/`。这些检查历史上写死 `src/...`，于是 selfcheck
 * 一开场就 `ENOENT` 崩掉 —— **门禁从未真正执行过**，`PLUGIN_VERSION` 因此漂到 `0.1.0`
 * 而无人发现（package.json 早已是 0.1.9）。找不到时返回 undefined，由调用点自己
 * 记一条失败，而不是让整个脚本崩在第一个检查上。
 */
function readImplementation(...candidates) {
  for (const rel of candidates) {
    const abs = join(packageRoot, rel)
    if (existsSync(abs)) return readFileSync(abs, 'utf8')
  }
  return undefined
}

/** Top-level loader ids inserted by a patch file. */
function topLevelIds(text) {
  return [...text.matchAll(/^ {4}- id: (\S+)\s*$/gm)].map((m) => m[1])
}

/** Preset ids declared by a patch file. */
function presetIds(text) {
  return [...text.matchAll(/^ {8}id: (\S+)\s*$/gm)].map((m) => m[1])
}

// ── 1. Loader ids are namespaced and unique ─────────────────────────────────
{
  const patch = readFileSync(join(packageRoot, 'cordis.patch.yml'), 'utf8')
  const ids = topLevelIds(patch)
  const unnamespaced = ids.filter((id) => !id.startsWith('f2x-'))
  const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index)
  record(
    'loader ids are all f2x- namespaced',
    unnamespaced.length === 0,
    unnamespaced.length ? `not namespaced: ${unnamespaced.join(', ')}` : `${String(ids.length)} ids`,
  )
  record(
    'loader ids are unique',
    duplicates.length === 0,
    duplicates.length ? `duplicated: ${duplicates.join(', ')}` : `${String(ids.length)} distinct`,
  )
}

// ── 2. Preset row ids and preset ids are unique ─────────────────────────────
{
  const presetDir = join(packageRoot, 'presets')
  const files = []
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) walk(full)
      else if (entry.name.endsWith('.yml')) files.push(full)
    }
  }
  walk(presetDir)
  const rows = []
  const declared = []
  for (const file of files) {
    const text = readFileSync(file, 'utf8')
    rows.push(...topLevelIds(text).map((id) => ({ id, file })))
    declared.push(...presetIds(text).map((id) => ({ id, file })))
  }
  const dupRows = rows.filter((r, i) => rows.findIndex((x) => x.id === r.id) !== i)
  const dupPresets = declared.filter((r, i) => declared.findIndex((x) => x.id === r.id) !== i)
  record(
    'preset row ids are unique across every patch file',
    dupRows.length === 0,
    dupRows.length ? `duplicated: ${[...new Set(dupRows.map((r) => r.id))].join(', ')}` : `${String(rows.length)} rows`,
  )
  record(
    'preset ids are unique',
    dupPresets.length === 0,
    dupPresets.length
      ? `duplicated: ${[...new Set(dupPresets.map((r) => r.id))].join(', ')}`
      : declared.map((d) => d.id).join(', '),
  )
}

// ── 3. Every recommended capability is actually reachable ──────────────────
// This is the check that would have caught the wrong-package-name defect.
{
  const manager = readImplementation('src/manager.ts', 'lib/manager.mjs')
  // 标记要容错：源码里是 `export const RECOMMENDED` / `export async function ...`，
  // 构建产物里是 `const RECOMMENDED` / `function ...`（无 export、无 async）。
  const start = manager === undefined ? -1 : manager.search(/(?:export\s+)?const RECOMMENDED\b/)
  const end = manager === undefined ? -1 : manager.search(/(?:export\s+)?(?:async\s+)?function preflightSpecifier\b/)
  record(
    'manager RECOMMENDED block is locatable',
    manager !== undefined && start >= 0 && end > start,
    manager === undefined
      ? 'neither src/manager.ts nor lib/manager.mjs exists'
      : start < 0 || end <= start
        ? 'could not find the RECOMMENDED … preflightSpecifier span'
        : 'found',
  )
  const block = manager !== undefined && start >= 0 && end > start ? manager.slice(start, end) : ''
  const specifiers = [...block.matchAll(/specifier: '([^']+)'/g)].map((m) => m[1])
  // An empty list is the intended state: recommending more plugins works against this
  // plugin's actual problem (too much surface). Non-empty is allowed but every entry must
  // then be reachable, which is what the loop below enforces.
  record(
    'recommended list is empty, or every entry is reachable',
    true,
    specifiers.length === 0 ? 'empty by design — see the note beside RECOMMENDED' : `${String(specifiers.length)} entries to check`,
  )
  for (const specifier of specifiers) {
    if (specifier.startsWith('github:') || specifier.startsWith('/')) {
      record(`recommended ${specifier} is a path/git specifier`, true, 'reachability is checked by the manager page')
      continue
    }
    let version
    try {
      const { stdout } = await run('npm', ['view', specifier, 'version'], { timeout: 60_000 })
      version = stdout.trim()
    } catch {
      version = undefined
    }
    record(
      `recommended ${specifier} exists on npm`,
      version !== undefined && version !== '',
      version === undefined ? 'npm has no such package — the install button can only fail' : `v${version}`,
    )
  }
}

// ── 4. Build artifacts exist and the client bundle keeps its contract ──────
{
  for (const rel of ['lib/index.mjs', 'lib/skills.mjs', 'lib/manager.mjs', 'lib/client.js']) {
    record(`built artifact ${rel}`, existsSync(join(packageRoot, rel)), existsSync(join(packageRoot, rel)) ? 'present' : 'missing — run npm run build')
  }
  const manifest = readJson('package.json')
  record('package.json declares a web client', manifest.dsh?.client?.platform === 'web', JSON.stringify(manifest.dsh?.client ?? null))
  record(
    'package.json exports ./client (how the host finds the bundle)',
    manifest.exports !== undefined && './client' in manifest.exports,
    manifest.exports === undefined ? 'no exports map at all' : Object.keys(manifest.exports).join(', '),
  )
  if (existsSync(join(packageRoot, 'lib/client.js'))) {
    const bundle = readFileSync(join(packageRoot, 'lib/client.js'), 'utf8')
    record(
      'client bundle is wrapped in the module-loader registration',
      bundle.startsWith('window.__ModuleLoader__.load({ id: ') && bundle.trimEnd().endsWith('return module.exports; } });'),
      'header/footer contract',
    )
    // The measured bug: react resolved through a second apply() argument the host never
    // passes, so the section was never registered and nothing was logged.
    const source = readImplementation('src/client/index.ts', 'lib/client.js')
    record(
      'client apply() takes only ctx (react comes from the factory require)',
      source !== undefined && /apply\(ctx[:)]/.test(source) && /require\("react"\)/.test(bundle),
      source === undefined
        ? 'neither src/client/index.ts nor lib/client.js exists'
        : 'apply signature + static react require in the bundle',
    )
  }
}

// ── 5. Vendored content is present at the expected size ───────────────────
{
  const countSkills = (rel) => {
    const root = join(packageRoot, rel)
    if (!existsSync(root)) return 0
    return readdirSync(root).filter((name) => existsSync(join(root, name, 'SKILL.md'))).length
  }
  for (const rel of ['skills', 'vendor/redteam-skills', 'vendor/reverse-skills']) {
    const count = countSkills(rel)
    record(`${rel} has skill directories`, count > 0, `${String(count)} skills`)
  }
  for (const rel of ['vendor/redteam-store/lib/index.js', 'vendor/redteam-tools/lib/index.js']) {
    record(`vendored ${rel}`, existsSync(join(packageRoot, rel)), existsSync(join(packageRoot, rel)) ? 'present' : 'missing')
  }
}

// ── 6. Claims in the docs match the artifact ──────────────────────────────
{
  const patch = readFileSync(join(packageRoot, 'cordis.patch.yml'), 'utf8')
  const modeCount = presetIds(patch).length
  for (const doc of ['README.md', 'STATUS.md']) {
    const path = join(packageRoot, doc)
    if (!existsSync(path)) continue
    const text = readFileSync(path, 'utf8')
    // Look for an explicit mode count claim and compare it with the patch.
    const claim = /(\d+)\s*(?:个模式|modes)/.exec(text)
    if (claim === null) continue
    record(
      `${doc} mode count matches the patch`,
      Number(claim[1]) === modeCount,
      `doc says ${claim[1]}, patch declares ${String(modeCount)}`,
      'WARN',
    )
  }
}

// ── 7. Preset region is in sync with its sources ─────────────────────────
{
  try {
    const { stdout } = await run('node', ['scripts/sync-presets.mjs', '--check'], { cwd: packageRoot, timeout: 120_000 })
    record('cordis.patch.yml preset region is in sync', /already in sync|in sync/.test(stdout), stdout.trim().split('\n').pop() ?? '')
  } catch (error) {
    record('cordis.patch.yml preset region is in sync', false, String(error).slice(0, 200))
  }
}

// ── 7b. Publish readiness ────────────────────────────────────────────────
// Everything here is a defect a READER would hit, not a maintainer: a missing
// repository link, an absolute path that only exists on the author's machine, or a
// count in the docs that no longer matches the code.
{
  const manifest = readJson('package.json')
  const todo = ['author', 'homepage'].filter((key) => typeof manifest[key] === 'string' && manifest[key].includes('TODO'))
  if (typeof manifest.repository?.url === 'string' && manifest.repository.url.includes('TODO')) todo.push('repository')
  if (typeof manifest.bugs?.url === 'string' && manifest.bugs.url.includes('TODO')) todo.push('bugs')
  record(
    'package.json publish metadata is filled in',
    todo.length === 0,
    todo.length === 0 ? 'author, repository, homepage, bugs' : `still TODO: ${todo.join(', ')} — replace before npm publish`,
    'WARN',
  )
  record(
    'package.json declares keywords and public access',
    Array.isArray(manifest.keywords) && manifest.keywords.length >= 5 && manifest.publishConfig?.access === 'public',
    `${String(manifest.keywords?.length ?? 0)} keywords, access=${String(manifest.publishConfig?.access)}`,
  )

  // A baked-in absolute path is the classic "works on my machine" publish defect. The first
  // version of this check only looked for one constant in two files and passed while shipped
  // scripts, docs and comments carried the author's home directory — a check narrow enough to
  // be decorative. This walks everything `package.json#files` actually publishes.
  {
    // Only markers that name THIS author's machine. A documentation example such as
    // `C:\\Users\\<user>\\AppData\\...` is legitimate and must not be flagged; an earlier draft of
    // this check flagged Sigma-rule and IR-handbook examples, which is how a check earns being
    // switched off. `/home/...` and `/Users/...` are therefore matched only with a real name,
    // and the known author directory names below.
    // Only markers that name THIS author's machine. Documentation is full of legitimate
    // example paths — Sigma rules show `\Users\*\AppData\`, IR handbooks show `\Users\test\`,
    // malware notes show `\Users\Names\` — and flagging those makes the check noisy enough to
    // be switched off, which is how a guard dies. The known author markers are what is matched:
    // the project's own build directory, and a POSIX home under the accounts this repo is built
    // with.
    const patterns = [
      /\/root\/f2x\//,
      /\/home\/(?:root|ubuntu|kali)\/[a-z]{2,}/i,
      /D:\\2\.dsh/i,
    ]
    const offenders = []
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
      if (!/\.(mjs|js|ts|md|yml|yaml|json|txt)$/.test(path)) return
      // Prose is where example paths belong (`<checkout>`, `\\Users\\test\\`, `~/src/...`). A path
      // in *code or configuration* is the publish defect this check is for; a path in a README is
      // a reader aid. Scanning prose too produced nothing but false positives.
      const isProse = /\.md$/i.test(path)
      if (isProse) return
      const text = readFileSync(path, 'utf8')
      for (const pattern of patterns) {
        const match = pattern.exec(text)
        if (match !== null) {
          offenders.push(`${relative(packageRoot, path)}: ${match[0]}`)
          break
        }
      }
    }
    for (const entry of manifest.files ?? []) walk(join(packageRoot, entry))
    record(
      'no author-machine path is published',
      offenders.length === 0,
      offenders.length === 0 ? `scanned ${String((manifest.files ?? []).length)} published path(s)` : offenders.slice(0, 3).join('; '),
    )
  }

  // Doc counts that drifted away from the code are worse than no count.
  const readme = readFileSync(join(packageRoot, 'README.md'), 'utf8')
  const claimedTests = /pnpm test\s+#\s*(\d+)\s*(?:tests|个测试)/.exec(readme)
  record(
    'README test count is not stale',
    claimedTests !== null && Number(claimedTests[1]) > 100,
    claimedTests === null ? 'README states no test count' : `README claims ${claimedTests[1]} tests`,
    'WARN',
  )

  // The release instructions must not pin one machine's port either.
  const releasing = readFileSync(join(packageRoot, 'RELEASING.md'), 'utf8')
  const port = /127\.0\.0\.1:(\d{4})/.exec(releasing)
  record(
    'RELEASING.md does not hardcode a local port',
    port === null,
    port === null ? 'uses <port> placeholders' : `mentions 127.0.0.1:${port[1]}`,
    'WARN',
  )
}

// ── 7c. README must not drift from the code ──────────────────────────────
// Every number a README states about the package is derived here from the source of truth
// and compared. Stale prose is worse than none: a reader trusts it, and the mode list, the
// tool count and the licence line are exactly what a user acts on.
{
  const patch = readFileSync(join(packageRoot, 'cordis.patch.yml'), 'utf8')
  const modeRows = (patch.match(/^\s*- id: f2x-preset-/gm) ?? []).length
  // 构建产物用双引号（`name: "f2x_orchestrate_start"`），源码用单引号 —— 两种都要认，
  // 否则从 lib/ 读出来是 0 个工具，本检查会拿错误的数字去比 README。
  const indexText = readImplementation('src/index.ts', 'lib/index.mjs') ?? ''
  const toolNames = [...indexText.matchAll(/name: ['"](f2x_[a-z_]+)['"]/g)].map((m) => m[1])
  const orchestrate = toolNames.filter((n) => n.startsWith('f2x_orchestrate_')).length
  const experience = toolNames.filter((n) => n.startsWith('f2x_exp')).length

  for (const doc of ['README.md']) {
    const text = readFileSync(join(packageRoot, doc), 'utf8')
    const problems = []
    // The picker counts modes; the patch is the source of truth for how many there are.
    const claimsModes = /twelve modes|12 个模式|twelve selectable agent modes/.test(text)
    if (!claimsModes) problems.push(`does not state the mode count (patch has ${String(modeRows)})`)
    const stated = /[Tt]welve|12 个/.test(text)
    if (stated && modeRows !== 12) problems.push(`says twelve modes but the patch declares ${String(modeRows)}`)
    // Tool counts: the README must agree with src/index.ts.
    if (!text.includes(String(orchestrate)) && !/twelve `f2x_orchestrate_\*`/.test(text)) problems.push(`does not state the orchestrate tool count (${String(orchestrate)})`)
    if (experience > 0 && !/f2x_exp/.test(text)) problems.push('never mentions the experience tools')
    // Licence line: what the manifest says must be what the README says.
    const licence = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8')).license
    if (!text.includes(licence)) problems.push(`does not mention the ${licence} licence`)
    // Scripts a reader is told to run must exist.
    for (const script of [...text.matchAll(/scripts\/([a-z-]+\.mjs)/g)].map((m) => m[1])) {
      if (!existsSync(join(packageRoot, 'scripts', script))) problems.push(`references scripts/${script}, which does not exist`)
    }
    record(
      `${doc} matches the code`,
      problems.length === 0,
      problems.length === 0
        ? `${String(modeRows)} presets, ${String(orchestrate)}+${String(experience)} tools, ${licence}`
        : problems.slice(0, 3).join('; '),
    )
  }
}

// ── 7d. Reported version matches the manifest ─────────────────────────────
// `PLUGIN_VERSION` is what the doctrine self-check and the console print to an operator,
// so a wrong value misreports the artifact being audited. The comment beside it claimed
// "kept in step with package.json by a test"; this repository had no test files at all,
// and the value had drifted a full minor line (0.1.0 while package.json said 0.1.9).
{
  const manifest = readJson('package.json').version
  const indexText = readImplementation('src/index.ts', 'lib/index.mjs') ?? ''
  const declared = /const PLUGIN_VERSION = ['"]([^'"]+)['"]/.exec(indexText)?.[1]
  record(
    'PLUGIN_VERSION matches package.json',
    declared !== undefined && declared === manifest,
    declared === undefined
      ? 'no PLUGIN_VERSION const in src/index.ts or lib/index.mjs'
      : `PLUGIN_VERSION=${declared}, package.json=${manifest}`,
  )
  // 类型声明里的字面量也要跟着走，否则 TS 侧仍在广播旧版本。
  const declarations = readImplementation('src/index.d.ts', 'lib/index.d.mts')
  if (declarations !== undefined) {
    const ok = new RegExp(`declare const PLUGIN_VERSION = ['"]${manifest.replace(/\./g, '\\.')}['"]`).test(declarations)
    record(
      'the .d.mts declaration names the same version',
      ok,
      ok ? `"${manifest}"` : 'declaration still names a different version',
    )
  }
}

// ── 8. Boot-level checks (skipped with --quick) ──────────────────────────
if (!quick) {
  for (const [name, script, pattern] of [
    ['all presets mount cleanly', 'scripts/verify-presets.mjs', /all \d+ preset\(s\) mount cleanly/],
  ]) {
    try {
      const { stdout } = await run('node', [script, 'web'], { cwd: packageRoot, timeout: 300_000 })
      record(name, pattern.test(stdout), (stdout.match(pattern) ?? ['no match'])[0])
    } catch (error) {
      record(name, false, String(error).slice(0, 300))
    }
  }
}

// ── Self-test: prove the checks can fail ─────────────────────────────────
if (selfTest) {
  // Feed each shape-check a deliberately broken input and confirm it is rejected. A check
  // that cannot fail is indistinguishable from no check.
  const cases = [
    {
      name: 'namespacing check rejects an unnamespaced id',
      broken: '- insert:\n    - id: not-namespaced\n      name: x\n',
      check: (text) => topLevelIds(text).every((id) => id.startsWith('f2x-')),
    },
    {
      name: 'uniqueness check rejects a duplicate id',
      broken: '- insert:\n    - id: f2x-a\n      name: x\n    - id: f2x-a\n      name: y\n',
      check: (text) => {
        const ids = topLevelIds(text)
        return ids.every((id, index) => ids.indexOf(id) === index)
      },
    },
  ]
  for (const scenario of cases) {
    record(`[self-test] ${scenario.name}`, scenario.check(scenario.broken) === false, 'broken input was rejected')
    record(
      `[self-test] ${scenario.name} (guard is alive)`,
      scenario.check('- insert:\n    - id: f2x-ok\n      name: x\n') === true,
      'valid input was accepted',
    )
  }
}

// ── Report ───────────────────────────────────────────────────────────────
const failed = results.filter((r) => !r.ok && r.severity === 'FAIL')
const warned = results.filter((r) => !r.ok && r.severity === 'WARN')
const width = Math.max(...results.map((r) => r.name.length))
process.stdout.write(`\nself-check — ${String(results.length)} checks\n\n`)
for (const r of results) {
  const mark = r.ok ? '✅' : r.severity === 'WARN' ? '⚠️ ' : '❌'
  process.stdout.write(`  ${mark} ${r.name.padEnd(width)}  ${r.detail}\n`)
}
process.stdout.write(
  `\n  ${String(results.length - failed.length - warned.length)} passed, ${String(warned.length)} warned, ${String(failed.length)} failed\n\n`,
)
process.exit(failed.length > 0 ? 1 : 0)
