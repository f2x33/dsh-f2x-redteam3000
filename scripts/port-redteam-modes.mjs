#!/usr/bin/env node
/**
 * Port `dsh-redteam-model`'s agent modes onto DSH 0.2.x, with this plugin's layer added.
 *
 * Why a port is required
 * ----------------------
 * redteam-model declares its ten modes the 0.1.x way: one directory per mode holding
 * `agent.cordis.yml` + `preset.yml`. DSH 0.2.0 dropped filesystem preset discovery —
 * `AgentPresetRegistry` takes only `default`/`selectedDefault` — so those modes never
 * appear in the roster on this runtime. Measured, not assumed: `compositionInventory()`
 * lists four shipped presets plus this plugin's, and none of redteam-model's ten.
 *
 * The mode *definitions* are static YAML (persona text + plugin rows + skill roots), so
 * they port cleanly. Only the declarations change shape; the mode content is copied
 * verbatim.
 *
 * Three transformations per mode
 * ------------------------------
 * 1. **Shape** — the row list becomes the `plugins:` of an inline
 *    `@deepseek-ai/dsh-agent-preset` row.
 * 2. **Skill roots** — the source locates skills with
 *    `new URL('skills/', baseUrl)`, which relies on 0.1.x `baseUrl` semantics (the
 *    mode's own directory). On 0.2.0 `baseUrl` is the profile directory, so every root
 *    is rewritten to resolve from this package instead.
 * 3. **Foreign plugins** — rows naming `@dsh-external/*` packages (scanner-tools,
 *    semgrep-audit) are marked `disabled: true`. Those packages ship inside
 *    redteam-model and are not installed here; left enabled, the row fails to mount and
 *    the registry marks the whole preset `broken`, which silently removes it from the
 *    UI picker. Disabled, the mode mounts and an operator who installs the plugin can
 *    switch the row back on — the same pattern DSH's own `standard` preset uses for the
 *    `codex` / `claude-code` subagent rows.
 *
 * Attribution
 * -----------
 * `dsh-redteam-model` is MIT licensed (© SeaOf0). Ported persona text and skill files
 * keep their origin recorded in each generated file's header.
 *
 * Usage
 * -----
 *   node scripts/port-redteam-modes.mjs                 # every mode
 *   node scripts/port-redteam-modes.mjs pentest         # named modes only
 *   REDTEAM_MODEL_ROOT=/path/to/dsh-redteam-model node scripts/port-redteam-modes.mjs
 */

import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = join(fileURLToPath(new URL('.', import.meta.url)), '..')
// No author-machine default: this is a maintainer script that needs an upstream checkout.
// Set REDTEAM_MODEL_ROOT to your clone, e.g. `REDTEAM_MODEL_ROOT=/path/to/dsh-redteam-model node scripts/port-redteam-modes.mjs`.
const SOURCE_ROOT = process.env.REDTEAM_MODEL_ROOT ?? ''
const OUT_ROOT = join(packageRoot, 'presets', 'redteam-modes')

/** Every mode the source declares, in roster order (redteam is the entry point). */
export const MODES = [
  'redteam',
  'pentest',
  'asset-mapping',
  'attack-defense',
  'av-evasion',
  'binary-analysis',
  'cloud-security',
  'code-audit',
  'ctf-solver',
  'incident-response',
]

/** Directory under `presets/redteam-modes/` holding each ported mode's assets. */
export const SHARED_SKILL_DIR = 'shared'

/**
 * Display-name overrides for ported modes.
 *
 * The roster name lives here rather than in the generated file because the generator
 * rewrites that file from the upstream `preset.yml`; an edit there would be lost on the
 * next re-port. Ids are deliberately NOT overridden — a session records its preset id
 * and the browser remembers the operator's last choice, so changing an id strands both.
 */
const NAME_OVERRIDES = {
  redteam: 'redteam3000总调',
}

/**
 * Roster order: the four built-in DSH presets take 1-4, so the dispatcher sits at 5 —
 * right after them and ahead of the specialists, which follow at 21-29.
 */
function orderOf(mode, index) {
  return mode === 'redteam' ? 5 : 20 + index
}

/** The skill roots the ported preset must declare, in the source's own order. */
export function skillRootsFor(mode, sourceText) {
  const roots = []
  const block = /customSkillDirs:\n((?:\s+- !!js.*\n)+)/.exec(sourceText)
  if (block === null) throw new Error(`${mode}: no customSkillDirs block`)
  for (const line of block[1].split('\n')) {
    if (!line.includes('!!js')) continue
    const self = /new URL\('skills\/'/.test(line)
    const sibling = /new URL\('\.\.\/([a-z-]+)\/skills\/'/.exec(line)
    const shared = /shared\/skills\//.test(line)
    if (self) roots.push(`${mode}/skills`)
    else if (sibling !== null) roots.push(`${sibling[1]}/skills`)
    else if (shared) roots.push(`${SHARED_SKILL_DIR}/skills`)
    else throw new Error(`${mode}: unrecognised skill root: ${line.trim()}`)
  }
  return roots
}

/** One `!!js` entry that resolves a bundled skill root from this package's location. */
function skillRootExpression(root) {
  return `- !!js "(() => { const m = process.getBuiltinModule('node:module'); const p = process.getBuiltinModule('node:path'); try { const pk = m.createRequire(baseUrl).resolve('@dsh-f2x/redteam3000/package.json'); return p.join(p.dirname(pk), 'presets', 'redteam-modes', ${root
    .split('/')
    .map((part) => `'${part}'`)
    .join(', ')}); } catch { return '' } })()"`
}

/**
 * Extra skill roots for specific ported modes.
 *
 * `vendor/reverse-skills` (45 skills vendored from `@dhicoc/dsh-reverse-skill`, MIT) is
 * deliberately NOT global: its categories are reverse engineering, CTF, firmware,
 * malware analysis, wireless and so on, and loading all 45 into every session would put
 * roughly 6.8 MB of descriptions in front of a pure web-pentest task. The three modes
 * below are the ones whose work it actually serves.
 */
export const MODE_EXTRA_SKILL_ROOTS = {
  'binary-analysis': ['vendor/reverse-skills'],
  'ctf-solver': ['vendor/reverse-skills'],
  'code-audit': ['vendor/reverse-skills'],
}

/**
 * One `!!js` entry resolving a root relative to THIS package's directory.
 *
 * Distinct from {@link skillRootExpression}, which prefixes `presets/redteam-modes` and is
 * therefore only correct for the ported assets. Passing a `vendor/...` root through that
 * helper produced `<pkg>/presets/redteam-modes/vendor/reverse-skills`, which does not
 * exist — and a skill root that points nowhere is skipped in silence, so the mode simply
 * came up without those skills.
 */
function packageRootSkillExpression(root) {
  const parts = root
    .split('/')
    .map((part) => `'${part}'`)
    .join(', ')
  return `- !!js "(() => { const m = process.getBuiltinModule('node:module'); const p = process.getBuiltinModule('node:path'); try { const pk = m.createRequire(baseUrl).resolve('@dsh-f2x/redteam3000/package.json'); return p.join(p.dirname(pk), ${parts}); } catch { return '' } })()"`
}

/**
 * One `!!js` entry resolving this plugin's own skill root (`<pkg>/skills`).
 *
 * Deliberately separate from {@link skillRootExpression}: that helper prefixes
 * `presets/redteam-modes`, which is right for the ported assets and wrong here.
 */
const F2X_SKILL_EXPRESSION =
  `- !!js "(() => { const m = process.getBuiltinModule('node:module'); const p = process.getBuiltinModule('node:path'); try { const pk = m.createRequire(baseUrl).resolve('@dsh-f2x/redteam3000/package.json'); return p.join(p.dirname(pk), 'skills'); } catch { return '' } })()"`

/** Replace the `customSkillDirs` block with package-resolved roots. */
function rewriteSkillRoots(rows, roots, mode) {
  const extra = MODE_EXTRA_SKILL_ROOTS[mode] ?? []
  const start = rows.findIndex((line) => /^\s+customSkillDirs:\s*$/.test(line))
  if (start < 0) throw new Error(`${mode}: no customSkillDirs row to rewrite`)
  const indent = /^(\s*)/.exec(rows[start])[1]
  let end = start + 1
  while (end < rows.length && /^\s+- !!js/.test(rows[end])) end += 1
  // This plugin's own methodology comes last, so every ported mode gets the f2x
  // *skills* alongside the f2x *tools*. Without it a mode has the tool surface and no
  // idea how to work it.
  const replacement = [
    ...roots.map((root) => `${indent}  ${skillRootExpression(root)}`),
    ...extra.map((root) => `${indent}  ${packageRootSkillExpression(root)}`),
    `${indent}  ${F2X_SKILL_EXPRESSION}`,
  ]
  return [...rows.slice(0, start + 1), ...replacement, ...rows.slice(end)]
}

/**
 * What this deployment actually has, appended to the ported persona as its `suffix`.
 *
 * The source personas are written for redteam-model's own plugin set: ten of them name
 * `campaign_memory_*`, all ten name `dsh-refusal-guard` and the `subagent_codex` /
 * `subagent_claude_code` providers, and five name `redteam_finding_register`. None of
 * those exist here, and a model told to reach for a tool that is not in the catalog
 * burns turns discovering that. The block below is the same "tool availability and
 * fallback" discipline this plugin's own skills carry, stated once per mode.
 */
const REALITY_SUFFIX = [
  '【本环境工具现实 —— 开工前先读，与上文冲突时以本节为准】',
  '',
  '本模式运行在 @dsh-f2x/redteam3000 之上。上文提到的工具与本环境实际提供的并不完全一致，按下列口径执行。',
  '',
  '可用（务必使用）：',
  '- `f2x_orchestrate_*`（12 个）：start / scope / status / switch / blackboard / checkpoint /',
  '  verify / mark / audit / finding / doctrine / export。',
  '  · 开场第一条发 `f2x_orchestrate_doctrine` —— 它会打印本环境实际有什么、当前授权范围、',
  '    以及素材仓库与知识库的绝对路径。先自检再动手。',
  '  · 证据与推进：`checkpoint` 记一条证据 → `verify` 过阶段门禁 → `mark` 推进阶段',
  '    （`mark` 是唯一推进通道，门禁未过会被拒绝）。',
  '  · 成果登记用 `f2x_orchestrate_finding`（**不是** `redteam_finding_register`；转 verified',
  '    强制要求基线/差分/marker 三件套）。',
  '  · 跨会话沉淀：本节列出的 `campaign_memory_*` 在本环境不可用；用 `f2x_orchestrate_blackboard`',
  '    记 fact/intent/hint，用 `f2x_orchestrate_export` 做交接。',
  '  · 授权范围默认**为空 = 拒绝一切**；开任务时用 `f2x_orchestrate_start` 的 allowlist 声明范围。',
  '- DSH 原生：shell（bash/pwsh）、文件系统与检索、子代理、计划模式、上下文压缩、待办、网页。',
  '',
  '不可用（上文提到时走上面的替代，**不要调用**）：',
  '- `campaign_memory_write` / `search` / `get` / `list` / `remove`',
  '- `redteam_finding_register` / `redteam_coverage_mark` / `redteam_atlas_target` / `stage_gate` /',
  '  `webshell_connect`',
  '- `dsh-refusal-guard`、`dsh-route-boost`、`dsh-sec-enforce`、`dsh-hunter`、`dsh-stage-gate`',
  '  （这些插件在本部署中未安装；其"拒答修复/逐轮治理信封/工具拦截"能力不存在，不需要配合）',
  '- `subagent_codex` / `subagent_claude_code`（对应 CLI 未安装，预设行已禁用）→ 用 `subagent` /',
  '  `subagent_fork`',
  '',
  '规则：目录里没有的工具一律不要调用。发现某个能力缺失时，走上面写的退路并在结论里注明。',
]

/** Append the reality block as the persona row's `suffix`. */
function addRealitySuffix(rows, mode) {
  const persona = rows.findIndex((line) => /^- id: persona\s*$/.test(line))
  if (persona < 0) throw new Error(`${mode}: no persona row`)
  let prefix = -1
  // Start past the `- id: persona` line itself: the row marker is not indented.
  for (let i = persona + 1; i < rows.length && /^\s/.test(rows[i]); i += 1) {
    if (/^\s+prefix:/.test(rows[i])) {
      prefix = i
      break
    }
  }
  if (prefix < 0) throw new Error(`${mode}: persona row has no prefix`)
  const base = /^(\s*)/.exec(rows[prefix])?.[1] ?? ''
  const indentWidth = (line) => (/^(\s*)/.exec(line)?.[1] ?? '').length
  // The block scalar runs until a non-blank line indented no deeper than its key.
  let end = prefix + 1
  while (end < rows.length) {
    const line = rows[end] ?? ''
    if (line.trim() !== '' && indentWidth(line) <= base.length) break
    end += 1
  }
  const block = [`${base}suffix: |-`, ...REALITY_SUFFIX.map((line) => (line === '' ? '' : `${base}  ${line}`))]
  return [...rows.slice(0, end), ...block, ...rows.slice(end)]
}

/** Mark every row that names a package outside this deployment as disabled. */
function disableForeignRows(rows) {
  const out = []
  for (let i = 0; i < rows.length; i += 1) {
    const line = rows[i]
    out.push(line)
    const name = /^\s+name: '(@dsh-external\/[^']+)'\s*$/.exec(line)
    if (name === null) continue
    const next = rows[i + 1]
    if (next !== undefined && /^\s+disabled:/.test(next)) continue
    const indent = /^(\s*)/.exec(line)[1]
    out.push(`${indent}disabled: true`)
  }
  return out
}

/** Parse `preset.yml` (flat `key: value` pairs). */
function readPresetMeta(mode) {
  const text = readFileSync(join(SOURCE_ROOT, 'modes', mode, 'preset.yml'), 'utf8')
  const meta = {}
  for (const line of text.split('\n')) {
    const m = /^([a-z]+):\s*(.*)$/.exec(line)
    if (m !== null) meta[m[1]] = m[2]
  }
  if (meta.name === undefined) throw new Error(`${mode}: preset.yml has no name`)
  return meta
}

/** Build one ported preset file. */
export function buildPreset(mode, index) {
  const sourcePath = join(SOURCE_ROOT, 'modes', mode, 'agent.cordis.yml')
  const sourceText = readFileSync(sourcePath, 'utf8')
  const lines = sourceText.split('\n')
  const start = lines.findIndex((line) => /^- id: /.test(line))
  if (start < 0) throw new Error(`${mode}: agent.cordis.yml declares no plugin rows`)
  let rows = lines.slice(start)
  while (rows.length > 0 && rows[rows.length - 1].trim() === '') rows.pop()

  rows = rewriteSkillRoots(rows, skillRootsFor(mode, sourceText), mode)
  rows = disableForeignRows(rows)
  rows = addRealitySuffix(rows, mode)

  const meta = readPresetMeta(mode)
  // `plugins:` sits at 8 spaces, so its sequence entries start at 10. Every source row
  // is at column 0 and keeps its own relative nesting under that prefix.
  const indent = (line) => `          ${line}`
  const head = [
    `# Ported from dsh-redteam-model@1.1.1 modes/${mode}/ (MIT, © SeaOf0) onto DSH 0.2.x.`,
    `# Generated by scripts/port-redteam-modes.mjs — edit the source, not this file.`,
    `#`,
    `# The mode's persona, tool rows and skill roots are the source's own. Two changes:`,
    `#   · skill roots resolve from this package instead of 0.1.x \`baseUrl\`;`,
    `#   · rows naming @dsh-external/* are disabled (those packages are not installed;`,
    `#     enabled, a row that cannot mount marks the whole preset broken and the UI`,
    `#     picker silently drops it).`,
    `#`,
    `# The f2x layer is appended last: this plugin's tools, ledger, gates, blackboard,`,
    `# findings, OT module and console ride on top of the ported mode.`,
    `- insert:`,
    `    - id: f2x-preset-${mode}`,
    `      name: '@deepseek-ai/dsh-agent-preset'`,
    `      config:`,
    `        id: ${mode}`,
    `        name: ${JSON.stringify(NAME_OVERRIDES[mode] ?? meta.name)}`,
    `        description: ${JSON.stringify(meta.description ?? '')}`,
    `        order: ${String(orderOf(mode, index))}`,
    `        plugins:`,
  ]
  const body = rows.map((line) => (line === '' ? '' : indent(line)))
  const layer = [
    ``,
    `          # ── f2x layer: this plugin rides on the ported mode ──────────────────`,
    `          - id: f2x-redteam3000`,
    `            name: '@dsh-f2x/redteam3000'`,
    `            config:`,
    `              registerSkillProvider: false`,
    `              persistState: true`,
    ``,
  ]
  return [...head, ...body, ...layer].join('\n')
}

/** Copy a mode's skills and refs next to the ported presets, preserving the refs layout. */
function copyAssets(mode, { refs }) {
  const from = join(SOURCE_ROOT, 'modes', mode)
  const to = join(OUT_ROOT, mode)
  const skills = join(from, 'skills')
  if (existsSync(skills)) {
    rmSync(join(to, 'skills'), { recursive: true, force: true })
    mkdirSync(to, { recursive: true })
    cpSync(skills, join(to, 'skills'), { recursive: true })
  }
  if (refs) {
    const refsDir = join(from, 'refs')
    if (existsSync(refsDir)) {
      rmSync(join(to, 'refs'), { recursive: true, force: true })
      cpSync(refsDir, join(to, 'refs'), { recursive: true })
    }
  }
}

function main() {
  const requested = process.argv.slice(2).filter((arg) => !arg.startsWith('-'))
  const withRefs = process.argv.includes('--refs')
  const modes = requested.length > 0 ? requested : MODES
  for (const mode of modes) {
    if (!MODES.includes(mode)) throw new Error(`unknown mode: ${mode}`)
  }
  if (!existsSync(join(SOURCE_ROOT, 'modes'))) {
    throw new Error(`no modes/ under ${SOURCE_ROOT} — set REDTEAM_MODEL_ROOT`)
  }
  mkdirSync(OUT_ROOT, { recursive: true })

  for (const mode of modes) {
    const index = MODES.indexOf(mode)
    writeFileSync(join(OUT_ROOT, `${mode}.patch.yml`), buildPreset(mode, index), 'utf8')
    copyAssets(mode, { refs: withRefs })
    process.stdout.write(`  ported ${mode}${withRefs ? ' (+refs)' : ''}\n`)
  }
  // Every ported preset loads every mode's skills, so copy them all regardless of
  // which presets were asked for.
  for (const mode of MODES) copyAssets(mode, { refs: false })
  const shared = join(SOURCE_ROOT, 'shared', 'skills')
  if (existsSync(shared)) {
    rmSync(join(OUT_ROOT, SHARED_SKILL_DIR, 'skills'), { recursive: true, force: true })
    mkdirSync(join(OUT_ROOT, SHARED_SKILL_DIR), { recursive: true })
    cpSync(shared, join(OUT_ROOT, SHARED_SKILL_DIR, 'skills'), { recursive: true })
  }
  process.stdout.write(`  skills copied for all ${String(MODES.length)} modes + shared\n`)
  return 0
}

if (process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`) {
  process.exit(main())
}
