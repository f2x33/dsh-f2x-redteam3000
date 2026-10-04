#!/usr/bin/env node
/**
 * Port `dsh-redteam-mode`'s agent preset onto DSH 0.2.x, with this plugin's layer added.
 *
 * Why a separate script from `port-redteam-modes.mjs`
 * --------------------------------------------------
 * That one ports `dsh-redteam-model`'s ten mode directories, which share a shape. This
 * preset comes from a different project with a different layout, and it needs two edits
 * the generic porter does not make. Keeping them apart means re-porting either upstream
 * cannot silently rewrite the other's output.
 *
 * The two edits
 * -------------
 * 1. **The source's `redteam-tools` row is replaced.** That tool set is vendored into
 *    this package (`vendor/redteam-tools`) and mounted by the generated preset as
 *    `f2x-rt-tools`, through this package's `./vendor/*` export — per-preset on purpose:
 *    `ctx.tools.register()` writes into the CALLING scope, so the 53 tool definitions
 *    are only paid for by the modes that use them. (Original note follows.)
 *    as a HOST bundle (`vendor/redteam-tools`), so its ~30 tools are already visible to
 *    every session. Mounting it again inside the preset would register them twice.
 *    The row in the source also uses a bare name (`dsh-redteam-tools`) that does not
 *    resolve to the scoped package this deployment has.
 * 2. **A `suffix` is added to the persona.** The source persona opens with "你是红队作战
 *    指挥智能体" — a commander. This deployment already has exactly one dispatcher
 *    (`redteam3000总调`), so the ported mode states its position rather than competing
 *    for it. The source text itself is untouched.
 *
 * Usage
 * -----
 *   REDTEAM_MODE_ROOT=/path/to/dsh-redteam-mode node scripts/port-redteam-mode-preset.mjs
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)))
// No author-machine default: this is a maintainer script that needs an upstream checkout.
// Set REDTEAM_MODE_ROOT to your clone, e.g. `REDTEAM_MODE_ROOT=/path/to/dsh-redteam-model node scripts/port-redteam-mode-preset.mjs`.
const SOURCE_ROOT = process.env.REDTEAM_MODE_ROOT ?? ''
const SOURCE = join(SOURCE_ROOT, 'preset', 'agent.cordis.yml')
const DEST = join(packageRoot, 'presets', 'redteam-modes', 'rt-drill.patch.yml')

/** The preset id and roster order this mode takes. */
export const PRESET_ID = 'rt-drill'
/** The loader row id, namespaced beside every other row this package inserts. */
export const ROW_ID = 'f2x-preset-rt-drill'
/** Roster order: after the ten specialists, so the dispatcher stays first. */
export const ORDER = 30

/**
 * The position statement appended to the source persona.
 *
 * Written as a statement of fact rather than an instruction to defer: the point is that
 * a reader (model or operator) knows where this mode sits, not that it should refuse work.
 */
/**
 * The vendored asset-ledger tool row, appended to every ported mode.
 *
 * `name` is a BARE package subpath on purpose. A preset row's `name` is not anchored
 * beside its patch file — `anchorInsertedPluginNames` rewrites relative names for
 * top-level insert rows and group children only — so a relative path resolves against
 * the PROFILE directory, points at nothing, and takes the whole preset down silently
 * (`broken` presets are filtered out of the UI mode picker). A bare subpath resolves
 * like any other specifier, through this package's `./vendor/*` export.
 *
 * ctf-solver / binary-analysis / av-evasion deliberately do not carry it: they never
 * touch the asset ledger, and the row costs them the full 53-tool definition per turn.
 */
export const VENDOR_ROWS = [
  '          # 资产台账工具行（53 个 redteam_*）：只在用得上它的模式里挂。',
  '          # 行名必须是**裸包名子路径**：anchorInsertedPluginNames 只锚定顶层 insert',
  '          # 与 group 子行，预设行的 name 落在 profile 目录解析——写相对路径',
  '          # 会指到不存在的文件，整条预设静默变 broken。',
  '          - id: f2x-rt-tools',
  "            name: '@dsh-f2x/redteam3000/vendor/redteam-tools/lib/index.js'",
]

export const RELATION_SUFFIX = [
  '【本模式在本部署中的位置】',
  '',
  '本模式是**执行层**，不是总入口。整个插件（@dsh-f2x/redteam3000）的**总指挥/总调度**是',
  '`redteam3000总调`（preset id `redteam`）：它负责判断任务类型、把任务派给专业模式、并汇总全局战果。',
  '',
  '在这里请专注做好**多角色演练的指挥执行**：',
  '- 本插件的编排工具与上游的 30 个 `redteam_*` 工具**都在场**，可直接调用。最常用的几个：',
  '  `f2x_orchestrate_doctrine`（开场自检）、`f2x_orchestrate_start`（开任务）、',
  '  `f2x_orchestrate_checkpoint` / `f2x_orchestrate_verify` / `f2x_orchestrate_mark`（证据→门禁→推进，唯一推进通道）、',
  '  `f2x_orchestrate_finding`（成果登记）；',
  '- 资产与得分都落进同一本 SQLite 台账（`redteam_engagement_open` / `redteam_score_hit` / `redteam_score_report`），',
  '  与其它模式共享——不要另起一本；',
  '- 若任务超出演练范畴（例如纯代码审计、应急溯源），在结论里建议用户切到对应专业模式，或回到 `redteam3000总调`。',
]

/** Indent one source row into the preset's `plugins:` list. */
const indent = (line) => (line === '' ? '' : `          ${line}`)

/**
 * Drop a top-level row and the block that belongs to it.
 *
 * @param rows - source rows, at column zero for top-level entries.
 * @param id - row id to remove.
 * @returns the rows without it, and how many were removed.
 */
export function dropRow(rows, id) {
  const out = []
  let removed = 0
  // An index loop rather than a for-of: consuming the row body advances the cursor past
  // the block, and a `continue` in a `for` loop would then step over the row that
  // follows. Measured on a fixture with no blank line between rows, that ate the next
  // row outright; the real source happens to have a blank line there, which hid it.
  let index = 0
  while (index < rows.length) {
    if (rows[index] === `- id: ${id}`) {
      removed += 1
      index += 1
      while (index < rows.length && rows[index].startsWith(' ')) index += 1
      continue
    }
    out.push(rows[index])
    index += 1
  }
  return { rows: out, removed }
}

/** Append a `suffix:` block to the first row that owns a `prefix:` block scalar. */
export function addSuffix(rows, suffix) {
  const at = rows.findIndex((line) => /^\s+prefix: /.test(line))
  if (at < 0) throw new Error('no persona row with a prefix block')
  const base = /^(\s*)/.exec(rows[at])[1]
  let end = at + 1
  while (end < rows.length) {
    const line = rows[end]
    if (line.trim() !== '' && /^(\s*)/.exec(line)[1].length <= base.length) break
    end += 1
  }
  const block = [`${base}suffix: |-`, ...suffix.map((line) => (line === '' ? '' : `${base}  ${line}`))]
  return [...rows.slice(0, end), ...block, ...rows.slice(end)]
}

/** Build the ported preset file's text. */
export function buildPreset() {
  // The source ships CRLF line endings, and a row compared with `===` would carry a
  // trailing `\r`. Normalising here also keeps the generated file LF, like every other
  // file in this repository.
  const text = readFileSync(SOURCE, 'utf8').replace(/\r\n/g, '\n')
  const lines = text.split('\n')
  const start = lines.findIndex((line) => /^- id: /.test(line))
  if (start < 0) throw new Error(`${SOURCE}: declares no plugin rows`)
  let rows = lines.slice(start)
  while (rows.length > 0 && rows[rows.length - 1].trim() === '') rows.pop()

  const dropped = dropRow(rows, 'redteam-tools')
  if (dropped.removed !== 1) {
    throw new Error(`expected exactly one redteam-tools row, removed ${String(dropped.removed)}`)
  }
  rows = addSuffix(dropped.rows, RELATION_SUFFIX)

  return [
    '# Ported from dsh-redteam-mode@0.12.5 preset/ (MIT, © Jueze-2019) onto DSH 0.2.x.',
    '# Generated by scripts/port-redteam-mode-preset.mjs — edit the source, not this file.',
    '#',
    "# The source's `redteam-tools` row is replaced by the vendored one below, mounted",
    "# through this package's `./vendor/*` export rather than a bare `dsh-redteam-tools`.",
    '# (vendor/redteam-tools), so mounting it here would register the same tools twice.',
    '# A `suffix` states this mode\'s position, because the source persona also calls itself',
    '# a commander and this deployment has exactly one dispatcher.',
    '#',
    '# The f2x layer is appended last, matching every other ported mode.',
    '- insert:',
    `    - id: ${ROW_ID}`,
    "      name: '@deepseek-ai/dsh-agent-preset'",
    '      config:',
    `        id: ${PRESET_ID}`,
    '        name: "红队演练模式（多角色）"',
    '        description: "多角色红队演练指挥：一发靶标即拉起信息收集/资产梳理/漏洞发现/漏洞利用/内网渗透五个执行角色，资产与得分落同一本 SQLite 台账。总调度是 redteam3000总调。"',
    `        order: ${String(ORDER)}`,
    '        plugins:',
    ...rows.map(indent),
    '',
    '          # ── f2x layer: this plugin rides on the ported mode ──────────────────',
    '          - id: f2x-redteam3000',
    "            name: '@dsh-f2x/redteam3000'",
    '            config:',
    '              registerSkillProvider: false',
    '              persistState: true',
    '',
    ...VENDOR_ROWS,
    '',
  ].join('\n')
}

function main() {
  if (!existsSync(SOURCE)) {
    throw new Error(`no ${SOURCE} — set REDTEAM_MODE_ROOT to the dsh-redteam-mode checkout`)
  }
  writeFileSync(DEST, buildPreset(), 'utf8')
  process.stdout.write(`  wrote ${DEST}\n`)
  return 0
}

if (process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`) {
  process.exit(main())
}
