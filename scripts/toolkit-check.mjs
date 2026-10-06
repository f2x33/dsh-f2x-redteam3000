#!/usr/bin/env node
/**
 * toolkit-check — 逐条实测技能点名的工具路径，并守住一个已修过的路径缺陷。
 *
 * 为什么存在
 * ----------
 * `vendor/redteam-skills/*\/SKILL.md` 把工具写成绝对路径，agent 照抄执行。
 * 装没装、路径对不对，技能自己看不出来 —— 只能在现场报 `command not found` 才发现，
 * 而那时往往已经进入交战、正打着目标。
 *
 * 本脚本把"技能引用什么"和"机器上真有什么"对一次账：
 *
 *   · 需要的路径 = 从 SKILL.md 反向推导（不是手写清单；改了技能就跟着变，
 *     和 `check-tool-subsets.mjs` 同一个套路）
 *   · 实际状态   = 存在性 + 可执行位 + 已知工具真跑一次取版本号（"不要只看文件存在"）
 *   · 回归守卫   = 任何 SKILL.md 再出现 `~/.dsh/redteam/` 即 FAIL。
 *     `~/.dsh` **不是** `DSH_HOME`；默认安装里那条路径根本不存在，
 *     照它调用必然失败。历史缺陷：3 个技能用 `~/.dsh/...`、10 个用 `$DSH_HOME/...`，
 *     而 `fscan-intranet` 自己两套都写。
 *
 * Usage
 * -----
 *   node scripts/toolkit-check.mjs             # 对账并报告
 *   node scripts/toolkit-check.mjs --manifest  # 顺便写 $DSH_HOME/redteam/toolkit/清单.md
 *   node scripts/toolkit-check.mjs --json      # 机器可读
 *
 * 退出码非零 = 必需工具缺失或守卫触发，可直接用作发布前门禁。
 */
import { existsSync, readFileSync, readdirSync, statSync, accessSync, constants, writeFileSync, mkdirSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { homedir } from 'node:os'

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)))
const argv = new Set(process.argv.slice(2))
const asJson = argv.has('--json')
const wantManifest = argv.has('--manifest')

const DSH_HOME = process.env.DSH_HOME?.trim() !== undefined && process.env.DSH_HOME.trim() !== ''
  ? process.env.DSH_HOME.trim()
  : join(homedir(), '.dsh')
const TOOLKIT = join(DSH_HOME, 'redteam', 'toolkit')

/** Skill roots, same set `check-tool-subsets.mjs` walks. */
function skillRoots() {
  const roots = [
    join(packageRoot, 'skills'),
    join(packageRoot, 'vendor', 'redteam-skills'),
    join(packageRoot, 'vendor', 'reverse-skills'),
  ]
  const presets = join(packageRoot, 'presets', 'redteam-modes')
  if (existsSync(presets)) {
    for (const entry of readdirSync(presets)) {
      roots.push(join(presets, entry, 'skills'))
      roots.push(join(presets, entry, 'shared', 'skills'))
    }
    roots.push(join(presets, 'shared', 'skills'))
  }
  return roots.filter((root) => existsSync(root))
}

/** Every `.md` under the skill roots, with its path (for reporting the offender). */
function skillFiles() {
  const out = []
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const abs = join(dir, entry.name)
      if (entry.isDirectory()) walk(abs)
      else if (entry.name.endsWith('.md')) out.push(abs)
    }
  }
  for (const root of skillRoots()) walk(root)
  return out.sort()
}

/**
 * 按需项：缺失不算失败 —— 要么必须由操作者提供（私钥、GUI 工具），
 * 要么本脚本自己生成（清单）。
 */
const ON_DEMAND = [
  { re: /^vps\//, why: 'VPS 私钥与 vps.sh：必须由操作者提供，技能不代取' },
  { re: /\.jar$/i, why: 'GUI WebShell 工具：需自行获取' },
  { re: /^AntSword\//i, why: '蚁剑 GUI：需自行获取' },
  { re: /^Godzilla\//i, why: '哥斯拉：需自行获取' },
  { re: /^Behinder\//i, why: '冰蝎 GUI 及其 server/ 载荷文件：需自行获取' },
  { re: /^kimi-chrome/, why: 'Kimi WebBridge 本机桥：需用户装好浏览器扩展后自备' },
  { re: /^oneforall\//i, why: 'OneForAll 源码：需自建 .venv' },
  { re: /^清单\.md$/, why: '由本脚本 --manifest 生成' },
  { re: /^技能工具清单\.md$/, why: '由本脚本 --manifest 生成' },
]

/** 拿不到就说明从哪拿 —— 缺什么、怎么补，一次说清。 */
const ACQUIRE = {
  'chisel/chisel': 'apt install chisel',
  'dirsearch/dirsearch': 'apt install dirsearch',
  'dnsx/dnsx': 'apt install dnsx',
  'httpx/httpx': 'apt install httpx-toolkit（Kali 里 PD 版 httpx 的官方包名）',
  'katana/katana': 'apt install katana',
  'naabu/naabu': 'apt install naabu',
  'subfinder/subfinder': 'apt install subfinder',
  'fscan/fscan': 'GitHub Release shadow1ng/fscan',
  'fscan/fscan_linux_arm64': 'GitHub Release shadow1ng/fscan',
  'fscan/fscan_windows_x64.exe': 'GitHub Release shadow1ng/fscan',
  'gogo/gogo': 'GitHub Release chainreactors/gogo',
  'gogo/gogo_linux_arm64': 'GitHub Release chainreactors/gogo',
  'gogo/gogo_windows_amd64.exe': 'GitHub Release chainreactors/gogo',
  'frp/frps': 'GitHub Release fatedier/frp',
  'frp/frpc': 'GitHub Release fatedier/frp',
  'suo5/suo5-linux-amd64': 'GitHub Release zema1/suo5',
  'ksubdomain/ksubdomain': 'GitHub Release boy-hack/ksubdomain',
}

/**
 * 已知工具的取版本参数。不在表里的只查存在性 + 可执行位，不执行 ——
 * 有些工具的 `-h` 会打一整屏，也有会写文件的。
 */
const PROBE = {
  'fscan/fscan': ['-help'], // 注意：fscan 的 `-h` 是"目标主机"，不是帮助
  'gogo/gogo': ['-h'],
  'chisel/chisel': ['--version'],
  'frp/frps': ['-v'],
  'frp/frpc': ['-v'],
  'suo5/suo5-linux-amd64': ['--version'],
  'httpx/httpx': ['-version'],
  'subfinder/subfinder': ['-version'],
  'dnsx/dnsx': ['-version'],
  'naabu/naabu': ['-version'],
  'katana/katana': ['-version'],
  'ksubdomain/ksubdomain': ['--version'],
}

/** 裸命令 / 目录型前置条件：技能里不写成路径，但一样是硬依赖。 */
const BARE = [
  { name: 'nuclei', kind: 'command', acquire: 'apt install nuclei' },
  {
    name: '~/.local/nuclei-templates',
    kind: 'yaml-dir',
    path: join(homedir(), '.local', 'nuclei-templates'),
    acquire: 'nuclei -update-templates；GitHub 直连不通时用 codeload.github.com 拉 projectdiscovery/nuclei-templates',
  },
  {
    name: 'pd-httpx',
    kind: 'command',
    acquire: 'apt install httpx-toolkit 后软链到 ~/.local/bin/pd-httpx（切勿 pip install httpx）',
  },
]

/** 展开 `frp/{frpc,frps}` 这类花括号写法。 */
function expandBraces(path) {
  const m = /\{([^}]*)\}/.exec(path)
  if (m === null) return [path]
  return m[1]
    .split(',')
    .flatMap((part) => expandBraces(path.slice(0, m.index) + part.trim() + path.slice(m.index + m[0].length)))
}

/** 从技能正文里抽工具引用。 */
function references(files) {
  const found = new Map() // relPath -> { onDemand, why, seenIn:Set }
  const toolkitRe = /(?:\$DSH_HOME|~\/\.dsh)\/redteam\/toolkit\/([^\s`）)，、|"'*]+)/g
  const binRe = /~\/\.local\/bin\/([^\s`）)，、|"'*]+)/g
  for (const file of files) {
    const text = readFileSync(file, 'utf8')
    for (const re of [toolkitRe, binRe]) {
      for (const match of text.matchAll(re)) {
        const raw = match[1].replace(/[.,;:]+$/, '')
        if (raw === '') continue
        for (const rel of expandBraces(raw)) {
          const rule = ON_DEMAND.find((entry) => entry.re.test(rel))
          const existing = found.get(rel)
          if (existing !== undefined) {
            existing.seenIn.add(file)
            continue
          }
          found.set(rel, {
            rel,
            onDemand: rule !== undefined,
            why: rule?.why ?? ACQUIRE[rel] ?? '（技能未给出获取方式，需人工确认）',
            seenIn: new Set([file]),
          })
        }
      }
    }
  }
  return [...found.values()].sort((a, b) => a.rel.localeCompare(b.rel))
}

/**
 * 版本号提取：先认 `version` 关键字，再退回三段式。
 * 两个都认不出就只证明"它能跑" —— 探针的目的是证明可执行，不是精确报版本。
 * （直接用"第一个 \d+\.\d+" 会抓错：fscan 的 banner 里 `0.1`、`10.8.0` 都排在版本号附近。）
 */
function extractVersion(text) {
  const keyword = /version[^0-9]{0,12}v?(\d+\.\d+(?:\.\d+)?)/i.exec(text)
  if (keyword !== null) return keyword[1]
  // 前后都排掉 IP：只加前瞻不够 —— `1.1.1.1/24` 里 `1.1.1` 从第二个 `1` 起算，
  // 后面正好是 `/`，前瞻放行，于是示例网段被当成了版本号。
  const threePart = /(?<![\d.])v?(\d+\.\d+\.\d+)(?![\d.])/.exec(text)
  if (threePart !== null) return threePart[1]
  return ''
}

function probeVersion(abs, rel) {
  const args = PROBE[rel]
  if (args === undefined) return ''
  // ProjectDiscovery 系把日志写 stderr，纯 stdout 会是空的 —— 两股都要。
  const result = spawnSync(abs, args, { timeout: 5000, encoding: 'utf8' })
  if (result.error !== undefined) return '(执行失败)'
  const text = `${result.stdout ?? ''}${result.stderr ?? ''}`
  const version = extractVersion(text)
  return version !== '' ? version : '(可执行)'
}

/**
 * 找裸命令：先 PATH，再 `~/.local/bin`。
 * 后者是技能约定的包装器落点，但**不保证在 PATH 上** —— 找到了要提醒调用方用绝对路径。
 */
function locateCommand(cmd) {
  const pathDirs = (process.env.PATH ?? '').split(':').filter((d) => d !== '')
  for (const dir of pathDirs) {
    const abs = join(dir, cmd)
    if (existsSync(abs)) return { abs, inPath: true }
  }
  const localBin = join(homedir(), '.local', 'bin', cmd)
  if (existsSync(localBin)) return { abs: localBin, inPath: false }
  return undefined
}

const files = skillFiles()
const refs = references(files)

// ── 回归守卫：`~/.dsh/redteam/` 不是 DSH_HOME ────────────────────────────────
// 注意：守卫是对**正文**做子串匹配，不区分"真在这么写命令"和"只是在讨论这个坏写法"。
// 想引用这条规则时，写成 `~/.dsh` 前缀 + 文字说明，别把完整字面量原样抄进技能 —— 否则
// 说明文字自己就会触发守卫（本脚本初版就这么中过一次招）。
const guardOffenders = files.filter((file) => /~\/\.dsh\/redteam\//.test(readFileSync(file, 'utf8')))
const guardOk = guardOffenders.length === 0

const rows = refs.map((ref) => {
  const abs = join(TOOLKIT, ref.rel)
  const exists = existsSync(abs)
  let mode = ''
  let version = ''
  if (exists) {
    try {
      accessSync(abs, constants.X_OK)
      mode = 'exec'
    } catch {
      mode = statSync(abs).isDirectory() ? 'dir' : 'not-exec'
    }
    if (mode === 'exec') version = probeVersion(abs, ref.rel)
  }
  const satisfied = exists && (mode === 'exec' || mode === 'dir')
  return { ...ref, abs, exists, mode, version, satisfied, seenIn: [...ref.seenIn] }
})

const bareRows = BARE.map((entry) => {
  if (entry.kind === 'command') {
    const found = locateCommand(entry.name)
    return {
      ...entry,
      satisfied: found !== undefined,
      detail:
        found === undefined
          ? ''
          : found.inPath
            ? found.abs
            : `${found.abs}（不在 PATH：请用绝对路径，或软链到 /usr/local/bin）`,
    }
  }
  const dir = entry.path
  if (!existsSync(dir)) return { ...entry, satisfied: false, detail: '目录不存在' }
  let count = 0
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const abs = join(d, e.name)
      if (e.isDirectory()) walk(abs)
      else if (/\.ya?ml$/i.test(e.name)) count += 1
    }
  }
  walk(dir)
  return { ...entry, satisfied: count > 0, detail: `${String(count)} 个模板` }
})

const required = rows.filter((r) => !r.onDemand)
const missingRequired = required.filter((r) => !r.satisfied)
const missingBare = bareRows.filter((r) => !r.satisfied)
const failed = missingRequired.length > 0 || missingBare.length > 0 || !guardOk

if (wantManifest) {
  const lines = [
    '# 工具箱清单（由 scripts/toolkit-check.mjs --manifest 生成，勿手改）',
    '',
    `- 生成时间：${new Date().toISOString()}`,
    `- DSH_HOME：\`${DSH_HOME}\``,
    `- 工具箱根：\`${TOOLKIT}\``,
    '',
    '| 状态 | 相对路径 | 版本 | 缺失时的获取方式 | 被哪些技能引用 |',
    '| --- | --- | --- | --- | --- |',
  ]
  for (const row of rows) {
    const seen = row.seenIn.map((f) => f.replace(`${packageRoot}/`, '')).join('<br>')
    lines.push(
      `| ${row.satisfied ? '✅' : row.onDemand ? '➖ 按需' : '❌'} | \`${row.rel}\` | ${row.version !== '' ? row.version : '—'} | ${row.onDemand ? row.why : row.satisfied ? '—' : row.why} | ${seen} |`,
    )
  }
  lines.push('')
  for (const row of bareRows) {
    lines.push(`- ${row.satisfied ? '✅' : '❌'} \`${row.name}\` — ${row.detail !== '' ? row.detail : row.acquire}`)
  }
  lines.push('')
  if (!guardOk) {
    lines.push('> ⚠️ 回归守卫未通过：下列技能仍在使用 `~/.dsh/redteam/`（不是 DSH_HOME）：')
    for (const file of guardOffenders) lines.push(`> - ${file.replace(`${packageRoot}/`, '')}`)
  }
  mkdirSync(TOOLKIT, { recursive: true })
  writeFileSync(join(TOOLKIT, '清单.md'), `${lines.join('\n')}\n`, 'utf8')
}

if (asJson) {
  console.log(JSON.stringify({ dshHome: DSH_HOME, toolkit: TOOLKIT, guardOk, rows, bare: bareRows, failed }, null, 2))
} else {
  console.log(`DSH_HOME = ${DSH_HOME}`)
  console.log(`工具箱   = ${TOOLKIT}\n`)

  console.log('必需工具（技能按绝对路径调用）')
  for (const row of required) {
    const mark = row.satisfied ? 'ok  ' : 'MISS'
    const ver = row.version !== '' ? `  ${row.version}` : ''
    const hint = row.satisfied ? '' : `   ← ${row.why}`
    console.log(`  ${mark} ${row.rel.padEnd(32)}${ver}${hint}`)
  }

  const onDemand = rows.filter((r) => r.onDemand)
  if (onDemand.length > 0) {
    console.log('\n按需 / 由操作者提供（缺失不算失败）')
    for (const row of onDemand) {
      console.log(`  ${row.satisfied ? 'ok  ' : '--  '} ${row.rel.padEnd(32)}  ${row.why}`)
    }
  }

  console.log('\n裸命令与前置条件（依赖 PATH / 磁盘）')
  for (const row of bareRows) {
    console.log(`  ${row.satisfied ? 'ok  ' : 'MISS'} ${row.name.padEnd(32)}  ${row.satisfied ? row.detail : `← ${row.acquire}`}`)
  }

  console.log('\n回归守卫')
  if (guardOk) {
    console.log(`  ok   没有 SKILL.md 使用 ~/.dsh/redteam/ 路径（共扫 ${String(files.length)} 个 .md）`)
  } else {
    console.log(`  FAIL ${String(guardOffenders.length)} 个文件仍在用 ~/.dsh/redteam/（那不是 DSH_HOME）：`)
    for (const file of guardOffenders) console.log(`         ${file.replace(`${packageRoot}/`, '')}`)
  }

  console.log(
    `\n汇总：必需 ${String(required.length - missingRequired.length)}/${String(required.length)} 就绪` +
      `，裸依赖 ${String(bareRows.length - missingBare.length)}/${String(bareRows.length)}` +
      `，守卫 ${guardOk ? '通过' : '未通过'}`,
  )
  if (failed) {
    console.log('\n缺什么、从哪拿，见上表 `←` 后的说明；修完重跑本脚本。')
  } else {
    console.log('工具箱就绪。')
  }
}

process.exit(failed ? 1 : 0)
