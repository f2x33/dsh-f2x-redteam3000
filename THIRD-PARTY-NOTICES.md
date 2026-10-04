# 第三方内容与许可声明 / Third-Party Notices

本包**不包含**任何 GPL、AGPL 或 Commons Clause 授权的内容。以下逐项列出随包分发的第三方
材料、其授权、版权归属，以及本项目对其所做的修改——这是许可证要求我们声明的最小集合。

> **作者注意（发布可保留）**：第 1.10 节列出仍需确认的条目。已确认的标 ✅ 并附**可复核依据**；
> 未确认的标 ☐。发布闸门（`node scripts/release-check.mjs`）会在存在 ☐ 时失败——
> 许可证声明的价值全在于准确，宁可留白也不许猜。

---

## 1. 随包分发的第三方内容

### 1.1 `dsh-redteam-store` / `dsh-redteam-tools`（`vendor/redteam-store`、`vendor/redteam-tools`）

| 项 | 内容 |
|---|---|
| 版本 | 0.11.4 |
| 来源 | <https://github.com/Jueze-2019/dsh-redteam-mode> |
| 版权 | Copyright (c) 2026 Jueze-2019 |
| 许可 | MIT |
| 分发的形式 | **原样 vendored**（把源码复制进本仓库的 `vendor/` 下，未作为依赖安装） |
| 本项目对其的修改 | ① **挂载方式适配**（未改上游源文件）：上游把 asset store 与 tool set 作为同一条预设行挂载；本项目把 store 留在宿主平面（`ctx.provide('redteam')` 每进程只能注册一次）、把工具行按模式挂载，并为工具包新增 `./vendor/*` 子路径导出以便从预设解析。② **`vendor/redteam-tools/lib/index.js` 有代码修改**：拆出 `applySubset(ctx, allowlist)`，把 53 个工具的注册改为走 allowlist；新增 `lib/ledger.js` 只注册 42 个（11 个模式挂子集，`rt-drill` 仍挂全量 53）；并压缩了 35 条工具/参数说明文案。**未改动任何 `name`/`type`/`required`/`enum` 与参数嵌套结构**（可用结构 diff 复核）。 |
| 许可全文 | `vendor/redteam-store/LICENSE`、`vendor/redteam-tools/LICENSE`（若上游未附，见上游仓库） |

### 1.2 移植的模式与预设（`presets/redteam-modes/*`）

| 项 | 内容 |
|---|---|
| 来源 | <https://github.com/SeaOf0/dsh-redteam-model>（v1.1.1）与 <https://github.com/Jueze-2019/dsh-redteam-mode> |
| 版权 | Copyright (c) 2026 SeaOf0；Copyright (c) 2026 Jueze-2019 |
| 许可 | MIT |
| 分发的形式 | **改编/移植**：由 `scripts/port-redteam-modes.mjs` 与 `scripts/port-redteam-mode-preset.mjs` 从上游 `modes/` 与 `preset/agent.cordis.yml` 生成 |
| 本项目对其的修改 | ① 行形状改为 DSH 0.2.x 的 `@deepseek-ai/dsh-agent-preset` 预设行；② 技能根改为本项目布局；③ 剔除上游引用的外来插件行；④ **追加本项目的层**（`f2x-orchestrate` 工具行、技能根、模式定位说明 `suffix`）；⑤ `rt-drill` 由 `port-redteam-mode-preset.mjs` 生成，并**替换**了上游的 `redteam-tools` 行为本仓库 vendored 的工具行；⑥ 为发布合规**移除了两棵第三方参考树**（见 §3）。`vendor/redteam-tools` 的改动见 §1.1。 |
| 上游原文 | 未随包分发；如需对照请从上游仓库获取 |

### 1.3 CTF 参考知识库（`presets/redteam-modes/ctf-solver/refs`，约 3.0 MB / 126 文件）

| 项 | 内容 |
|---|---|
| 版权 | Copyright (c) 2026 Lukasz Jagiello |
| 许可 | MIT（全文见 `presets/redteam-modes/ctf-solver/refs/LICENSE`） |
| 分发的形式 | 原样随包（含许可证文件） |
| 原始出处 | <https://github.com/ljagiello/ctf-skills>（版权人与仓库内 `LICENSE` 的 Lukasz Jagiello 一致） |
| 本项目对其的修改 | 无 |

### 1.4 `src-hunter`（`vendor/reverse-skills/pentest-tools/src-hunter`，约 3.8 MB）

| 项 | 内容 |
|---|---|
| 版权 | Copyright (c) 2026 MyuriKanao |
| 许可 | MIT（全文见 `vendor/reverse-skills/pentest-tools/src-hunter/LICENSE`） |
| 分发的形式 | 原样随包 |
| 原始出处 | <https://github.com/MyuriKanao/src-hunter-skill>（版权人与自带 `LICENSE` 的 MyuriKanao 一致） |
| 本项目对其的修改 | 无 |

### 1.5 技能与知识内容的来源（内容 SHA-256 全树比对）

判定方法：对**每一个文件**取 SHA-256，与上游检出（`dsh-redteam-model`、`dsh-redteam-mode`）
的全树哈希集合比对。与文件名无关——这正是前一版方法出错的地方。

| 区域 | 与上游逐字节相同 | 类型分布 | 判定 |
|---|---|---|---|
| `vendor/redteam-skills/` | **23 / 24** | 22 `.md` 与上游相同；1 个（`UPSTREAM-LICENSE-*.txt`）为本包加入；**1 个 `.md` 经本项目修改**（见下） | 上游复制件为主 |
| `vendor/reverse-skills/` | **115 / 373** | 130 `.md`、**6 个可执行脚本**（4 `.sh`、2 `.ps1`）、1 许可；**22 个 `.md` 的 `description` 经本项目压缩**（正文未改，见下） | 复制件为主 |
| `presets/redteam-modes/` | **1084 / 1118** | 约 1012 `.md`、**53 个可执行脚本**（`.py`/`.sh`/`.ps1`/`.js`/`.go`）、`.yaml`/`.json`/`.xlsx` 若干；**34 个文件经本项目修改** | **内容主体来自上游** |
| `skills/`（5 通用 + 6 电力） | **0 / 11** | — | 本仓库产出 |
| `persona/`、`playbook/` | 0 / 2、0 / 2 | — | 本仓库产出 |
| `refs/power/` | 0 / 7 | — | 本仓库产出 |

**本项目对上游内容所做的修改（与"复制"区分开）**：因为要移除反取证的义务性条款与幻影门禁引用，
本项目改写了下列属于上游复制件范围内的文件，因此它们**不再逐字节相同**：

- `presets/redteam-modes/attack-defense/skills/ad-playbook/SKILL.md`（§12 改为"痕迹与防守方可见性"）
- `presets/redteam-modes/av-evasion/refs/techniques/OPSEC_HARDENING.md`（§2 日志抑制 → 遥测面/detection gap）
- `presets/redteam-modes/av-evasion/refs/README.md`、`incident-response/refs/README.md`、
  `code-audit/refs/README.md`（索引行与已移除内容的说明）
- `vendor/reverse-skills/attack-chain/SKILL.md`（§七 痕迹清理 → 防守方可见性）
- `vendor/redteam-skills/frp-tunnel/SKILL.md`（授权句改写）
- 另有 **34 个 `SKILL.md` 只压缩了 frontmatter 的 `description`**（正文一字未动）：11 个移植模式的 playbook、`shared/skills/` 的 4 个，以及 `vendor/reverse-skills/` 的 22 个；判据关键词全部保留。
  逐字节命中的分母不变、分子相应减少：`vendor/reverse-skills/` 137→115、`presets/redteam-modes/` 1096→1084。

> 上面的数字可用 `node scripts/provenance-content.mjs --upstream <上游检出>` 复现。
> 数字会随修改浮动——**每次改动后重跑这条命令再更新本表**，不要沿用上一版数字。

> **更正记录（两次）**
> 1. 本节最初声称三个区域"与上游逐字节零命中"。方法用错：按**文件名**匹配，而移植时
>    `skills/x.md` 被改写成 `x/SKILL.md`，复制件因此全部漏检。
> 2. 第一次更正只发现了 `reverse-engineering/` 的 136 个文件，仍称 `vendor/redteam-skills`
>    为"本仓库产出"。改用内容哈希全树比对后事实相反：**`vendor/redteam-skills` 的 24 个文件
>    全部与上游相同**（例如 `active-scan/SKILL.md` ← `packages/redteam-bundle/skills/active-scan.md`）。
>    上一版结论的错误来源是：把"上游没有同名技能"当成了"内容不是复制来的"。
>
> **可复核的结论必须能重跑**：`node scripts/provenance-content.mjs`（本包自带，输出上面这张表）。

**许可义务**：以上复制件均为上游 MIT 材料（© 2026 SeaOf0 / © 2026 Jueze-2019）。随包分发须保留
版权声明与许可原文，已放：`presets/redteam-modes/UPSTREAM-LICENSE-MIT-dsh-redteam-model.txt`、
`vendor/redteam-skills/UPSTREAM-LICENSE-MIT-dsh-redteam-model.txt`、
`vendor/reverse-skills/UPSTREAM-LICENSE-MIT-dsh-redteam-model.txt`，以及各 vendor 目录内的 `LICENSE`。

**可执行内容的额外提醒（给再分发者）**：`presets/redteam-modes/` 里有 **53 个上游脚本**
（Python / Shell / PowerShell / Go / JS）。它们不是文档，是**会被执行的代码**。使用前请自行阅读；
本包不对其行为作任何担保（见 `DISCLAIMER.md` §3）。

**一处无法判定方向**：`vendor/reverse-skills/pentest-tools/src-hunter` 有 27 个文件同时与上游
`dsh-redteam-model` 相同，而该目录自带 `LICENSE` 标注 © 2026 MyuriKanao、上游为
`MyuriKanao/src-hunter-skill`。没有上游克隆无法判定谁先，因此**两份归属同时保留**
（本包已放入上游许可原文 + 该目录自带许可），任一方向的义务均已满足。

### 1.5b 各模式 playbook（`presets/*/*/skills/`，58 个）

**其中 56 个是上游 `dsh-redteam-model`（MIT，© SeaOf0）的逐字节复制**，2 个经过修改：
`audit-playbook`、`ir-playbook`（修改内容见 §1.2 与各文件内的"本环境工具现实"段）。

来源与依据：`scripts/port-redteam-modes.mjs` 从上游 `modes/` 生成这些预设；
逐字节 SHA-256 比对显示 56/58 与上游一致。

**许可义务**：MIT 要求保留版权与许可声明。因此随包附上上游许可原文两份：

- `vendor/redteam-skills/UPSTREAM-LICENSE-MIT-dsh-redteam-model.txt`
- `presets/redteam-modes/UPSTREAM-LICENSE-MIT-dsh-redteam-model.txt`

### 1.6 各模式知识树（`presets/redteam-modes/*/refs/`，约 1005 个 md）

| 项 | 内容 |
|---|---|
| 来源 | <https://github.com/SeaOf0/dsh-redteam-model> |
| 版权 | Copyright (c) 2026 SeaOf0 |
| 许可 | MIT（原文随包：`presets/redteam-modes/UPSTREAM-LICENSE-MIT-dsh-redteam-model.txt`） |
| 分发的形式 | **逐字节复制**：1005 个 md 中 **1003 个**与上游同一文件 SHA-256 相同（余 2 个为本地修改/新增） |
| 复现方式 | `node scripts/skill-provenance.mjs`（对 `SKILL.md`）与 §1.5 所述 SHA-256 比对方法（对 `refs/` 下 md） |

**这说明本包的知识内容主体是上游作品**，不是本项目作者编写——此前基于
"上游没有同名技能"的局部证据对 `refs/` 作出的"作者编写"判断是**错误的**，已按实测更正。
MIT 允许这种再分发，条件是**保留版权声明与许可原文**，即本节与随包的 LICENSE 文本。

其中 `ctf-solver/refs` 另含一份 MIT 库（版权人为 Lukasz Jagiello），许可原文在其目录内
（见 §1.3）；其 125 个 md 同时命中上游，说明两处来源都覆盖到了这些文件——两份 MIT 许可
均已随包，义务已满足。

### 1.9 本项目自身的部分（整合层与 AI 协助产出；按本项目许可证 MIT 授权）

| 路径 | 说明 |
|---|---|
| `lib/` | 构建产物（`tsdown` + `scripts/build-client.mjs`）；源码在仓库 `src/`，不随包分发 |
| `cordis.patch.yml` | bundle patch（`scripts/sync-presets.mjs` 由 `presets/**` 生成 + 宿主层行） |
| `persona/`、`playbook/` | 模式定位说明与作业流程文档 |
| `skills/f2x-*`、`skills/power/` | 本项目产出（0/11 与上游相同，见 §1.5） |
| `vendor/redteam-skills/`、`vendor/reverse-skills/` | **上游 MIT 复制件为主**（24/24 与 137/373，见 §1.5），非本项目产出 |
| `scripts/` | 维护脚本（sync/port/selfcheck/verify/smoke/release-check/provenance-audit/skill-provenance） |
| `refs/` | 上游参考树索引 |
| `LICENSE`、`NOTICE`、`DISCLAIMER.md`、`THIRD-PARTY-NOTICES.md`、`README.md`、`TESTING.md`、`RELEASING.md`、`HOW-TO-VERIFY.md`、`AUDIT-FIXES.md`、`DELIVERY.md` | 本项目文档与法律文件 |

> 覆盖性由 `scripts/provenance-audit.mjs` 断言：`package.json#files` 里每个路径都必须在本文件
> 被命名。它只能查"有没有声明"，不查"声明是否属实"——属实性由 §1.5/§1.5b/§1.6 的逐字节比对保证。

## 1.10 来源声明（发布前由维护者确认）

**本节不主张作者身份。** 它陈述的是"随包内容的来源已逐项核查，结论如下"。本项目大量内容由
AI 助手生成、再由维护者审阅整理，因此**不在此宣称任何文字由某个人独立创作**；纯机器生成
部分的版权状态可能不确定（见 `NOTICE` 的 "Nature of this project"）。随包再分发的上游材料
均为 MIT 授权，许可原文已随包。

| # | 事项 | 结论与依据 |
|---|---|---|
| A | `vendor/redteam-skills/*` | **23/24 与上游逐字节相同 → 上游 MIT 材料**（另 1 个经本项目改写；许可原文随包。§1.5 含两次更正记录） |
| B | `vendor/reverse-skills/*`（44 个） | **115/373 与上游逐字节相同**（含 6 个脚本）→ 上游 MIT 材料，许可原文随包；**22 个 `.md` 的 `description` 经本项目压缩**（正文未改），其余为 0 命中（§1.5） |
| C | `skills/*`（11 个，5 通用 + 6 电力） | **0/11 与上游相同** → 本仓库产出 |
| D | `presets/redteam-modes/` 整体 | **1084/1118 与上游逐字节相同**（含 53 个可执行脚本；**34 个经本项目改写**：22 个为合规改写 + 12 个仅压缩 `description`）→ MIT 材料，许可原文随包（§1.5 / §1.5b） |
| E | `presets/*/*/refs/`（1005 个 md） | **1003 个与上游逐字节相同** → MIT 材料，许可原文随包（§1.6） |
| F | `presets/redteam-modes/ctf-solver/refs` | MIT © Lukasz Jagiello — <https://github.com/ljagiello/ctf-skills>（§1.3） |
| G | `vendor/reverse-skills/pentest-tools/src-hunter` | MIT © MyuriKanao — <https://github.com/MyuriKanao/src-hunter-skill>（§1.4） |
| H | chanzi-rules（ChanziSAST 规则知识库） | **不随包分发**，仅作 `code-audit/refs/README.md` 的引用说明 → 无分发义务 |
| I | semgrep 开源规则集 / NOP Team 手册 | **不随包分发**（Commons Clause+AGPL-3.0 / GPL-3.0），见 §3 |

**复核方式（任何人可重跑，不依赖记忆）**：

```sh
node scripts/provenance-audit.mjs    # 随包每个路径是否都有来源声明
node scripts/skill-provenance.mjs    # 与上游逐字节比对：COPIED / MODIFIED / OWN
```

**维护者确认**（陈述"以上来源结论已核查，随包内容无来源不明项"）：

```
确认人：风二西   日期：2026-10-04
签名：风二西
```

## 2. 运行时依赖（不随包分发）

本项目不打包这些包，它们由 DSH 安装提供，按各自的许可授权：

`@deepseek-ai/cordis`、`@deepseek-ai/dsh-skill`、`@deepseek-ai/dsh-tools`、
`@deepseek-ai/schemastery`（`peerDependencies`）。

---

## 3. 因许可限制而**未**随包分发的内容

以下内容曾出现在开发环境的参考树中，**已从随包内容里移除**。它们是本包刻意不包含的部分，
不是遗漏：

| 内容 | 许可 | 为什么移除 | 使用者如何自备 |
|---|---|---|---|
| semgrep 开源规则集（`refs/standards/semgrep-oss/`，约 5.8 MB / 1081 文件） | **Commons Clause**（限制商业转售，非 OSI 开源）＋ `trailofbits/` 子目录为 **AGPL-3.0** | 随包再分发会把这些限制带给整个包，与本项目按 MIT 分发不兼容 | 从上游仓库自行获取，放到 `refs/standards/semgrep-oss/<语言>/`；`code-audit` 技能自带自建规则与 registry 兜底，缺它不影响基本使用 |
| Linux 应急响应手册（`refs/linux/cookbook-linux/`，约 400 KB / 17 文件） | **GPL-3.0**（NOP Team） | 同上：GPL 的传染性会使整个包必须按 GPL 分发 | 从上游获取，放到 `refs/linux/cookbook-linux/` |

两处引用已在技能文本中改为"本包不随附，自行获取"并注明许可，见
`presets/redteam-modes/code-audit/skills/audit-playbook/SKILL.md` 与
`presets/redteam-modes/incident-response/skills/ir-playbook/SKILL.md`。

---

## 4. 本项目的许可

本项目自身的整合层、工具、脚本与文档按 **MIT License** 授权（全文见 `LICENSE`，归属与来源
说明见 `NOTICE`）。**选 MIT 而不是 Apache-2.0 的理由是与上游一致**：随包内容主体来自 MIT
授权的上游项目（§1），本项目是其上的整合与适配层；同一份极简许可能减少使用者的合规负担，
也省掉解释两种许可差异的成本。

**再分发条件（全部由 MIT 决定）**：保留版权声明与许可原文即可 —— 即本文件、`NOTICE`、
`LICENSE`，以及 §1 各处的上游许可原文（`UPSTREAM-LICENSE-MIT-*.txt`、
`presets/redteam-modes/ctf-solver/refs/LICENSE`、两个 vendor 包的 `LICENSE`）。

## 5. 再分发者的义务（简表）

1. 保留本文件、`NOTICE`、`LICENSE` —— MIT 的全部条件就是保留版权与许可声明；
2. 保留 §1 各处的许可证原文（尤其 `ctf-solver/refs/LICENSE`、两份 `vendor` 的 MIT 文本）；
3. 不得把 §3 的内容打进你自己的分发（除非你按 GPL/AGPL/Commons Clause 各自的要求重新合规）；
4. 若你修改了本包，请在说明中标注你的改动（MIT 不强制，但有助于下游追溯）。

---

## 6. 待办（作者在首次发布前完成）

- [ ] §1.3 补上游仓库 URL；§1.4 补上游仓库 URL；
- [ ] §1.5 技能集合：确认原创并在此声明，或补来源与许可，或从包中移除；
- [ ] §1.6 逐项确认其余参考树的来源；
- [ ] 如将来要把 `semgrep-oss` 或 `cookbook-linux` 加回来，**先把项目整体改为兼容的 copyleft 许可**，
      不要以 MIT 名义分发它们。

> 本文件按各许可证的常见要求编写，力求准确，但**不构成法律意见**。涉及商用、
> 多地分发或合规审查时，请咨询律师。若发现任何一处归属或结论不准确，请开 issue ——
> 修正它比坚持它重要。
