# dsh-f2x-redteam3000

> **本项目是为 [deepseek-harness](https://github.com/deepseek-ai/deepseek-harness) 赋能的项目：先装好 deepseek-harness，再装本项目。**
>
> **请勿用于非法行为。** 本项目仅面向**已获得书面授权**的安全测试、CTF 竞赛、漏洞赏金与
> 安全研究场景。完整使用条款、风险与责任限制见 **[DISCLAIMER.md](DISCLAIMER.md)**；
> 本项目包含第三方材料，其版权与许可见 **[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)**。

一个面向 DeepSeek Harness 的**红队多模式插件**：12 个可选择的智能体模式，覆盖通用红队、
渗透、代码审计、逆向、攻防、免杀、云安全、应急溯源、CTF 解题、资产测绘，外加一个
**可插拔的能源/工控（OT/ICS）模块**。它不是某个行业专用工具——能源/工控只是一层可按需启用的覆盖层，面向能源类比赛与工控靶场。

所有工具注册在 `f2x_` 前缀、技能注册在 `f2x-` 前缀之下；本包不含任何与其它插件同名的工具行或技能名。

## 兼容性

| 面 | 状态 |
|---|---|
| Harness | DeepSeek Harness **`0.2.0-rc.2`**（本仓库当前实测的运行版本） |
| peer 声明 | `@deepseek-ai/cordis ^4.0.2`、`dsh-skill` / `dsh-tools` `>=0.1.2-rc.1 <0.2.0 \|\| >=0.2.0-0 <0.3.0`、`schemastery ^3.18.2` —— 两条版本线都覆盖，见下方说明 |
| Node | `^22.19.0 \|\| >=24.0.0`（`engines`） |
| 平台 | 全部（纯 ESM；无原生代码；加载时不联网） |

> `@deepseek-ai/*` 这些 peer 由 **DSH 安装自带**，不要用 npm 装（npm 上的版本比运行时旧）。

## 它提供什么

### 12 个模式（同一个插件，选择器里选）

| 顺序 | 模式 id | 选择器中的名称 | 定位 |
|---|---|---|---|
| 5 | `redteam` | **redteam3000总调** | 总调度：判断任务类型、路由给专业模式、汇总战果 |
| 21 | `pentest` | 渗透测试模式 | 黑盒渗透 |
| 22 | `asset-mapping` | 资产测绘模式 | 外部资产测绘与清册 |
| 23 | `attack-defense` | 攻防评估模式 | 红蓝对抗评估 |
| 24 | `av-evasion` | 免杀对抗模式 | 免杀与对抗 |
| 25 | `binary-analysis` | 二进制分析模式 | 逆向与二进制分析 |
| 26 | `cloud-security` | 云安全攻防模式 | 云与容器攻防 |
| 27 | `code-audit` | 代码审计模式 | 白盒代码审计 |
| 28 | `ctf-solver` | CTF 解题模式 | CTF 竞赛解题 |
| 29 | `incident-response` | 应急溯源模式 | 应急响应与攻击溯源 |
| 30 | `rt-drill` | 红队演练模式（多角色） | 多角色演练指挥：一发靶标拉起五个执行角色 |
| 100 | `f2x-power` | 能源比赛模式 | 能源/工控：四段式资产模型、OT 写门禁、防守方交付物 |

模式选择器**只对新建（blank）会话生效**——已存在的会话记得住自己创建时的模式。

### 15 个工具（`f2x_orchestrate_*` 12 个 + 经验库 `f2x_exp*` 3 个）

编排与门禁（指挥方的控制面）：

| 工具 | 用途 |
|---|---|
| `f2x_orchestrate_start` | 开启任务；用允许清单校验每一个目标 |
| `f2x_orchestrate_status` | 读台账：任务、阶段、门禁裁决、黑板、成果 |
| `f2x_orchestrate_switch` | 在通用平面与能源/OT 模块之间切换 |
| `f2x_orchestrate_blackboard` | IT 与 OT 共享的 `fact` / `intent` / `hint` 记录 |
| `f2x_orchestrate_checkpoint` | 记录证据检查点（`confirmed` / `partial` / `unknown`） |
| `f2x_orchestrate_verify` | 阶段门禁：PASS/FAIL + 显式列出未闭合缺口 |
| `f2x_orchestrate_mark` | 打卡推进：**唯一**允许推进阶段的通道，门禁未过即拒 |
| `f2x_orchestrate_scope` | 不启动任何东西，只校验目标是否在授权范围内 |
| `f2x_orchestrate_audit` | OT 审计门禁：未经确认的写操作一律拒绝 |
| `f2x_orchestrate_finding` | 自带的成果登记；转 `verified` 需要基线/差分/marker 三件套 |
| `f2x_orchestrate_doctrine` | 生效中的规则 + 运行时自检（有哪些可选能力、台账与知识库路径） |
| `f2x_orchestrate_export` | 交接文档：证据、门禁、审计轨迹、未闭合缺口 |

**经验库**（跨会话、跨模式共享的打法沉淀；见下节）：

| 工具 | 用途 |
|---|---|
| `f2x_exp` | 记一条经验（同题刷新不重复；按 kind 有默认时效） |
| `f2x_exp_search` | 召回：多词 OR 匹配、中文子串可查、按"匹配 × 使用 × 30 天半衰"排序 |
| `f2x_exp_work` | 治理：list / forget（归档不删）/ purge-expired / stats |

### 经验系统（本插件的跨模式记忆）

12 个模式共享**一本经验库** `<dshHome>/f2x-redteam3000/experience.db`（SQLite + FTS5）：

- **按"模式 × 工作目录"作用域**：渗透记的坑不会漏进代码审计的会话；同名目录不会串场（路径哈希）。
- **自动注入**：模式+工作目录有记录时，装配期注入一个 `<dsh-f2x-experience>` 标记块（预算 700 字符，
  超限先砍数据行）；**空库零成本**。
- **5 类记录**：`tactic` / `fingerprint` / `tooling` / `lesson` / `detect`，其中 `detect` 默认 30 天过期、
  `fingerprint` 180 天（到期退出自动注入，检索仍可命中）。
- **热度排序**：只有读全文才算一次"使用"，30 天半衰——久未使用的自然让位。
- **有界**：单作用域 400 条封顶，超限把最冷的**归档**（`experiences_archive` 表，可恢复）而不是删除。

技能与知识库：

```text
persona/                    模式定位（总调 / 电力覆盖层）
playbook/                   作业流程（七阶段 + 电力双通道）
skills/                     5 个通用技能（recon / asset-mapping / vuln-discovery /
                            exploitation / internal-pentest）
skills/power/               6 个电力技能（modbus / s7comm / iec61850 / scada-recon / traceback / dnp3）
refs/power/                 电力知识库（protocols / ics-attack / business-scenarios）
vendor/redteam-skills/      23 个红队技能（**上游 MIT 复制件**，见 THIRD-PARTY-NOTICES §1.5）
vendor/reverse-skills/      44 个逆向技能（**多数为上游 MIT 复制件**）
presets/redteam-modes/      10 个移植模式各自的 playbook 技能与知识树（含 shared/skills）
presets/dsh-0.2/            能源比赛模式的预设源
```

**技能是怎么到会话里的**（已实测，2026-10-03）：

每个模式的技能目录由预设行的 `skill-filesystem` 决定，10 个移植模式用 `customSkillDirs`
里的 JS 表达式**从插件包位置**解析根目录（`.../presets/redteam-modes/<模式>/skills`
＋共享的 `.../presets/redteam-modes/shared/skills`）：

| 模式 | 会话内可见技能数 | 技能根 |
|---|---|---|
| 10 个移植模式 | 33–90（各模式不同，取决于注入几个根） | 自己的 playbook 技能 + `shared/skills` 的 5 个通用技能 + 各模式互相引用的根 |
| `rt-drill` | 28 | 不设自定义根，走 DSH **原生技能发现**（`$DSH_HOME/skills`、`.dsh/skills`、`.agents/skills`） |
| `f2x-power` | 33 | 插件自带的 `<包>/skills` 与 `<包>/skills/power`（6 个电力技能） |

> **电力技能的作用域（已修复，2026-10-03 实测）**：`skills/power/` 曾与 `skills/` 一起从宿主行
> 发布到**全局技能层**，导致那 5 个电力技能出现在**每一个**模式的会话目录里（代码审计、逆向、
> 红队演练都看得到 Modbus/S7comm/IEC 61850）。现在宿主行设 `publishPowerSkillsGlobally: false`，
> 电力技能根只由**电力预设**通过 `customSkillDirs` 注入。清洁安装实测：`f2x-power` 见 5 个电力技能，
> `code-audit` / `rt-drill` / `pentest` / `ctf-solver` 均为 **0**。

### 是强制实施的安全，不是写在文档里的安全

- **允许清单默认拒绝**：空清单拒绝**每一个**目标；范围外目标被 `f2x_orchestrate_start` /
  `f2x_orchestrate_scope` 拒绝。
- **OT 写门禁**：寄存器写入、设定值变更、PLC 启停、固件下载、GOOSE 伪造、IED 配置，
  未经 `f2x_orchestrate_audit` 二次确认一律拒绝。
- **阶段门禁只认证据**：没跑过的门禁不算通过；阶段里没有 `confirmed` 检查点不能推进；
  记录在案的违规会阻断推进；电力模式下 `traceback` 门禁额外要求一份防守方检测结论。
- **上限都是配置项**：每目标并发 3、每阶段检查点上限、门禁有效期。

## 安装

```sh
dsh plugin --profile web add dsh-f2x-redteam3000     # npm
# 或本地开发用：
#   cd <checkout> && pnpm install && pnpm run build
#   dsh plugin --profile web add link:<checkout>
```

装完**重启 `dsh web`**，在**新建会话**的模式选择器里应看到 **12 个模式**。

**第一次用之前必须配授权范围，否则什么都不会开工。** 本插件默认拒绝：`allowedTargets` 为空时
**每一次 `f2x_orchestrate_start` 都会被拒**——刚装完看起来像坏了，就是这个原因。在 profile patch
（或 `cordis.patch.yml` 的插件行）里加上：

```yaml
- id: f2x-redteam3000
  config:
    allowedTargets:
      - '10.10.0.0/24'      # 支持 IPv4 / CIDR / 主机名 / 前导点域后缀（如 '.lab.example'）
```

然后在会话里跑一次 `f2x_orchestrate_doctrine`：它会打印当前生效的范围与各可选能力是否在场。
`f2x_orchestrate_scope` 可以在不启动任何东西的前提下校验某个目标是否在范围内。

**12 个模式随插件自己的 bundle patch 到达**（`dsh.bundle.patch` → `./cordis.patch.yml`，
其中内联了 `presets/**`）。不需要手工改 profile patch；但插件必须出现在
`dsh.profile.bundles` 里才会被激活。

**装完先验证预设真的挂上了**——预设里任何一行挂不上，整条模式会**静默**从选择器消失，
浏览器不报错：

```sh
DSH_HOME=<你的 dsh home> node scripts/verify-presets.mjs web
# 期望：all 12 preset(s) mount cleanly and are selectable.
```

想不碰在用 profile 就试，用一个临时 `DSH_HOME`：

```sh
export DSH_HOME=/tmp/dsh-f2x-scratch
dsh plugin --profile web --from-default-profile web
dsh plugin --profile web add dsh-f2x-redteam3000
```

卸载：`dsh plugin --profile web remove dsh-f2x-redteam3000`

**与 `dsh-plugin-guide check` 的已知偏差**：它报 `manifest-peers` 失败，因为它要求 peer 范围
**恰好等于**一个止于 `0.2.0` 之前的固定串；而 DSH 的实际门禁用
`semver.satisfies(runtime, range, { includePrerelease: true })` 比对，那个固定串匹配不了
`0.2.0` 正式版。本包因此声明 `>=0.1.2-rc.1 <0.2.0 || >=0.2.0-0 <0.3.0`，两条线都覆盖。

### 可选伴随能力（不是依赖）

本插件**探测**这些由别的插件提供的能力，在场时用它们，缺席时走自带退路：
`redteam_finding_register`、`redteam_coverage_mark`、`redteam_atlas_target`、
`campaign_memory_write`、`webshell_connect`、`stage_gate`。
`f2x_orchestrate_doctrine` 每次都会打印哪些在场。缺少它们不影响本插件工作。

## 控制台

插件在 Web 主机上提供一个**只读**页面：

```
http://127.0.0.1:<dsh web 端口>/f2x-console
```

渲染任务台账、黑板、成果、OT 审计轨迹与运行时自检。它挂普通 web 路由，**不走 `/api`**，
因此不需要会话 token。`f2x_orchestrate_doctrine` 会打印当前主机的确切路由。

## 配置

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `allowedTargets` | string[] | `[]` | 授权范围（IPv4 / CIDR / 主机名 / 前导点域名）。**为空 = 拒绝一切** |
| `extraSkillDirs` | string[] | `[]` | 追加到内置技能根之后的目录 |
| `enablePowerModule` | boolean | `true` | `false` 则完全剥离能源/OT 覆盖层 |
| `registerSkillProvider` | boolean | `true` | 把 `skills/` 与 `vendor/redteam-skills/` 发布到全局技能层；预设已按模式注入时应设 `false` |
| `publishPowerSkillsGlobally` | boolean | `true` | 是否**再**把 `skills/power/` 发布到全局层。裸宿主挂载默认 true；接了 `presets/` 的部署应在宿主行设 `false`，只让电力预设自己注入 —— 否则每个模式都会看到电力技能 |
| `persistState` | boolean | `true` | 台账持久化为 JSON；`false` 仅内存 |
| `stateDir` | string | `''` | 状态目录；空则 `<dshHome>/f2x-redteam3000` |
| `referenceRoot` | string | `''` | 只读参考树；空则 `$REDTEAM_REFS` → `<dshHome>/redteam-refs`（存在才用） |
| `maxConcurrencyPerTarget` | number | `3` | 每目标并发上限（门禁规则） |
| `maxCheckpointsPerStage` | number | `12` | 阶段饱和前的检查点上限 |
| `gateValidityStages` | number | `1` | 门禁裁决的有效推进次数 |

由 `src/config.ts` 的 Schemastery `Config` 校验。带注释示例见 `cordis.patch.yml`。

## 开发

```sh
pnpm install
pnpm run typecheck
pnpm test                                  # 180 个测试
node scripts/selfcheck.mjs                 # 29 项自检（含发布就绪）
node scripts/verify-presets.mjs <profile>  # 12 个预设是否都能挂载
node scripts/smoke-live.mjs                # 每个模式一次真实模型调用（要凭据）
node scripts/release-check.mjs --pack      # 发布闸门（含法律文件与 copyleft 检查）
```

源码分布：`src/scope.ts`（允许清单）、`src/skills.ts`（技能 provider）、
`src/orchestrate.ts`（台账/黑板/审计/门禁）、`src/experience.ts`（经验库）、
`src/index.ts`（工具与入口）。测试分层见 `TESTING.md`，发布流程见 `RELEASING.md`。

## 法律与许可

### 使用条款（摘要——全文见 [DISCLAIMER.md](DISCLAIMER.md)）

**仅限已获授权的合法用途。** 本项目是红队作业编排与知识工具，**只**面向已取得**书面授权**的
安全测试、红蓝对抗、CTF 竞赛、漏洞赏金与安全研究。用于未获授权的系统可能构成犯罪
（我国《刑法》第二百八十五条、第二百八十六条，《网络安全法》《数据安全法》；其他司法辖区另有规定）。

- **它会真实动作**——发网络流量、上传文件、建隧道、执行命令、使用凭据。只在可随时丢弃的
  隔离环境里运行，绝不要在存放私钥或生产数据的机器上跑。
- **配置不等于授权**：内置目标白名单是防误伤的技术闸门，**不是授权证明，也不是法律意见**。
- **按"现状"提供，无任何担保**；法律允许的最大范围内，作者对使用本项目造成的损害、
  数据丢失、服务中断、法律后果或第三方索赔**不承担责任**（MIT 的免责条款）。
- 工具产出的**得分/成果/报告仅供演练内部记录**，不构成审计结论。
- 你有责任遵守全部适用法律，包括出口管制与制裁规则。

### 第三方内容（完整清单与改动说明见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)）

本包**再分发了 MIT 授权材料**，必须保留其声明：

| 随包内容 | 许可 | 版权 |
|---|---|---|
| `dsh-redteam-model` v1.1.1 —— 移植的模式、playbook 与知识树（`presets/`） | MIT | © 2026 SeaOf0 |
| `dsh-redteam-mode` —— `vendor/redteam-store`、`vendor/redteam-tools`、`rt-drill` 预设 | MIT | © 2026 Jueze-2019 |
| `ljagiello/ctf-skills` —— `presets/redteam-modes/ctf-solver/refs` | MIT | © 2026 Lukasz Jagiello |
| `MyuriKanao/src-hunter-skill` —— `vendor/reverse-skills/pentest-tools/src-hunter` | MIT | © 2026 MyuriKanao |
| PayloadsAllTheThings 范例载荷（CTF 参考索引） | MIT | © 2019 Swissky |

许可原文随包分发（`presets/redteam-modes/UPSTREAM-LICENSE-MIT-*.txt`、
`vendor/redteam-skills/UPSTREAM-LICENSE-MIT-*.txt`，以及各目录旁的 `LICENSE`）。

**刻意不包含**：semgrep 开源规则集（Commons Clause / AGPL-3.0）与 NOP Team《Linux 应急响应手册》
（GPL-3.0）——它们与"本包按 MIT 分发"不兼容；用到它们的技能已改为"自行获取"，
方式见 THIRD-PARTY-NOTICES.md §3。

## 许可

[MIT License](LICENSE) © 2026 dsh-f2x-redteam3000 contributors。

### 关于本项目的性质（请读一下）

本包主体是一层**整合与适配**：把 MIT 授权的 `dsh-redteam-model`、`dsh-redteam-mode`
接入 DeepSeek Harness 的智能体预设并统一到同一工具前缀下，再加上本项目的工具
（分段编排台账、阶段门禁、经验库）、技能与文档。

其中相当一部分文本、技能与预设内容由 **AI 助手产出**，再由维护者审阅、整理与编辑。
纯机器生成部分的版权状态可能不确定；凡从上游再分发的部分均为 MIT 授权且保留其声明
（详见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)，其中记录了每条来源结论所依据的
逐字节比对方式）。

## 名字由来：要你命3000

这个命名是**向周星驰致敬**。`redteam3000` 里的 **"3000"** 取自他 1994 年的电影《国产凌凌漆》中那件经典搞笑武器
**「要你命3000」**（粤语「攞你命3000」）。

- **发明者**：罗家英饰演的「达闻西」（粤语谐音「达文西」），自称「费了一生的精力」研究成功。
- **外观与构成**：它不是什么高科技装置，而是用铁丝把西瓜刀、铁链、火药、硫酸、毒药、手枪、
  手榴弹、杀虫剂、三角锉等日常或违禁物品胡乱捆绑在一起的一串「烂东西」。
- **搞笑反差**：达闻西吹嘘它「每样都能独当一面，集中在一起威力惊人」，可还没等他展示，
  就被反派司令一枪打中手臂直接倒地，武器毫无作用——电影无厘头风格的集中体现，
  也是「达闻西」这个「无用发明家」人设的巅峰。

本插件借这个梗自嘲——而且**说实话也差不多**：它本身就是个**缝合怪**，是在一堆现成基础上缝出来的。
上游的模式、别人的技能与知识库、MIT 的组件，用本项目的编排层、门禁与台账像铁丝一样捆在一起；
每一样单拎出来都能独当一面，捆在一起是不是「威力惊人」，得由你实测。

但电影里真正的教训更值得记住——**再花哨的武器，也不该在关键时刻先把自己人放倒**。
所以本插件的经验召回是**防呆**的：注入文本会先被中和、并在出口自检，最坏结果只是「这一轮没有经验召回」，
绝不会让会话收不到你的指令（需要时可用环境变量 `DSH_F2X_EXPERIENCE_INJECT=off` 一键静音）。
