# 审计发现 → 修复对照表

三份独立审计（安全闸门 / 内容 / 盲审）发现的问题，**逐条**对照现状。每条都写了**怎么自己验**。

**复现约定**：`DSH_HOME=<某 profile> node scripts/verify-presets.mjs <profile>` 确认 12 模式挂载；
下面的"实测输出"是在**从 tgz 干净安装**的 profile 里跑出来的，不是读代码推的。

---

## A. 已修并有实测证据

### A1 允许清单可自我扩权（审计 F-01，严重）
**原状**：`f2x_orchestrate_start{targets:["8.8.8.8"], allowlist:["*"]}` 在 `allowedTargets=[]` 时
返回 `Started`——被约束方自己给自己发了通配权限。

**现在**：
```
Refused: the wildcard "*" is not in the configured target range, so a task cannot grant it.
```
具名范围仍可按任务授权（保住原功能），只有通配符改为**仅能来自配置**。

### A2 门禁接受自报的 confirmed（审计 F-02，严重）
**原状**：`{summary:"done", evidence:"n/a", level:"confirmed", advance:true}` 一条就推进阶段。

**现在**：`confirmed` 必须带**真实证据指针**；`n/a`/`done`/`x` 等占位符不计（`isEvidencePointer`）。
口径是"只拒占位符、不评判质量"——`runs/recon-nmap.txt` 这类正常写法不受影响。

### A3 写操作自报成只读即免确认（审计 F-03，高）
**原状**：`operation:"register-read"` + `action:"PLC stop"` → 记成 `impact=read-only`、免确认。

**现在**：分类**从动作文本判定**（`src/conduct.ts`），不看自报类别；影响级别也按语义记。
```
【行为准则】删除 / 脱库 / PLC停机+确认
   Refused: "rm -rf /var/lib/mysql" is on the prohibited list and cannot be performed...
   Refused: "mysqldump production" is on the prohibited list and cannot be performed...
   Logged audit-1 [impact=reversible] on f2x-task-1: PLC stop
```

### A4 阶段可跨级推进 / 直接关账（审计 F-04，高）
**原状**：`checkpoint{stage:"internal-pentest", level:"confirmed"}` + `verify{advance:true}`
把 `recon` 阶段的任务送到 `traceback`；一条 `collection` 检查点直接把任务关掉。

**现在**：检查点与门禁都只允许**当前阶段或紧邻下一阶段**：
```
   Refused: cannot record a checkpoint for "internal-pentest" while the task is on "recon".
   Refused: cannot attest "collection" while the task is on "recon".
```

### A5 手写裁决被打卡消费（审计 F-05，高）
**原状**：`state.json` 里手写一个 `pass:true` 的裁决，`f2x_orchestrate_mark` 直接消费。

**现在**：裁决带**内容绑定的完整性凭证**（`verdictToken`/`verdictIsIntact`），被改写或凭空写入的
裁决无效。注意其边界（已写进代码注释）：**这不是签名**——能改状态文件的人可以重算凭证。
它移除的是"写一个 JSON 对象就通关"这条实际可被模型走到的路径。

### A6 八进制 IP 判定与实际连接不一致（审计 F-06，高）
**原状**：`010.0.0.5` 被插件当成 `10.0.0.5`（在 `10.0.0.0/8` 内），而系统实际连 `8.0.0.5`。

**现在**：**前导零八位组一律判非法**（`parseIpv4`）。判定与数据包目的地不一致，比不判定更危险。

### A7 配了 `:port` 的允许清单条目永不匹配（审计，中）
**现在**：条目按主机部分匹配（`10.0.0.5:502` 授权该主机）。

### A8 管理端点的 CSRF（盲审 F6，中）
**原状**：`/f2x-manager/install` 只做 loopback 校验，**不看 Origin/Referer**；且
`installPlugin` 的校验写着 `|| !specifier.startsWith('/')`——**把绝对路径当成接受的理由**，
恶意网页可让宿主安装任意包（代码执行）。

**现在**：
- 状态变更请求必须**同源**（Origin/Referer 为 loopback 且 Host 为 loopback；非浏览器客户端无
  这两个头时仍放行，因为不存在混淆代理风险）
- `isInstallableSpecifier`：**拒绝绝对路径、`../` 逃逸、裸 URL 协议**；保留
  `npm 名 / @scope/pkg / github:owner/repo / link:./dir / file:./dir`
- 回归测试 2 条（拒绝项 + README 里教用户用的写法必须仍被接受）

### A9 幻影配置（审计：只印在文案里）（中）
- `gateValidityStages`：**已实现**——裁决离开产出阶段超过 N 步即失效（默认 1 保持原行为）
- `maxConcurrencyPerTarget`：**明确标注为建议值**，不再暗示它在拦（插件无法观测扫描器自身的并发）

### A10 作者本机路径进包（盲审 F9，中）
**原状**：`scripts/*.mjs` 默认 `/root/f2x/...`、`refs/INDEX.md`、`cordis.patch.yml` 注释里的
`D:\2.dsh\...`；而自检只查一个配置项就说"无本机路径"。

**现在**：
- 脚本去掉作者默认值（改为**必须显式指定上游**：`--upstream <dir>` / `REDTEAM_MODEL_ROOT`）
- 文档与注释里的本机路径改为 `<checkout>` / `<plugin-root>` 占位符
- 自检的那条检查**改为扫描 `package.json#files` 里的全部发布内容**（.md 按文档处理，代码与配置严格查）

### A11 来源声明与事实相反（盲审 F3，高）——**我方法错，结论错**
**原状**：我用**按文件名**比对得出"vendor 技能与上游零命中"，并把它写进了法律声明。
移植时 `skills/x.md` 被改写成 `x/SKILL.md`，按名比对自然查不到。

**现在**（内容 SHA-256 全树比对，`scripts/provenance-content.mjs`）：

| 区域 | 与上游逐字节相同 |
|---|---|
| `vendor/redteam-skills/` | **24 / 24**（23 个 SKILL.md 全部来自上游） |
| `vendor/reverse-skills/` | **137 / 373**（含 6 个可执行脚本） |
| `presets/redteam-modes/` | **1103 / 1118**（含 **53 个上游脚本**：.py/.sh/.ps1/.js/.go） |
| `skills/` | 0 / 11（这才是本项目产出） |

`THIRD-PARTY-NOTICES.md` §1.5 已按事实重写，并**保留两次更正记录**（第一次只纠了一半）。
上游许可原文已放 3 份（`presets/redteam-modes/`、`vendor/redteam-skills/`、`vendor/reverse-skills/`）。

### A12 文档数字与代码不符（盲审 F8，中）
已更正：测试数 169→**182**、自检项 27→**29**、`skills/power` 5→**6**（新增 DNP3 技能）、
`rt-drill` 技能数、以及"每个技能都在 `f2x-` 前缀下"（**59 个上游技能并不带该前缀**，属勘误）。

### A13 `release-check --pack` 覆盖仓库内 tarball（盲审 F12，中）
**现在**：`pnpm pack --pack-destination <临时目录>`，不再写进仓库根。

### A14 内容层：反取证义务 / 幻影门禁引用 / "给名字即授权"（内容审计 B1–B4，发布阻断）
见下节 D：**部分已改，部分仍需按下面清单处理**。

---

## B. 新增：行为准则（用户直接要求）

`src/conduct.ts`——**分类由动作文本决定**，规则表可读（`f2x_orchestrate_doctrine` 会打印）：

- **PROHIBITED（硬拒，`confirmedBy` 无效）**：删数据/清日志/毁数据/勒索类；**整库导出·脱库**
- **NEEDS CONFIRMATION**：改口令、提权、持久化、抓哈希/爆破、上传马或隧道、横向、任何 OT 写、停服务
- **FREE**：扫描、探测、只读、被动抓包

中文规则用**子串匹配**（`\b` 对 CJK 无效），测试覆盖 9 条禁止 + 10 条需确认 + 6 条放行 + 绕过用例。

---

## C. 仍未闭合（**不隐瞒**）

| # | 事项 | 影响 |
|---|---|---|
| C1 | **插件不拦 shell** | 直接敲 `nmap` 它管不着；门禁只覆盖经它登记的动作。README 已按此改写，不再声称"数据包离开主机前就被拒绝" |
| C2 | 跨进程并发写 `state.json` 仍可能丢记录（审计 5/5 轮丢 28–30/60） | 台账在极端并发下不完整；已有 mtime 刷新与原子写，但无文件锁 |
| C3 | 内容层 6 项阻断项 | ✅ D1–D6 六项**均已处理**（见 §D）。仍待办：`refs/` 约 1000 篇未逐篇审（C4）、53 个上游脚本未逐个人读 |
| C4 | `cookbook-linux` / `semgrep-oss` 之外的 `refs/` 约 1000 篇未逐篇审 | 盲审最大盲区；来源已按内容哈希声明，但内容正确性未审 |
| C5 | 复现性测试在无上游检出时**跳过**（打印 skip 警告） | 跳过不是通过；作者需在有上游的机器上跑一次 |
| C6 | `ctf-solver` / `src-hunter` 的上游方向未定 | 两份归属同时保留，义务已满足，但方向未判 |
| C7 | 我的自检**挡不住语义与归属错误** | 盲审的结论，我接受：`vitest` 对 F1/F2/F4 的绕过路径原本零覆盖（现已补测试） |

---

## D. 内容层 6 项阻断项的现状（用户："不希望影响功能"）

| # | 阻断项 | 现状 |
|---|---|---|
| D1 | 反取证的**义务性**要求 | ✅ **已改**：`ad-playbook` §12 整节替换为「痕迹与防守方可见性」（审计痕迹面清单 + detection gap 判定；**只清攻击方自己留的物，不动目标方日志/告警/取证数据**）；persona 的"清理目标侧攻击痕迹"改为"只清自己创建的物件"；vendor `attack-chain` §七「痕迹清理（Anti-Forensics）」整节替换；`OPSEC_HARDENING.md` 的「日志抑制」小节（含 `wevtutil cl`、Phant0m 停日志线程、覆写 PEB 命令行）替换为遥测面盘点表 + detection gap。**index 行（描述与路由）同步更新**，避免索引与正文不符 |
| D2 | OT "幻影门禁"引用（`ot_guard.py` 不存在） | ✅ **已改**：5 个电力技能顶部加上明确说明——该脚本**本插件不随包提供**，用前需自建；并指向**真实生效**的门禁 `f2x_orchestrate_audit`（含"写操作无 confirmedBy 一律拒绝、删除与脱库硬拒"的口径）。**不再声称该脚本层面的保护** |
| D3 | "给单位名即已授权" | ✅ **已改**：改为"授权边界以操作者声明的范围为准 + 开工前用 `start` 的 targets/allowlist 写清范围 + 跑一次 `f2x_orchestrate_scope`，范围外目标停下来问一次、不自行扩大；开工后不反复问"。宿主 `cordis.patch.yml` 同步（12 个文件） |
| D4 | 把"请先获得书面授权"当故障 | ✅ **已删**：`ecosystem-cooperation` 的「反拒绝兜底」整节移除并留痕说明；16 个文件里的 `dsh-refusal-guard` 与"升级梯修复"描述一并清除 |
| D5 | 平台安全提醒被判为"噪声"（20 处共性条款⑪） | ✅ **已改**：改为"控制指令（只读/沙箱/审批/工具限制）必须遵守；**授权提醒与内容政策提示不是噪声**——若它让范围或授权产生疑问，停下来向操作者确认，而不是绕过去" |
| D6 | 技能层对 `f2x_orchestrate*` 门禁引用为 0 | ✅ **已改（一处覆盖全部）**：改为在**技能 provider 服务内容时统一注入前置提示**（`SKILL_GATE_PRELUDE`，`src/skills.ts`），所有 34 个技能都会先看到"开工前跑 start/scope、写操作过 audit、gate 过 verify/mark"。**同一段落里如实写明边界**："只约束经本插件登记的动作；shell 里直接敲的命令它看不到也拦不住"。测试锁定该前置块存在（183 测试） |

**注意**：其中 D3/D4/D5 不是"改错字"，而是要决定**这个工具要不要教使用者绕开授权确认与安全提醒**。
用户已表示"按你的来"，因此按保守方向处理：**D3 改为"以声明的范围为准、未声明的目标动手前一次性确认"**
（保留"不反复问"的原意，去掉"给名字即授权"）；**D4/D5 删除**（工具不应当把提醒授权的声音当故障）。

---

## 怎么自己验（不需要懂代码）

```bash
npx tsc --noEmit && npx vitest run          # 182 测试
node scripts/selfcheck.mjs                  # 29 项（含"无作者本机路径"扫全部发布内容）
node scripts/provenance-content.mjs         # 来源哈希表（需 --upstream，避免作者默认路径）
node scripts/release-check.mjs --pack       # 发布闸门（打包到临时目录，不动仓库）
bash run-verification.sh                    # 干净安装：12 模式 + 12/12 可调工具
```

**当前闸门状态**：只剩两项——`package.json` 的 `repository/homepage/bugs` 仍是 TODO、
`THIRD-PARTY-NOTICES.md` §1.10 的"确认人/日期"未签。**这两项需要作者本人提供，我不代填。**


---

# 第二轮对抗审计（round-2）的结果与修复

第二轮审计的结论是：**9 条声称里 4 条只做了一半、3 条实质没修、2 条站得住**，根因是
**"检查加在了函数上，没加在调用路径上"**。这一节记录它的发现与修复，每条都用自己的复现手法复验过
（测试文件 `tests/round2-fixes.test.ts`，5 组断言）。

## R1 · F-05 是死代码 —— ✅ 已修（本次最严重）
`verdictIsIntact` 写好了、也测了，但 `f2x_orchestrate_mark` **一次都没调用它**，打包器还把它当死代码
消掉了（`grep -c verdictIsIntact lib/index.mjs` = 0）。手写 `state.json` 里的裁决照样被消费并推进阶段。
**修复**：校验加进 `mark` 的**消费路径**，`src/index.ts` 里现在有真实调用点（3 处：import + 注释 + 调用）。
**复验**：`mark` 在无裁决时拒绝。

## R2 · F-01 只拦了字面 `*` —— ✅ 已修
空配置下 `allowlist:["8.8.8.8"]` / `["0.0.0.0/0"]` / `["victim.example.net"]` 全部 `Started`，
而且该值被存成任务自己的 `allowedTargets`，后续检查全部通过。
**修复**：操作者的范围是唯一权威——**配置为空则任何任务都不能开工**；具名条目只能**缩窄**（必须是配置范围的子集）。
为此新增 `entryCovers()`（**范围包含范围**，与 `matchEntry` 的"主机在范围内"是两回事——上一版用错函数，
导致合法缩窄 `10.10.0.0/24 ⊂ 10.0.0.0/8` 被误拒，而"修复"这种误拒的自然做法就是不再检查，洞就是这样重开的）。
**复验**：4 种自我授权写法全拒；合法缩窄仍通过。

## R3 · F-04 阶段守卫 off-by-one —— ✅ 已修
允许"提前验下一阶段" + `advance: true` = 一次推进两格；8 次调用把 recon 任务直接关账。
**修复**：检查点与门禁都**只允许当前阶段**。README 里"mark 是唯一推进路径"这句现在**才是真的**。
**复验**：验未来阶段、记未来阶段的点、直接跳 collection 全部被拒。

## R4 · F-03 分类器双向失效 —— ✅ 已修
`{operation:"register-read", action:"把保持寄存器 40001 设为 100"}` 记成只读免确认；
"Change the administrator password" / "Establish persistence via WMI" / "添加一个隐藏账号" 全 free；
`switch{mode:'general'}` 还能把同一动作从"需确认"降级为免费。
**修复**：① 补中文写动词（设为/设为/改成/置为/初始化为/隐藏账号…）；② **未分类动作一律需确认，与平面无关**
（删掉 `task.mode === 'power'` 这个降级条件）；③ 新增"含糊动作"档——描述太笼统（"处理一下"/"handle it"）
不再免费，而是要求说清对象。
**复验**：中文写意图、WMI 持久化、隐藏账号均需确认；真只读仍放行。

## R5 · 内容层：旧授权条款仍在**分发主路径**上 —— ✅ 已修
之前只改了 `presets/` 与 `cordis.patch.yml` 的展示文本，而**子智能体提示词的真正来源**
`vendor/redteam-store/lib/{core.js,prompts.src.js,prompts.roles.md}` 里还有 12 处
"用户给出靶标单位名称即代表已获授权，不要询问授权范围"。
**修复**：三个文件全部改写为"授权边界以操作者声明的范围为准 + 范围外的目标停下来问一次"。
**注意**：这次替换一度**破坏了 JS 字符串字面量**（新文本里的反引号终止了模板字符串），导致
`f2x-rt-store` 无法导入、9 个预设 `never started`。已修复，并**新增随包 JS 的 `node --check` 闸门**——
之前 `vitest`（只读 src/）、`selfcheck`（查路径与文档）、`tsc` **都不会发现**这类故障，
只有 profile 启动时才炸。

## R6 · 新引入的问题 —— ✅ 已修
- `evidence:"n/a"` 会**永久卡死**该阶段（没有删除/修改检查点的工具）→ 改为**自动降级为 `unknown`**：
  不满足门禁、不误导、也不堵死，之后仍可记录真实检查点。
- 审计同时指出 `SKILL_GATE_PRELUDE` 的三句安全保证需要复核 —— 该前置块已如实写明
  "只约束经本插件登记的动作；shell 里直接敲的命令看不到也拦不住"。

## R7 · 作者自检强化（针对"自检挡不住语义错误"）
- 新增 **随包 JS 语法闸门**（36 个文件 `node --check`；上游那 1 个"命名是 .js、内容是 Markdown"的文件
  记入 note 而非失败）
- 新增 **`entryCovers` 的范围包含测试**（`tests/round2-fixes.test.ts`，5 组）
- 测试数：**183 → 188**

## 仍未闭合（第二轮确认）
- ~~并发写 `state.json` 丢记录~~ → ✅ **已修（本轮）**：`update()` 的"读→改→写"现在整段持一把**文件锁**
  （`wx` 排他创建即获取；持锁者写 pid，等待者可清理死进程留下的锁；10s 视为陈旧）。
  **反向验证**：把锁临时去掉 → **丢失 29/60**（与两轮审计报的 28–30 一致）；装上锁 → **0 丢失、0 重复 id**。
  检查已进发布闸门（`scripts/race-check.mjs`，3 进程 × 10 条，秒级）。
  注意：`refresh()` 也移进了锁内——在锁外读会拿到别人提交前的副本，那正是这个竞态本身。
- **插件不拦 shell**：本质限制，已在 README 与技能前置块中如实声明
- `refs/` 约 1000 篇与 44 个 reverse 技能：只做模式扫描，未逐篇审
- 两件只能作者做的：`package.json` 的 `repository/homepage/bugs`、`THIRD-PARTY-NOTICES.md` §1.10 的确认人签名


---

# 第三轮对抗审计（round-3）的结果与修复

第三轮结论：**3 条站得住 / 2 条只做了一半 / 2 条与声称不符**，另发现 1 个潜伏缺陷与 2 类可用性回归。
它的判定方法值得记下：**全部结论都走真实工具调用路径**（`apply()` + `ctx.tools.execute`），
函数级单测一律不作证据。

| # | 它的发现 | 修复 | 复验 |
|---|---|---|---|
| V1 | 【严重】**`command` 字段完全不参与分类**——`{action:"read registers", operation:"register-read", command:"rm -rf /var/lib/mysql"}` 被记成 `impact=read-only` 免确认 | 分类器把 `command` 一起读 | `rm -rf`/`mysqldump` 塞进 `command` 也硬拒；真只读仍放行 |
| V2 | 任务范围存的是 **union**，"缩窄"等于没缩 | 存**缩窄后的集合**；`f2x_orchestrate_scope` 默认改用**当前任务**的范围（原来只在显式传 `taskId` 时用） | 任务外的 `10.20.0.5` 现在被判 outside |
| V3 | `10.0.0.5/32` 被误拒（当成"放宽"） | `/32` 按单主机处理 | 合法缩窄通过 |
| V4 | 只允许当前阶段**把正常回补也堵死了** | 允许**回补重验已完成阶段**，仍禁止前跳 | 前跳被拒、回补可用 |
| V5 | `node --check` 闸门**可被绕过**（启发式把真语法错误判成 "prose" 放过）；声称 36 实际 37 | "非代码"改为**显式清单**（新文件必须能解析，加入清单需显式动作） | 37 个文件全过，清单内 1 个记为 note |
| V6 | 装饰过的占位符照样算 confirmed（`"n/a."` / `"done."` / `"待定。"`） | 判定前先**归一化**（去尾部标点、全角、markdown 装饰） | 三种写法都被降级为 `unknown` |
| V7 | 旧授权条款**仍在 26 行随包内容**里（14 行在真正挂载的技能根） | 逐条改写全部变体（"命名即授权、不逐任务复核"→"以声明的范围为准"） | 该类表述已清零 |

**仍未闭合（第三轮补充）**：
- **占位符/未解决检查点仍会永久阻塞阶段**（`unknown` 是永久 gap，无删除/修改检查点的工具）。
  已把占位符降级为 `unknown` 并给出可继续记录的路径，但**没有提供删除检查点的工具**——
  操作者只能继续记录一条合格检查点来满足门禁。
- 第三轮**没有审计**本轮新加的文件锁本身（它的盲区，已在报告 §5 声明）。


---

# 第三轮审计的后续修复（它回报的完整清单）

第三轮判定：**3 项站得住 / 2 项只做了一半 / 2 项站不住**，另有 1 条**新回归**与 4 类可用性回归。

## 已修

| # | 发现 | 修法 | 复验 |
|---|---|---|---|
| W1【新回归】 | 我把 `verify` 放宽成"允许回验早前阶段"却**没同步 `advance`**：`verify{stage:"recon",advance:true}` 让已到 `exploitation` 的任务**倒退**回 `asset-mapping`，`mark` 随后复用**旧裁决**再打卡 | `advance` 只在**验的正是当前阶段**时生效；回验早前阶段只记录不移动 | `round3-fixes` 断言：任务仍在 `asset-mapping`、输出含 "advance ignored" |
| W2 | 写意图仍是词表：`调成/调整/change … to/寄存器 = 100` 配 `register-read` → 记 `read-only` 免确认；`导出用户表全部记录为 csv` 同样洗白 | ① 只读类**必须有正向只读信号**（`declaresReadIntent`）才可信；② 补中文写动词（调成/调为/设定/导出为…）；③ 批量导出进**禁止表** | 三种写法全部被拒；`nmap -sV` 仍放行 |
| W3 | 占位证据：`unknown`/`not applicable`/`see notes`/`待补充` 仍算 confirmed | 占位符表补全（含 `n.a.`/`暂无`/`未知`/`不适用`/`见备注` 等） | 8 种写法均被降级 |
| W4 | **可用性回归**：`nmap -sV` 被拒（修复前是 `Logged`）；确认后的**读**操作被记成 `impact=reversible` | 正向只读信号覆盖常见读取动词与工具名；只读类确认后记 `read-only` | `nmap -sV` 放行且记 `read-only` |
| W5 | **永久卡死**：`n/a` 降级为 `unknown` 后该阶段无工具可清理 | `f2x_orchestrate_checkpoint` 新增 `action:"delete"` + `id`；删除时**同时作废**该阶段的旧裁决（它由被删检查点推导而来） | 测试覆盖：删掉占位检查点 → 记录合格检查点 → 门禁 PASS |

测试数 **194 → 198**。

## 仍未闭合（第三轮后续）

- **分类器仍是词表**：本轮补了定向变体，但 fuzz 级变体（零宽字符、繁简混排、任意同义词）仍可能漏。
  根本修法是**只读类必须由调用方提供可验证的只读证据**（例如引用具体只读命令的完整 argv），
  或干脆**取消"声明只读即免确认"这条路**——让所有操作都要确认。后者最安全，代价是可用性。
  **这是一个产品取舍，我不擅自决定。**
- **可用性 vs 严格性**：把未分类一律设为需确认，必然误拦一些正常只读操作（本轮已收窄，但没消除）。
- 第三轮**未审**新加的文件锁本身、未起真实 profile、manager/console 端点未审（它的盲区）。
