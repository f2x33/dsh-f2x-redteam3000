# 预设（agent presets）——两代格式与坑

本插件提供 **12 个模式**：**1 个总调度（`redteam3000总调`）** + **11 个专业**。分两族：

**A. 直接编写（本仓库）** —— 文件在 `presets/dsh-0.2/`

| 模式 id | 用途 | 文件 |
|---|---|---|
| `f2x-power` | **能源比赛模式**（OT 写门禁 + 审计） | `dsh-0.2/f2x-power.patch.yml` |

**B. 从 `dsh-redteam-model` 移植** —— 文件在 `presets/redteam-modes/`

| 顺序 | 模式 id | 用途 |
|---|---|---|
| **5** | `redteam` | **总调度** —— 安全总入口、任务路由、多任务协同（跑分等综合性工作由它调度专业模式） |
| 21 | `pentest` | 渗透测试 |
| 22 | `asset-mapping` | 资产测绘 |
| 23 | `attack-defense` | 攻防评估 |
| 24 | `av-evasion` | 免杀对抗 |
| 25 | `binary-analysis` | 二进制分析 / 逆向 |
| 26 | `cloud-security` | 云安全攻防 |
| 27 | `code-audit` | 代码审计 |
| 28 | `ctf-solver` | CTF 解题 |
| 29 | `incident-response` | 应急溯源 |
| 30 | `rt-drill` | 红队演练（多角色，来自 `dsh-redteam-mode`） |

移植族由 `scripts/port-redteam-modes.mjs` 生成，做三处必要转换（形状 / 技能根 / 外来插件行），
并追加本插件的层与一段「本环境工具现实」。**改这些文件请改源（`dsh-redteam-model/modes/`）后重跑脚本。**

`presets/f2x-*/preset.yml` + `agent.cordis.yml` 之类的**兄弟目录是 DSH 0.1.x 的格式**，在 0.2.0 上
不被读取，已在移植后移除以免混淆。

---

## 1. 两代格式的差别（坑 1）

| | DSH 0.1.x | **DSH 0.2.0** |
|---|---|---|
| 包名 | `dsh-agent-presets`（复数） | `dsh-agent-preset`（单数）+ `-registry` |
| 预设发现 | 扫文件系统目录（`Config.roots`） | **不扫目录**；`Config` 只有 `default` / `selectedDefault` |
| 声明方式 | 每模式一个 `agent.cordis.yml` | **行内** `insert:` + `plugins:` 清单 |

0.2.0 下预设就是 profile patch 里的一条 `- insert:` 记录：

```yaml
- insert:
    - id: preset-f2x-bench
      name: '@deepseek-ai/dsh-agent-preset'
      config:
        id: f2x-bench
        name: 'f2x 跑分/测评（redteam3000）'
        order: 10
        plugins: [ ... ]
```

`insert` 不给 `id` 就是追加到根条目列表（schema：*"An insert appends entries, optionally inside the group identified by id"*）。

## 2. 技能根不能用相对路径（坑 2）

`skill-filesystem` 的 `customSkillDirs` 用 `resolve(root)` 锚定 **cwd**，而 `!!js` 里的 `baseUrl` 在 0.2.0 行内格式下是 **profile 目录**，不是仓库目录。所以必须**从插件包位置解析**：

```js
const pk = m.createRequire(baseUrl).resolve('dsh-f2x-redteam3000/package.json')
p.join(p.dirname(pk), 'skills')          // 通用技能
p.join(p.dirname(pk), 'skills', 'power') // 电力技能
```

这样插件装在什么位置都对。**不要改回相对路径。**

## 3. ⚠️ 最隐蔽的坑：broken 预设会从 UI 里静默消失

DSH 在**注册预设时立即挂载**它的 `plugins:` 列表（registry 的 `register()` 会 `await activate()`）。**任何一行挂载失败，整个预设被标记 `broken`**：

```
agent preset f2x-power: tool-todo (@deepseek-ai/dsh-tool-todo): invalid config:
  - $.allowParallelInProgress missing required value
```

而 Web UI 的模式选择器**会把 broken 预设直接过滤掉**：

```js
// dsh-client-ui-agent-preset/lib/client.js
presets.filter((preset) => preset.broken === void 0)
```

**症状**：三个模式在 UI 里完全不出现，浏览器控制台也没有任何报错，日志里只有一条容易被忽略的 `logger.warn`。本项目就踩过这个坑——预设里这两行当时没带 `config:`：

| 插件行 | schema 必填键 |
|---|---|
| `@deepseek-ai/dsh-tool-fs-search` | `sampleOverCapGlobResults` |
| `@deepseek-ai/dsh-tool-todo` | `allowParallelInProgress` |

> 内置 `preset-standard` 给的值是 `sampleOverCapGlobResults: false` 和 `allowParallelInProgress: true`。

**升级 DSH 后重新推导必填键**：

```bash
grep -rn -A6 'const Config = z.object' \
  <dsh-install>/node_modules/@deepseek-ai/dsh-tool-XXXX/lib/index.js
```

任何 `.required()` 的键，预设里都必须给值。

### 怎么验证（两条路）

```bash
# 端到端：真启动一次 profile，读 UI 读的同一份花名册
node scripts/verify-presets.mjs web

# 静态回归：不启动进程，扫 patch 文件里的必填 config
pnpm test            # tests/presets.test.ts
```

`verify-presets.mjs` 是权威检查——它读的是 `ctx.agentPresets.list()`，和 UI 同源，任何挂载失败都会被它抓到（不只是上表那两个键）。健康时输出：

```
  OK     f2x-bench — f2x 跑分/测评（redteam3000）
  OK     f2x-ctf   — f2x CTF 比赛（redteam3000）
  OK     f2x-power — f2x 能源比赛（redteam3000）

all 3 f2x preset(s) mount cleanly and are selectable.
```

## 4. 装进一个 profile

**不需要手工合并。** 三个预设被**内联进插件自己的 bundle patch**
（`cordis.patch.yml` 末尾的标记区域），所以一条命令就够，模式随安装到位：

```bash
dsh plugin --profile web add dsh-f2x-redteam3000
dsh web --port 3090                       # 重启后生效
node scripts/verify-presets.mjs web       # 确认三个模式真的挂上了
```

`presets/dsh-0.2/*.patch.yml` 是**源文件**（每个模式一份，便于编辑）；内联区域由

```bash
node scripts/sync-presets.mjs          # 重新生成
node scripts/sync-presets.mjs --check  # 仅检查是否过期
```

生成。`tests/presets.test.ts` 有一条守卫断言内联区域与源文件**逐字节一致**，所以两边
不会悄悄漂移——改了源文件忘了同步，测试就会红。

> **为什么必须走 bundle patch，而不是让用户改 profile patch**：`dsh plugin add`
> 只应用**包自己的** patch 层，**不会**碰操作者的 profile patch。若预设只写在
> profile patch 里，用户装完会得到"工具有、模式没有"的插件，而界面上**没有任何
> 提示**说明原因。
>
> **为什么不用 `dsh.bundle.patch` 数组**：DSH 的加载器**明确支持**数组
> （`bundlePatchFiles()`：*"one file for a string `patch`, the listed files in order
> for an array"*），运行时实测也没问题。但已发布的 `dsh-plugin-guide@0.3.19`
> 静态检查器**假定它是字符串**，遇到数组直接崩（`paths[1] must be of type string`）。
> 为了同时满足运行正确与静态检查可用，这里改为内联 + 同步脚本 + 一致性测试。

改完 preset 必须重启——bundle patch 只在启动时读取。（对比：改 `skills/**/SKILL.md`
不需要重启，插件每次调用重新扫盘。）

## 5. 各模式挂了什么

三个模式结构相同，差别在 persona、技能根和门禁强度：

- **共用**：`persona`、`agent-instructions`、`tool-bash`/`tool-pwsh`、`tool-fs`、`tool-fs-search`、`tool-jobs`、`skill-filesystem`、`tool-skill`、`tool-todo`、`tool-web`，以及本插件 `dsh-f2x-redteam3000`。
- **插件行**统一设 `registerSkillProvider: false`——技能由上面的 `skill-filesystem` 按模式提供，避免同一批技能既进全局层又进模式层。
- **`allowedTargets` 默认空 = 拒绝一切**，开工前必须用 `f2x_orchestrate_start` 的 `allowlist` 逐次声明授权范围。

## 复核

```
node scripts/sync-presets.mjs --check   # 预设是否与内联区一致（含行 id 查重）
node scripts/verify-presets.mjs web     # 12 个模式是否挂载健康 + 有无悬空引用
node scripts/smoke-live.mjs             # 12 个模式各真跑一轮（消耗模型调用）
```
