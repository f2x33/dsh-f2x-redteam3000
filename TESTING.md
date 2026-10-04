# 测试怎么做

四层，从"几秒钟、不花钱"到"真上手用"。发布前至少做完前三层。

---

## 第 1 层：自动检查（免费，秒级）

```sh
npx tsc --noEmit                        # 类型干净
npx vitest run                          # 169 个测试
node scripts/sync-presets.mjs --check   # 生成区域与源文件一致（不一致说明预设改了没重新生成）
node scripts/selfcheck.mjs              # 27 项，含发布就绪项
```

**看什么**：全绿。`sync-presets --check` 是**唯一能提前发现"改了预设但忘了重新生成"**的检查——
这个区域就是模式本身，它过期 = 装完还是旧模式。

---

## 第 2 层：预设挂载（免费，需要 DSH 安装）

```sh
DSH_HOME=<你的 dsh home> node scripts/verify-presets.mjs <profile>
```

**看什么**：`all 12 preset(s) mount cleanly and are selectable.`

**为什么必须有**：**预设 broken 是静默的**——任何一行挂不上（少个必填 config、包名解析不到），
整条预设就从 UI 模式选择器里消失，**浏览器里不报任何错**。这一条不跑，你可能发一个"12 模式只剩 2 个"的包出去。

`DSH_HOME` 必须指对（默认 `~/.dsh`）：指错了会得到"none of this plugin's presets are registered"，那是**路径错**，不是包坏。

---

## 第 3 层：活体冒烟（要模型凭据，每个模式一次真实调用）

```sh
DSH_HOME=<dsh home> PROFILE=<profile> node scripts/smoke-live.mjs                 # 全部模式
DSH_HOME=<dsh home> PROFILE=<profile> node scripts/smoke-live.mjs pentest redteam # 指定模式
```

**它比第 2 层多证明什么**：挂载 ≠ 能用。一个模式可以挂载成功，但 persona 是空的、技能没解析到、
工具没送到模型。只有真实一轮才能看出差别。每个模式发一句最小提示，然后断言四件事：

| 断言 | 含义 |
|---|---|
| `persona=yes` | 模型收到的是**这个模式自己的**指令，不只是 harness 前言 |
| `skills=yes` | 该会话的技能目录注入了 |
| `tools=yes` | `f2x_orchestrate_*` 出现在模型可见的工具里 → 本插件那一层真的到了模型 |
| `reply="…"` | 模型真的回答了 → provider、凭据、流式都通 |

**看什么**：`N of N mode(s) PASSED`。

**一个坑（我自己踩过）**：`reply=""` 而其余三项全 yes = **这一侧没有模型凭据**，
不是插件的问题。换一个配了模型的 profile 复跑即可确认：
同一份代码在 `DSH_HOME=/root/.dsh PROFILE=web` 上是 3/3 PASS。

---

## 第 4 层：真实上手（人来点，30 分钟，最值得）

在**另一个 DSH_HOME**（干净环境）里走一遍新用户的完整路径：

```sh
# 1) 用一个独立 home + 官方模板建 profile（别拿你现在用的那个）
DSH_HOME=/tmp/fresh dsh rt --from-default-profile web --no-open

# 2) 装包（用打包好的 tgz，而不是 link 到源码——link 会掩盖"打包漏文件"这类问题）
cd /tmp/fresh/profiles/rt
python3 - <<'PY'
import json; m = json.load(open('package.json'))
m['dependencies'] = {'dsh-f2x-redteam3000': 'file:/path/to/dsh-f2x-redteam3000-0.1.0.tgz'}
m['dsh']['profile']['bundles'].append('dsh-f2x-redteam3000')
json.dump(m, open('package.json', 'w'), indent=2)
PY
DSH_HOME=/tmp/fresh dsh plugin --profile rt install

# 3) 起来，在浏览器里当一次用户
DSH_HOME=/tmp/fresh dsh --profile rt --port 3091 --no-open
```

**然后只用鼠标做这四件事**（这才是"别人装的会不会好使"）：

1. 模式选择器里能看到 **12 个模式**吗？
2. 选一个模式，**新开一个会话**，它能回答吗？
3. 让它干一件**它该干的事**（比如让 `rt-drill` 跑一次 `f2x_orchestrate_doctrine`），
   工具真的执行了吗（看工具卡片，不是看它嘴上说）？
4. 让它写一条经验（`f2x_exp`），再问它召回（`f2x_exp_search`）——经验系统在你手上能转吗？

**看什么**：四件都成立 = 新用户能成功。这一层能抓到前三层抓不到的：配置文件缺项、
README 步骤踩空、UI 里缺东西。

---

## 第 5 层：发布闸门（打包后再看一遍实物）

```sh
node scripts/release-check.mjs --pack
```

**它拦的是什么**：元数据还是 TODO、`lib/` 比 `src/` 旧（**测试读 src 全绿，但 tarball 发的是旧构建**——
最阴的一种）、缺 `dsh.bundle.patch` 或 `./vendor/*` 导出、预设区域不同步、
tarball 夹带 `node_modules/src/tests`。

---

## 发布前的顺序（照抄即可）

```sh
npx tsc --noEmit && npx vitest run && node scripts/selfcheck.mjs
node scripts/sync-presets.mjs --check
DSH_HOME=/root/.dsh node scripts/verify-presets.mjs web        # 12/12
DSH_HOME=/root/.dsh PROFILE=web node scripts/smoke-live.mjs     # 全模式 PASS
node scripts/release-check.mjs --pack                           # 全绿（填完 4 个 TODO 后）
npm pack                                                        # 实物
# 第 4 层：干净 home 里手动过一次（发布前最后一道）
npm publish --tag next
```

**一条判断标准**：**没跑过的检查不算通过。** 尤其第 2、3 层——它们各自对应一类"
看起来好的坏包"：模式静默消失、和模式挂载了但模型收不到。
