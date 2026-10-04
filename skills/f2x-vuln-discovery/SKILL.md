---
name: f2x-vuln-discovery
description: 漏洞发现技能——Web 漏洞、配置缺陷与已知 CVE 的发现流程，含 nuclei 限速模板匹配、逐参数单次探测与基线差分判定、未授权访问只读核验，以及严格受限的弱口令人工验证（≤20 条精选样本）。有资产清册后进入验证阶段时触发。
whenToUse: 已完成 f2x-asset-mapping 且拿到 P0/P1 入口面队列后使用；用于把候选漏洞从"疑似"推进到可复核的 `verified`，或在复测中确认修复是否生效。需要明确禁止爆破与高频扫描的场景下同样适用。
---

# f2x-vuln-discovery — 漏洞发现（禁爆破）

> **工具可用性与退路（先读这一节）**
> 本技能只依赖本插件自带的 `f2x_orchestrate_*` 工具，**不依赖任何其他插件**。下文出现的
> `redteam_*` / `webshell_*` / `campaign_memory_*` 属于**可选增强**：
> - **成果登记**：用 `f2x_orchestrate_finding`（本插件自带，任何部署都有）。
>   仅当部署里确实存在 `redteam_finding_register` 且需要共享成果页时才改用它。
> - **开场自检**：不确定当前部署有哪些能力时，先跑 `f2x_orchestrate_doctrine`，
>   末尾会列出可选能力的 AVAILABLE / absent。
> **规则**：目录里没有的工具一律不要调用——按上面的退路走，不要报错后硬试。

## 操作步骤

### 0. 前置与准入

1. 从 `assets/web-entries.tsv` 取 `priority=P0/P1` 且 `scope_status=in-scope` 的入口面；P2/P3 不在本阶段处理。
2. 固化测试条件：授权范围、禁测接口（支付、删除、发信、批量导出）、允许时间窗、停止条件（业务异常/告警/用户投诉即停）、单目标失败上限（同入口连续 3 次失败即停）。
3. 为每个目标建立稳定基线：同一请求重复 3 次，记录状态码、响应长度、响应体哈希、耗时中位数。后续一切判定都相对基线做差分。

```bash
# 基线采样（无害 GET，3 次取稳定值）
for i in 1 2 3; do
  curl -sS -o /tmp/b.$i -w '%{http_code} %{size_download} %{time_total}\n' --max-time 10 \
    -A 'Mozilla/5.0 (authorized-redteam)' 'https://example.com/item?id=1'
done
sha256sum /tmp/b.* ; cat /tmp/b.1 | head -c 200
```

### 1. 已知漏洞匹配（组件版本 → CVE）

```bash
# 版本 → CPE → CVE（NVD 2.0 API，单次查询，注意其限速：无 key 时 ≤5 次/30s）
curl -s --max-time 30 \
  "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*" \
  | jq -r '.vulnerabilities[].cve | [.id, (.metrics.cvssMetricV31[0].cvssData.baseScore // "n/a"), .published] | @tsv'

# nuclei：限速 30 rps、并发 10，只打 cve/exposures/misconfiguration 且排除破坏性标签
nuclei -l recon/web/urls.txt \
  -t http/cves/ -t http/exposures/ -t http/misconfiguration/ \
  -severity critical,high -rl 30 -c 10 -timeout 10 -retries 1 \
  -exclude-tags dos,fuzz,intrusive -stats \
  -jsonl -o vuln/nuclei.jsonl -o vuln/nuclei.txt
```

- 硬性禁用：`-t http/fuzzing/` 全量、`-t http/default-logins/` 批量跑口令、`-headless` 批量渲染、任何 `dos`/`intrusive` 标签模板。
- 命中 ≠ 漏洞：nuclei 命中常只是版本 banner 或错误页特征，必须手工复核响应并补基线/差分/回显，否则记 `partial`。

### 2. Web 漏洞发现（逐参数、单次探测、基线差分）

**SQLi**：先做布尔/算术对照，不做批量注入。
```bash
# 基线 vs 差分：id=1 / id=2-1 / id=1' / id=1" 各一次，比较状态码、长度、哈希、耗时
curl -sS -o /tmp/s1 -w 'base %{http_code} %{size_download} %{time_total}\n' 'https://example.com/item?id=1'
curl -sS -o /tmp/s2 -w 'math %{http_code} %{size_download} %{time_total}\n' 'https://example.com/item?id=2-1'
curl -sS -o /tmp/s3 -w 'quote %{http_code} %{size_download} %{time_total}\n' "https://example.com/item?id=1%27"
```
判定：`math` 与 `base` 内容一致、`quote` 相对基线出现稳定差异（500/长度突变/DB 报错特征）→ 候选 confirmed SQLi。时间盲注要求 ≥3 次可重复、延迟 ≥4s，且同页非注入参数无延迟。若用 sqlmap，仅限 `--level=1 --risk=1 --threads=1 --delay=1 --technique=BEU --batch`，禁止 `--os-shell`/`--file-write`。

**XSS**：只用无害唯一 marker 验证反射与编码，不投放窃取脚本。
```bash
MARK="f2x$(date +%s)z7"
curl -sS --max-time 10 "https://example.com/search?q=$MARK%3Cb%3E" | grep -o "$MARK.\{0,20\}"
```
判定：marker 以未编码形式回显在 HTML 上下文 = 反射 confirmed；仅在 JS 字符串里被转义 = `partial`。

**SSRF / 出网**：用自建带外监听，不扫内网、不读云元数据凭据。
```bash
interactsh-client -n 1 -v            # 取得唯一 OOB 域名：<id>.oob.example
curl -sS --max-time 15 "https://example.com/fetch?url=http://<id>.oob.example/f2x"
```
判定：OOB 侧收到 DNS/HTTP 命中 = 出网 confirmed；只有延迟差异 = `partial`。云元数据 `169.254.169.254` 仅在授权书写明且为自有云时，允许 GET 无凭据路径证明可达，**禁止读取/回传任何临时凭据**。

**路径穿越 / LFI**：只读无害文件。
```bash
curl -sS --max-time 10 'https://example.com/dl?file=../../../../etc/hostname'
curl -sS --max-time 10 'https://example.com/dl?file=..%5c..%5cwindows%5cwin.ini'
```
判定：返回内容与目标平台无害文件特征一致 = confirmed。禁止读取 `/etc/shadow`、私钥、业务数据（读到了也只记录"可读"事实并立即停止，不摘录内容）。

**越权 / IDOR（会话归属门）**：必须双账号对照，并写清请求是否携带会话。
```bash
curl -sS -b 'session=A账号会话' 'https://example.com/api/orders/1001' -o /tmp/a.txt   # 基线：自己的对象
curl -sS -b 'session=A账号会话' 'https://example.com/api/orders/2002' -o /tmp/b.txt   # 差分：他人的对象
curl -sS 'https://example.com/api/orders/2002' -o /tmp/c.txt                          # 剥离会话再验一次
```
判定规则：带会话拿到他人对象 = IDOR（**不得写成"匿名未授权"**）；剥离凭据仍可达才写未授权。仅有 HTTP 200 不算，必须证明对象内容属于他人（如订单号/邮箱后缀差异）。

**上传**：只验证类型校验，不上传可执行文件。允许的无害证明：上传文本 marker 文件并立即删除（需批准），或改 `Content-Type` + 双扩展名观察是否被接受且能被 GET 到。

### 3. 弱口令验证（严格受限，禁止爆破）

> **硬约束（红线）：仅允许 ≤20 条人工精选样本、失败即停、禁止暴力枚举。**
> 禁止 hydra、medusa、ncrack、crowbar、patator 等多线程爆破模式；禁止从字典文件灌入；禁止 credential spraying（多账号轮换同一口令）；禁止对同一账号连续尝试超过 3 次。

样本构成（人工挑选，写在 `vuln/weakpw/samples.tsv`，总数 ≤20）：
1. 产品/设备文档公开的出厂默认口令（如 `admin/admin`、`admin/admin123`、`root/root`）——不超过 8 条；
2. 组织画像推导的 1-2 条猜测（公司域名+年份、产品名+版本）；
3. 授权方书面提供的测试账号口令（用于验证判定逻辑本身）。

执行方式：每条样本一次请求，样本之间间隔 ≥10s，全程留证。

```bash
# 基线：故意用明显错误口令，取得失败响应特征
curl -sS -i --max-time 10 -c /tmp/f2x.jar -X POST https://example.com/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=admin&password=__f2x_wrong_baseline__' -o vuln/weakpw/baseline.txt

# 单个样本验证（一次一请求；命中即停，失败累计 3 次即终止该入口）
curl -sS -i --max-time 10 -c /tmp/f2x.jar -X POST https://example.com/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=admin&password=<sample-01>' -o vuln/weakpw/attempt-001.txt
```

判定（必须过"存活门"）：与基线对照——状态码、响应长度、`Location`、`Set-Cookie` 是否出现新会话；随后用该会话做**一次只读请求**确认身份或进入受保护页面。
- 拿到有效会话 + 只读请求返回身份/受保护内容 → `confirmed`；
- 仅状态码变化、无会话、无受保护内容 → `partial`（线索，不入正式成果，"弱口令但从未签发会话"不算结果）；
- 记录表必须能证明样本数 ≤20 且已停止。

### 4. 配置缺陷与未授权访问（只读单次）

```bash
# 信息面：一次 HEAD 取安全头与服务指纹
curl -sS -I --max-time 10 https://example.com | grep -iE 'server|x-powered-by|strict-transport|content-security|x-frame'

# 敏感路径：单次 GET，只看状态码 + 前 200 字节，不下载
for p in /.git/config /.env /actuator/env /actuator/health /swagger-ui.html /server-status /phpinfo.php; do
  code=$(curl -sS -o /tmp/p.out -w '%{http_code}' --max-time 8 "https://example.com$p")
  echo -e "$p\t$code\t$(head -c 200 /tmp/p.out | tr -d '\n')"
done

# TLS 面（单目标、低负载；禁用 --sneaky 与并行批量）
testssl.sh --quiet --fast https://example.com

# 中间件未授权：只读命令，任何写/删命令必须先批准
redis-cli -h <host> -p 6379 --no-auth-warning INFO server      # 禁 CONFIG SET / FLUSHALL / KEYS *
curl -sS --max-time 10 'http://<host>:9200/_cat/indices?v'      # 禁 DELETE / _delete_by_query
curl -sS --max-time 10 'http://<host>:2375/version'             # 禁 docker run / rm
curl -sS --max-time 10 'https://<host>:6443/version' -k         # 禁 create/delete 资源
```
判定与过滤：
- 仅缺安全头、仅过期证书且无利用路径 → **不单独计 finding**（记录为强化建议）。
- 未授权访问判定 = 只读命令返回真实数据（如 Redis `INFO` 有 `redis_version`、ES 返回索引清单）；返回 403/401 或空 JSON 不算。
- 目录列举、`.git/config` 命中只证明可读；要成为成果须证明能导致凭据、源码或配置泄露，且摘录最小必要片段。

### 5. 判定与误报控制（硬规则）

1. **三件套齐一才算 confirmed**：`baseline`（基线）、`diffEvidence`（差分）、`markerEcho`（唯一 marker 回显或带外命中）；缺任一件降为 `partial`。
2. 时间型漏洞：≥3 次可重复、阈值明确（如延迟 ≥4s）、且同页对照参数无延迟。
3. 半链不算成果：弱口令但未取得会话；只有 host 没有凭据的连接串；只有 `200` 的 JSON；仅自身可见的 CSRF；无利用路径的过期证书；同角色或公开可读的运维数据。
4. 同 URL 同类型不重复登记；同一发现只留一条，历史记录写进 `retest` 注记。

### 6. 登记、回写与交接

- 每条候选登记成果（`f2x_orchestrate_finding`，本插件自带），`status=pending`，必填：`title`、`type`、`target`、`summary`、`evidenceLevel`、`evidence`；三件套（`baseline`/`diffEvidence`/`markerEcho`）齐备后才能转 `verified`。
- 覆盖矩阵逐格回写：命中的格子 `tested-found` 并挂 finding id；测过未命中的 `tested-clear` 并写清"未排除面"（如"仅测 GET 参数，未测 JSON body"）；不适测的 `na` 写原因。
- 交给 `f2x-exploitation` 的前提：finding `status=verified` 且三件套齐全；`partial` 只能作为线索，不得直接进入利用阶段。

## 安全约束

- 只测授权白名单内的目标与接口；禁测清单（支付、删除、发信、批量导出、用户数据下载）逐条遵守，越界即停并上报。
- **禁止爆破**：禁止 hydra/medusa/ncrack/patator 等批量口令工具；禁止字典灌入与 credential spraying；弱口令验证仅限上述 ≤20 条人工精选样本，**失败即停**（同账号 3 次、同入口累计 3 次），命中即停并转人工记录。
- 禁止 DDoS 与高频扫描：nuclei `-rl ≤30 -c ≤10`，扫描器一律显式限速，单目标同时只跑一个主动扫描器；禁止 `dos`/`intrusive`/`fuzz` 类模板与 masscan 高 pps。
- 写操作、上传、删除类操作需明确批准并留台账；默认全程只读。上传验证只用无害文本 marker 并立即删除。
- 不做破坏性 payload：禁 `DROP/DELETE/UPDATE`、禁 `--os-shell`、禁写入 webshell、禁修改目标配置；SQLi 只证明可读，数据只取最小必要样本（如 `version()`、`current_user`）。
- 不摘录业务敏感数据：证明可读即可，禁止批量导出、禁止把用户数据写进报告；凭据只写指位与指纹。
- 发现即验证，证据分级 `confirmed/partial/unknown`（缺三件套即降级）；禁止把扫描器输出、版本号匹配、推测写成已验证漏洞。
- 命中立即上报条件：可未授权读改生产数据、拿到域管或云 AK 级别凭据、发现正在进行的入侵、测试造成业务影响（锁定、宕机）。
- 被 WAF/IPS 拦截（403 激增、连接重置）：停止当前动作、降速或转被动核验，并在 `vuln/notes/incidents.md` 记录时间与证据，不改写 UA 反复试探。

## 产出与证据

| 交付物 | 路径 | 必含字段 | 计分口径 |
|---|---|---|---|
| 测试计划 | `vuln/plan.md` | 队列来源、禁测接口、时间窗、停止条件 | 缺项不得开测 |
| 基线记录 | `vuln/baseline/*.txt` | 状态码、长度、哈希、耗时（3 次） | 一切差分的对照基准 |
| 扫描原始件 | `vuln/nuclei.jsonl` | template-id/matched-at/severity/请求响应片段 | 命中必须手工复核 |
| 逐条发现 | `findings/F-<id>.md` | 标题/资产/环境/前提/复现步骤/基线/差分/回显/影响/非破坏声明/修复建议/附件 | 每条登记成果页 |
| 弱口令记录 | `vuln/weakpw/samples.tsv` + `attempts.tsv` | 样本来源、序号、时间、响应码、长度、结论、**样本总数与停止原因** | 必须可证明 ≤20 且已停 |
| 未授权核验 | `vuln/unauth/*.txt` | 命令、原始响应（脱敏）、是否可读真实数据 | 只读证据 |
| 覆盖回写 | 覆盖矩阵行 | `cat/item`、终态、原因、finding id | tested-clear 须写未排除面 |
| 证据索引 | `evidence-index.md` | `EV-VULN-nnn`、时间、命令、原文路径、confidence | 支撑 finding 回溯 |

收口要求：`tested-found` 与 `tested-clear` 之和 + `na` + `budget-stop` = 覆盖分母；`partial` 发现单独成列声明为线索，不得混入已验证计数；所有弱口令尝试记录保留原始响应以便复核"失败即停"确实执行。
