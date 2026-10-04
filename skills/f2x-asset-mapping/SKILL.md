---
name: f2x-asset-mapping
description: 资产梳理技能——把信息收集的原始结果归一成可计分的资产清册，覆盖主机、服务、Web 入口面、账号与技术栈五类实体，含横向去重规则、P0-P3 优先级分级、网段拓扑与覆盖分母对账。收集完成或每轮复测前资产漂移核对时触发。
whenToUse: 已有 f2x-recon-basic 的原始产物（httpx.jsonl、nmap XML、被动子域清单）而需要落成清册时使用；也用于渗透中途新增资产登记、复测前账实核对、以及收口时把清册条数与覆盖矩阵分母对齐。
---

# f2x-asset-mapping — 资产梳理与清册

## 操作步骤

### 1. 输入校验（原始事实源，不接受二手结论）

1. 只接受实测产物：`recon/web/httpx.jsonl`、`recon/ports/*.xml`、`recon/dns/resolved.txt`、`recon/passive/*.txt`、手工核验记录。拒绝把测绘平台历史条目、聊天转述、猜测直接当资产。
2. 校验每条记录都带 `source` 与 `confidence`（`confirmed` 实测有响应 / `partial` 仅被动来源 / `unknown` 仅字符串）；缺失的退回 `f2x-recon-basic` 补齐。
3. 校验白名单：清册中任何目标必须能在 `recon/scope.txt` 命中，否则标 `out-of-scope` 且不得进入测试队列。

### 2. 实体归一与去重（五类实体，键必须唯一）

| 实体 | 唯一键（entity key） | 归一规则 |
|---|---|---|
| 主机 host | `ip` 或（无 IP 时）`hostname` | hostname 小写去末尾点；同一 IP 多域名合并为一行，域名收进 `aliases` |
| 服务 service | `host + port + proto` | 同端口多 banner 取最新一次实测，历史存 `banner_history` |
| Web 入口 entry | `scheme + host + port + path` | 301/302 链合并，保留 `final_url`；query 顺序差异合并、原串存 `raw_url` |
| 账号 account | `system + username` | 同名不同系统分行；角色/权限写 `role` |
| 技术栈 tech | `entry + product + version` | 版本取实测 banner，未知写 `unknown` 而非猜 |

去重纪律：同实体重复出现时**合并来源、保留最早 `first_seen` 与最新 `last_seen`**，不新增行；冲突字段（不同版本号）保留两条并标 `conflict` 待人工核验。

### 3. 从原始产物抽表（脚本化，避免手抄出错）

```bash
# 端口/服务表：nmap XML 是唯一事实源，逐文件解析并去重
python3 - <<'PY'
import glob, xml.etree.ElementTree as ET, csv
rows, seen = [], set()
for f in glob.glob('recon/ports/*.xml'):
    for h in ET.parse(f).getroot().findall('host'):
        addr = h.find("address[@addrtype='ipv4']")
        ip = addr.get('addr') if addr is not None else ''
        for p in h.findall('ports/port'):
            st = p.find('state')
            if st is None or st.get('state') != 'open':
                continue
            svc = p.find('service')
            name = svc.get('name', '') if svc is not None else ''
            ver = ' '.join(filter(None, [svc.get('product', ''), svc.get('version', '')])) if svc is not None else ''
            k = (ip, p.get('portid'), p.get('protocol'))
            if k in seen:
                continue
            seen.add(k)
            rows.append([ip, p.get('portid'), p.get('protocol'), name, ver, f])
with open('assets/services.tsv', 'w', newline='') as fh:
    w = csv.writer(fh, delimiter='\t')
    w.writerow(['host', 'port', 'proto', 'service', 'version', 'source'])
    w.writerows(sorted(rows))
print('services:', len(rows))
PY
```

```bash
# Web 入口面表：httpx JSONL 抽关键字段
jq -r '[.host,.port,.scheme,.status_code,.title,.webserver,(.tech|join(";")),.content_length,.favicon,.jarm,.input]|@tsv' \
  recon/web/httpx.jsonl | sort -u > assets/web-entries.tsv

# 被动来源合并进主机表（标注来源与可信度）
cat recon/passive/subfinder.txt | sort -u | awk -v OFS='\t' '{print $0,"","","","passive","partial"}'
```

### 4. 清册模板（五个 TSV + 一份人读总表）

`assets/hosts.tsv`
```
host	ip	os_guess	segment	role	owner	business	first_seen	last_seen	source	confidence	notes
```

`assets/services.tsv`
```
host	port	proto	service	version	banner_hash	tls	auth_required	source	confidence
```

`assets/web-entries.tsv`
```
entry_id	url	final_url	method	status	title	tech	auth_surface	waf	priority	scope_status	source
```

`assets/accounts.tsv`
```
account_id	system	username	role	auth_type	verified	secret_ref	scope	note
```
凭据明文只入本地凭据库 `creds/vault.tsv`（权限 600），清册只写 `secret_ref`（指位）与后四位/指纹。

`assets/techstack.tsv`
```
entry_id	product	version	cpe	known_cve_flag	evidence_source	confidence
```

`assets/ASSETS.md`（人读总表）：按网段/业务线分组，每组给「主机数 / 开放服务数 / Web 入口数 / 高优先级数」四个计数，并链到上述 TSV。

### 5. 优先级分级（判定标准必须可复核）

| 等级 | 判定标准（同时满足） | 处置 |
|---|---|---|
| P0 | 互联网可达 + 属认证口/管理后台/API 写入面 + 承载核心业务或版本命中已知高危 CVE | 首轮测，逐条留证，逐条回写覆盖 |
| P1 | 互联网可达的业务面（无需认证或边界薄弱），或 P0 同网段的相邻系统 | 第二轮测，可批量模板化 |
| P2 | 仅内网可达的服务/主机（需先获得立足点） | 内网阶段（`f2x-internal-pentest`）处理 |
| P3 | 第三方托管、CDN 节点、无业务价值或范围外资产 | 只登记不测，`scope_status=out-of-scope` 或 `third-party` |

分级纪律：等级由「可达性 × 入口性质 × 业务权重」三者共同决定，**不得因"看起来老"就升 P0**；每行的等级必须能指回上表某一行判定标准。

### 6. 入口面归类（决定后续测试队列）

- 认证口：登录页、SSO、OAuth 回调、API token 端点 → 走 `f2x-vuln-discovery` 的弱口令受限流程。
- 管理后台/运维面：`/admin`、`/manage`、actuator、中间件控制台 → 未授权访问优先。
- API 面：`/api`、`/swagger`、`/openapi.json`、GraphQL → 参数面与越权面。
- 文件与数据面：上传、导出、报表、附件 → 越权与类型校验。
- 第三方集成：回调、Webhook、外链跳转 → SSRF/开放重定向。
- 每个入口标注 `auth_surface`（none/session/token/mfa）与 `waf`（none/unknown/product）。

### 7. 拓扑与链路登记

- 按 `segment` 汇总网段（如 `10.1.1.x`），标注关口（VPN、堡垒机、反向代理、跳板）与域控/身份源位置。
- 攻击链随战役生长：登记入口节点（`entry`）、主机节点（`host`）、凭据节点（`cred`）、网段关口（`segment`），重大成果节点标 `major`；动作边写「获取权限/凭据复用/隔离突破」。
- 拓扑来源必须是实测证据；未验证的相邻关系标注 `hypothesis`，不画成实线。

### 8. 账实核对与覆盖分母对账

1. 清册条数 = 覆盖矩阵分母：`assets/hosts.tsv` 行数（去重后）必须与覆盖矩阵中登记的资产条数一致，收口时逐条对账。
2. 每条资产给终态：`tested-found`（有发现，挂 finding id）/ `tested-clear`（测过未命中，写清未排除面）/ `na`（不适测，写原因）/ `budget-stop`（时间/额度耗尽，写原因）。
3. 不允许"沉默条目"：清册里没回写终态的行，报告中一律按未覆盖计入，不得算已完成。
4. 复测时重跑第 1-3 步生成 `assets/hosts.tsv.new`，与旧表 diff 出 `added/removed/changed` 写入 `assets/drift-<date>.md`。

## 安全约束

- 清册登记不是探测授权：把资产写进清册不构成测试许可；范围外资产只登记 `scope_status=out-of-scope`，不排进测试队列。
- 梳理过程中任何主动探测一律沿用 `f2x-recon-basic` 的低频纪律（`-T2`、显式限速、并发 ≤10）；禁止以"核实资产"为名做高频扫描或爆破。
- 凭据只写指位与指纹：明文只进本地凭据库（600 权限），清册、报告、聊天正文不出现完整口令、Cookie、私钥、连接串。
- 客户业务信息最小化：只记识别资产必需的字段（域名、端口、产品、版本），不抄录业务数据、用户名单、内部文档正文。
- 证据分级不可拔高：仅被动来源的资产标 `partial`，禁止在报告中按 `confirmed` 计数；冲突字段必须显式标 `conflict` 待核验。
- 任何写操作（在目标系统建账号、改备注、打标签）需明确批准；默认只写本地清册文件。
- 覆盖分母不得注水：清册可以只登记授权范围内的必需面，但一旦登记就必须给终态，禁止靠扩大或缩小分母使覆盖率好看。

## 产出与证据

| 交付物 | 路径 | 必含字段 | 计分口径 |
|---|---|---|---|
| 主机清册 | `assets/hosts.tsv` | host/ip/os_guess/segment/role/first_seen/last_seen/source/confidence | 去重后行数即覆盖分母 |
| 服务清册 | `assets/services.tsv` | host/port/proto/service/version/banner_hash/tls/auth_required | 每行可指回 nmap XML |
| Web 入口清册 | `assets/web-entries.tsv` | entry_id/url/status/title/tech/auth_surface/waf/priority/scope_status | 每行可指回 httpx.jsonl |
| 账号面 | `assets/accounts.tsv` | account_id/system/username/role/auth_type/verified/secret_ref | 凭据明文不入表 |
| 技术栈 | `assets/techstack.tsv` | entry_id/product/version/cpe/known_cve_flag/evidence_source | 供 CVE 匹配直接消费 |
| 人读总表 | `assets/ASSETS.md` | 分组计数（主机/服务/入口/高优先级） | 与 TSV 行数一致 |
| 优先级说明 | `assets/priority.md` | 每等级判定标准 + 逐条资产定级理由 | 每条能指回判定行 |
| 漂移记录 | `assets/drift-<date>.md` | added/removed/changed 三类差异 | 复测必需 |
| 证据索引 | `evidence-index.md` | `EV-ASSET-nnn`、来源命令、原始文件路径、confidence | 支撑 finding 回溯 |

交接要求：`assets/techstack.tsv` 的 `known_cve_flag` 是 `f2x-vuln-discovery` 的输入队列；`assets/hosts.tsv` 的每条终态（tested-found/tested-clear/na/budget-stop）与覆盖矩阵逐条对账，P2 资产显式移交 `f2x-internal-pentest`，不得在报告中按已测计数。
