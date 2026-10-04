---
name: f2x-recon-basic
description: 授权红队信息收集基础技能——被动优先的资产面盘点、低频端口与服务识别、Web 指纹采集、目录与参数枚举、DNS 与证书透明度挖掘，产出可复核的原始证据与去重清单。首次外部侦察、需要在低告警低影响前提下摸清入口面时触发。
whenToUse: 拿到授权范围（域名/IP 段/组织名）后、尚未接触或刚开始接触目标时使用。目标是把资产面与入口面在不触发告警、不打崩服务的前提下摸清，并产出能被 f2x-asset-mapping 直接消费的原始数据；也用于每轮复测前的资产漂移核对。
---

# f2x-recon-basic — 授权信息收集基础

## 操作步骤

### 0. 授权与范围固化（未完成不得发包）

1. 建 `recon/scope.md`，逐条写清：授权方、授权书编号或邮件时间、目标白名单（域名、IP/CIDR、URL 前缀）、**排除项**（生产库、支付、OT/ICS 网段、第三方托管）、允许时间窗、紧急联系人、熔断条件（目标服务异常即停并上报）。
2. 生成机器可读白名单 `recon/scope.txt`（每行一个 host 或 CIDR）。后续所有工具必须 `-l recon/scope.txt` 或人工比对；解析结果落到范围外（第三方云、兄弟域名、CDN 回源）只标注 `third-party`，不主动探测。
3. 记录环境事实到 `recon/env.md`：出口 IP（`curl -s https://ifconfig.me`）、测试机时区与当前时间、工具版本（`nmap --version`、`httpx -version`），保证证据时间线可对齐。

### 1. 被动收集优先（不向目标发包）

```bash
# 子域多源被动聚合（-all 拉全源；不含 DNS 爆破）
subfinder -d example.com -all -silent -o recon/passive/subfinder.txt
amass enum -passive -d example.com -o recon/passive/amass.txt

# 证书透明度：覆盖子域与历史证书（crt.sh 单次拉取，失败重试间隔 ≥30s）
curl -s --max-time 30 "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' | tr ',' '\n' | sed 's/\*\.//' | sort -u \
  > recon/passive/crtsh.txt

# 历史 URL 与参数面（Wayback / Common Crawl），限并发
waybackurls example.com | sort -u > recon/passive/wayback.txt
gau --threads 2 example.com >> recon/passive/wayback.txt

# 公开信息与人员/邮箱面（用于后续账号面梳理，不用于钓鱼）
theHarvester -d example.com -b bing,duckduckgo -l 200 -f recon/passive/harvester
```

搜索引擎与空间测绘语法（只用于枚举，命中后必须实测确认）：

```
FOFA     domain="example.com" && country="CN"
         cert="example.com" && protocol="https"
         icon_hash="-1234567890"            # favicon 哈希反查同源系统
Shodan   ssl.cert.subject.CN:"example.com" 200
         org:"Example Corp" port:8443
Censys   services.tls.certificates.leaf_data.names: example.com
Quake    domain:"example.com" AND service:"http"
Google   site:example.com -www (filetype:pdf OR filetype:xls OR filetype:sql OR filetype:bak)
         site:example.com (inurl:login OR inurl:admin OR inurl:api OR inurl:swagger)
```

测绘平台 AK/SK 属凭据，只入本地凭据库，不写进报告正文与聊天输出。

### 2. 存活判定与 Web 指纹（低频）

```bash
# 主动解析（仅 DNS 查询，轻量）
dnsx -l recon/passive/subfinder.txt -a -resp -silent -o recon/dns/resolved.txt

# HTTP 存活 + 指纹：并发 10、限速 20 rps，禁止默认全速
httpx -l recon/dns/resolved.txt -ports 80,443,8080,8443,8000,8888 \
  -threads 10 -rate-limit 20 -timeout 8 -retries 1 -follow-redirects \
  -status-code -title -tech-detect -web-server -content-length -favicon -jarm \
  -json -o recon/web/httpx.jsonl

# 单目标人工核验：先 HEAD 再按需 GET，避免拉取大响应
curl -sS -I --max-time 10 https://example.com | sed -n '1,20p'
curl -sS -D - -o /dev/null --max-time 10 -A 'Mozilla/5.0 (authorized-redteam)' https://example.com

# whatweb 低侵略模式（-a 1 单请求指纹；禁止 -a 3/-a 4 的侵略级别）
whatweb -a 1 --no-errors --log-json recon/web/whatweb.json https://example.com

# favicon mmh3 哈希，用于 FOFA icon_hash 反查同源系统
curl -s --max-time 10 https://example.com/favicon.ico -o /tmp/f.ico
python3 -c "import base64,mmh3;print(mmh3.hash(base64.encodebytes(open('/tmp/f.ico','rb').read())))"
```

指纹判读字段：`Server`、`X-Powered-By`、`X-Generator`、`Set-Cookie` 名称（`PHPSESSID`=PHP、`JSESSIONID`=Java、`ASP.NET_SessionId`=IIS/.NET、`csrftoken`=Django、`_rails_session`=Rails）、`<meta name="generator">`、静态资源路径特征、错误页特征、favicon 哈希、`jarm` 指纹。

### 3. 端口与服务识别（低频、限速、分档）

```bash
# 档 1：常见端口快筛（先小后大，绝不上 -T4/-T5）
nmap -sS -Pn -T2 --top-ports 100 --max-rate 50 --max-retries 2 --host-timeout 5m \
  -oA recon/ports/top100_<host> <host>

# 档 2：仅对档 1 确认开放的端口做服务/版本识别（version-intensity 2 降低交互）
nmap -sS -Pn -sV -T2 --version-intensity 2 --max-rate 50 --max-retries 2 \
  -p 22,80,443,3306,6379,8080,8443 -oA recon/ports/svc_<host> <host>

# 档 3（需明确批准）：网段清单式扫描，限速并按 /24 分批，逐批记录
nmap -sS -Pn -T2 --max-rate 100 --host-timeout 10m --open \
  -iL recon/scope.txt -oA recon/ports/seg_<cidr>
```

- `-sS` 需 root；无 root 用 `-sT`（更慢但可用）。
- 禁止 `-T4/-T5`、禁止 `masscan --rate=1000` 级高 pps；同一目标同时只跑 1 个 nmap 实例。
- UDP 仅在授权明确时做，且限 `--top-ports 20 -T2 --max-rate 20`（UDP 易被判定为攻击）。
- 出现连接重置、403 激增、源 IP 被封等拦截信号：停止当前档位、降速一半或转人工抓包核验，并记入 `recon/notes/incidents.md`。

### 4. 目录、文件与参数枚举（必须做基线差分）

```bash
# 基线：取不存在路径的状态码与响应长度，用于过滤软 404
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' https://example.com/__f2x_nonexistent__

# ffuf：并发 5、限速 20，按状态码 + 基线长度过滤，-ac 自动校准
ffuf -u https://example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -t 5 -rate 20 -timeout 8 -mc 200,204,301,302,307,401,403,405 -fs <基线长度> -ac \
  -of json -o recon/web/ffuf_dirs.json

# 备份与敏感文件名探测：只记状态码/长度/哈希，不下载内容本体
ffuf -u https://example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt \
  -t 5 -rate 20 -e .bak,.zip,.tar.gz,.sql,.env,.git/config,.svn/entries -mc all -fc 404
```

- 命中判定：**状态码 + 响应长度 + 响应体哈希**三者与基线不同才算命中；单独 `200` 不算（软 404 普遍）。
- 目录列举命中（`Index of /`）只留证据，禁止批量下载。
- 参数面优先从被动数据（wayback/gau 的 URL query）提取，不做全量参数爆破；确需时 `arjun -u <url> --stable -t 4`。

### 5. 去重、归一与可信度标注

- 归一：host 统一小写、去末尾点；IP 记录归属网段；URL 的 query 顺序差异合并但保留原始串在 `raw` 字段。
- 每条记录带 `source`（subfinder/crtsh/httpx/手工）与 `confidence`：
  - `confirmed` — 本次实测取得响应（HTTP 状态码、端口 banner 实际到手）；
  - `partial` — 仅被动来源（CT 日志、测绘平台）或仅 DNS 解析、服务未验证；
  - `unknown` — 仅字符串出现，无解析证据。
- 禁止把测绘平台历史结果直接写成"目标当前在线"。

### 6. 落盘与交接

- 原始输出全留 `recon/raw/`，中间产物放 `recon/`，结论另存；不得只留结论。
- 证据登记到 `evidence-index.md`，编号 `EV-RECON-nnn`，每条写：时间（含时区）、命令、目标、原始输出路径、confidence。
- 交接给 `f2x-asset-mapping`：`recon/web/httpx.jsonl` 与 `recon/ports/*.xml` 是清册的唯一数据源。

## 安全约束

- 只测 `recon/scope.md` 中逐条列明的授权目标；范围外资产（含解析到的第三方云/CDN、兄弟域名）只做被动记录，不主动探测；越界即停并上报。
- 禁止 DDoS/压力测试；禁止高并发高频扫描：nmap 一律 `-T2` 且显式 `--max-rate`（外网 ≤50、内网 ≤100），httpx `-threads ≤10 -rate-limit ≤20`，ffuf `-t 5 -rate 20`；禁止 `-T4/-T5`、禁止高 pps masscan、禁止多实例并扫同一目标。
- 禁止爆破：目录枚举只用精选小字典并做基线差分；不对登录口做字典喷洒或凭据枚举（弱口令验证属 `f2x-vuln-discovery`，且受 ≤20 条人工精选样本约束）。
- 任何写操作（上传、注册、改配置、删文件）需目标方明确批准并记录；DNS 区域传送（AXFR）仅在被授权且明确许可时尝试。
- 不下载不落盘业务敏感数据（数据库导出、用户文件、私钥、凭据文件）；只记录状态码、长度、哈希等元信息。
- 发现即验证，证据分级 `confirmed/partial/unknown`；禁止把测绘平台历史数据、字符串匹配或推测写成事实；无法复现的观察写"未验证线索"。
- 被 WAF/IPS 拦截或目标出现异常（5xx 激增、延迟飙升）立即停止当前动作、降速或转被动方式，并在 `recon/notes/incidents.md` 记录时间与影响。
- 凭据（测绘平台 AK/SK、代理账号、代理池）只入本地凭据库，不写进报告正文与聊天输出。

## 产出与证据

| 交付物 | 路径 | 必含字段 | 计分口径 |
|---|---|---|---|
| 范围与授权 | `recon/scope.md` + `recon/scope.txt` | 授权方/白名单/排除项/时间窗/联系人/熔断条件 | 缺此项本阶段全部产出不计分 |
| 环境事实 | `recon/env.md` | 出口 IP、工具与版本、时区 | 可复核 |
| 被动收集原始件 | `recon/passive/*.txt` | 来源标签、采集时间 | 每条带 source |
| 存活与指纹 | `recon/web/httpx.jsonl`、`recon/web/whatweb.json` | host/port/scheme/status/title/tech/server/content_length/favicon_hash/jarm | `confirmed` 需实测响应支撑 |
| 端口与服务 | `recon/ports/*.xml`、`*.gnmap` | host/port/state/service/version/banner | 三档各留原始 XML |
| 目录与参数面 | `recon/web/ffuf_*.json` | url/status/length/words/content-hash/基线差分结论 | 每条命中附基线对照 |
| 资产初表 | `recon/hosts.tsv` | `host	ip	port	scheme	status	tech	source	confidence	first_seen` | 去重后行数即本阶段覆盖分母 |
| 证据索引 | `evidence-index.md` | `EV-RECON-nnn`、时间、命令、原文路径、confidence | 支撑后续 finding 回溯 |

收口要求：把 `recon/hosts.tsv` 的行数写入覆盖矩阵作为分母；`partial`/`unknown` 条目在报告中显式声明未验证面，不得混入 confirmed 计数。本阶段产出是 `f2x-asset-mapping` 的唯一输入；未产出 `recon/scope.md` 时清册不得进入下一阶段。
