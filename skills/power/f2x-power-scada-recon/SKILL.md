---
name: f2x-power-scada-recon
description: 电力 SCADA 与 HMI 侦察技能——Web 管理界面指纹（SCADA-LTS / WinCC / iFIX / Ignition 等）、工程师站识别、OPC 与历史数据库接口枚举、跨区可达性测绘，全程低频被动优先。
whenToUse: 已进入电力靶场的 DMZ 或站控层网段，需要发现 SCADA/HMI 服务、区分工程师站与操作员站、枚举 OPC 与历史库接口，或判定跨区（DMZ↔ICS）可达性时使用。
---

# SCADA / HMI 侦察技能（f2x-power-scada-recon）

> **工具可用性与退路（先读这一节）**
> 本技能只依赖本插件自带的 `f2x_orchestrate_*` 工具，**不依赖任何其他插件**。
> 下文工作流里出现的 `redteam_coverage_mark` / `redteam_atlas_*` / `redteam_finding_register`
> 都是**可选增强**，本插件没有对应替代品时按下面的退路走：
> - **成果登记** → `f2x_orchestrate_finding`（本插件自带）
> - **资产与跨区链路** → 写进证据文件（如 `evidence/ot-assets.tsv`、`evidence/cross-zone.md`）
>   并用 `f2x_orchestrate_blackboard`（kind=fact，必须带 evidence）登记，供后续阶段与回溯引用
> - **覆盖矩阵** → 本插件无此面；用 `f2x_orchestrate_export` 的产出作为覆盖记录，
>   或仅在部署里确实有 `redteam_coverage_mark` 时才回写
> **规则**：目录里没有的工具一律不要调用。开场先跑 `f2x_orchestrate_doctrine` 自检。

> **定位**：本技能解决"**这块网络里谁是谁**"——上位机/SCADA、HMI、工程师站（EWS）、历史库、OPC 接口、跨区通道。协议层深挖见 `f2x-power-modbus-attack` / `f2x-power-s7comm-attack` / `f2x-power-iec61850-analysis`；流量回溯与防守视角见 `f2x-power-traceback`。
>
> **素材引用（本机只读）**：
> - 协议端口表：`$REDTEAM_REFS/awesome-industrial-protocols/protocols/` —— Modbus `502/tcp`、S7comm `102/tcp`、IEC-61850（MMS 102 + GOOSE/SV 二层）、DNP3 `20000/tcp|udp`、IEC-60870-5-104 `2404/tcp`、OPC-UA `4840/tcp`、`4840/udp`、`4843/tcp`（TLS）。
> - 靶场拓扑参照：`$REDTEAM_REFS/GRFICSv3/docker-compose.yml` —— 一套真实的电力仿真靶场编排（见下方"靶场拓扑参照"）。
> - 工具清单：`$REDTEAM_REFS/ICS-Pentesting-Tools/README.md` —— s7scan / Snap7 / plcscan / ModScan / smod / ISF / CSET，以及蜜罐与固件类工具。
>
> **靶场拓扑参照（来自 GRFICSv3，用于校准"什么叫正常的电力靶场分区"）**：

| 角色 | 容器 | 网段与地址 | 对外端口 | 侦察价值 |
|---|---|---|---|---|
| 过程仿真 | `simulation` | `192.168.95.45`（b-ics-net） | `80:80` | 仿真过程；与 PLC 交换 Modbus |
| PLC | `plc` | `192.168.95.2`（b-ics-net） | `8080:8080` | OpenPLC Web 管理界面 |
| 工程师站 | `EWS` | `192.168.95.5`（b-ics-net） | `6080:6080` | **noVNC 远程桌面**——工程师站的典型暴露面 |
| HMI（SCADA） | `HMI` | `192.168.90.107`（c-dmz-net） | `6081:8080` | **SCADA-LTS，位于 DMZ**——跨区可达性的关键节点 |
| 攻击者 | `kali` | `192.168.90.6`（c-dmz-net） | `6088:6080` | 起点：与 HMI 同段，与 ICS 段隔离 |
| 路由/防火墙 | `router` | `192.168.95.200` / `192.168.90.200` | `51820/udp` | **防火墙 UI（FWUI）**——分区边界的真实控制点 |
| 编排/C2 | `caldera` | `192.168.90.250`（c-dmz-net） | `8888:8888` | 攻击编排 |
| SIEM | `wazuh` | `192.168.90.20`（c-dmz-net） | `1514/1515/55000/5601` | **防守视角的日志汇聚点** |

> 三个网段：`a-grfics-admin`（bridge）、`b-ics-net`（macvlan `192.168.95.0/24`）、`c-dmz-net`（macvlan `192.168.90.0/24`）。**DMZ 与 ICS 之间唯一的通路由 router 上的防火墙规则控制**——因此"跨区可达性"本身就是一个高价值 finding，而不是扫描的副产品。

---

## 操作步骤

> **⚠️ 关于 `evidence/tools/ot_guard.py`（必读）**
>
> 本技能多处引用 `evidence/tools/ot_guard.py`，它是**你工作区里的一个辅助脚本，本插件不随包提供**。
> 在创建它之前，下面这些 `ot_guard.py` 命令会直接失败。两个选择：
>
> 1. **用本插件真实存在的门禁兜底（推荐）**：所有写操作在上报前先用
>    `f2x_orchestrate_audit` 登记并取得二次确认——本插件的审计门禁会**按动作文本**判定
>    "只读 / 需确认 / 禁止"，写操作没有 `confirmedBy` 一律拒绝，删除与脱库类**硬拒**。
>    这是本插件里**唯一实际生效**的门禁路径。
> 2. **自行实现 `ot_guard.py`**：按本技能「安全约束」一节列出的门禁值（白名单、并发上限、
>    限速、审计可写性）自行编写，并保留它的范围声明与操作配对记录。
>
> 本包**不声称**任何 `ot_guard.py` 层面的保护——没有那个文件时它不存在。


### 0. 授权与前置门禁

```bash
python3 evidence/tools/ot_guard.py scope --declared "10.10.0.0/24" \
  --authorization "RANGE-2026-POWER-A" --operator "$(whoami)"
mkdir -p evidence/audit evidence/scada/{sweep,http,opc,hist,ews}
python3 evidence/tools/ot_guard.py selftest
```

统一门禁值：

```python
AUTHORIZED_SCOPE = ("10.10.0.0/24", "192.168.1.0/24")
# AUTHORIZED_SCOPE += ("192.168.90.0/24", "192.168.95.0/24")   # GRFICS 叠加段，须显式启用
MAX_CONCURRENCY  = 3
MIN_INTERVAL_S   = 1.0
AUDIT            = "evidence/audit/ot-ops.jsonl"
FORBID_ONLINE_BRUTEFORCE = True
```

### 1. 被动画像（零发包，先做这一步）

**先看清流量再谈扫描**——SCADA 网络里"谁在轮询谁"直接给出上位机/工程师站名单，且完全不给 OT 设备增加负载。

```bash
# 1.1 采集（有镜像口/TAP 时）
sudo tcpdump -i eth0 -nn -s0 -w evidence/scada/passive-$(date +%s).pcap \
  'not port 22 and not port 3389' -G 900 -W 1

# 1.2 Zeek 离线：会话矩阵 + 各 OT 协议日志
zeek -r evidence/scada/passive-*.pcap local
cat conn.log    | zeek-cut id.orig_h id.resp_h id.resp_p proto duration orig_bytes resp_bytes | sort -k3 -n | head -50
# Zeek 内建 OT 分析器：modbus / enip / dnp3（IEC 61850 需 icsnpp 扩展包）
ls *.log    # modbus.log enip.log dnp3.log conn.log dns.log http.log ssl.log

# 1.3 ICS 协议的"客户端"名单 → 工程师站/上位机嫌疑
cat modbus.log | zeek-cut id.orig_h id.resp_h | sort | uniq -c | sort -rn | head -20
cat enip.log   | zeek-cut id.orig_h id.resp_h | sort | uniq -c | sort -rn | head -20
```

```bash
# 1.4 没有镜像口时，只用 ARP/广播可达性做"谁在线"（极低影响，仍须限速）
sudo arp-scan --interface=eth0 --bandwidth=1M --delay=200 10.10.0.0/24 \
  | tee evidence/scada/sweep/arp-scan.txt
# 判读：MAC OUI 指向西门子/施耐德/罗克韦尔/研华等 → 直接标 OT 资产
```

### 2. 端口与资产面测绘（低频）

```bash
# 2.1 单次网段探测：OT + IT 混合端口集，T2 限速，串行
nmap -Pn -sT -T2 --max-rate 10 --max-parallelism 1 --host-timeout 180s \
  -p 21,22,80,102,135,139,443,445,502,3389,4840,4843,5900,5985,5986,8080,8081,8088,8443,8888,2404,2222,3306,5432,1433,1521,5450,8043,20000,44818,49320 \
  --open 10.10.0.0/24 -oA evidence/scada/sweep/10.10.0.0-24-ports

# 2.2 从结果快速生成分类清单
python3 evidence/tools/classify_assets.py \
  --nmap evidence/scada/sweep/10.10.0.0-24-ports.xml \
  --out evidence/scada/sweep/asset-classification.csv
#   分类口径：502/102/20000/2404/44818 => OT 设备
#             80/443/8080/8088/8043 => Web 界面（OT 或 IT）
#             3306/5432/1433/1521/5450 => 数据库/历史库
#             135/445/3389/5985      => Windows（工程师站候选）
#             4840/4843              => OPC UA
```

### 3. Web 管理界面指纹（SCADA / HMI / 网关）

```bash
# 3.1 服务与版本（低强度；一次请求一主机，串行）
nmap -Pn -sT -T2 --max-rate 10 --max-parallelism 1 \
  -p 80,443,8080,8081,8088,8443,8043,8888 \
  --script http-title,http-headers,http-auth-finder \
  --script-args "http.useragent=Mozilla/5.0 (compatible; authorized-OT-assessment)" \
  10.10.0.0/24 -oA evidence/scada/http/10.10.0.0-24-http

# 3.2 whatweb 低强度指纹（-a 1 = 被动/最轻，绝不 -a 3/-a 4）
while read -r ip; do
  for url in "http://$ip" "http://$ip:8080" "http://$ip:8088" "http://$ip:8043"; do
    timeout 8 whatweb -a 1 --wait=1 --no-errors "$url" 2>/dev/null | tee -a evidence/scada/http/whatweb.txt
    sleep 1        # 硬编码 ≥1 s/请求
  done
done < evidence/scada/sweep/live-hosts.txt
```

**主流 SCADA/HMI 指纹表**（用于把"开放端口"变成"这是什么系统"）：

| 系统 | 默认端口 / 路径 | 指纹特征 | 侦察要点 |
|---|---|---|---|
| **SCADA-LTS** | HTTP `8080`，上下文 `/Scada-LTS/`；登录 `/Scada-LTS/login.htm` | `<title>Scada-LTS</title>`、静态资源 `/Scada-LTS/resources/`、JS 包中含 `ScadaLTS` 命名 | 位于 DMZ 的典型 HMI；版本从 `/Scada-LTS/` 页脚或 `resources` 时间戳判定；**历史上有目录遍历/任意文件读取类 CVE，版本确认后按版本号核对官方公告，不得凭猜测引用 CVE 编号** |
| **Ignition（Inductive Automation）** | 网关 HTTP `8088`、HTTPS `8043`；`/web/home`、`/Status`、`/system/gateway` | `<title>Ignition Gateway</title>`；`/Status` 页在默认配置下**免认证**即列出网关版本与已装模块 | **`/Status` 是最高价值的单请求信息泄露**：一次 GET 拿到版本 + 模块清单；内置 OPC UA 服务端端点端口以 `/Status` 显示为准 |
| **Siemens SIMATIC WinCC（经典）** | 依赖 Windows 栈：`135/445/1433`；WebNavigator `80/443`，路径 `/WebNavigator` | Windows + SQL Server + 与 PLC 的 `102/tcp` 长连接 | 版本从 WebNavigator 页面/`/WebNavigator` 资源判定；WinCC 与 S7 的连接关系可从被动流量确认 |
| **SIMATIC HMI Comfort/Unified 面板** | HTTP `80`、VNC `5900`；同时开放 `102/tcp`（S7） | `Server: ` 头 + 精简 HTML 登录页；面板型号常在页脚/`/` 首页注释中 | **VNC 暴露 = 可直接操作画面**（高危）；面板与 S7 PLC 同网段 |
| **GE Proficy iFIX** | Windows 栈 `135/445/1433`；Web/HMI 通过 Proficy Web `80/443` | Windows + 大量 DCOM 动态端口；`iFIX`/`Proficy` 关键字出现在 HTTP 或 SMB 共享名 | OPC DA 走 DCOM（见第 5 步）；历史数据在 SQL Server |
| **AVEVA / Wonderware InTouch + System Platform** | Windows 栈；SQL Server `1433`；自有 API 端口（**以本机监听枚举为准**） | `ArchestrA`/`InTouch`/`Wonderware` 出现在 HTTP 标题、SMB 共享或服务名 | 历史数据在 SQL Server（`Runtime`/`History` 库） |
| **Rockwell FactoryTalk View SE** | EtherNet/IP `44818/tcp`（显式）+ `2222/udp`（隐式）；FT Directory 走 Windows 栈 | 大量 `44818` 会话；CIP 标识 `List Identity` 回包含厂商/型号 | 与 Logix PLC 的 CIP 会话数量可区分 HMI 与 EWS |
| **Kepware KEPServerEX** | OPC UA 默认 `49320`；配置 REST API 端口以本机监听为准 | OPC UA `GetEndpoints` 回包中 `ApplicationName` 含 `KEPServerEX` | OPC 汇聚点：**拿下它等于拿下所有下游 PLC 的读写通道** |
| **OpenPLC（实验室/仿真）** | HTTP `8080` | `<title>OpenPLC</title>`、登录 `/login`、默认口令 `openplc`/`openplc` | GRFICS 的 `plc` 容器即此类；**默认口令只允许一次性验证** |
| **OSIsoft / AVEVA PI** | PI Data Archive `5450`（PI-API）；PI Web API `443` | PI Web API `/piwebapi/`；PI System Explorer | 历史库：全厂工艺数据的长期存档 |
| **通用历史库/数据库** | MySQL `3306`、PostgreSQL `5432`、SQL Server `1433`、Oracle `1521`、InfluxDB `8086`（HTTP） | 版本横幅 + 库名 | SCADA-LTS 用 MySQL（GRFICS 挂载 `scadalts_db`）；WinCC/Wonderware 用 SQL Server |

```bash
# 3.3 逐条确认关键页面（HEX/头部/标题，全部只读 GET）
for u in "http://10.10.0.20:8088/Status" "http://10.10.0.20:8080/Scada-LTS/login.htm" \
         "http://10.10.0.30/" "http://10.10.0.30:8080/login"; do
  echo "=== $u"
  curl -s -i -m 8 --max-time 8 -A 'Mozilla/5.0 (compatible; authorized-OT-assessment)' "$u" \
    | sed -n '1,40p' | tee -a evidence/scada/http/key-pages.txt
  sleep 1
done

# 3.4 版本判定（这是 finding 的可执行部分：版本 → 已知问题核对）
curl -s -m 8 "http://10.10.0.20:8088/Status" | grep -iEo 'version[^<]{0,40}|ignition[^<]{0,30}' \
  | tee evidence/scada/http/ignition-status.txt
curl -s -m 8 "http://10.10.0.40/Scada-LTS/" | grep -iEo 'scada[^<]{0,40}|version[^<]{0,30}' \
  | tee evidence/scada/http/scadalts-version.txt
```

**只读探测的边界**：只做 `GET` 与头部判读。**不做**：登录爆破、默认口令字典遍历、上传接口试探、修改配置、触发扫描类功能、导入/导出接口调用。默认凭据只允许**一个**已公开组合的一次性验证，且必须记审计日志（门禁第 3/6 条）。

### 4. 工程师站（EWS）识别

EWS 的价值在于它**同时持有工程组态与到全部 PLC 的通道**——识别它，等于识别出攻击面上最短的那条路径。判别维度（按可靠性排序）：

**4.1 流量关系（最可靠，零发包）**

```bash
# 与多个 PLC 建立长连接、周期性小帧通信的主机 = EWS 或 SCADA 服务器
tshark -r evidence/scada/passive-*.pcap -Y 's7comm || mbtcp || enip || dnp3 || iec104' \
  -T fields -e ip.src -e ip.dst -e tcp.dstport \
  | sort | uniq -c | sort -rn | head -30 | tee evidence/scada/ews/polling-pairs.txt

# 单主机连接 PLC 数量（EWS/SCADA 服务器往往连 >3 台；HMI 常只连 1–2 台）
tshark -r evidence/scada/passive-*.pcap -Y 's7comm' -T fields -e ip.src -e ip.dst \
  | sort -u | awk '{print $1}' | sort | uniq -c | sort -rn | head
```

**4.2 主机名 / 共享 / 服务指纹**

```bash
# NetBIOS / NBNS / mDNS / LLMNR 名称（仪器命名惯例：EWS / ENG / STEP7 / TIA / WINCC）
tshark -r evidence/scada/passive-*.pcap -Y 'nbns || mdns || llmnr' -T fields -e ip.src -e nbns.name -e dns.qry.name \
  | sort -u | tee evidence/scada/ews/hostnames.txt

# SMB 与 RDP（只读枚举：脚本 smb-os-discovery/smb2-security-mode 均为只读）
nmap -Pn -sT -T2 --max-rate 10 -p 135,139,445,3389,5985 \
  --script smb-os-discovery,smb2-security-mode,smb2-time,rdp-enum-encryption \
  10.10.0.0/24 -oA evidence/scada/ews/10.10.0.0-24-windows

# 工程师站常见暴露面：noVNC / VNC / RDP
nmap -Pn -sT -T2 --max-rate 10 -p 5900,6080,6081,3389 \
  --script vnc-info --script-args vnc-info.timeout=5 \
  10.10.0.0/24 -oA evidence/scada/ews/10.10.0.0-24-remote-desktop
# ⚠️ 绝不使用 vnc-brute.nse（在线爆破，门禁第 6 条硬拒绝）
```

**4.3 EWS 判据汇总表**（写进报告的判定依据）

| 判据 | EWS/工程站特征 | HMI/操作员站特征 |
|---|---|---|
| OT 连接数 | 连 ≥3 台 PLC/RTU（组态下装需覆盖全站） | 通常 1–2 台 |
| 协议组合 | S7 `102` + ENIP `44818` + Modbus `502` 混合 | 单一协议为主 |
| 流量方向 | 双向（读写、下装、诊断） | 以上行为主（采集） |
| 服务面 | `135/445/3389/5985` + 工程软件共享目录 | 常有加固（仅 Web） |
| 主机名 | `EWS` / `ENG` / `STEP7` / `TIA` / `WINCC` / `WS-*` | `HMI` / `OP` / `SCADA` |
| 远程桌面 | RDP `3389` 或 noVNC `6080` | 面板自身 VNC `5900` |
| 与工程师活动时段 | 白天集中写入 | 24×7 均匀采集 |

**4.4 离线补充**（若已在 EWS 上取得访问）：确认 TIA Portal / STEP7 / WinCC 工程目录、组态备份、以及 `.ap*`/`.s7p`/`.zap*` 工程文件（**离线分析，不在线批量拉取**）。

### 5. OPC 接口枚举（OPC UA / OPC Classic）

```bash
# 5.1 OPC UA 端点发现（只读：GetEndpoints 是标准只读服务）
nmap -Pn -sT -T2 --max-rate 10 -p 4840,4843 --script=banner 10.10.0.0/24 \
  -oA evidence/scada/opc/10.10.0.0-24-opcua-ports
```

```python
# evidence/tools/opcua_enum.py —— 只读枚举：GetEndpoints + 有限命名空间浏览
import asyncio
from asyncua import Client

async def enum(url: str):
    async with Client(url=url, timeout=8) as c:
        # 无凭据匿名端点：先看服务端是否允许匿名
        eps = await c.get_endpoints()          # 只读
        for e in eps:
            print(f"endpoint={e.EndpointUrl}")
            print(f"  SecurityMode={e.SecurityMode}  SecurityPolicy={e.SecurityPolicyUri}")
            print(f"  AppName={e.Server.ApplicationName.Text}  AppUri={e.Server.ApplicationUri}")
        # 浏览根节点（严格串行，每次 ≤ 1 个 NodeId，间隔 1 s）
        import time
        root = c.nodes.objects
        for child in (await root.get_children())[:20]:      # 限 20 个，禁止全树递归
            print("  node:", await child.read_browse_name())
            time.sleep(1.0)

asyncio.run(enum("opc.tcp://10.10.0.20:4840"))
```

OPC UA 侦察判读要点：

- **`SecurityPolicy` 为 `None`（`http://opcfoundation.org/UA/SecurityPolicy#None`）→ 明文无签名通道**，这是一条独立的高价值 finding（对应参考素材中 Claroty/BSI 对 OPC UA 部署的分析：安全启动与证书信任链常被跳过）。
- **匿名端点可读 → 未授权数据访问**；进一步试探 `Write` 属写操作，须走门禁（🔴，见「OT 影响评估」）。
- `Server.ApplicationUri` / `ApplicationName` 直接给出产品与站点标识（KEPServerEX / Ignition / 各家 PLC 内置 OPC UA）。

```bash
# 5.2 OPC Classic（DA/HDA/AE）走 DCOM —— 只做"是否存在"判定，不做 DCOM 调用
nmap -Pn -sT -T2 --max-rate 10 -p 135 --script msrpc-enum 10.10.0.0/24
# 已知 OPCEnum CLSID（用于离线比对与资产说明，不在线实例化）：
#   {13486D51-4821-11D2-A494-3CB306C10000}
# DCOM 端点动态分配（1024–65535），仅做资产标注，不做端点爆破
```

### 6. 历史库与数据库接口枚举

历史库持有**全厂长期工艺数据**——其泄露价值往往高于单台 HMI。

```bash
# 6.1 数据库端口与只读指纹（不登录、不猜口令）
#     只允许 mysql-info / ms-sql-info / ms-sql-ntlm-info 这类"只读横幅+配置"脚本。
#     ❌ mysql-brute / pgsql-brute / ms-sql-brute / oracle-brute 一律禁止（门禁第 6 条）。
nmap -Pn -sT -T2 --max-rate 10 -p 3306,5432,1433,1521,5450,8086,27017 \
  --script mysql-info,ms-sql-info 10.10.0.0/24 \
  -oA evidence/scada/hist/10.10.0.0-24-db

# 6.2 SCADA-LTS 的历史库（MySQL）—— 版本与库名判定
nmap -Pn -sT -p 3306 -T2 --max-rate 10 --script mysql-info 10.10.0.40 \
  | tee evidence/scada/hist/scadalts-mysql-info.txt

# 6.3 InfluxDB（HTTP API 自身即指纹）
curl -s -i -m 8 "http://10.10.0.50:8086/ping" | head -12 | tee evidence/scada/hist/influx-ping.txt
curl -s -m 8 "http://10.10.0.50:8086/health" | tee -a evidence/scada/hist/influx-ping.txt
```

```bash
# 6.4 SQL Server 只读信息收集（ms-sql-info 为只读；空口令检查属"一次性默认凭据验证"）
nmap -Pn -sT -p 1433 -T2 --max-rate 10 --script ms-sql-info,ms-sql-ntlm-info 10.10.0.60
# ❌ 禁止 ms-sql-brute / ms-sql-empty-password 的字典化使用；如需验证空口令，
#    仅允许单次、记审计日志、失败即停（门禁第 6 条）。
```

历史库接口清单（报告需明确到"库名 + 表名/接口名 + 数据粒度"）：

| 目标 | 接口 | 侦察产出 |
|---|---|---|
| SCADA-LTS | MySQL `3306`（库如 `scadalts`）、Web `/Scada-LTS/api/...` | 点位表、历史值表、事件表 |
| WinCC / Wonderware | SQL Server `1433`（库如 `Runtime`/`History`/`WW` 前缀） | 报警归档、趋势归档 |
| PI System | PI-API `5450`、PI Web API `/piwebapi/` | PI Point 清单、AF 层级 |
| Ignition | 网关 `/Status` + 标签历史库（内建 DB 或外接） | 标签提供者、历史提供者 |
| 通用 | InfluxDB `8086`、PostgreSQL `5432`、Oracle `1521` | measurement/表结构 |

**枚举边界**：只做**端口 + 版本 + 库名/接口名**级别枚举。`SELECT` 取样属读取（🟢，但需授权与记日志）；`UPDATE/DELETE/DROP`、历史数据篡改、删库属 🔴 且**本技能一律不做**。

### 7. 跨区可达性测绘（DMZ ↔ ICS）—— 电力靶场的核心 finding

参照 GRFICSv3 的分区设计：攻击者通常在 `c-dmz-net`，与 HMI 同段，而 PLC/EWS 在 `b-ics-net`，两段之间只有 router 的防火墙规则。**"从 DMZ 能否直达 ICS"就是一条 finding。**

```bash
# 7.1 逐跳、逐端口的可达性矩阵（每端口单次 SYN 探测；用 -sT 避免半开）
python3 evidence/tools/reach_matrix.py \
  --src-note "attacker@dmz" \
  --targets 192.168.95.2,192.168.95.5,192.168.95.45,192.168.95.200 \
  --ports 80,102,502,8080,6080,44818,4840 \
  --interval 1.0 --out evidence/scada/sweep/cross-zone-matrix.csv

# 7.2 路由与分区边界识别（只读）
ip route
traceroute -n -w 2 -q 1 -m 5 192.168.95.2      # 单次、限跳数
nmap -Pn -sT -T2 --max-rate 5 -p 22,80,443,51820 192.168.95.200 192.168.90.200
```

判读要点：

- **DMZ → ICS 的 OT 端口（`502`/`102`/`44818`）通 = 分区失效**，这是电力靶场最高价值的网络面 finding（等于攻击者可从暴露面直达控制器）。
- 防火墙设备自身的管理面（GRFICS 的 `router` 带 **FWUI**，环境变量 `FWUI_SECRET_KEY`）若从 DMZ 可达 → 规则可被改写，属 🔴 级风险发现（**只记录，不改规则**）。
- 跨区若仅 **Web/跳板**可达（如 DMZ 的 HMI 能访问 ICS），则攻击路径为"打 HMI → 以 HMI 为跳板"——这条链要与 `f2x-power-modbus-attack` 串联。
- 结论必须区分"**实测可达**"与"**路由表/规则推断**"，不得混写。

### 8. 证据固化与资产台账

```bash
# 8.1 生成统一资产台账（后续所有技能都引用它）
python3 evidence/tools/build_asset_ledger.py \
  --nmap evidence/scada/sweep/*.xml \
  --http evidence/scada/http/ \
  --out evidence/scada/asset-ledger.csv
#   列：ip,hostname,role(scada|hmi|ews|plc|historian|opc|network|it|unknown),vendor,product,version,ports,evidence,confidence

# 8.2 资产与跨区链路登记
#    f2x_orchestrate_blackboard { action:"write", kind:"fact", title:"<资产/链路>", evidence:"<证据路径>" }
#      —— 本插件自带，任何部署都有；kind=fact 必须带 evidence
#    若部署里存在 redteam_atlas_target / redteam_atlas_chain（可选增强），
#    才额外登记进 AttackAtlas 成图

# 8.3 归档与校验
sha256sum evidence/scada/**/* > evidence/scada/SHA256SUMS
python3 evidence/tools/ot_guard.py audit-verify --expect-pairs
```

---

## 安全约束

> 以下六条为**硬编码门禁**，在任何目标、任何阶段、任何理由下不得豁免。由 `evidence/tools/ot_guard.py` 在工具调用前强制执行。

1. **单目标并发不超过 3 个工具调用。**
   同一目标 IP 上并发的工具进程（nmap / whatweb / curl 循环 / OPC UA 客户端 / 数据库客户端）总数 **≤ 3**，默认串行为 1。SCADA 与 HMI 主机通常是低配工控机或嵌入式面板（CPU 余量与并发连接数都很小），并发请求会直接拖慢甚至卡死画面。禁止多终端齐发、禁止 `xargs -P`、禁止对同一 Web 界面并行拉取多路径、禁止 `--script` 批量叠加多个耗时脚本。

2. **模糊测试必须低频化，禁止高频扫描 OT 设备。**
   硬性限速参数：
   - 端口/主机扫描：`nmap -T2 --max-rate 10 --max-parallelism 1 --host-timeout 180s`（禁止 `-T3/-T4/-T5`、禁止 `--min-rate`、禁止 `-sU` 大范围 UDP 扫描——UDP 扫描对 OT 设备更易致异常）。
   - Web 指纹：`whatweb -a 1 --wait=1`（**禁止 `-a 3`/`-a 4`**，激进模式会主动探测大量路径）。
   - HTTP 请求间隔 **≥ 1 秒**（脚本内硬编码 `sleep 1`）；`curl` 一律带 `-m 8`（超时兜底）。
   - 数据库/OPC 枚举：每次连接间隔 ≥ 1 s，单目标连接数 ≤ 3。
   - **禁止对任何 SCADA/HMI/数据库做模糊测试**（不跑 `http-fuzz`、`*-fuzz`、`wfuzz`、参数爆破）。若在隔离仿真靶场必须做，单请求 ≤ 1 req/s、总量 ≤ 300 次/目标/小时。
   - 熔断条件：目标 Web 响应时间显著劣化（如 `curl` 的 `time_total` 变为基线 5 倍以上）、出现 5xx 连续 2 次、或 TCP 连接被拒连续 2 次 → **立即停止该目标全部探测并退避 60 秒**，写审计日志后由指挥官裁决。
   - **ARP 扫描**用 `--bandwidth=1M --delay=200`（不得用默认全速风暴模式）。

3. **写操作（寄存器写入、线圈强制、固件修改、PLC 启停）必须经过指挥官二次确认，且记入审计日志。**
   本技能中"写操作"的等价物为：**HMI/SCADA 上的任何非 GET 请求**（标签写入、下发命令、启动/停止设备、配置保存）、**OPC UA `Write`/`Call` 服务**、**数据库写操作**（`INSERT/UPDATE/DELETE/DROP`，含历史数据篡改）、**SCADA 用户/角色/报警确认**类接口、**防火墙规则修改**。流程强制：`request-write` 拿 `ack-id` → 指挥官显式确认 → 带 `ack-id` 执行 → **执行前**写审计日志、执行后写结果日志 → 回读确认。无 `ack-id` 的写命令由门禁拒绝。**本技能的默认真实立场是"只读侦察"——绝大多数场景下不应出现任何写操作。**

4. **任何可能影响工控设备正常运行的命令，必须先记录到审计日志再执行。**
   保守判据：**凡不能证明是纯只读，就先记日志**。本技能中需先记日志的"只读但高风险"动作包括：`/Status` 一类免认证信息页读取（虽只读但属未授权访问取证，必须留痕）、OPC UA `GetEndpoints` 与命名空间浏览（占用会话资源）、数据库连接与库名枚举（失败尝试会计入审计与锁定计数）、默认凭据一次性验证、RDP/VNC 指纹探测（会写入对端安全日志）、跨区可达性探测（防火墙日志）。**先记后做，禁止事后补记。** 审计条目含 `ts`（ISO8601 带时区）、`op`、`target`、`url`/`port`/`service`、`class`（read/write/control/fuzz）、`rate`、`authorization`、`commander_ack`、`purpose`、`result`；写操作前后各一条，成对可核。

5. **目标范围白名单硬编码，超出白名单一律拒绝执行。**
   ```python
   AUTHORIZED_SCOPE = ("10.10.0.0/24", "192.168.1.0/24")   # 已授权电力靶场段
   # 授权靶场叠加段（须在授权书范围内显式启用；默认关闭）
   # AUTHORIZED_SCOPE += ("192.168.90.0/24", "192.168.95.0/24")
   ```
   所有扫描/请求/连接前跑 `assert_in_scope(ip)`（`ipaddress.ip_address(host) in ipaddress.ip_network(cidr)`），**不匹配即 `sys.exit(2)` 并记录拒绝日志**；`assert_in_scope` 必须对 **重定向目标** 与 **DNS 解析结果** 各验一次（防止 `302` 把请求带出白名单——这在 Web 侦察里是最常见的越界方式）。禁止用域名/别名绕过；禁止 `-iL` 外置范围；禁止对白名单外的**上游/下游节点**（如 HMI 反连的云、厂商远程运维通道）发起探测，只做记录与说明。

6. **禁止 DDoS，禁止爆破；S7 口令只允许离线爆破参考脚本，禁止在线爆破。**
   - 禁止 DoS/DDoS 与泛洪：禁止 `hping3 --flood`、禁止 Web 并发压测、禁止数据库连接耗尽、禁止 OPC UA 会话耗尽、禁止 ARP 风暴、禁止对 HMI 做大量并发 HTTP 请求（**把 HMI 打挂等于让操作员失去画面**，在电力场景是安全事件）。
   - **禁止在线口令爆破**：Web 登录（SCADA-LTS / Ignition / OpenPLC / 面板）**一律禁止**字典或暴力尝试；禁止 `http-form-brute`、`*-brute`、`hydra`、`medusa`、`patator`、`wfuzz` 认证模式。数据库口令同禁（含 `ms-sql-brute`、`pgsql-brute`、`mysql-brute`、`vnc-brute`）。
   - S7 口令仅允许**离线**路线（从 pcap 提 challenge/response → 本地字典，见 `f2x-power-s7comm-attack`），离线爆破不得产生任何网络流量；命中后不得回连目标做在线验证。
   - 唯一例外是"**单个**已公开默认凭据的**一次性**验证"（如 SCADA-LTS `admin/admin`、OpenPLC `openplc/openplc`），必须记审计日志；**一旦失败即停止，不得继续尝试第二个口令**，也不得对同一系统的第二个账户重试。

---

## OT 影响评估

| 等级 | 本技能中的操作 | 影响机制 | 缓解/边界 |
|---|---|---|---|
| 🟢 **只读** | 被动抓包与 Zeek 离线分析（第 1 步）、ARP 慢速扫描、端口态确认（第 2 步）、`http-title`/`http-headers`/`http-auth-finder`、`whatweb -a 1`、`curl -s -i` 单次 GET（第 3 步）、`vnc-info`/`smb-os-discovery`/`smb2-security-mode`（只读脚本）、OPC UA `GetEndpoints` 与有限浏览（第 5 步） | 不改变任何过程变量与配置；影响仅为网络与会话资源占用 | 1 s/请求、并发 ≤3、`curl -m 8` 超时兜底、whatweb `-a 1`；发现响应劣化即熔断退避 60 s |
| 🟢/🟡 **边界** | 免认证信息页读取（Ignition `/Status`）、数据库 `mysql-info`/`ms-sql-info`、库名与表名枚举、默认凭据**一次性**验证、跨区可达性探测 | 不改变过程值，但**会在对端留下日志**（安全日志/失败计数/防火墙日志），失败认证可能触发账户锁定或告警 | 单次尝试、失败即停、先写审计日志；对端有锁定策略时**放弃**而非重试 |
| 🟡 **可恢复写入** | 经授权的 HMI 配置类只写（如报警确认）、数据库**只读**外的轻度写入测试（仅在隔离仿真靶场且可回滚）、OPC UA 写非安全相关且被 PLC 逻辑覆盖的变量 | 可被写回或下一扫描周期覆盖 | 二次确认 + 先审计 + 记录原值 + 写后回读 + 明确回滚；**默认为不做** |
| 🔴 **不可逆 / 停机风险** | HMI 上的**下发命令/标签写/启停设备/设定值修改**（等同直接操作生产过程）、OPC UA `Write`/`Call` 到控制类节点、SCADA 用户与角色变更、**SQL 写入/删库/历史数据篡改**（破坏审计与追溯）、**防火墙规则修改**（改变分区边界）、数据库 `DROP` | 设备误动、保护误动/拒动、非计划停电、**取证链被破坏**（历史库篡改会让后续事件无法追溯）、分区失效导致全网暴露 | **默认拒绝**；仅"隔离仿真靶场 + 指挥官二次确认 + 先审计后执行 + 明确回滚方案 + 现场有人值守"五条件齐备才可执行；**防火墙规则与历史库删除在本技能中一律不做** |
| 🔴 **停机风险** | 取消限速、并发 >3、对 HMI 的并发 HTTP 压测、Web 模糊测试、数据库连接耗尽、ARP 风暴 | 工控机/嵌入式面板 CPU 与连接数被打满 → HMI 画面卡死/断开 → **操作员失去监视与控制手段**，可能触发误操作或保护 fallback | 门禁第 2/6 条硬拒绝；熔断即退避 60 s 并上报指挥官 |
| ⚫ **绝对禁止** | 任何在线口令爆破、DDoS/泛洪、生产环境 HMI 写操作、历史库删改、防火墙规则改写 | 直接停机、取证破坏、分区失效、人身风险 | 硬拒绝，不设例外 |

**一句话结论**：本技能是**纯侦察型**技能，其价值 90% 以上来自 🟢 只读面——**被动流量 + 低频指纹 + 单次 GET** 足以产出"资产台账 / 角色划分 / 版本清单 / 跨区可达性 / OPC 与历史库暴露面"五类高价值结论。写操作在本技能中**没有存在的必要**：跨区可达性与 HMI 暴露面本身就是 finding，完全不需要通过"改一个值"来证明。

---

## 产出与证据

### 必交交付物

| # | 交付物 | 路径 | 计分要点 |
|---|---|---|---|
| 1 | 范围声明与门禁自检 | `evidence/audit/ot-ops.jsonl`（首条 scope 声明；含拒绝越界记录） | 全程白名单内 + 限速合规 + 重定向目标已复验 |
| 2 | **资产台账（核心）** | `evidence/scada/asset-ledger.csv` | 列：`ip,hostname,role,vendor,product,version,ports,evidence,confidence`；`role` 需区分 scada/hmi/ews/plc/historian/opc/network |
| 3 | Web 界面指纹证据 | `evidence/scada/http/whatweb.txt`、`10.10.0.0-24-http.*`、`key-pages.txt` | 每个界面给出标题/头部/版本与判定依据 |
| 4 | **SCADA/HMI 产品与版本清单（核心）** | `evidence/scada/http/product-versions.md` | SCADA-LTS / Ignition / WinCC / iFIX / Wonderware / FactoryTalk / Kepware / OpenPLC 各自版本与来源页 |
| 5 | 免认证信息泄露证据 | `evidence/scada/http/ignition-status.txt`（含 `/Status` 原文） | 单请求即取到版本 + 模块清单 → 独立 finding |
| 6 | **工程师站识别报告（核心）** | `evidence/scada/ews/ews-identification.md` + `polling-pairs.txt` + `hostnames.txt` | 判据逐条对照（OT 连接数、协议组合、服务面、主机名、远程桌面），结论含置信度 |
| 7 | 远程桌面暴露面 | `evidence/scada/ews/10.10.0.0-24-remote-desktop.*` | VNC/noVNC/RDP 开放清单（**VNC 可直接操作画面 = 高危**） |
| 8 | OPC 接口枚举 | `evidence/scada/opc/opcua-endpoints.md` | 端点 URL、`SecurityPolicy`（**是否 `None`**）、`SecurityMode`、匿名可读性、`ApplicationUri` |
| 9 | 历史库与数据库暴露面 | `evidence/scada/hist/*` + 接口清单表 | 端口、版本、库名、接口名（不清库、不猜口令） |
| 10 | **跨区可达性矩阵（核心）** | `evidence/scada/sweep/cross-zone-matrix.csv` | DMZ→ICS 的 OT 端口可达性；区分"实测"与"推断" |
| 11 | 分区边界与网络设备 | `evidence/scada/sweep/routes.txt`、防火墙管理面可达性记录 | 分区是否失效；防火墙管理面是否暴露（只记录不改） |
| 12 | 资产与跨区链路登记 | `f2x_orchestrate_blackboard`（kind=fact，带 evidence；本插件自带） | 入口资产与 DMZ→ICS 跨区链路可被后续阶段引用 |
| 13 | finding 登记 | `f2x_orchestrate_finding`（本插件自带） | finding：HMI 未授权访问 / 版本信息泄露 / EWS 暴露 / OPC UA SecurityPolicy=None / 跨区可达（分区失效）/ 免认证管理页 |

### 证据质量要求

- **被动优先**：能用流量得到的结论（谁连谁、谁是 EWS、周期多少）绝不用主动扫描"验证"——被动证据更可靠且零风险。
- **单请求可复现**：每条 Web 结论附**一条** `curl` 命令与响应头部/标题片段，第三方可独立复现。
- **角色判定要给判据**：`role` 列的每个值都要有对照表中的至少 2 条判据支撑，单判据只能标 `confidence=low`。
- **版本必须可溯源**：版本号必须给出**具体来源**（页面路径 / HTTP 头部 / 横幅原文），不得凭记忆填写；**不得凭版本号猜测 CVE 编号**——只写"版本已确认，需按版本核对厂商公告"。
- **危险动作留痕**：任何 🔴 动作（本技能默认应无）必须留"审批 → 执行前审计 → 执行 → 执行后审计 → 回滚 → 回滚验证"六段链，缺段即违规。
- **诚实标注**：区分"实测可达 / 规则推断 / 未知"；把 `filtered`、超时、连接被拒原样记录（这些恰恰是防火墙存在的证据，是 finding 的一部分）。

### 速用命令卡

```bash
# 资产面（只读，限速）
nmap -Pn -sT -T2 --max-rate 10 --max-parallelism 1 -p 80,102,502,1433,3306,3389,4840,5900,8080,8088,8888,20000,44818,2404 --open 10.10.0.0/24
# Web 指纹（只读，单请求）
curl -s -i -m 8 http://10.10.0.20:8088/Status | head -40          # Ignition：版本 + 模块
curl -s -i -m 8 http://10.10.0.40:8080/Scada-LTS/login.htm | head -40
whatweb -a 1 --wait=1 http://10.10.0.20:8088/                      # 低强度
# EWS 判定（被动，零发包）
tshark -r passive.pcap -Y s7comm -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn | head
# 跨区可达性（单次 SYN，逐端口）
nmap -Pn -sT -T2 --max-rate 5 -p 102,502,44818 192.168.95.2 192.168.95.5
# ❌ 禁止：http-form-brute / hydra / medusa / wfuzz / vnc-brute / ms-sql-brute / pgsql-brute / whatweb -a 3 / nmap -T4 / hping3 --flood / HMI 写操作 / SQL 写入
```

### 与其他技能的衔接

- 指纹确认了 Modbus / S7 / IEC 61850 设备后 → 对应协议技能做深挖（`f2x-power-modbus-attack` / `f2x-power-s7comm-attack` / `f2x-power-iec61850-analysis`）。
- 需要判定上游攻击者、还原入侵时间线、给出防守检测点 → `f2x-power-traceback`。
- 需要从 DMZ 主机跳到 ICS 段 → 本技能产出的 EWS/HMI 名单与跨区矩阵就是**跳板与路径清单**。
