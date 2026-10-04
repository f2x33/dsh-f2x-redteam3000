---
name: f2x-power-iec61850-analysis
description: 电力变电站 IEC 61850 安全分析技能——SCL/SCD/CID 文件解析、IED 建模、MMS 与 GOOSE/SV 报文分析、监控基线提取与 GOOSE 伪造风险分析，含隔离实验段门禁与零注入只读优先原则。
whenToUse: 目标为变电站自动化系统（保护 IED、合并单元、智能终端、站控层），已取得 SCL/SCD/CID/IID 工程文件或站控层/过程层抓包，需要还原 IED 模型、分析 GOOSE/SV/MMS 报文或评估 GOOSE 伪造风险时使用。
---

# IEC 61850 变电站安全分析技能（f2x-power-iec61850-analysis）

> **工具可用性与退路（先读这一节）**
> 本技能只依赖本插件自带的 `f2x_orchestrate_*` 工具，**不依赖任何其他插件**。
> 工作流里出现的 `redteam_coverage_mark` / `redteam_atlas_*` / `redteam_finding_register`
> 是**可选增强**：
> - **成果登记** → `f2x_orchestrate_finding`（本插件自带）
> - **IED ↔ IP/MAC/GOOSE 控制块映射、跨区链路** → 写进证据文件（如 `evidence/ied-map.tsv`）
>   并用 `f2x_orchestrate_blackboard`（kind=fact，必须带 evidence）登记
> - **覆盖矩阵** → 本插件无此面；用 `f2x_orchestrate_export` 作为覆盖记录，
>   或仅在部署里确实有 `redteam_coverage_mark` 时才回写
> **规则**：目录里没有的工具一律不要调用。开场先跑 `f2x_orchestrate_doctrine` 自检。

> **定位**：本技能覆盖 **IEC 61850** 体系（站控层 MMS、过程层 GOOSE/SV）。Modbus/S7 见 `f2x-power-modbus-attack` / `f2x-power-s7comm-attack`；流量回溯与防守检测规则见 `f2x-power-traceback`；SCADA/HMI 面见 `f2x-power-scada-recon`。
>
> **协议事实（来源：`$REDTEAM_REFS/awesome-industrial-protocols/protocols/iec-61850.md`）**：IEC 61850 是"电力公用事业自动化的通信网络与系统"，关键词 **Power grid**，规范为**付费**（<https://webstore.iec.ch/publication/6028>）；别名 IEC-61850/GOOSE、IEC-61850/GSSE、IEC-61850/SV；Nmap NSE `iec61850-mms.nse`；Wireshark 解析器 `packet-goose.c`、`packet-sv.c`；开源实现 **libiec61850**（mz-automation）。
>
> **核心安全事实**：GOOSE 与 SV 是 **二层组播、无认证、无加密** 的协议（IEC 61850-8-1 / 9-2 原生如此；认证能力需叠加 IEC 62351-6）。因此"GOOSE 伪造"不是实现漏洞，而是**协议设计面的固有风险**——评分价值在于"伪造面被识别 + 可伪造性被论证 + 防守检测点被给出"，而不在于"真的让断路器跳了"。
>
> **素材引用（本机只读）**：`$REDTEAM_REFS/IEC61850SecurityDataset/` —— 含 `Normal/`（基线）、`Disturbance/`（扰动：BusbarProtection / BreakFailure / UnderFrequency，附 18 个 IED 的逐秒 CSV）、`Attack/`（Data Manipulation (DM) / Message Suppression (MS) / Denial of Service (DoS) / CompositeAttack.pcapng）、`SCL Files/`（18 个 IID 定义）。该数据集是**离线分析的首选语料**——10 分钟/文件、18 个 IED、1 Hz 组播，是建立"正常态基线"的最佳素材。

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
mkdir -p evidence/audit evidence/iec61850/{scl,goose,sv,mms}
python3 evidence/tools/ot_guard.py selftest
```

统一门禁值：

```python
AUTHORIZED_SCOPE = ("10.10.0.0/24", "192.168.1.0/24")
# AUTHORIZED_SCOPE += ("192.168.90.0/24", "192.168.95.0/24")
MAX_CONCURRENCY  = 3
MIN_INTERVAL_S   = 1.0
AUDIT            = "evidence/audit/ot-ops.jsonl"
# IEC 61850 专属：GOOSE/SV 注入仅允许在隔离过程层实验段，且功能位 test=1
ALLOW_GOOSE_INJECTION_SEGMENT = None    # 形如 "isolated-lab-procseg-A"；None = 一律不注入
```

### 1. 资产与工程文件盘点（**先文件、后网络**）

IEC 61850 工程的价值极大比例在 **SCL 文件**里——它能让你在不发一个包的情况下拿到整站拓扑、IED 能力、数据集与组播地址。

| 文件类型 | 全称 | 作用 |
|---|---|---|
| **SSD** | System Specification Description | 一次系统接线 + 逻辑节点需求（单线图） |
| **SCD** | Substation Configuration Description | **整站**配置：所有 IED + 通信 + 数据集 + 控制块 |
| **ICD** | IED Capability Description | 单型号 IED 的能力描述（厂家模板） |
| **CID** | Configured IED Description | 单台 IED 的实例化配置（下装到设备的文件） |
| **IID** | Instantiated IED Description | 实例化 IED 描述（数据集用的就是这类） |
| **SED** | System Exchange Description | 站间交换描述 |

```bash
# 1.1 盘点手头素材（含只读参考数据集）
find evidence -iname '*.scd' -o -iname '*.cid' -o -iname '*.icd' -o -iname '*.iid' -o -iname '*.ssd' \
  | sort > evidence/iec61850/scl/scl-inventory.txt
ls -la "$REDTEAM_REFS/IEC61850SecurityDataset/SCL Files/" | head -25
ls -la "$REDTEAM_REFS/IEC61850SecurityDataset/Attack/"

# 1.2 每个文件的版本与工具标识（溯源用）
for f in $(cat evidence/iec61850/scl/scl-inventory.txt); do
  echo "== $f"; xmllint --xpath "//Header/@version | //Header/@revision | //Header/@toolID | //Header/@nameStructure" "$f"; echo
done
```

### 2. SCL 静态解析（零发包，产出整站模型）

SCL 是 XML，顶层元素为 `<SCL>`，关键子树：`Header` / `Substation` / `Communication` / `IED` / `DataTypeTemplates`。

```bash
# 2.1 整站 IED 清单
xmllint --xpath "//IED/@name" station.scd

# 2.2 通信映射：IED → AccessPoint → ConnectedAP → IP / MAC（伪造检测的基线就在这里）
xmllint --xpath "//Communication/SubNetwork/@name | //Communication/SubNetwork/@type" station.scd
xmllint --xpath "//Communication/SubNetwork/ConnectedAP/@iedName | //Communication/SubNetwork/ConnectedAP/@apName" station.scd
xmllint --xpath "//Communication/SubNetwork/ConnectedAP/Address/P[@type='IP']/text()" station.scd
xmllint --xpath "//Communication/SubNetwork/ConnectedAP/Address/P[@type='MAC-Address']/text()" station.scd
xmllint --xpath "//Communication/SubNetwork/ConnectedAP/GSE/@ldInst | //Communication/SubNetwork/ConnectedAP/GSE/@cbName | //Communication/SubNetwork/ConnectedAP/GSE/Address/P[@type='MAC-Address']/text()" station.scd

# 2.3 GOOSE 控制块（GSEControl）：伪造要复现的字段全在这里
xmllint --xpath "//GSEControl/@name | //GSEControl/@datSet | //GSEControl/@appID | //GSEControl/@confRev | //GSEControl/@type | //GSEControl/@fixedOffs" station.scd

# 2.4 SV 控制块（SampledValueControl）：9-2LE 采样值通道
xmllint --xpath "//SampledValueControl/@name | //SampledValueControl/@datSet | //SampledValueControl/@confRev | //SampledValueControl/@smpRate | //SampledValueControl/@nofASDU" station.scd

# 2.5 报告控制块（站控层 MMS 侧）
xmllint --xpath "//ReportControl/@name | //ReportControl/@datSet | //ReportControl/@rptID | //ReportControl/@bufTime | //ReportControl/@intgPd" station.scd
```

```python
# evidence/tools/scl_parse.py —— 用 lxml 做关系型抽取，产出可机读的整站模型
from lxml import etree
import json, sys, csv

NS = {"s": "http://www.iec.ch/61850/2003/SCL"}
tree = etree.parse("station.scd"); root = tree.getroot()

# a) 一次系统（Substation → VoltageLevel → Bay → ConductingEquipment）
substation = [{"name": s.get("name"), "desc": s.get("desc")}
              for s in root.findall(".//s:Substation", NS)]

# b) 逻辑节点实例（LNode）与所属 IED/AccessPoint
ieds = []
for ied in root.findall(".//s:IED", NS):
    for ap in ied.findall("s:AccessPoint", NS):
        lns = []
        for ln in ap.findall(".//s:LN", NS):
            lns.append({"lnClass": ln.get("lnClass"), "inst": ln.get("inst"),
                        "prefix": ln.get("prefix"), "lnType": ln.get("lnType")})
        ieds.append({"ied": ied.get("name"), "manufacturer": ied.get("manufacturer"),
                     "type": ied.get("type"), "configVersion": ied.get("configVersion"),
                     "ap": ap.get("name"), "lns": lns})

# c) 数据集成员（伪造/篡改的目标数据面）
datasets = {}
for ds in root.findall(".//s:DataSet", NS):
    datasets[ds.get("name")] = [{"ldInst": f.get("ldInst"), "prefix": f.get("prefix"),
                                 "lnClass": f.get("lnClass"), "lnInst": f.get("lnInst"),
                                 "doName": f.get("doName"), "daName": f.get("daName"),
                                 "fc": f.get("fc")} for f in ds.findall("s:FCDA", NS)]

# d) GOOSE 控制块 → 期望的报文指纹（gocbRef / goID / datSet / confRev / appID）
gse = []
for gc in root.findall(".//s:GSEControl", NS):
    gse.append({"name": gc.get("name"), "datSet": gc.get("datSet"),
                "appID": gc.get("appID"), "confRev": gc.get("confRev"),
                "type": gc.get("type")})

# e) 数据类型模板链（用于把 DO/DA 还原成工程量与类型）
dtt = {}
for t in root.findall(".//s:LNodeType", NS):
    dtt[t.get("id")] = {"lnClass": t.get("lnClass"),
                        "dos": [{"name": d.get("name"), "type": d.get("type")}
                                for d in t.findall("s:DO", NS)]}

json.dump({"substation": substation, "ieds": ieds, "datasets": datasets,
           "gseControl": gse, "lNodeTypes": dtt},
          open("evidence/iec61850/scl/station-model.json", "w"),
          ensure_ascii=False, indent=2)
print("IED:", len(ieds), "DataSets:", len(datasets), "GSEControl:", len(gse))
```

### 3. IED 建模（把 SCL 变成"可判定基线"）

IED 模型的三级链：`LNodeType → DOType → DAType/EnumType`，配合功能约束 FC 与品质/时标属性 `q` / `t`。

```python
# evidence/tools/ied_model.py —— 展开到 DA 级，标注 cdc / fc / 类型 / 工程单位
from lxml import etree
NS = {"s": "http://www.iec.ch/61850/2003/SCL"}
root = etree.parse("station.scd").getroot()
dotype = {t.get("id"): t for t in root.findall(".//s:DOType", NS)}
datype = {t.get("id"): t for t in root.findall(".//s:DAType", NS)}
lnode  = {t.get("id"): t for t in root.findall(".//s:LNodeType", NS)}

rows = []
for lnid, lnt in lnode.items():
    for do in lnt.findall("s:DO", NS):
        dt = dotype.get(do.get("type"))
        if dt is None: continue
        for da in dt.findall("s:DA", NS):
            rows.append({"lnodeType": lnid, "lnClass": lnt.get("lnClass"), "cdc": dt.get("cdc"),
                         "do": do.get("name"), "da": da.get("name"), "bType": da.get("bType"),
                         "fc": da.get("fc"), "dchg": da.get("dchg"), "qchg": da.get("qchg"),
                         "dupd": da.get("dupd")})
import csv, sys
w = csv.DictWriter(open("evidence/iec61850/scl/ied-data-attributes.csv","w",newline=""),
                   fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
print(len(rows), "个数据属性")
```

**必须还原的工程语义**（这是把报文变成"断路器在跳"的关键）：

| 逻辑节点 | 语义 | 攻击价值 |
|---|---|---|
| `XCBR` | 断路器（`Pos` = 位置：`stVal` 通断、`q` 品质、`t` 时标） | **DM.2 直接篡改开关位置** |
| `CSWI` | 开关控制器（`Pos` 控制输出） | 跳合闸控制 |
| `PTOC` | 过流保护（`Str`/`Op` 启动与动作） | 保护误动/拒动 |
| `PDIS` | 距离保护 | 同上 |
| `PTRC` | 跳闸逻辑（`Tr` 跳闸输出） | 组合攻击的核心 |
| `MMXU` | 测量（`A` 相电流、`PhV` 相电压、`TotW`） | **DM.1 篡改电流测量** |
| `TVTR` / `TCTR` | 电压/电流互感器 | 采样值来源 |
| `CILO` | 联锁 | 联锁绕过 |
| `RREC` | 重合闸 | 反复跳合 |
| `UFIED` 类 | 低频减载 | Under Frequency 场景 |

### 4. 被动流量采集（GOOSE / SV / MMS）

**优先**在站控层/过程层交换机的 **SPAN 镜像口或 TAP** 上采集。GOOSE 是二层组播，不要指望三层抓包工具。

| 协议 | EtherType | 传输 | 默认周期 |
|---|---|---|---|
| **GOOSE** | `0x88B8` | L2 组播 | 稳态 1 s 起，事件后重传密集（ms 级） |
| **GSSE** | `0x88B9` | L2 组播 | 老式 UCA |
| **SV** | `0x88BA` | L2 组播 | 9-2LE：80 点/周波 @50 Hz ≈ 4000 帧/s |
| **MMS** | — | TCP 102（TPKT/COTP/ISO 9506） | 请求/响应 + 报告 |
| **时间同步** | `0x88F7`（PTP）/ SNTP | L2 / UDP 123 | 品质 `q` 与时标 `t` 的前提 |

```bash
# 4.1 采集（只读；二层要带 -e 打印 MAC，并落盘保留原始帧）
sudo tcpdump -i eth0 -nn -e -s0 -w evidence/iec61850/passive-$(date +%s).pcap \
  '(ether proto 0x88b8) or (ether proto 0x88ba) or (tcp port 102) or (ether proto 0x88f7)' -G 600 -W 1

# 4.2 协议占比速览
tshark -r evidence/iec61850/passive-*.pcap -q -z io,phs
```

### 5. GOOSE 报文分析（伪造与抑制分析的正面）

```bash
# 5.1 单条 GOOSE 的完整字段（先看懂一条，再看一万条）
tshark -r capture.pcapng -Y goose -c 1 -V | sed -n '/IEC 61850 GOOSE/,/^$/p'

# 5.2 逐帧关键字段导出台账（伪造检测/基线建模的输入）
tshark -r capture.pcapng -Y goose -T fields -E separator=, \
  -e frame.number -e frame.time_relative -e eth.src -e eth.dst \
  -e goose.gocbRef -e goose.timeAllowedtoLive -e goose.datSet -e goose.goID \
  -e goose.confRev -e goose.stNum -e goose.sqNum -e goose.test -e goose.ndsCom \
  -e goose.numDatSetEntries -e goose.allData \
  > evidence/iec61850/goose/goose-frames.csv

# 5.3 每个控制块的心跳与序号基线（正常态 = stNum 不变、sqNum 递增、间隔稳定）
python3 evidence/tools/goose_baseline.py \
  --in evidence/iec61850/goose/goose-frames.csv \
  --out evidence/iec61850/goose/goose-baseline.json

# 5.4 报文内容差异定位（哪一帧的数据集值变了 → 对应一次事件）
tshark -r capture.pcapng -Y 'goose && goose.stNum != 0' -T fields \
  -e frame.number -e frame.time_relative -e goose.gocbRef -e goose.stNum -e goose.allData
```

**GOOSE 帧关键字段语义（伪造面清单）**：

| 字段 | 含义 | 伪造/篡改后果 |
|---|---|---|
| `gocbRef` | 控制块引用 `IED/LD$GO$cbName` | 决定接收方把它当谁的消息 |
| `datSet` | 数据集引用 | 必须与接收方期望一致，否则丢弃 |
| `goID` | 应用标识（常与 `appID` 同） | 部分实现据此过滤 |
| `confRev` | 配置版本（**SCL 变更后必须递增**） | **不一致即被接收方丢弃**——伪造者必须知道正确值 |
| `stNum` | 状态号（数据集值变化时 **+1**，随后 `sqNum` 归 0） | 抬高 `stNum` → 接收方认为"有更新"，合法帧被压制（**MS 抑制攻击**） |
| `sqNum` | 序号（`stNum` 不变时逐帧递增） | 乱序/超范围 → 接收方判丢帧 |
| `timeAllowedtoLive` | TTL（接收方超时判据） | 与发送周期不匹配 → 误判通信中断 |
| `test` | 测试位 | `test=1` 的帧应被接收方忽略——**实验段注入必须置 1** |
| `ndsCom` | 需重新配置标志 | 置 1 会引发接收方配置动作 |
| `allData` | 数据集值（含 `q` 品质与 `t` 时标） | **DM 攻击的落点**：改布尔位跳闸、改电流值误导状态估计 |

### 6. MMS 分析（站控层，TCP 102）

```bash
# 6.1 MMS 服务指纹（只读；iec61850-mms.nse）
nmap -Pn -sT -p 102 -T2 --max-rate 10 --script iec61850-mms 10.10.0.5 \
  -oN evidence/iec61850/mms/10.10.0.5-iec61850-mms.txt

# 6.2 MMS 会话与调用统计（谁在读谁、谁在发报告）
tshark -r capture.pcapng -Y mms -T fields \
  -e frame.number -e ip.src -e ip.dst -e mms.confirmedServiceRequest -e mms.service \
  > evidence/iec61850/mms/mms-calls.csv
```

```bash
# 6.3 libiec61850 客户端示例（只读浏览 IED 命名空间）
#     仅使用 examples 中的 *客户端* 程序，禁止运行任何 publisher/控制类示例
./iec61850_client_example2 10.10.0.5 102      # 浏览 LD/LN/DO/DA 树
./iec61850_client_example1 10.10.0.5 102      # 连接 + 读取基本数据
# 读取指定对象引用（只读）：IED1LD0/CSWI1.Pos.stVal
```

**只读浏览的行为边界**：MMS 的 `GetNameList` / `Read` 是只读服务；`Control`（`Oper`/`SBOw`/`Cancel`）是**控制服务**——后者禁止执行（等同遥控跳闸），归 🔴。

### 7. SV 报文分析（9-2LE 采样值）

```bash
# 7.1 SV 帧字段（每帧 8 通道：4 电流 + 4 电压 或 按 confRev 定义）
tshark -r capture.pcapng -Y sv -c 1 -V | sed -n '/Sampled Values/,/^$/p'

# 7.2 采样连续性与同步状态（smpCnt 必须连续；smpSynch 反映时钟同步品质）
tshark -r capture.pcapng -Y sv -T fields -E separator=, \
  -e frame.number -e frame.time_relative -e eth.src -e sv.svID -e sv.confRev \
  -e sv.smpCnt -e sv.smpSynch -e sv.phasMeas \
  > evidence/iec61850/sv/sv-frames.csv

# 7.3 采样缺口与乱序（丢帧会直接影响保护算法输入）
python3 evidence/tools/sv_gap_check.py --in evidence/iec61850/sv/sv-frames.csv \
  --out evidence/iec61850/sv/sv-gaps.csv --expect-rate 4000
```

SV 的攻击面：`smpCnt` 回绕/跳变、`smpSynch` 由同步置为不同步（可诱使保护闭锁）、`phasMeas` 幅值/相位注入（**DM.1 的采样级版本**，直接污染保护判据）。SV 注入速率极高（4000 帧/s），**在真实过程层注入等于制造采样风暴**，因此本技能在 SV 上**只做只读分析**。

### 8. GOOSE 伪造风险分析（**默认离线建模，不注入**）

做"可伪造性"论证，而不是"去伪造"。论证链四段：

**8.1 前置条件提取（全部来自 SCL，零发包）**

```bash
# 伪造者必须知道的五个值 —— 全部可从 SCD/CID 直接读出
xmllint --xpath "//GSEControl/@appID | //GSEControl/@datSet | //GSEControl/@confRev" station.scd
xmllint --xpath "//Communication/SubNetwork/ConnectedAP/GSE/Address/P[@type='MAC-Address']/text()" station.scd
xmllint --xpath "//Communication/SubNetwork/ConnectedAP/GSE/Address/P[@type='APPID']/text()" station.scd
xmllint --xpath "//Communication/SubNetwork/ConnectedAP/Address/P[@type='VLAN-ID']/text() | //Communication/SubNetwork/ConnectedAP/Address/P[@type='VLAN-PRIORITY']/text()" station.scd
```

**8.2 接收方接受条件推断（这决定"伪造要满足什么"）**

接收端 IED 通常按以下顺序过滤 GOOSE 帧（依据 IEC 61850-8-1 与实现通例）：

1. EtherType `0x88B8` + 目标组播 MAC 与 VLAN 匹配；
2. `gocbRef` / `datSet` / `goID`（或 `appID`）与本地配置匹配 → 否则丢弃；
3. `confRev` 与本地配置一致 → 否则丢弃（这是**最强的天然阻断**，前提是 SCD 与设备一致）；
4. `test` 位一致性（`test=1` 的帧在非测试模式下应被忽略）；
5. `stNum`/`sqNum` 序列判定（见「OT 影响评估」与 `f2x-power-traceback` 的检测规则）；
6. `timeAllowedtoLive` 用于通信中断判据（连续 `2×TTL` 无帧 → 通信失败告警/闭锁）。

**结论**：`confRev` 与 `datSet` 是伪造的**硬门槛**，而它们**明文存在于工程文件与在线流量中**——这就是"可伪造"的核心论据。若现场使用 IEC 62351-6（GOOSE 报文签名），第 2–4 步之上还有签名校验，伪造不可行——**必须核实并如实报告**。

**8.3 攻击类型映射（对齐数据集命名，用于报告口径一致）**

| 类型 | 手法 | 对应数据集样本 |
|---|---|---|
| **DM（Data Manipulation）** | 篡改电流/电压测量值误导状态估计；篡改 `XCBR.Pos.stVal` 布尔位直接改变开关状态；重放历史有效帧 | `Attack/Data Manipulation (DM)/AS1.pcapng`（注入 380/270/360 A）、`AS2.pcapng`（CB FALSE→TRUE）、`AS3.pcapng`（重放旧帧） |
| **MS（Message Suppression）** | 注入高 `stNum`（如 9999）或与旧值冲突的 `sqNum`，使合法帧被接收方判定为"过期/乱序"而丢弃 | `Attack/Message Suppression (MS)/AS1..AS4.pcapng` |
| **DoS** | 泛洪伪造 GOOSE 帧拥塞站控/过程层网络，挤占合法报文 | `Attack/Denial of Service (DoS)/AS1.pcapng`（每 IED 约 10 s 内 5000 帧） |
| **Composite** | 先抑制（高 `stNum`）再篡改开关位置，掩盖跳闸动作 | `Attack/CompositeAttack.pcapng` |
| **Disturbance（非攻击基线）** | 母线保护 / 断路器失灵 / 低频减载的正常保护动作，**用于区分"真事件"与"假数据"** | `Disturbance/{Busbar Protection,Breaker Failure,Under frequency}/` + 18 个逐秒 CSV |

**8.4 隔离实验段验证（**唯一允许注入的场景**，五条件门禁）**

仅当 `ALLOW_GOOSE_INJECTION_SEGMENT` 被显式命名、且过程层已与真实一次设备物理隔离时：

```bash
# a) 申请（缺任一参数即拒绝）
python3 evidence/tools/ot_guard.py request-control \
  --target 10.10.0.5 --action goose_publish \
  --isolation "isolated-lab-procseg-A" --commander-ack REQUIRED \
  --recovery "停止 publisher 进程并恢复原 publisher（原 IED 自动重新占用组播）" \
  --on-site-operator REQUIRED \
  --rationale "在隔离过程层实验段验证 GOOSE 伪造可行性（test=1，无一次设备连接）"

# b) 复用真实抓包作为模板（libiec61850 的 goose_publisher 以报文模板发布）
#    必须：test=1、stNum 从基线+1 起、sqNum 从 0 起、confRev 与 SCD 一致、TTL 与基线的稳态值一致
./goose_publisher eth1                      # 接口必须是隔离实验段接口，绝不可指向生产过程层
```

铁律（写进报告与审计日志）：

- `test = 1` **强制**；`stNum` **只能 +1**（不得用 9999 这类压制值——那已构成对合法 IED 的抑制）；不得 `ndsCom=1`。
- 注入接口必须通过 `assert_in_scope` 与 `assert_isolated_segment` 双重校验；生产过程层接口一律拒绝。
- 单次注入时长 ≤ 10 s，随后立即停止并确认原 publisher 恢复（抓包确认合法帧恢复原 `stNum` 序列）。
- **禁止 DoS 类注入**（泛洪、抑制）——门禁第 6 条硬拒绝，仅允许在离线 pcap 上做分析复现。

### 9. 数据集离线复现（**零风险的分析路径，优先做这个**）

```bash
DS="$REDTEAM_REFS/IEC61850SecurityDataset"
# 9.1 建立正常态基线（Normal 目录）
tshark -r "$DS/Normal/No_Variable_Loading/Normal.pcapng" -Y goose -T fields -E separator=, \
  -e frame.time_relative -e eth.src -e goose.gocbRef -e goose.stNum -e goose.sqNum -e goose.timeAllowedtoLive \
  > evidence/iec61850/goose/baseline-normal.csv

# 9.2 逐个攻击样本与基线做差分（stNum/sqNum 异常、帧率异常、数据集值异常）
for f in "$DS/Attack/Data Manipulation (DM)/AS1.pcapng" \
         "$DS/Attack/Data Manipulation (DM)/AS2.pcapng" \
         "$DS/Attack/Data Manipulation (DM)/AS3.pcapng" \
         "$DS/Attack/Message Suppression (MS)/AS1.pcapng" \
         "$DS/Attack/Message Suppression (MS)/AS2.pcapng" \
         "$DS/Attack/Message Suppression (MS)/AS3.pcapng" \
         "$DS/Attack/Message Suppression (MS)/AS4.pcapng" \
         "$DS/Attack/Denial of Service (DoS)/AS1.pcapng" \
         "$DS/Attack/CompositeAttack.pcapng"; do
  name=$(basename "$f" .pcapng); dir=$(basename "$(dirname "$f")" | tr ' ()' '___')
  out="evidence/iec61850/goose/attack-${dir}-${name}.csv"
  tshark -r "$f" -Y goose -T fields -E separator=, \
    -e frame.number -e frame.time_relative -e eth.src -e goose.gocbRef \
    -e goose.stNum -e goose.sqNum -e goose.confRev -e goose.test -e goose.allData > "$out"
  echo "== $dir/$name  frames=$(wc -l < "$out")"
  python3 evidence/tools/goose_anomaly.py --frames "$out" --baseline evidence/iec61850/goose/baseline-normal.csv
done

# 9.3 与扰动场景 CSV 交叉（区分"真保护动作"与"假数据"）
head -3 "$DS/Disturbance/Breaker Failure/csv/LIED11.csv"
python3 evidence/tools/csv_cross_check.py \
  --csv "$DS/Disturbance/Breaker Failure/csv/LIED11.csv" \
  --goose evidence/iec61850/goose/attack-___Data_Manipulation__DM__-AS1.csv
```

判读要点（数据集文档给出的具体坐标，可直接用于验证自己的检测逻辑）：

- **DM.1**：LIED10 在 11.9 s / 22.5 s / 33.1 s 分别注入 A/B/C 相电流 380 / 270 / 360 —— 电流幅值**阶跃且无对应扰动事件**即为假数据特征。
- **DM.2**：LIED11 在 12.3 s 把断路器状态 FALSE→TRUE（"tripped"）——**开关变位但保护启动量（PTOC/PDIS `.Str`）未动作**即为非法跳闸特征。
- **DM.3**：重放 53.8 s / 54.8 s 的旧帧（"open"）与 155.8–159.88 s 的旧故障电流帧 —— 帧内 `t` 时标**倒退**即为重放特征。
- **MS.1**：注入 `stNum=9999, sqNum=10`（13.9 s）与 `stNum=5, sqNum=15`（18.9 s）——`stNum` 跳变且 `sqNum≠0`。
- **MS.2**：重放 `stNum=9999, sqNum=0` 但**时标陈旧**（10.4 s / 15.5 s）。
- **MS.3**：注入 `stNum=9999, sqNum=0` 且**时标比已收到的更新**（最难检测的一类，必须靠 `stNum` 跳变幅度 + 与 SCD 配置交叉判定）。
- **MS.4**：注入 `sqNum=9999` 导致接收端判乱序（12.7 s）。
- **DoS.1**：LIED10 在 12.5–22.1 s 注入 5000 帧、LIED12 在 54.7–68.3 s 注入 5000 帧 —— 相对 1 Hz 基线是 **~500 倍**帧率。
- **Composite**：11.3 s 先 `stNum=9999` 抑制，16.3 s 再改 CB-11 布尔值 —— **两步关联**才是完整攻击链。

### 10. 证据固化

```bash
sha256sum evidence/iec61850/**/* > evidence/iec61850/SHA256SUMS
python3 evidence/tools/ot_guard.py audit-verify --expect-pairs
# 若发生过 GOOSE 注入：必须额外留存"注入前 / 注入中 / 注入后"三段抓包 + 原 publisher 恢复证据
```

---

## 安全约束

> 以下六条为**硬编码门禁**，在任何目标、任何阶段、任何理由下不得豁免。由 `evidence/tools/ot_guard.py` 在工具调用前强制执行。

1. **单目标并发不超过 3 个工具调用。**
   同一目标上并发的采集/连接进程（tcpdump/tshark、nmap、libiec61850 客户端、publisher）总数 **≤ 3**，默认顺序执行为 1。IEC 61850 的 MMS 服务端连接数有限（部分 IED 仅允许少量并发关联），过程层组播订阅同样会占用资源。禁止多终端齐发、禁止并发遍历 MMS 对象树、禁止 `xargs -P`。

2. **模糊测试必须低频化，禁止高频扫描 OT 设备。**
   IEC 61850 的"高频"含义比 Modbus/S7 更严重：GOOSE 稳态是 1 Hz，**SV 是 ~4000 Hz**。硬性限速参数：
   - 端口/主机扫描：`nmap -T2 --max-rate 10 --max-parallelism 1`（禁止 `-T3/-T4/-T5`、禁止 `--min-rate`）。
   - MMS 服务调用（`GetNameList`/`Read`）间隔 **≥ 1 秒**（`time.sleep(1.0)`）。
   - **禁止对 IEC 61850 做协议模糊测试**（历史上已有 Fuzz Testing IEC 61850 导致 IED 异常的先例，见参考素材 CS3STHLM 2019）。若必须在离线仿真上做，单帧 ≤ 1 req/s、总量 ≤ 300 帧/设备/小时，且熔断条件为"MMS 关联被拒 2 次 / GOOSE 订阅中断 2 次 → 立即停止并退避 60 s"。
   - **SV 面绝对不做任何注入或模糊**（4000 帧/s 的注入即采样风暴，会直接污染保护判据）。
   - GOOSE 注入（仅隔离实验段）帧率**不得超过**被模仿 publisher 的稳态速率。

3. **写操作（寄存器写入、线圈强制、固件修改、PLC 启停）必须经过指挥官二次确认，且记入审计日志。**
   本技能中"写操作"的等价物为：**GOOSE/SV 报文注入、MMS 控制服务（`Oper`/`SBOw`/`Cancel`）、IED 配置下装（CID 下载）、报告控制块属性写（`Write`）**——其中 MMS 控制服务等同"遥控跳闸"，属最高危。流程强制：`request-control` 拿 `ack-id` → 指挥官显式确认 → 带 `ack-id` 执行 → **执行前**写审计日志、执行后写结果日志 → 抓包确认目标状态与恢复。无 `ack-id` 的注入/控制命令由门禁拒绝。

4. **任何可能影响工控设备正常运行的命令，必须先记录到审计日志再执行。**
   保守判据：**凡不能证明是纯只读，就先记日志**。本技能中需先记日志的"只读但高风险"动作包括：MMS 全命名空间遍历（`GetNameList` 大范围请求会占用 IED CPU）、报告控制块使能/属性读取、IED 配置读回（`GetVariableAccessAttributes`）、长时 GOOSE/SV 订阅（占用组播资源）、时间同步探测。**先记后做，禁止事后补记。** 审计条目含 `ts`（ISO8601 带时区）、`op`、`target`、`interface`、`gocbRef`/`svID`/`mmsService`、`class`（read/write/control/fuzz）、`rate`、`isolation_segment`、`authorization`、`commander_ack`、`recovery`、`purpose`；注入/控制操作前后各一条，成对可核。

5. **目标范围白名单硬编码，超出白名单一律拒绝执行。**
   ```python
   AUTHORIZED_SCOPE = ("10.10.0.0/24", "192.168.1.0/24")   # 已授权电力靶场段
   # 授权靶场叠加段（须在授权书范围内显式启用；默认关闭）
   # AUTHORIZED_SCOPE += ("192.168.90.0/24", "192.168.95.0/24")
   ALLOW_GOOSE_INJECTION_SEGMENT = None   # 仅隔离过程层实验段可命名；None = 禁止注入
   ```
   所有发包/注入动作前跑 `assert_in_scope(ip)`（`ipaddress.ip_address(host) in ipaddress.ip_network(cidr)`），**不匹配即 `sys.exit(2)` 并记录拒绝日志**。GOOSE/SV 注入额外要求 `assert_isolated_segment(iface)` 与 `/proc/net/arp` + LLDP 邻居核对，确认该接口所在网段**不含任何一次设备**；生产过程层接口一律拒绝。禁止以 VLAN tag/组播 MAC 绕过白名单；禁止对未授权站控层段发起网段遍历。

6. **禁止 DDoS，禁止爆破；S7 口令只允许离线爆破参考脚本，禁止在线爆破。**
   - **禁止 DoS/DDoS 与泛洪**：IEC 61850 场景下这尤其致命——GOOSE 泛洪（数据集的 DoS.1 样本即每 IED 10 s 内 5000 帧）会挤占合法保护报文，**可直接导致保护拒动**。禁止任何形式的 GOOSE/SV 泛洪、组播风暴、MMS 连接耗尽、ARP/组播表投毒。DoS 类攻击**只允许在离线 pcap 上做检测复现**，不得在网络上实施。
   - **禁止抑制类注入**（高 `stNum` 压制合法 publisher、`sqNum` 乱序注入）——这是"阻断保护通信"，等同 DoS。
   - 禁止在线口令/认证爆破：MMS 认证、IED Web 口令、SCL 文件口令一律禁止在线猜解。
   - S7 口令仅允许**离线**路线（见 `f2x-power-s7comm-attack` 的 `s7-cracker.py` / `s7-brute-offline.py`），离线爆破不得产生任何网络流量；命中后不得回连目标做在线验证。
   - 唯一例外是"单个已公开默认凭据的一次性验证"，须记审计日志；失败即停止，不得继续尝试第二个口令。

---

## OT 影响评估

| 等级 | 本技能中的操作 | 影响机制 | 缓解/边界 |
|---|---|---|---|
| 🟢 **只读** | SCL/SCD/CID/IID 解析与 IED 建模（第 1–3 步，纯文件操作）、GOOSE/SV/MMS 被动抓包与离线解析（第 4/5/7 步、第 9 步数据集复现）、`iec61850-mms.nse` 单次指纹、`iec61850_client_example` 只读浏览 | 不改变任何过程变量；组播订阅仅增加极小的交换机转发负载 | 采集接 SPAN/TAP 而非在生产口上抓；MMS 调用 ≥1 s 间隔；SV 只做离线分析 |
| 🟢/🟡 **边界** | MMS 全命名空间遍历（`GetNameList`）、报告控制块读取、IED 配置读回、长时订阅 | 不改变过程值，但会**占用 IED 有限的 MMS 关联与 CPU 资源**；部分 IED 在重负载下会延迟报告上送 | 分片遍历、1 s 间隔、并发 ≤3；发现关联被拒/MSS 相关错误即停止；先写审计日志 |
| 🟡 **可恢复写入** | MMS `Write` 写非安全相关的配置类属性（如报告控制块的 `IntgPd`）、在**隔离实验段**发布 `test=1` 且 `stNum=基线+1` 的 GOOSE 帧（被测 IED 处于测试模式） | 配置类写入可被写回；实验段 GOOSE 只影响实验段订阅者 | 二次确认 + 先审计 + 记录原值 + 写后回读 + 注入 ≤10 s 并确认恢复 |
| 🔴 **不可逆 / 停机风险** | **GOOSE 伪造/重放**（尤其篡改 `XCBR.Pos`、`PTRC.Tr`、`PTOC.Op` 等跳闸相关数据集成员）→ **可直接导致断路器误跳闸**；**SV 注入**污染保护采样判据；**MMS 控制服务**（`Oper`/`SBOw`）等同遥控跳闸；**CID 下装**改写 IED 配置；高 `stNum` **抑制合法 publisher**（保护通信被阻断 → 保护拒动） | 保护误动/拒动、非计划停电、设备损坏、人身风险。此类动作在真实变电站属**安全事件**级别 | **默认拒绝**；仅"隔离过程层实验段（无一次设备）+ 指挥官二次确认 + 先审计后执行 + 明确恢复方案 + 现场有人值守"五条件齐备才可执行；MMS 控制服务与抑制类注入**在任何情况下禁止**；生产过程层接口一律拒绝注入 |
| 🔴 **停机风险** | 取消限速、并发 >3、GOOSE 泛洪、SV 高频注入、协议模糊测试 | 站控/过程层网络拥塞 → 合法 GOOSE/SV 报文被丢弃或延迟 → 保护算法输入异常 → 保护拒动或误动 | 门禁第 2/6 条硬拒绝；熔断即退避 60 s 并上报 |
| ⚫ **绝对禁止** | 在含一次设备的网络上做 GOOSE/SV 注入、GOOSE 泛洪、抑制注入、MMS 遥控、生产 IED 配置下装 | 非计划停电、设备损坏、人身伤害 | 硬拒绝，不设例外 |

**一句话结论**：本技能的价值**几乎全部可以由只读路径拿到**——SCL 工程文件 + 被动流量即可完成 IED 建模、伪造前置条件提取、可伪造性论证与检测点设计；真正的注入动作只在**隔离实验段**用于"可伪造性实证"，且 `test=1`、`stNum` 只 +1、时长 ≤10 s。**任何面向生产过程层的 GOOSE/SV 注入、泛洪与抑制，本技能一律不做，只给分析结论与防守规则。**

---

## 产出与证据

### 必交交付物

| # | 交付物 | 路径 | 计分要点 |
|---|---|---|---|
| 1 | 范围声明与门禁自检 | `evidence/audit/ot-ops.jsonl`（首条 scope 声明；注入/控制操作成对条目） | 全程白名单内 + 限速合规 + 注入有 ack-id 与隔离段证明 |
| 2 | SCL 文件台账 | `evidence/iec61850/scl/scl-inventory.txt` + 每文件 Header（version/revision/toolID） | 工程文件版本溯源 |
| 3 | **整站模型（核心）** | `evidence/iec61850/scl/station-model.json` | IED 清单、制造商/型号/`configVersion`、AccessPoint、Logical Node 清单、DataSet 成员 |
| 4 | IED 数据属性展开 | `evidence/iec61850/scl/ied-data-attributes.csv` | `lnClass/cdc/do/da/bType/fc` + `q`/`t` 属性，可还原工程量 |
| 5 | **通信映射基线（核心）** | `evidence/iec61850/scl/comm-mapping.csv` | `iedName, apName, IP, MAC-Address, APPID, VLAN-ID, VLAN-PRIORITY, gocbRef/svID` —— 伪造检测的对照表 |
| 6 | GOOSE 控制块清单 | `evidence/iec61850/scl/gse-control.csv` | `name, datSet, appID, confRev, type` —— 伪造必知参数 |
| 7 | GOOSE 帧台账 + 基线 | `evidence/iec61850/goose/goose-frames.csv`、`goose-baseline.json` | 每 `gocbRef` 的稳态周期、`stNum`/`sqNum` 递进规律、`timeAllowedtoLive` |
| 8 | SV 帧台账 + 缺口报告 | `evidence/iec61850/sv/sv-frames.csv`、`sv-gaps.csv` | `svID/confRev/smpCnt/smpSynch/phasMeas`、采样连续性 |
| 9 | MMS 指纹与调用台账 | `evidence/iec61850/mms/10.10.0.5-iec61850-mms.txt`、`mms-calls.csv` | 服务集合 + 客户端角色（谁在读谁） |
| 10 | **GOOSE 伪造风险分析报告（核心）** | `evidence/iec61850/goose-forgery-assessment.md` | 四段论证：前置条件（从 SCL 读出） → 接收方接受条件 → 攻击类型映射 → IEC 62351-6 有无核实；含"可伪造/不可伪造"明确结论 |
| 11 | 数据集攻击样本复现报告 | `evidence/iec61850/dataset-attack-replay.md` | 9 个攻击样本逐个给出检测判据与命中坐标（对齐 README 的时间点） |
| 12 | 隔离实验段注入记录（如执行） | `evidence/iec61850/injection-record-<opid>.json` + 注入前/中/后三段抓包 | 五条件证据 + `test=1` + `stNum=基线+1` + 原 publisher 恢复证据 |
| 13 | finding 登记 | `f2x_orchestrate_finding`（本插件自带） | finding：SCL 工程信息泄露 / GOOSE 无认证可伪造 / MMS 未授权读写 / 缺 IEC 62351-6；`evidenceLevel=confirmed` 或 `impact` |

### 证据质量要求

- **文件优先**：能用 SCL 静态解析得到的结论，绝不用网络探测去"验证"。IEC 61850 的工程信息量极大，**一份 SCD 约等于整站的地图**。
- **基线必须存在**：任何"异常"判定都必须先有正常态基线（用 `Normal/` 数据集或现场稳态抓包建立），否则无法区分"保护真动作"与"攻击假数据"——`Disturbance/` CSV 就是用来做这个区分的。
- **可复现**：所有 `tshark` 字段导出命令原样保留，允许第三方离线复算；原始 pcapng 与导出 CSV 一并归档并 `sha256sum`。
- **危险动作留痕**：任何 🔴 动作必须留"审批 → 执行前审计 → 隔离段证明 → 执行 → 执行后审计 → 恢复 → 恢复验证（抓包）"七段链，缺段即违规。
- **诚实标注**：区分"SCL 声明"与"设备实际行为"（工程文件常与现场不一致，`configVersion` 与 `confRev` 可能已漂移）；把"未核实是否部署 IEC 62351-6"如实写进结论的不确定性，不得默认无签名就断言"可伪造"。

### 速用命令卡

```bash
# 整站 IED 与通信映射（零发包）
xmllint --xpath "//IED/@name" station.scd
xmllint --xpath "//Communication/SubNetwork/ConnectedAP/Address/P[@type='MAC-Address']/text()" station.scd
xmllint --xpath "//GSEControl/@name | //GSEControl/@appID | //GSEControl/@confRev" station.scd
# GOOSE 字段导出（离线）
tshark -r capture.pcapng -Y goose -T fields -e goose.gocbRef -e goose.stNum -e goose.sqNum -e goose.allData
# MMS 指纹（只读，限速）
nmap -Pn -sT -p 102 -T2 --max-rate 10 --script iec61850-mms 10.10.0.5
# SV 采样连续性（离线）
tshark -r capture.pcapng -Y sv -T fields -e sv.smpCnt -e sv.smpSynch | head
# ❌ 禁止：生产过程层 GOOSE/SV 注入 / GOOSE 泛洪 / 高 stNum 抑制 / MMS Oper 遥控 / SV 模糊 / CID 下装
```

### 与其他技能的衔接

- 需要把 GOOSE 异常转成可落地的**检测规则与回放取证** → `f2x-power-traceback`（本技能判"是什么"，回溯技能给"怎么发现、怎么取证"）。
- 站控层 MMS/OPC 与 HMI、历史库 → `f2x-power-scada-recon`。
- 站内还有 Modbus/S7 设备（通信网关、辅控系统）→ `f2x-power-modbus-attack` / `f2x-power-s7comm-attack`。
