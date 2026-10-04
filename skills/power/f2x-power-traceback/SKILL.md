---
name: f2x-power-traceback
description: 电力工控流量回溯与攻击链重构技能——从 pcapng 还原攻击动作、建立正常态基线、映射 MITRE ATT&CK for ICS，并从防守视角给出可落地的检测点与规则。
whenToUse: 已获得电力 OT 网络的 pcap/pcapng（现场镜像、TAP、或 IEC61850SecurityDataset 等语料），需要还原"发生了什么"、重构攻击链，或为防守方设计 GOOSE/Modbus/S7/SCADA 异常检测规则时使用。
---

# 工控流量回溯与攻击链重构技能（f2x-power-traceback）

> **工具可用性与退路（先读这一节）**
> 本技能只依赖本插件自带的 `f2x_orchestrate_*` 工具，**不依赖任何其他插件**。
> 工作流里出现的 `redteam_coverage_mark` / `redteam_finding_register` 是**可选增强**：
> - **成果登记** → `f2x_orchestrate_finding`（本插件自带；检测 gap 建议 `evidenceLevel=confirmed`
>   并带 `evidence` 指位）
> - **覆盖矩阵** → 本插件无此面；用 `f2x_orchestrate_export` 作为覆盖记录，
>   或仅在部署里确实有 `redteam_coverage_mark` 时才回写
> **规则**：目录里没有的工具一律不要调用。开场先跑 `f2x_orchestrate_doctrine` 自检。

> **定位**：本技能是**双向**的——一半是**攻击方视角的事后还原**（我做过什么、过程如何、证据链是否闭合），一半是**防守方视角的检测设计**（换我是蓝队，怎么发现这次攻击）。攻击执行见 `f2x-power-modbus-attack` / `f2x-power-s7comm-attack` / `f2x-power-iec61850-analysis` / `f2x-power-scada-recon`；本技能负责把它们的痕迹变成**时间线 + 攻击链 + 检测规则**。
>
> **素材引用（本机只读，绝不可修改）**：`$REDTEAM_REFS/IEC61850SecurityDataset/`
> - `Normal/No_Variable_Loading/Normal.pcapng` —— **正常态基线**：18 个 IED，每秒 1 帧 GOOSE，`stNum`/时间戳不变、`sqNum` 递增。
> - `Attack/Data Manipulation (DM)/AS1..AS3.pcapng`、`Attack/Message Suppression (MS)/AS1..AS4.pcapng`、`Attack/Denial of Service (DoS)/AS1.pcapng`、`Attack/CompositeAttack.pcapng` —— 9 个攻击样本（每文件 10 分钟）。
> - `Disturbance/{Busbar Protection,Breaker Failure,Under frequency}/` + 各自 `csv/` 下 18 个逐秒 CSV —— **真扰动基线**，用来区分"真实保护动作"与"攻击伪造数据"。
> - `SCL Files/` —— 18 个 IID，给出 IED ↔ IP/MAC ↔ GOOSE 控制块的**权威映射**（检测的对照表）。
>
> **为什么这份语料特别适合做检测设计**：攻击样本与正常样本**建立在同一基线上**（README 明确说明"attacking scenario is based on the normal scenario's transmission traffic"），因此可以做到**单变量差分**——这是验证检测规则误报率的最佳条件。

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
mkdir -p evidence/audit evidence/trace/{pcaps,timeline,baseline,detect,replay}
python3 evidence/tools/ot_guard.py selftest
```

统一门禁值：

```python
AUTHORIZED_SCOPE = ("10.10.0.0/24", "192.168.1.0/24")
# AUTHORIZED_SCOPE += ("192.168.90.0/24", "192.168.95.0/24")
MAX_CONCURRENCY  = 3
MIN_INTERVAL_S   = 1.0
AUDIT            = "evidence/audit/ot-ops.jsonl"
ALLOW_REPLAY_SEGMENT = None      # 形如 "isolated-lab-A"；None = 禁止任何重放
READONLY_REF = "$REDTEAM_REFS/IEC61850SecurityDataset"   # 只读，禁止写入
```

### 1. 证据接收与完整性固定（**回溯的第一步永远是固定证据**）

```bash
# 1.1 只读复制到证据区（绝不就地分析——分析过程不得改动原始件）
cp -a "$READONLY_REF/Normal/No_Variable_Loading/Normal.pcapng" evidence/trace/pcaps/
cp -a "$READONLY_REF/Attack/CompositeAttack.pcapng" evidence/trace/pcaps/

# 1.2 计算哈希并留存（证据链起点）
sha256sum evidence/trace/pcaps/*.pcapng | tee evidence/trace/pcaps/SHA256SUMS
stat -c '%n %s %y' evidence/trace/pcaps/*.pcapng | tee evidence/trace/pcaps/provenance.txt

# 1.3 文件级元数据（时长、包数、链路类型、时间范围）——注意二层协议必须有正确的 DLT
capinfos evidence/trace/pcaps/*.pcapng | tee evidence/trace/pcaps/capinfos.txt
#   关键字段：Encapsulation type（Ethernet）、Capture duration、Number of packets、First/Last packet time
```

> **时间基准**：回溯的准确性取决于时间。GOOSE 的 `t` 字段来自 IED 本地时钟（常见 SNTP/PTP 同步），pcapng 的 `frame.time` 来自采集机。**两者必须区分开**，并检查 `frame.time_epoch` 与 GOOSE 时标的偏移（第 2.4 步）。时标偏移本身就是一条证据（时钟不一致会让"时标倒退"检测产生假阳性）。

### 2. 协议栈全景盘点（先知道有哪些协议，再谈异常）

```bash
# 2.1 协议分层统计
tshark -r evidence/trace/pcaps/CompositeAttack.pcapng -q -z io,phs | tee evidence/trace/timeline/proto-hierarchy.txt

# 2.2 端点与承载会话矩阵（谁在跟谁说话、说了多少）
tshark -r evidence/trace/pcaps/CompositeAttack.pcapng -q -z endpoints,eth | head -40
tshark -r evidence/trace/pcaps/CompositeAttack.pcapng -q -z conv,eth | grep -i '88:b8\|88ba' | head -30

# 2.3 逐秒包量（DoS/泛洪窗口的第一眼判据）
tshark -r evidence/trace/pcaps/CompositeAttack.pcapng -q -z io,stat,1,"COUNT(frame)frame" \
  | tee evidence/trace/timeline/pkts-per-second.txt

# 2.4 时钟一致性：pcap 采集时间 vs GOOSE 帧内时标
tshark -r evidence/trace/pcaps/Normal.pcapng -Y goose -T fields -E separator=, \
  -e frame.time_epoch -e goose.timestamp -e goose.gocbRef \
  > evidence/trace/baseline/clock-offset.csv
python3 evidence/tools/clock_offset.py --in evidence/trace/baseline/clock-offset.csv
```

### 3. 建立正常态基线（**没有基线就没有异常**）

```bash
# 3.1 正常样本的 GOOSE 逐帧台账（18 IED × 10 分钟 × 1 Hz ≈ 10800 帧）
tshark -r evidence/trace/pcaps/Normal.pcapng -Y goose -T fields -E separator=, \
  -e frame.number -e frame.time_relative -e eth.src -e eth.dst \
  -e goose.gocbRef -e goose.timeAllowedtoLive -e goose.datSet -e goose.goID \
  -e goose.confRev -e goose.stNum -e goose.sqNum -e goose.test -e goose.ndsCom \
  -e goose.allData \
  > evidence/trace/baseline/normal-goose.csv

# 3.2 每个控制块的统计基线（周期、TTL、stNum/sqNum 递进、数据集字节长度）
python3 evidence/tools/goose_baseline.py \
  --in evidence/trace/baseline/normal-goose.csv \
  --out evidence/trace/baseline/goose-baseline.json
#   产出：per-gocbRef {mac, dst_mac, interval_p50_ms, interval_p99_ms, ttl, confRev,
#                      stNum_start, stNum_end, sqNum_max, nds_com, data_len, data_hash}
```

```bash
# 3.3 从 SCL 取权威对照表（IED ↔ MAC ↔ 控制块 ↔ 数据集），作为"合法性"的判据来源
for f in "$READONLY_REF/SCL Files"/*.iid; do
  echo "== $(basename "$f")"
  xmllint --xpath "//IED/@name | //Communication/SubNetwork/ConnectedAP/Address/P[@type='IP']/text() | //Communication/SubNetwork/ConnectedAP/Address/P[@type='MAC-Address']/text() | //GSEControl/@name | //GSEControl/@appID | //GSEControl/@datSet | //GSEControl/@confRev" "$f"
  echo
done > evidence/trace/baseline/scl-authoritative.txt
```

```bash
# 3.4 真扰动基线（关键！用于区分"保护真动作"与"攻击伪造"）
for csv in "$READONLY_REF/Disturbance/Breaker Failure/csv/"*.csv; do
  echo "== $(basename "$csv")"; head -2 "$csv"
done | tee evidence/trace/baseline/disturbance-csv-head.txt
```

> **三者关系**：`Normal` = 稳态；`Disturbance` = **合法**的保护动作（母线保护/断路器失灵/低频减载，其特点是"保护启动量先动、随后开关变位"）；`Attack` = **非法**动作（其特点常是"开关变位但保护启动量不动"，或"测量值阶跃但无扰动"）。**检测规则必须同时通过这两组样本**——只有"命中攻击且不误报扰动"的规则才算合格。

### 4. 攻击动作还原（逐类差分，对齐数据集文档的具体坐标）

```bash
DS="$READONLY_REF"
run() {  # $1=样本路径 $2=标签
  local out="evidence/trace/timeline/${2}.csv"
  tshark -r "$1" -Y goose -T fields -E separator=, \
    -e frame.number -e frame.time_relative -e eth.src -e eth.dst -e goose.gocbRef \
    -e goose.confRev -e goose.stNum -e goose.sqNum -e goose.test \
    -e goose.timeAllowedtoLive -e goose.allData > "$out"
  echo "[$2] frames=$(($(wc -l < "$out")-1))"
  python3 evidence/tools/goose_anomaly.py --frames "$out" \
    --baseline evidence/trace/baseline/goose-baseline.json \
    --scl evidence/trace/baseline/scl-authoritative.txt \
    --out "evidence/trace/timeline/${2}-anomalies.csv"
}
run "$DS/Attack/Data Manipulation (DM)/AS1.pcapng" dm-as1
run "$DS/Attack/Data Manipulation (DM)/AS2.pcapng" dm-as2
run "$DS/Attack/Data Manipulation (DM)/AS3.pcapng" dm-as3
run "$DS/Attack/Message Suppression (MS)/AS1.pcapng" ms-as1
run "$DS/Attack/Message Suppression (MS)/AS2.pcapng" ms-as2
run "$DS/Attack/Message Suppression (MS)/AS3.pcapng" ms-as3
run "$DS/Attack/Message Suppression (MS)/AS4.pcapng" ms-as4
run "$DS/Attack/Denial of Service (DoS)/AS1.pcapng" dos-as1
run "$DS/Attack/CompositeAttack.pcapng" composite
```

**攻击动作还原对照表**（数据集 README 给出的确切坐标，用于验证自己的检测逻辑是否命中）：

| 样本 | 时间 | 攻击者（伪造的 IED） | 动作 | 包号 | **检测判据** |
|---|---|---|---|---|---|
| DM AS1 | 11.9 / 22.5 / 33.1 s | LIED10 | 注入 A/B/C 相电流 380 / 270 / 360 | 588 / 1175 / 1771 | 测量值阶跃**且无对应扰动事件**（与 Disturbance CSV 对照） |
| DM AS2 | 12.3 s | LIED11 | CB 状态 FALSE → TRUE（"tripped"） | 597 | **开关变位但保护启动量（PTOC/PDIS `.Str`）未动作** → 非法跳闸 |
| DM AS3 | 53.8 / 54.8 s；155.8–159.88 s | LIED11 / LIED22 | 重放旧的 "open" 帧与旧故障电流帧 | 2734 / 2764；7847/7901/7955/8009/8063 | **帧内 `t` 时标倒退**（相对同 `gocbRef` 已收到的最大时标） |
| MS AS1 | 13.9 / 18.9 s | LIED10 / LIED12 | 注入 `stNum=9999, sqNum=10` 与 `stNum=5, sqNum=15` | 542 / 784 | `stNum` 跳变（> 前值 +1）**且 `sqNum ≠ 0`** |
| MS AS2 | 10.4 / 15.5 s | LIED10 / LIED12 | 重放高 `stNum`、`sqNum=0`、**时标陈旧** | 534 / 774 | `stNum` 跳变 + `sqNum=0` + 时标倒退 |
| MS AS3 | 10.4 / 15.5 s | LIED10 / LIED12 | 注入高 `stNum`、`sqNum=0`、**时标比已收到的更新** | 534 / 774 | **最难检测**：只能靠 `stNum` 跳变幅度 + 与 SCD `confRev`/配置交叉判定 |
| MS AS4 | 12.7 s | LIED10 | 注入 `sqNum=9999` | 556 | `sqNum` 超范围/乱序（同 `stNum` 下 `sqNum` 非递增） |
| DoS AS1 | 12.5–22.1 s；54.7–68.3 s | LIED10 / LIED12 | 各注入约 5000 帧 | — | **帧率相对 1 Hz 基线约 500 倍**（逐秒包量尖峰） |
| Composite | 11.3 s 抑制 → 16.3 s 篡改 | LIED11 | 先 `stNum=9999` 抑制，再把 CB-11 布尔值 1→0 | 542 / 792 | **两步关联**：抑制窗口内紧接着出现开关变位 → 高置信攻击链 |

```bash
# 4.1 单独验证"抑制 → 篡改"的两步关联（Composite 样本的核心）
tshark -r "$DS/Attack/CompositeAttack.pcapng" -Y 'goose && (goose.stNum == 9999 || goose.stNum > 1)' \
  -T fields -e frame.number -e frame.time_relative -e goose.gocbRef -e goose.stNum -e goose.sqNum -e goose.allData \
  | sed -n '1,30p' | tee evidence/trace/timeline/composite-two-step.txt

# 4.2 交叉核对"开关变位 vs 保护启动"（区分 DM AS2 与 Disturbance/Breaker Failure）
tshark -r "$DS/Attack/Data Manipulation (DM)/AS2.pcapng" -Y goose -T fields -e frame.time_relative -e goose.gocbRef -e goose.allData \
  > evidence/trace/timeline/dm-as2-alldata.csv
python3 evidence/tools/cb_vs_pickup.py \
  --attack evidence/trace/timeline/dm-as2-alldata.csv \
  --disturbance "$DS/Disturbance/Breaker Failure/csv/LIED11.csv" \
  --out evidence/trace/timeline/dm-as2-verdict.md
```

### 5. 攻击链重构（时间线 + 阶段 + ATT&CK 映射）

```bash
# 5.1 生成统一时间线（把 GOOSE 异常、Modbus/S7 写、HTTP/DB 动作合并到一条轴）
python3 evidence/tools/build_timeline.py \
  --goose-anomalies evidence/trace/timeline/*-anomalies.csv \
  --pcap evidence/trace/pcaps/*.pcapng \
  --out evidence/trace/timeline/attack-timeline.csv
#   列：ts, phase, actor(claimed), actor(mac), protocol, action, target, evidence_ref, confidence
```

```bash
# 5.2 Modbus / S7 侧的写与状态变更痕迹（若样本含这些协议）
tshark -r evidence/trace/pcaps/*.pcapng -Y 'mbtcp.func==5||mbtcp.func==6||mbtcp.func==15||mbtcp.func==16||mbtcp.func==23' \
  -T fields -e frame.time_relative -e ip.src -e ip.dst -e mbtcp.func -e mbtcp.reference_num -e mbtcp.regval \
  > evidence/trace/timeline/modbus-writes.csv
tshark -r evidence/trace/pcaps/*.pcapng -Y 's7comm.param.func==0x05 || s7comm.param.func==0x29 || s7comm.param.func==0x1a || s7comm.param.func==0x1b || s7comm.param.func==0x1c || s7comm.param.func==0x27' \
  -T fields -e frame.time_relative -e ip.src -e ip.dst -e s7comm.param.func -e s7comm.header.rosctr \
  > evidence/trace/timeline/s7-control.csv
#   判读：0x05 写、0x29 STOP、0x1a/0x1b/0x1c 下载、0x27 口令交互 —— 任何一条来自非 EWS 源都是高置信告警
```

**MITRE ATT&CK for ICS 映射（攻击链标注）**：

| 阶段 | 动作（本技能可见的痕迹） | ATT&CK for ICS |
|---|---|---|
| 侦察 | 网络嗅探（被动采集期）、资产/点位枚举 | T0842 Network Sniffing、T0846 Remote System Discovery、T0888 Remote System Information Discovery、T0861 Point & Tag Identification |
| 初始访问 | 利用暴露的 HMI/Web/OPC、默认凭据 | T0812 Default Credentials、T0819 Exploit Public-Facing Application、T0883 Internet Accessible Device、T0886 Remote Services |
| 立足与横移 | 从 DMZ 跳入 ICS、工具投放 | T0866 Exploitation of Remote Services、T0867 Lateral Tool Transfer、T0885 Commonly Used Port、T0884 Connection Proxy |
| **抑制（MS）** | 高 `stNum` / `sqNum` 乱序注入，阻断合法 publisher | **T0814 Denial of Service、T0815 Denial of View、T0804 Block Reporting Message、T0813 Denial of Control** |
| **篡改（DM）** | 改开关位置、改电流测量、重放旧帧 | **T0831 Manipulation of Control、T0832 Manipulation of View、T0836 Modify Parameter、T0855 Unauthorized Command Message、T0856 Spoof Reporting Message** |
| 泛洪（DoS） | GOOSE 帧率暴增 | **T0814 Denial of Service、T0826 Loss of Availability、T0829 Loss of View** |
| 持久化/影响 | 修改控制逻辑、下装程序、改定值 | T0843 Program Download、T0889 Modify Program、T0858 Change Operating Mode、T0800 Activate Firmware Update Mode |
| 掩盖 | 抑制报警、篡改历史数据 | T0878 Alarm Suppression、T0838 Modify Alarm Settings、T0872 Indicator Removal on Host |
| 后果 | 保护拒动/误动、非计划停电 | T0837 Loss of Protection、T0880 Loss of Safety、T0827 Loss of Control、T0879 Damage to Property |

> ⚠️ ATT&CK for ICS 的编号会随版本调整（v14 → v18 期间有合并与重编号）。**报告引用前用官方矩阵复核编号与名称**；本表用于建立映射框架，不替代官方核对。

### 6. 防守视角：检测点设计（**本技能的核心交付**）

对每一类攻击，回答三个问题：**在哪一层能看见？看见什么？什么阈值能区分真假？**

#### 6.1 检测点分层地图

| 层 | 检测点 | 能发现什么 | 盲区 |
|---|---|---|---|
| **交换机 / L2** | 端口安全（MAC 绑定）、静态组播表、组播风暴抑制、VLAN 边界、端口镜像 | 非法 MAC 出现（MAC 欺骗）、组播表被改写、帧率风暴、未经授权的端口接入 | 加密/签名报文内容；同 MAC 内的应用层篡改 |
| **网络 / IDS（Zeek、Suricata、icsnpp）** | GOOSE/SV 字段级解析、Modbus/S7/DNP3 功能码、OPC UA 服务 | **stNum/sqNum 异常、confRev 不符、TTL 异常、写功能码、STOP/下载、帧率** | 加密 MMS/S7commPlus 内容；时钟不同步导致的时标误判 |
| **IED / 设备层** | 设备自身诊断日志、GOOSE 通信中断告警、`q` 品质位、`t` 时标、保护启动/动作记录 | **接收侧对非法帧的丢弃计数**、通信中断（`2×TTL`）、品质失效 | 多数 IED 不导出细粒度日志；需厂商工具 |
| **SCADA / 历史库** | HMI 审计日志、点位越限告警、操作员动作记录、历史库写入审计 | 非计划操作、设定值变更、报警被确认/抑制 | 攻击者若已控制 SCADA 可清日志（需外送日志） |
| **主机 / EDR（EWS、SCADA 服务器）** | 进程、命令行、工程软件启动、USB、计划任务 | 工程文件被改、TIA/STEP7 异常启动、横移工具落地 | OT 主机常无 EDR（老旧 Windows） |
| **SIEM 汇聚（如 GRFICS 的 wazuh）** | 跨源关联、规则命中、告警去重 | **跨区流量 + 协议异常 + 主机异常的组合告警** | 规则需按现场基线调参，否则误报淹没 |

#### 6.2 GOOSE 检测规则（**核心，7 条**）

| # | 规则名 | 判据 | 阈值/参数 | 命中样本 | 误报控制 |
|---|---|---|---|---|---|
| G1 | `confRev` 与 SCL 不符 | 帧内 `confRev` ≠ SCD/CID 中的配置值 | 精确匹配 | 伪造者配置漂移 | 工程变更后必须同步更新基线（变更窗口豁免） |
| G2 | `stNum` 非单调 | 同 `gocbRef` 下 `stNum` 增量 > 1（排除回绕） | 增量 > 1 即告警；回绕按 2³² 处理 | MS AS1/AS2/AS3、Composite | 设备重启后 `stNum` 归零属正常 → 需白名单化重启事件 |
| G3 | `stNum` 变化但 `sqNum ≠ 0` | `stNum` 递增时 `sqNum` 必须归 0 | 严格判据 | **MS AS1（9999/10、5/15）** | 无（协议规定如此） |
| G4 | `sqNum` 乱序/超范围 | 同 `stNum` 下 `sqNum` 非递增，或出现极大值 | `sqNum` 跳变 > 基线 P99 × 10 | **MS AS4（sqNum=9999）** | 丢包导致的小幅跳变需容忍 |
| G5 | 帧内时标倒退 | GOOSE `t` 字段 < 同 `gocbRef` 已收到的最大 `t` | 任何倒退即告警（先做时钟偏移校正） | **DM AS3（重放）、MS AS2（重放）** | **必须先去时钟偏移**（第 2.4 步），否则假阳性 |
| G6 | 帧率异常（泛洪/静默） | 单 `gocbRef` 帧率相对基线偏离 | 泛洪 > 基线 × 10；静默 > `2 × TTL` | **DoS AS1（约 500×）**、MS 抑制后的静默 | 事件突发重传是正常行为 → 用 `stNum` 变化解释突发 |
| G7 | 发布者指纹不符 | 源 MAC / 交换机端口 ∉ SCL 中该 `gocbRef` 的合法发布者集合 | 精确匹配 | MAC 未欺骗的伪造 | IED 更换/冗余切换需白名单 |

**G8（组合规则，最高置信）**：`stNum` 抑制事件（G2/G3）**之后 30 秒内**出现开关量（XCBR `Pos.stVal`）变位 **且** 保护启动量（PTOC `Str` / PDIS）未动作 → **高置信攻击链**（命中 `CompositeAttack`，且不误报 `Disturbance/Breaker Failure`，因为后者保护启动量先动）。

```bash
# G1–G7 一条命令式快检（tshark 逐帧字段 + Python 状态机）
tshark -r evidence/trace/pcaps/MS-AS3.pcapng -Y goose -T fields -E separator=, \
  -e frame.time_relative -e eth.src -e goose.gocbRef -e goose.confRev -e goose.stNum -e goose.sqNum -e goose.test \
  | python3 evidence/tools/detect_goose.py --baseline evidence/trace/baseline/goose-baseline.json \
      --scl evidence/trace/baseline/scl-authoritative.txt --rules G1,G2,G3,G4,G6,G7 \
      --out evidence/trace/detect/ms-as3-alerts.csv
```

```python
# evidence/tools/detect_goose.py —— 核心状态机（节选）
# 每 gocbRef 维护：last_stNum / last_sqNum / max_ts / last_frame_time / confRev_expected / legal_macs
def check(rec, st):
    alerts = []
    if rec.confRev != st.confRev_expected:                       # G1
        alerts.append(("G1 confRev-mismatch", rec))
    if rec.stNum != st.last_stNum:
        if rec.stNum - st.last_stNum > 1 and rec.stNum > st.last_stNum:   # G2
            alerts.append(("G2 stNum-jump", rec))
        if rec.sqNum != 0:                                        # G3
            alerts.append(("G3 sqNum-not-reset", rec))
    else:
        if rec.sqNum != st.last_sqNum + 1 and rec.sqNum <= st.last_sqNum:  # G4
            alerts.append(("G4 sqNum-out-of-order", rec))
    if rec.ts is not None and st.max_ts is not None and rec.ts < st.max_ts:  # G5
        alerts.append(("G5 timestamp-rollback", rec))
    if rec.mac not in st.legal_macs:                              # G7
        alerts.append(("G7 unknown-publisher", rec))
    return alerts
```

#### 6.3 Modbus / S7 检测规则

| # | 规则名 | 判据 | 命中 | 误报控制 |
|---|---|---|---|---|
| M1 | 首次出现的写功能码来源 | `func ∈ {5,6,15,16,23}` 且源 IP 不在"合法写入者"白名单 | 非法写入者 | 白名单随工程师站变更维护 |
| M2 | 非工作时段写 | 写操作落在运维窗口外 | 潜伏期改写 | 检修/调试窗口豁免 |
| M3 | 写速率异常 | 单位时间写次数 > 基线 P99 × 5 | 批量改写 | 组态下装本身是突发写 → 用来源+时段联合判定 |
| M4 | 诊断类功能码 | `func == 8`（尤其子功能 `0x0004` Force Listen Only Mode） | 致盲攻击 | 无（正常运维不应出现） |
| S1 | **PLC STOP** | `s7comm.param.func == 0x29` | 停机 | 无（唯一合法来源是工程师站，仍需告警） |
| S2 | **程序下载** | `s7comm.param.func ∈ {0x1a,0x1b,0x1c}` | 控制逻辑被改写 | 仅组态变更窗口豁免 |
| S3 | 口令交互 / 保护探测 | `s7comm.param.func == 0x27` 且源非工程师站 | 口令爆破/保护级别探测 | 工程师站合法登录需白名单 |
| S4 | 连接资源耗尽 | 同源 IP 并发 102 连接数 > 基线 × 3 | 连接耗尽攻击 | 工程软件本身会开多条连接 → 基线要按软件测 |

```bash
# 一键生成 Modbus/S7 告警
tshark -r capture.pcapng -Y 'mbtcp.func==5||mbtcp.func==6||mbtcp.func==15||mbtcp.func==16||mbtcp.func==8||s7comm.param.func==0x29||s7comm.param.func==0x1a||s7comm.param.func==0x1c||s7comm.param.func==0x27' \
  -T fields -E separator=, -e frame.time_relative -e ip.src -e ip.dst -e mbtcp.func -e s7comm.param.func \
  | python3 evidence/tools/detect_ot_writes.py --whitelist evidence/trace/baseline/writers.txt \
      --out evidence/trace/detect/ot-write-alerts.csv
```

#### 6.4 Zeek 规则（生产可用形态）

Zeek 配合 **icsnpp** 系列分析器（CISA 开源：`icsnpp-goose`/`icsnpp-s7comm`/`icsnpp-modbus`/`icsnpp-enip`）可在生产网做实时检测：

```bash
# 载入 icsnpp 包后离线跑，产出结构化日志（goose.log / s7comm.log / modbus.log）
zeek -r capture.pcapng icsnpp-goose icsnpp-s7comm icsnpp-modbus
ls goose.log s7comm.log modbus.log
```

```zeek
# evidence/trace/detect/goose-anomaly.zeek —— stNum/sqNum/帧率 检测骨架
@load icsnpp-goose

module GOOSEAnomaly;

export {
    redef enum Notice::Type += { StNum_Jump, SqNum_Out_Of_Order, Goose_Flood, Unknown_Publisher };
    const stnum_jump_threshold = 1 &redef;          # stNum 增量上限
    const flood_factor = 10 &redef;                 # 相对基线的帧率倍数
}

global last_stnum: table[string] of count &default=0;
global last_sqnum: table[string] of count &default=0;
global last_seen: table[string] of time &default=network_time();
global frame_count: table[string] of count &default=0;

event GOOSE::Message(c: connection, pdu: GOOSE::PDU)
    {
    local cb = pdu$gocbRef;

    # G2: stNum 非单调（跳变）
    if ( pdu$stNum > last_stnum[cb] + stnum_jump_threshold )
        NOTICE([$note=StNum_Jump, $msg=fmt("GOOSE stNum 跳变 %s: %d -> %d", cb, last_stnum[cb], pdu$stNum),
                $conn=c, $identifier=cb]);

    # G3/G4: sqNum 规则
    if ( pdu$stNum == last_stnum[cb] && pdu$sqNum <= last_sqnum[cb] )
        NOTICE([$note=SqNum_Out_Of_Order, $msg=fmt("GOOSE sqNum 乱序 %s: %d", cb, pdu$sqNum),
                $conn=c, $identifier=cb]);

    last_stnum[cb] = pdu$stNum;
    last_sqnum[cb] = pdu$sqNum;

    # G6: 帧率泛洪
    frame_count[cb] += 1;
    if ( frame_count[cb] > 10 )      # 稳态 1 Hz → 10 秒窗口内 >10 帧即可疑
        NOTICE([$note=Goose_Flood, $msg=fmt("GOOSE 帧率异常 %s", cb), $conn=c, $identifier=cb]);
    }
```

> Zeek 脚本需按现场的**实际稳态速率**调参（GOOSE 稳态可能是 1 s，也可能是 20 ms）。上线前必须用现场基线流量回放验证误报率。
> ⚠️ 上例为**检测骨架**：`GOOSE::PDU` 的字段名（`$gocbRef`/`$stNum`/`$sqNum` 等）须以**实际安装的 icsnpp-goose 包所定义的 record 为准**——先 `zeek -NN icsnpp-goose | grep -i goose` 与包内 `*.zeek` 定义核对字段名，再落地；字段名不符时脚本不会编译通过。

#### 6.5 Suricata / Wazuh 侧

- **Suricata**：对 102/tcp 与 502/tcp 可用规则检测"非白名单源的写功能码/STOP/下载"（内容匹配需处理 TCP 流重组下 S7 的 `param.func` 位置随会话变化的问题——建议用 `flow:established` + `dsize` + 字节偏移组合，或用 Zeek 替代）。
  示例（S7 STOP 的经典判据只能靠 `param.func=0x29`，其特征字节随 TPKT/COTP 长度变化，**必须用现场抓包生成精确规则**，不要凭记忆写魔数）。
- **Wazuh（GRFICS 靶场带 `wazuh` 容器，`55000` REST + `5601` Dashboard）**：把 Zeek `notice.log`/`goose.log` 与 Windows/SCADA 主机日志汇聚，做跨源关联：
  ```
  关联规则示例：
    (A) goose.log 出现 G2/G3 告警
    (B) 同一 30s 窗口内 host-based 侧出现 工程软件异常启动 / 工程文件被改 (Syscheck FIM)
    (C) 同窗口出现 跨区流向 ICS 的新会话（防火墙日志）
    → A ∧ (B ∨ C) = 高置信告警，显著降低单一规则误报
  ```
- **交换机侧**：静态组播表 + 端口安全（MAC 绑定）+ 组播风暴抑制。**GOOSE 检测的最强单点其实是交换机**——因为组播 MAC 表与端口绑定是硬件级、攻击者难以在应用层绕过的。

#### 6.6 检测覆盖与盲区（必须写进报告）

| 攻击类型 | 可检测性 | 最强检测点 | 残余盲区 |
|---|---|---|---|
| DM（改测量/改开关/重放） | **中** | 应用层字段 + 与扰动 CSV 交叉 | 若攻击者同时伪造保护启动量，则 G8 组合规则也失效 → 需一次系统物理量交叉（PMU/独立测量） |
| MS（stNum/sqNum 抑制） | **高** | 网络层字段级（G2/G3/G4） | MS AS3（高 stNum + 有效新时标）最难，需与 SCD 配置交叉 |
| DoS（泛洪） | **高** | 交换机风暴抑制 + 帧率（G6） | 攻击者低速慢速抑制可规避帧率阈值 |
| Composite | **高** | G8 组合规则 | 需先有可靠的单事件规则 |
| 真实保护动作 | （对照组） | 保护启动量先动 + 与电气量一致 | — |

### 7. 检测规则验证（**用两组样本同时验证，缺一不可**）

```bash
# 7.1 攻击样本：规则必须命中
for f in evidence/trace/timeline/*-anomalies.csv; do
  echo "== $(basename "$f"): $(($(wc -l < "$f")-1)) 命中"
done | tee evidence/trace/detect/detection-recall.txt

# 7.2 正常样本 + 扰动样本：规则必须不误报（**这才是检测规则的价值所在**）
python3 evidence/tools/detect_goose.py \
  --frames evidence/trace/baseline/normal-goose.csv \
  --baseline evidence/trace/baseline/goose-baseline.json \
  --scl evidence/trace/baseline/scl-authoritative.txt \
  --rules G1,G2,G3,G4,G6,G7 \
  --out evidence/trace/detect/false-positives-normal.csv

for d in "Busbar Protection" "Breaker Failure" "Under frequency"; do
  # 扰动场景 pcap（若目录内只有 CSV 则用 CSV 侧交叉）
  find "$READONLY_REF/Disturbance/$d" -name '*.pcapng' -print
done | tee evidence/trace/detect/disturbance-pcaps.txt

# 7.3 产出检测效果矩阵：TP / FP / FN（按规则逐条）
python3 evidence/tools/detection_matrix.py \
  --recall evidence/trace/detect/detection-recall.txt \
  --fp evidence/trace/detect/false-positives-normal.csv \
  --out evidence/trace/detect/detection-matrix.md
```

**验收标准**（写进报告）：

- 每条规则必须在 **9 个攻击样本**上给出"命中 / 未命中"的明确结论（未命中的要说明是**设计如此**还是**规则不足**）。
- 每条规则必须在 **Normal 样本**上 FP = 0（或给出 FP 数量与原因）。
- G8 组合规则必须在 **Disturbance 样本**上 FP = 0——**这是区分"检测"与"噪音"的分水岭**。

### 8. 复现与回放（**受门禁严格限制**）

原始 pcap 的分析**永远是离线的**。只有在隔离实验段验证检测规则时才考虑回放：

```bash
# 8.1 申请（缺任一参数即拒绝）
python3 evidence/tools/ot_guard.py request-control \
  --target 10.10.0.5 --action pcap_replay \
  --isolation "isolated-lab-A" --commander-ack REQUIRED \
  --recovery "停止 tcpreplay；实验段订阅者重新绑定原 publisher" \
  --on-site-operator REQUIRED \
  --rationale "在隔离实验段回放攻击样本以验证 Zeek 检测规则"

# 8.2 回放（仅隔离实验段；限速；绝不回放到生产过程层）
#     ⚠️ tcpreplay 会原样重放 GOOSE 注入帧 —— 在生产网回放等于真的发起攻击
sudo tcpreplay -i eth-lab --mbps=1 --loop=1 evidence/trace/pcaps/CompositeAttack.pcapng

# 8.3 回放后立即验证：检测规则是否触发、实验段设备是否需恢复
zeek -i eth-lab icsnpp-goose
cat notice.log | zeek-cut ts note msg
```

铁律：

- 回放目标接口必须通过 `assert_isolated_segment(iface)`：`/proc/net/arp` + LLDP 邻居确认该段**不含任何真实过程层设备或保护 IED**。
- 回放速率 ≤ 1 Mbps 且 `--loop=1`（禁止 `--loop=0` 无限循环——那等同于持续注入攻击流量）。
- 回放结束后必须抓包确认原 publisher 恢复、实验段设备状态正常，并写审计日志。
- **禁止在生产网回放任何 Attack 样本**——pcapng 里的注入帧是**真的攻击指令**，重放即执行。

### 9. 报告与取证包

```bash
# 9.1 取证包结构（可移交第三方复算）
#   evidence/trace/
#   ├── pcaps/           原始抓包 + SHA256SUMS + capinfos + provenance
#   ├── baseline/        正常态基线（goose-baseline.json、SCL 权威对照、扰动 CSV）
#   ├── timeline/        逐样本逐帧台账 + 异常清单 + attack-timeline.csv
#   ├── detect/          检测规则（*.py/*.zeek）+ 效果矩阵 + 误报清单
#   ├── replay/          隔离段回放记录（如执行）
#   └── SHA256SUMS       全包校验

sha256sum -c evidence/trace/pcaps/SHA256SUMS
python3 evidence/tools/build_report.py --dir evidence/trace --out evidence/trace/TRACEBACK-REPORT.md
```

---

## 安全约束

> 以下六条为**硬编码门禁**，在任何目标、任何阶段、任何理由下不得豁免。由 `evidence/tools/ot_guard.py` 在工具调用前强制执行。

1. **单目标并发不超过 3 个工具调用。**
   同一目标上并发的工具进程（tshark 实时解析、zeek、nmap、数据库/HTTP 查询）总数 **≤ 3**，默认串行为 1。本技能以离线分析为主，**离线分析天然不产生目标侧负载**——因此"并发超限"在本技能里通常意味着"有人在边分析边对现场发包"，这本身就是危险信号。禁止多终端齐发、禁止并发跑多个 zeek 实例对同一接口、禁止 `xargs -P`。

2. **模糊测试必须低频化，禁止高频扫描 OT 设备。**
   本技能**不做任何模糊测试**。若为了验证检测规则必须产生流量，唯一形式是**隔离实验段内的 pcap 回放**，且受限速约束：
   - 离线解析：**无任何速率限制需求**（不产生网络流量）——这是首选路径，优先做。
   - 现场采集：`tcpdump -i <iface> -G 600 -W 1` 分段落盘，采集本身不打设备。
   - 若做主动探测补充证据：`nmap -T2 --max-rate 10 --max-parallelism 1`（禁止 `-T3/-T4/-T5`、禁止 `--min-rate`）；任何 OT 请求间隔 **≥ 1 秒**。
   - 回放验证：`tcpreplay --mbps=1 --loop=1`（单次，≤1 Mbps）；**禁止 `--loop=0`**（无限循环 = 持续注入攻击流量）。
   - 熔断条件：回放/验证期间实验段设备出现异常状态、订阅者失联、或规则告警数量超预期 → **立即停止并退避 60 秒**，写审计日志后由指挥官裁决。
   - **禁止对生产网做任何形式的模糊测试或攻击样本回放**。

3. **写操作（寄存器写入、线圈强制、固件修改、PLC 启停）必须经过指挥官二次确认，且记入审计日志。**
   本技能中"写操作"的等价物是两类：**（a）分析过程中的任何在线动作**（主动探测补充、数据库查询、HTTP 复核）；**（b）pcap 回放**——回放 GOOSE 注入帧/Modbus 写帧/S7 STOP 帧**在语义上等同于真的执行了这些攻击动作**，因此回放按最高危写操作处理。流程强制：`request-control` 拿 `ack-id` → 指挥官显式确认 → 带 `ack-id` 执行 → **执行前**写审计日志、执行后写结果日志 → 回放后抓包确认恢复。无 `ack-id` 的回放命令由门禁拒绝。

4. **任何可能影响工控设备正常运行的命令，必须先记录到审计日志再执行。**
   保守判据：**凡不能证明是纯离线，就先记日志**。本技能中需先记日志的动作包括：现场实时抓包（占用交换机镜像端口/端口资源）、任何主动探测、检测规则**上线**（规则本身可能因误报导致运维中断——上线即视为变更）、回放。**先记后做，禁止事后补记。** 审计条目含 `ts`（ISO8601 带时区）、`op`、`target`/`iface`、`pcap`（文件名 + sha256）、`class`（read/collect/replay/rule-deploy）、`rate`、`isolation_segment`、`authorization`、`commander_ack`、`purpose`、`result`；回放前后各一条，成对可核。

5. **目标范围白名单硬编码，超出白名单一律拒绝执行。**
   ```python
   AUTHORIZED_SCOPE = ("10.10.0.0/24", "192.168.1.0/24")   # 已授权电力靶场段
   # 授权靶场叠加段（须在授权书范围内显式启用；默认关闭）
   # AUTHORIZED_SCOPE += ("192.168.90.0/24", "192.168.95.0/24")
   ALLOW_REPLAY_SEGMENT = None     # 仅隔离实验段可命名；None = 禁止任何回放
   READONLY_REF = "$REDTEAM_REFS/IEC61850SecurityDataset"   # 只读，禁止写入
   ```
   所有在线动作前跑 `assert_in_scope(ip)`（`ipaddress.ip_address(host) in ipaddress.ip_network(cidr)`），**不匹配即 `sys.exit(2)` 并记录拒绝日志**。回放额外要求 `assert_isolated_segment(iface)`（`/proc/net/arp` + LLDP 邻居核对，确认段内无一次设备/保护 IED）。**离线分析不受网络白名单限制**，但必须遵守下一行的只读约束。
   **参考素材只读**：`$REDTEAM_REFS/` 下的一切内容（尤其 `IEC61850SecurityDataset/`）**只读**——复制到证据区后再分析，绝不就地修改、绝不写入、绝不 `git` 操作。

6. **禁止 DDoS，禁止爆破；S7 口令只允许离线爆破参考脚本，禁止在线爆破。**
   - **禁止 DoS/DDoS 与泛洪**：禁止在生产网回放 `Denial of Service (DoS)` 样本（那是真的泛洪）；禁止 `hping3 --flood`；禁止 `--loop=0` 回放；禁止用检测规则验证为名对现场注入流量。
   - 本技能的 DoS 样本分析**只在离线 pcap 上做**——离线复现 DoS 检测规则是合法且必须的，但在网络上执行是绝对禁止的。
   - **禁止在线口令爆破**：本技能不做任何认证尝试。若时间线里发现口令爆破痕迹，那是**被分析对象的行为**，只做记录与特征提取，**不复制该行为**。
   - S7 口令仅允许**离线**路线（从 pcap 提 challenge/response → 本地字典，见 `f2x-power-s7comm-attack` 的 `s7-cracker.py` / `s7-brute-offline.py`），离线爆破不得产生任何网络流量；命中后不得回连目标做在线验证。
   - 若在回溯中发现现场存在**在线爆破痕迹**，应作为**攻击者行为证据**记录并告警，而不是"跟进尝试"。

---

## OT 影响评估

| 等级 | 本技能中的操作 | 影响机制 | 缓解/边界 |
|---|---|---|---|
| 🟢 **只读** | **全部离线分析**：`capinfos`/`tshark` 字段导出、`zeek -r` 离线跑日志、基线建模、异常检测、时间线构建、ATT&CK 映射、检测规则开发与离线验证（第 1–7 步、第 9 步） | **零网络流量、零设备负载**——这是本技能约 95% 的工作量，也是最应当优先做完的部分 | 无特殊限制；只需保证原始 pcap 只读（先复制再分析） |
| 🟢 **只读** | 现场被动采集（`tcpdump -i <mirror> -G 600 -W 1`） | 仅占用镜像端口/交换机转发资源；不向 OT 设备发包 | 使用 SPAN/TAP 而非在设备口上抓；分段文件避免超大文件；先写审计日志 |
| 🟢/🟡 **边界** | 主动探测补充证据（少量 `nmap -T2`、单次 HTTP 复核）、数据库只读查询复核 | 会向 OT 设备发包，但功能码为只读；会写入对端日志 | 1 s 间隔、并发 ≤3、限速 10 pkt/s；能不用就不用（离线能得到的结论不补主动探测） |
| 🔴 **停机风险** | **pcap 回放**（`tcpreplay`）——尤其回放含 GOOSE 注入帧、Modbus 写帧、S7 STOP 帧的样本 | **回放 = 真的执行攻击动作**：注入帧会让订阅者 IED 采信伪造状态、写帧会改过程值、STOP 帧会让 PLC 停机。回放到生产网**等同于发起攻击**，后果与非计划停电同级 | **默认拒绝**；仅"隔离实验段（无一次设备/保护 IED）+ 指挥官二次确认 + 先审计后执行 + `--mbps=1 --loop=1` + 现场有人值守"五条件齐备才可执行；**禁止生产网回放** |
| 🔴 **停机风险** | 检测规则直接上线（未经验证） | 误报率高的规则会让运维**忽略告警**或触发自动化响应（如隔离端口/切换备用）→ 可能造成非计划切换 | 规则必须先离线用 Normal + Disturbance 两组样本验证 FP=0，再以**观察模式**（仅告警不联动）上线；上线视为变更，需记审计日志 |
| ⚫ **绝对禁止** | 在生产网回放 Attack 样本、`tcpreplay --loop=0`、对现场做 DoS 复现、修改原始证据文件（含 `redteam-refs` 只读仓库） | 直接停机、证据链破坏（回溯报告失去法律/审计效力）、越界 | 硬拒绝，不设例外 |

**一句话结论**：本技能是**全技能集中风险最低、价值密度最高的一环**——95% 的工作（还原、重构、检测设计、规则验证）完全在离线完成，**零设备负载、零停机风险**。唯一的 🔴 风险点是 **pcap 回放**，而它在绝大多数场景下**根本不必要**：检测规则完全可以用离线样本验证（攻击样本验召回、Normal 与 Disturbance 样本验误报）。**默认立场：只离线，不回放。**

---

## 产出与证据

### 必交交付物

| # | 交付物 | 路径 | 计分要点 |
|---|---|---|---|
| 1 | 范围声明与门禁自检 | `evidence/audit/ot-ops.jsonl` | 含 `redteam-refs` 只读声明；回放（如有）成对条目 + 隔离段证明 |
| 2 | 证据完整性包 | `evidence/trace/pcaps/SHA256SUMS` + `capinfos.txt` + `provenance.txt` | 原始哈希、采集元数据、链路类型；**证明分析过程未改动原件** |
| 3 | 协议栈全景 | `evidence/trace/timeline/proto-hierarchy.txt` + 端点/会话矩阵 + `pkts-per-second.txt` | 协议构成、对话量、逐秒包量（DoS 窗口一眼可见） |
| 4 | **正常态基线（核心）** | `evidence/trace/baseline/normal-goose.csv` + `goose-baseline.json` | 每 `gocbRef` 的周期/TTL/`confRev`/`stNum`-`sqNum` 规律/数据长度 |
| 5 | SCL 权威对照表 | `evidence/trace/baseline/scl-authoritative.txt` | IED ↔ IP ↔ MAC ↔ `gocbRef`/`appID`/`datSet`/`confRev`——检测合法性的判据来源 |
| 6 | 时钟偏移校正记录 | `evidence/trace/baseline/clock-offset.csv` + 校正结论 | 证明 G5（时标倒退）规则未受时钟差异污染 |
| 7 | **逐样本攻击还原台账（核心）** | `evidence/trace/timeline/{dm-as1..3,ms-as1..4,dos-as1,composite}-anomalies.csv` | 逐样本给出包号、时间、`gocbRef`、异常类型、判据 |
| 8 | 攻击动作还原对照表 | `evidence/trace/timeline/attack-reconstruction.md` | 与数据集 README 坐标逐条对齐；含"命中/未命中" |
| 9 | Two-step 关联证据 | `evidence/trace/timeline/composite-two-step.txt` + `dm-as2-verdict.md` | 抑制→篡改的两步关联；开关变位 vs 保护启动的交叉核对 |
| 10 | **统一攻击时间线（核心）** | `evidence/trace/timeline/attack-timeline.csv` | 列：`ts,phase,actor(claimed),actor(mac),protocol,action,target,evidence_ref,confidence` |
| 11 | ATT&CK for ICS 映射 | `evidence/trace/timeline/attack-chain-attck.md` | 逐阶段映射 + **官方矩阵复核声明** |
| 12 | **检测点设计（核心交付）** | `evidence/trace/detect/detection-design.md` | 六层检测点地图 + GOOSE G1–G8 + Modbus/S7 M1–M4/S1–S4 + Zeek/Wazuh/Suricata 落地方案 + **盲区清单** |
| 13 | 可执行检测规则 | `evidence/trace/detect/detect_goose.py`、`goose-anomaly.zeek`、`detect_ot_writes.py` | 可直接部署的规则代码（含参数与调参说明） |
| 14 | **检测效果矩阵（核心）** | `evidence/trace/detect/detection-matrix.md` | 逐规则 TP（9 攻击样本）/ FP（Normal）/ FN，及 FP=0 的扰动样本验证 |
| 15 | 回放记录（如执行） | `evidence/trace/replay/` + 审计成对条目 | 五条件证据 + `--mbps=1 --loop=1` + 回放后恢复确认 |
| 16 | finding 登记 | `f2x_orchestrate_finding`（本插件自带） | finding：检测 gap（哪类攻击在当前防守下不可见）、IEC 62351-6 缺失、交换机无端口安全、无基线监控 |

### 证据质量要求

- **证据链第一**：原始 pcap 的哈希在分析开始前固定，分析全部在副本上进行。**任何对原始证据的修改都会让整份回溯报告失效。**
- **结论必须可复算**：每条"某帧是攻击帧"的结论都要给出 **可独立执行的 `tshark` 过滤命令** + 包号 + 字段值，第三方能自己跑出来。
- **对照组不可省**：只报"攻击样本命中了什么"是**不合格**的回溯。必须同时给出 **Normal 样本的 FP** 与 **Disturbance 样本的 FP**——否则无法证明检测有效而非噪音。
- **区分"看见"与"推断"**：协议字段级命中 = `confirmed`；从模式推断"这是同一攻击者的第二步" = `inferred`；两者必须在时间线的 `confidence` 列区分开。
- **盲区要明写**：检测设计必须包含"**这条规则挡不住什么**"——例如 G1–G7 挡不住"攻击者同时伪造保护启动量"，必须转向一次系统物理量交叉。**隐瞒盲区是回溯报告最常见的失真方式。**
- **诚实标注**：pcap 缺失时段、时钟不可信、样本不完整都要写清楚；`filtered`/超时/无响应原样记录。

### 速用命令卡

```bash
DS="$REDTEAM_REFS/IEC61850SecurityDataset"    # 只读
# 证据固定
capinfos "$DS/Attack/CompositeAttack.pcapng"
# 逐秒包量（DoS 一眼可见）
tshark -r "$DS/Attack/Denial of Service (DoS)/AS1.pcapng" -q -z io,stat,1,"COUNT(frame)frame"
# 正常态基线
tshark -r "$DS/Normal/No_Variable_Loading/Normal.pcapng" -Y goose -T fields \
  -e goose.gocbRef -e goose.stNum -e goose.sqNum -e goose.timeAllowedtoLive
# 抑制攻击（高 stNum）快检
tshark -r "$DS/Attack/Message Suppression (MS)/AS1.pcapng" -Y 'goose && goose.stNum > 100' -T fields \
  -e frame.number -e frame.time_relative -e goose.gocbRef -e goose.stNum -e goose.sqNum
# 重放攻击（时标倒退）快检
tshark -r "$DS/Attack/Data Manipulation (DM)/AS3.pcapng" -Y goose -T fields \
  -e frame.time_relative -e goose.gocbRef -e goose.timestamp
# 组合攻击（两步关联）
tshark -r "$DS/Attack/CompositeAttack.pcapng" -Y goose -T fields \
  -e frame.number -e frame.time_relative -e goose.stNum -e goose.allData
# ❌ 禁止：生产网回放 Attack 样本 / tcpreplay --loop=0 / 修改 redteam-refs / 现场 DoS 复现
```

### 与其他技能的衔接

- 需要补协议细节（字段语义、设备行为）→ `f2x-power-iec61850-analysis` / `f2x-power-modbus-attack` / `f2x-power-s7comm-attack`。
- 需要补资产与角色（谁是 EWS、谁在跨区）→ `f2x-power-scada-recon` 的资产台账与跨区矩阵。
- 检测规则落地需要现场基线时，回到 `f2x-power-scada-recon` 的被动采集（SPAN/TAP）取基线流量。
- 本技能产出的 `detection-matrix.md` 是**收口报告"防守验证（detection gap）"章节的直接输入**。
