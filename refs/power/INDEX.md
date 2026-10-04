# 电力知识库索引（`refs/power/`）

> 本索引覆盖 `refs/power/` 下 **6 个知识文件**（不含索引自身）。
> 全部为**参考手册**语气（客观描述协议结构、资产与映射），不含操作步骤教程。
> 关联技能名对应本插件 `skills/power/` 与 `skills/` 下的 `f2x-*` 技能。
> 行数口径见 §2 脚注（**不要用 `Get-Content` 的 `.Count`**：本机默认按 ANSI 代码页解码 UTF-8 会误计行数）。

---

## 1. 目录结构

```
refs/power/
├── INDEX.md                          ← 本文件
├── protocols/
│   ├── modbus.md                     Modbus/TCP + Modbus RTU/ASCII
│   ├── s7comm.md                     S7comm / S7comm-plus（西门子）
│   ├── iec61850.md                   IEC 61850（信息模型/MMS/GOOSE/SV/SCL）
│   └── dnp3.md                       DNP3（IEEE 1815，含 DNP3-SA）
├── ics-attack/
│   └── mitre-ics-mapping.md          MITRE ATT&CK for ICS 电力场景映射
└── business-scenarios/
    └── power-grid.md                 电力业务场景与资产地图（发/输/变/配）
```

---

## 2. 文件清单

| # | 文件 | 一句话摘要 | 关联技能 | 行数 |
|---|---|---|---|---|
| 1 | `protocols/modbus.md` | Modbus/TCP（MBAP 7 字节头）与 RTU/ASCII 的帧结构、4 张地址表、公共功能码与异常码、真实 CRC 帧示例，以及无认证/无完整性导致的功能码滥用面（电力：配网、计量、辅控、新能源） | `f2x-power-modbus-attack`、`f2x-power-scada-recon`、`f2x-power-traceback` | 328 |
| 2 | `protocols/s7comm.md` | TPKT/COTP/ISO-TSAP（102/tcp）封装、Job 作业类型（Read/Write Var、Setup Comm、PLC Stop、Download/Upload、PI Service）、S7ANY 地址模型、**免认证 SZL 设备指纹**、访问保护等级与 S7comm-plus 结构（电力：辅控、厂用电、新能源、小型站控） | `f2x-power-s7comm-attack`、`f2x-power-scada-recon`、`f2x-asset-mapping` | 328 |
| 3 | `protocols/iec61850.md` | 信息模型（LD/LN/DO/DA、FC、CDC）、MMS over ISO-on-TCP（102/tcp）服务与报告/控制模型、GOOSE（`0x88B8`，BER 标签全集 + 自洽示例帧 + stNum/sqNum 状态机）、SV（`0x88BA`）、SCL 文件族（SSD/SCD/ICD/CID/IID/SED）、IEC 62351 对照与已知弱点（电力：变电过程层与站控层） | `f2x-power-iec61850-analysis`、`f2x-power-traceback`、`f2x-asset-mapping` | 398 |
| 4 | `protocols/dnp3.md` | 链路层帧（10 字节头块 + 16+2 数据块、DNP3 CRC 实测复算）、传输功能、应用层功能码/对象组/限定词/IIN 位域、CROB 结构与控制码、**DNP3-SA 认证机制与未启用风险**（电力：输电与配网远动主力） | `f2x-power-scada-recon`、`f2x-power-traceback`、`f2x-exploitation` | 361 |
| 5 | `ics-attack/mitre-ics-mapping.md` | MITRE ATT&CK for ICS v19 全 **12 战术**覆盖、**69 条技术条目**（技术/子技术 ID + 名称 + 电力落地示例）、电力业务影响分级收敛表与战术覆盖对账表 | 电力 5 技能全覆盖 + 通用 4 技能 | 256 |
| 6 | `business-scenarios/power-grid.md` | 发电/输电/变电/配电四环节业务差异、安全 I/II/III 区与横向隔离/纵向认证边界、典型系统（DCS/SIS/SCADA/EMS/SAS/DMS）与设备（PLC/RTU/IED/HMI/EWS/保护装置）的协议映射、攻击面与业务影响分级（含 5 类攻击路径模式） | `f2x-power-scada-recon`、`f2x-asset-mapping`、`f2x-power-traceback` | 196 |

合计：**6 个知识文件 / 1867 行**。

> **行数口径**：按文件 LF 字节计数（UTF-8）。实测命令：
> `[System.IO.File]::ReadAllBytes($f)` 统计 `0x0A` 个数。
> ⚠️ **不要用 `(Get-Content $f).Count`**：本机 PowerShell 的 `Get-Content` 默认按 ANSI(936) 解码 UTF-8 文件，
> 会把中文行的字节组合误判，导致行数偏小（实测 `iec61850.md` 报 337，真值 398）。

---

## 3. 按“遇到什么情况看哪个文件”导航

| 情境 | 首读 |
|---|---|
| 看到 502/tcp，要判断设备类型与可读写面 | `protocols/modbus.md` |
| 看到 102/tcp，先要区分是 S7 还是 IEC 61850 MMS | `protocols/s7comm.md` §3.3 + `protocols/iec61850.md` §3.1（COTP 之后载荷判定） |
| 看到 20000/tcp，要判断点表模型与遥控通道 | `protocols/dnp3.md` §4 |
| 抓到二层组播（`0x88B8`/`0x88BA`） | `protocols/iec61850.md` §4/§5 |
| 需要免认证设备指纹（型号/固件/序列号） | `protocols/s7comm.md` §4（SZL）、`protocols/modbus.md` §5.1（0x2B/0x0E）、`protocols/iec61850.md` §2.4（DPL） |
| 要把发现映射成战术/技术编号写报告 | `ics-attack/mitre-ics-mapping.md` |
| 要判断影响等级（是否触及保护/安全） | `business-scenarios/power-grid.md` §7 + `ics-attack/mitre-ics-mapping.md` §13 |
| 要写攻击链拓扑（分区/关口/边动作） | `business-scenarios/power-grid.md` §2/§6 |
| 做流量回溯定责 | `protocols/dnp3.md` §8、`protocols/iec61850.md` §8、`protocols/modbus.md` §7 |

---

## 4. 覆盖范围与已知缺口（诚实声明）

**已覆盖**：Modbus、S7comm/S7comm-plus、IEC 61850（含 GOOSE/SV/SCL）、DNP3、MITRE ATT&CK for ICS 映射、电力业务资产地图。

**未单列，仅在文件内以索引形式提及**（需要时应扩展或直接查上游素材）：

| 协议/主题 | 提及位置 | 上游素材（只读仓库） |
|---|---|---|
| IEC 60870-5-104（2404/tcp） | `protocols/dnp3.md` §9 | `redteam-refs\awesome-industrial-protocols\protocols\iec-60870-5-104.md` |
| ICCP / TASE.2（102/tcp） | `protocols/dnp3.md` §9 | 同上 `protocols\iccp.md` |
| IEEE C37.118 同步相量 | `protocols/dnp3.md` §9、`business-scenarios/power-grid.md` §3 | 同上 `protocols\ieee-c37118.md` |
| OPC UA / OPC DA | `business-scenarios/power-grid.md` §4 | 同上 `protocols\opc-ua.md`、`protocols\opc-da.md` |
| PROFINET / EtherNet/IP / Modbus↔其它网关 | `protocols/modbus.md` §6.4 | 同上 `protocols\profinet-io.md`、`protocols\ethernetip.md` |
| DL/T645 电表规约 | `business-scenarios/power-grid.md` §4 | 上游素材未收录（本知识库仅作业务提及，未给帧结构） |
| IEC 61850 攻击/扰动 pcap 数据集 | `protocols/iec61850.md` §4.4 | `redteam-refs\IEC61850SecurityDataset\` |
| 工控靶场拓扑 | `business-scenarios/power-grid.md` §2.2 | `redteam-refs\GRFICSv3\` |

**未做**：不含具体利用脚本/EXP（本项目技能目录承担该职责）；不含现场抓包原文（仅 61850 给出**按标准构造的自洽示例帧**，
已在文内明确标注为非抓包）；不复制上游素材原文（仅做分类、摘编与索引）。

---

## 5. 来源与引用规范

本目录文件在头部标注了所参考的只读素材路径。引用约定：

1. **只读仓库**：`$REDTEAM_REFS/` 为只读参考仓库，本项目**只读不写**。
2. **摘编不复制**：仅做分类、摘要、字段级摘编与索引；大段原文引用在文件内注明来源路径。
3. **自算数值**：Modbus CRC16、DNP3 CRC、S7/GOOSE 帧长度等均由本文件逐字段推导或脚本复算（已在文内说明），
   不依赖上游素材的转述。所有十六进制示例帧已用脚本回读校验（TPKT/MBAP/DNP3 Length 字段与 BER 字段长度自洽）。
4. **版本标注**：MITRE 映射标注了核对版本（ICS Matrix v19 / 内容 v19.2）。

---

## 6. 关联

- 上级索引：`../INDEX.md`（`refs/` 全树索引）
- 技能：`skills/power/f2x-power-modbus-attack`、`f2x-power-s7comm-attack`、
  `f2x-power-iec61850-analysis`、`f2x-power-scada-recon`、`f2x-power-traceback`
