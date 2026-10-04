# `refs/` 知识库总索引

> 本索引覆盖 本包的 `refs/` 目录 全树。
> 实测统计：**6 个知识文件 + 2 个索引文件，共 8 个文件**（`refs/power/` 下 6 个知识文件 + 1 个子索引；`refs/` 根 1 个总索引）。
> 全部文件为**参考手册**语气（客观描述），不含利用脚本或操作教程（该职责归 `skills/`）。
> 来源纪律：引用只读仓库 `$REDTEAM_REFS/` 时**只做分类、摘编与索引，不整文件复制**；
> 大段原文引用在文件内注明来源路径。见 §5。

---

## 1. 分类总表（全量）

| 分类 | 文件路径 | 一句话摘要 | 行数 |
|---|---|---|---|
| **电力·协议** | `power/protocols/modbus.md` | Modbus/TCP（MBAP 7 字节头）与 RTU/ASCII 帧结构、4 张地址表、公共功能码与异常码表、真实 CRC 帧示例、无认证导致的功能码滥用面 | 328 |
| **电力·协议** | `power/protocols/s7comm.md` | TPKT/COTP/ISO-TSAP（102/tcp）封装、Job 作业类型表、S7ANY 地址模型、免认证 SZL 设备指纹、访问保护等级、S7comm-plus 结构 | 328 |
| **电力·协议** | `power/protocols/iec61850.md` | 信息模型（LD/LN/DO/DA、FC、CDC）、MMS 服务与报告/控制模型、GOOSE（`0x88B8`）字段与状态机、SV（`0x88BA`）、SCL 文件族、IEC 62351 对照 | 398 |
| **电力·协议** | `power/protocols/dnp3.md` | 链路层帧与实测复算 CRC、传输功能、应用层功能码/对象组/IIN、CROB 控制码、DNP3-SA 机制与未启用风险 | 361 |
| **电力·攻击映射** | `power/ics-attack/mitre-ics-mapping.md` | MITRE ATT&CK for ICS v19 全 12 战术、69 条技术条目与电力落地示例、业务影响分级收敛表 | 256 |
| **电力·业务场景** | `power/business-scenarios/power-grid.md` | 发电/输电/变电/配电四环节业务差异、安全 I/II/III 区与隔离认证边界、典型系统与设备协议映射、5 类攻击路径模式 | 196 |
| **电力·索引** | `power/INDEX.md` | 电力知识库子索引：目录结构、文件清单、按情境导航表、覆盖缺口声明 | 94 |

合计：**6 个知识文件 / 1867 行** + 2 个索引文件（`refs/INDEX.md` 本文件、`power/INDEX.md`）。

> **行数口径**：按文件 LF 字节计数（UTF-8）。实测命令：`[System.IO.File]::ReadAllBytes($f)` 统计 `0x0A` 个数。
> ⚠️ **不要用 `(Get-Content $f).Count`**：本机 PowerShell 的 `Get-Content` 默认按 ANSI(936) 代码页解码 UTF-8 文件，
> 会误判中文行，导致行数偏小（实测 `power/protocols/iec61850.md` 报 337，真值 398）。

---

## 2. 电力知识库 `refs/power/`（子索引）

详细导读（情境导航、覆盖缺口、来源标注）见 **`power/INDEX.md`**。此处给出分类结构：

```
refs/power/
├── INDEX.md                              ← 子索引（导航 + 缺口声明）
├── protocols/                            ← 协议参考手册（4 篇）
│   ├── modbus.md
│   ├── s7comm.md
│   ├── iec61850.md
│   └── dnp3.md
├── ics-attack/                           ← 攻击战术映射（1 篇）
│   └── mitre-ics-mapping.md
└── business-scenarios/                   ← 业务与资产（1 篇）
    └── power-grid.md
```

| 子分类 | 文件数 | 覆盖内容 | 关联技能 |
|---|---|---|---|
| `protocols/` | 4 | Modbus、S7comm/S7comm-plus、IEC 61850（MMS/GOOSE/SV/SCL）、DNP3（含 SA） | `f2x-power-modbus-attack`、`f2x-power-s7comm-attack`、`f2x-power-iec61850-analysis` |
| `ics-attack/` | 1 | ATT&CK for ICS 战术/技术 → 电力资产、协议字段与业务后果 | 电力 5 技能 + 通用 `f2x-*` |
| `business-scenarios/` | 1 | 发/输/变/配业务差异、分区与边界、系统与设备、影响分级 | `f2x-power-scada-recon`、`f2x-asset-mapping`、`f2x-power-traceback` |

---

## 3. 其它分类

| 分类 | 状态 | 说明 |
|---|---|---|
| `refs/general/`（通用知识库） | **未创建** | 本插件本次仅交付电力模块知识库；通用能力由 `persona/` 与 `playbook/` 承担。若后续新增 `refs/general/`，应在此表补行并在 §1 追加条目 |

> 除 `refs/power/` 外，`refs/` 下当前**无其它子目录或文件**（已用 `Get-ChildItem -Recurse -Force` 实测确认）。

---

## 4. 覆盖范围与已知缺口

**已覆盖**：电力侧 4 个核心协议（Modbus / S7comm / IEC 61850 / DNP3）、MITRE ATT&CK for ICS 全战术映射、
电力四环节业务与资产地图。

**未单列**（在文件内以索引形式提及，需要时查上游只读素材）：

| 主题 | 上游素材（`$REDTEAM_REFS/`） |
|---|---|
| IEC 60870-5-104、ICCP/TASE.2、IEEE C37.118 | `awesome-industrial-protocols\protocols\iec-60870-5-104.md`、`iccp.md`、`ieee-c37118.md` |
| OPC UA / OPC DA | `awesome-industrial-protocols\protocols\opc-ua.md`、`opc-da.md` |
| PROFINET / EtherNet/IP / 其它现场总线 | `awesome-industrial-protocols\protocols\profinet-io.md`、`profinet-dcp.md`、`ethernetip.md` |
| IEC 61850 攻击/扰动数据与 SCL(IID) 样例 | `IEC61850SecurityDataset\`（README + normal/attack trace + `SCL/`） |
| 工控靶场拓扑（IT→DMZ→OT） | `GRFICSv3\`（README + `docker-compose.yml`） |
| 工控协议元数据与抓包样例 | `awesome-industrial-protocols\db\protocols.json`、`db\packets.json`、`db\links.json` |
| ICS 工具与 S7 口令校验脚本 | `ICS-Pentesting-Tools\README.md`、`awesome-industrial-control-system-security\source\s7-cracker.py`、`s7-brute-offline.py` |
| ICS 会议议题与写作素材 | `awesome-ics-writeups\awesome-ics-videos.md`、`awesome-industrial-protocols\protocols\*.md` 的 Conferences/Tools 节 |

**未包含**：利用脚本与 EXP（归 `skills/`）；现场抓包原文（IEC 61850 给出的是**按标准构造并标注的自洽示例帧**，
非抓包）；对只读仓库素材的整文件复制。

---

## 5. 使用与维护约定

1. **读取入口**：先读本索引 → 再读 `power/INDEX.md` 的情境导航表 → 最后读具体文件。
2. **写入边界**：本知识库**只允许**在 本包的 `refs/` 目录 下写入；
   `$REDTEAM_REFS/` 为**只读**参考仓库，不得修改。
3. **数值可信度**：协议文档中的 CRC、帧长度、功能码数值均为逐字段推导或脚本复算（文内已注明），
   不依赖二手转述；**构造示例帧**与**现场抓包**在文内明确区分。
   所有十六进制示例帧已用脚本回读校验（TPKT / MBAP / DNP3 Length 字段与 GOOSE BER 字段长度自洽）。
4. **版本时效**：MITRE 映射标注核对版本（ICS Matrix v19 / 内容 v19.2）；协议规范版本在各自文件头部标注。
5. **新增文件**：新增知识文件后需同步更新本索引 §1 与 `power/INDEX.md` §2（保持“文件数/行数”可对账）。

---

## 6. 关联

- 子索引：`power/INDEX.md`
- 技能目录：`skills/`（通用 5 项）、`skills/power/`（电力 5 项）
- 只读素材仓库：`$REDTEAM_REFS/`
