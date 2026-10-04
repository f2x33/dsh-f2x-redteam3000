# MITRE ATT&CK for ICS 映射（电力场景落地）

> 定位：**参考手册**。把 ATT&CK for ICS 的战术/技术 ID 与电力行业的具体资产、协议字段、业务后果对齐，
> 供影子编排、覆盖对账、报告归因与检测映射使用。
> 版本核对：**ATT&CK for ICS Matrix v19（站点内容版本 v19.2）**，逐战术页抓取技术 ID 与名称核对。
> 来源：<https://attack.mitre.org/matrices/ics/> 及各战术页（`/tactics/TA01xx/`）。
> 覆盖度：**12 个战术全部覆盖**，共 **69 条技术条目**（技术/子技术按条目计；同一技术可出现在多个战术下，与官方矩阵一致）。
> 协议细节见同目录 `../protocols/`；业务资产见 `../business-scenarios/power-grid.md`。

---

## 0. 使用说明

| 列 | 含义 |
|---|---|
| 技术 ID | ATT&CK for ICS 技术编号（`T1xxx`，子技术为 `T1xxx.00x`） |
| 名称 | 官方英文名（中文为通行译名，仅辅助理解） |
| 电力落地示例 | 在发电/输电/变电/配电环节中的**具体可观测形态**（资产 + 协议字段 + 业务后果） |

三条落地原则：

1. **协议字段优先**：电力 OT 的“技术”最终都落在具体报文字段上（GOOSE `stNum`、DNP3 CROB 控制码、
   Modbus 功能码 0x05/0x10、S7 Write Var），报告与检测应以字段为锚，而非仅贴战术标签。
2. **业务影响分级**：同类技术在**保护/安全系统**上和在**辅控/计量**上，影响等级完全不同（见 §13）。
3. **双面归因**：同一字段既是攻击面也是检测点（如 DNP3 `DISABLE_UNSOLICITED`、
   IIN `EVENT_BUFFER_OVERFLOW`、GOOSE `test=1`），映射时应同时给出检测抓手。

---

## 1. Initial Access — 初始访问（TA0108）

> 官方收录 12 项技术；下表选取电力场景最相关的 8 项。

| 技术 ID | 名称 | 电力落地示例 |
|---|---|---|
| T0819 | Exploit Public-Facing Application | 暴露于互联网的**光伏/风电集中监控平台、充电桩运营平台、配网 Web 组态、远动网关管理口**被漏洞利用；此类系统常为“一个平台管千站”，单点即全域入口 |
| T0883 | Internet Accessible Device | 直连公网的 RTU/测控装置/IED 管理口（502、102、20000、2404 暴露）；部分 4G 回传模块自带 Web 管理 |
| T0848 | Rogue Master | **伪造主站**接入 Modbus/DNP3 从站（无认证即成立）；或伪造 IEC 61850 客户端读全模型 |
| T0822 | External Remote Services | 厂商远程诊断/运维 VPN、调度数据网远程维护通道；凭据复用或 VPN 设备漏洞 |
| T0865 | Spearphishing Attachment | 钓鱼附件投递到**厂站办公终端或工程师站**，经双网卡/共享目录进入 OT（IT→OT 典型起点） |
| T0847 | Replication Through Removable Media | 检修用 U 盘/移动硬盘接入工程师站或装置维护口；工程交接介质是历史性传染源 |
| T0864 | Transient Cyber Asset | 移动运维笔记本、调试终端、USB 转串口/网口适配器；接入即临时获得 OT 网络可见性 |
| T0860 | Wireless Compromise | 无线数传电台、230MHz/1.8GHz 电力无线专网、4G/5G 回传模块、辅控 WiFi |

---

## 2. Execution — 执行（TA0104）

> 官方收录 10 项；下表 6 项。

| 技术 ID | 名称 | 电力落地示例 |
|---|---|---|
| T0858 | Change Operating Mode | 将 PLC/保护装置切至 **PROG/维护/就地**模式，解除写保护与联锁，为后续下发命令打开通路 |
| T0871 | Execution through API | 经 **OPC/Modbus 写 / DNP3 OPERATE / IEC 61850 Oper** 执行控制动作——OT 里“执行”常常就是一次协议写 |
| T0807 | Command-Line Interface | 站控层服务器/前置机 shell；PLC 私有 CLI（调试串口、厂商工具命令行） |
| T0821 | Modify Controller Tasking | 改控制器任务/中断块优先级与循环周期（如把恶意逻辑挂在快任务上、拖慢保护配合） |
| T0853 | Scripting | 站控层脚本（轮询/下发）、装置侧脚本化逻辑；批量站点脚本化操作 |
| T0863 | User Execution | 诱导运维打开伪装的“定值单/录波分析工具/固件升级包” |

---

## 3. Persistence — 持久化（TA0110）

> 官方收录 **5 项（含子技术）**，下表全列。

| 技术 ID | 名称 | 电力落地示例 |
|---|---|---|
| T0889 | Modify Program | 改 PLC/RTU 用户逻辑留存后门（例：特定遥测组合即闭锁跳闸；特定点写触发隐藏分支） |
| T0873 | Project File Infection | 污染**工程师站工程文件**，每次下装即复活（T0873.001 明确指向 Siemens 工程文件格式） |
| T0859 | Valid Accounts | 使用合法工程师/HMI/运维账户长期驻留；共享账户使归因困难 |
| T1694 | Insecure Credentials | .001 默认凭据（装置/网关/后台出厂口令）；.002 硬编码凭据（固件内固定口令、DNP3-SA Update Key 全网相同） |
| T1693 | Modify Firmware | .001 系统固件（RTU/网关 OS）；.002 模块固件（通信模块、保护 CPU 插件、合并单元）——低于应用层的驻留 |

---

## 4. Privilege Escalation — 提权（TA0111）

> 官方收录 **2 项**（本战术在 ICS 矩阵中技术最少），下表全列。

| 技术 ID | 名称 | 电力落地示例 |
|---|---|---|
| T0890 | Exploitation for Privilege Escalation | 从 HMI 只读账户提至工程师权限；后台 Web 应用漏洞提权到 OS；装置维护口弱口令获得配置权 |
| T0874 | Hooking | 在站控层/前置机 Hook 控制 API 或协议栈，拦截与改写控制指令流（隐蔽改写比直接写更难察觉） |

---

## 5. Evasion — 规避（TA0103）

> 官方收录 7 项；下表 6 项。

| 技术 ID | 名称 | 电力落地示例 |
|---|---|---|
| T0849 | Masquerading | 伪装为合法主站 IP/链路地址、伪造 GOOSE **源 MAC 与 APPID**、冒用合法 `origin` 标识；使伪造报文与真实报文难以区分 |
| T1692 | Unauthorized Message | .001 命令报文（伪造 GOOSE 跳闸、伪造 DNP3 CROB、伪造 MMS Oper）；.002 报告报文（伪造遥测/采样值使调度看到正常工况） |
| T0872 | Indicator Removal on Host | 清站控层/服务器日志、清 PLC 诊断缓冲、清事件与操作记录；改装置时间戳使事件排序失真 |
| T0858 | Change Operating Mode | 切维护模式以避开联锁与告警逻辑，使异常行为不产生报警 |
| T0851 | Rootkit | 站控层 OS 级 rootkit 隐藏进程与连接；PLC 级隐藏（如仅在被读取时返回“正常值”） |
| T0894 | System Binary Proxy Execution | 借系统自带可信工具（组态软件自带 CLI、计划任务、远程管理组件）执行动作 |

---

## 6. Discovery — 发现（TA0102）

> 官方收录 5 项（T0846 含 3 个子技术）；下表全列。

| 技术 ID | 名称 | 电力落地示例 |
|---|---|---|
| T0846 | Remote System Discovery | .001 端口扫描（502/102/20000/2404/4840/80/443）；.002 广播发现（DNP3 广播、Modbus 广播）；.003 **组播发现**（监听 GOOSE/SV 组播即枚举 IED 及其数据集） |
| T0840 | Network Connection Enumeration | 站控层连接表/ARP 表/会话表 → 还原主站与装置映射关系、识别前置机与网关 |
| T0842 | Network Sniffing | 镜像口/SPAN 抓包直接得到 GOOSE/MMS/DNP3 报文与点表；**GOOSE/SV 为组播，接入任一交换机端口即可见** |
| T0888 | Remote System Information Discovery | 免认证设备指纹：S7 **Read SZL**（型号/固件/序列号）、Modbus `0x2B/0x0E` Read Device ID、ICMP/SNMP sysDescr、IEC 61850 `DPL`（铭牌 CDC） |
| T0887 | Wireless Sniffing | 无线专网/4G/电台链路监听；对无线回传的配网终端构成直接威胁 |

---

## 7. Lateral Movement — 横向移动（TA0109）

> 官方收录 6 项（含子技术）；下表全列。

| 技术 ID | 名称 | 电力落地示例 |
|---|---|---|
| T0866 | Exploitation of Remote Services | 利用站控层服务漏洞跨主机；利用前置机/网关服务漏洞跨安全区 |
| T0886 | Remote Services | RDP/SSH/VNC/SMB 从办公网 → DMZ → 站控层 → 工程师站；OT 内常用远程桌面运维 |
| T0867 | Lateral Tool Transfer | 经共享目录、文件服务（MMS FileOpen/Write、DNP3 文件服务、FTP/SMB）投递工具与载荷 |
| T0843 | Program Download | .001 整体下装（Download All）；.002 **在线修改**（Online Edit，不停机改逻辑）；.003 程序追加（Program Append）——把载荷落到多台同类装置 |
| T0859 | Valid Accounts | 复用工程师/HMI 账户横向登录各站后台 |
| T1694 | Insecure Credentials | .001/.002：站间同口令、装置默认口令使横向授权成本趋零 |

---

## 8. Collection — 收集（TA0100）

> 官方收录 11 项；下表 8 项。

| 技术 ID | 名称 | 电力落地示例 |
|---|---|---|
| T0861 | Point & Tag Identification | 建立点表语义：Modbus 全地址扫描、DNP3 `Group 60 Var 1 Qualifier 06` 全表读、IEC 61850 `GetNameList` + `GetDataSetDirectory` 穷举 |
| T0877 | I/O Image | 读 PLC I/O 映像（S7 区域 `0x81/0x82/0x83`）掌握实时输入输出状态 |
| T0801 | Monitor Process State | 长期读遥测/负荷曲线，判断机组出力、负荷水平与运行方式（为攻击窗口选时机） |
| T0845 | Program Upload | 上载 PLC/RTU 程序与保护定值，理解控制逻辑（S7 Upload 作业 `0x1D`–`0x1F`） |
| T0811 | Data from Information Repositories | 从 historian、报表库、SCD/CID 配置库、图纸与定值单库获取全站结构与参数 |
| T0893 | Data from Local System | 工程师站本地工程文件、定值单、录波（COMTRADE）、点表 Excel 与脚本 |
| T0802 | Automated Collection | 脚本化周期轮询（多站批量点表采集），把单站情报扩展为全网画像 |
| T0868 | Detect Operating Mode | 识别装置处于就地/远方/维护/试验态——决定“能不能写、写了会不会立刻被人工发现” |

---

## 9. Command and Control — 命令与控制（TA0101）

> 官方收录 **3 项**，下表全列（并在“电力落地”中给出协议承载细节）。

| 技术 ID | 名称 | 电力落地示例 |
|---|---|---|
| T0885 | Commonly Used Port | 复用 502/102/20000/2404/4840 等 OT 常用端口承载控制通道，穿透“只放行工控端口”的防火墙策略 |
| T0869 | Standard Application Layer Protocol | 以 **Modbus 轮询、DNP3 非请求上报、MMS InformationReport、OPC UA 订阅**为 C2 承载，流量与正常业务同构 |
| T0884 | Connection Proxy | 经远动网关/前置机/正向隔离装置代理，把控制通道折叠进合法主站通道 |

---

## 10. Inhibit Response Function — 抑制响应功能（TA0107）

> 官方收录 13 项；下表 8 项。**本战术是电力行业造成实质物理后果的核心（打击保护、安全与告警）。**

| 技术 ID | 名称 | 电力落地示例 |
|---|---|---|
| T0878 | Alarm Suppression | 屏蔽保护动作与告警上送：关 DNP3 非请求上报（`DISABLE_UNSOLICITED`）、改 IEC 61850 报告控制块（`RptEna=0`）、压掉告警点 |
| T0838 | Modify Alarm Settings | 改告警死区/越限定值/延时，使真实异常不再越限或延迟告警 |
| T0814 | Denial of Service | GOOSE/SV 泛洪（参考数据集 DoS.1：5000 帧级注入）；Modbus 高频请求；DNP3 风暴；合并单元链路拥塞导致跳闸报文丢失 |
| T0816 | Device Restart/Shutdown | DNP3 `0x0D/0x0E` 重启、`0x12` STOP_APPL；S7 `0x29` PLC Stop；装置反复重启使保护退出 |
| T1691 | Block Operational Technology Message | .001 阻断命令报文（跳闸命令到不了开关）；.002 阻断报告报文（调度看不到真实工况） |
| T1695 | Block Communications | .001 串行 COM（RS-485 总线被短接/占用）；.002 以太网（链路/VLAN/端口）；.003 WiFi（辅控与无线回传） |
| T0835 | Manipulate I/O Image | 改 I/O 映像或启用强制/置位功能，使保护与控制逻辑“看不到”真实一次量 |
| T0800 | Activate Firmware Update Mode | 保护/测控装置进入固件升级模式后退出服务（该模式常停止保护功能），且不留常规告警 |

---

## 11. Impair Process Control — 破坏过程控制（TA0106）

> 官方收录 **4 项（含子技术）**；下表全列。

| 技术 ID | 名称 | 电力落地示例 |
|---|---|---|
| T0836 | Modify Parameter | 改保护定值（过流/距离/差动定值与延时）、重合闸次数、AGC/AVC 参数、逆变器功率设定点与变化率 |
| T1692 | Unauthorized Message | .001 命令报文：伪造 GOOSE 跳闸/闭锁、伪造 DNP3 CROB（控制码 `0x41`/`0x81`）、伪造 MMS `Oper`；.002 报告报文：伪造采样值（SV）与遥测，含只改幅值而不同步改 `q`/`t` 的隐蔽改法 |
| T0806 | Brute Force I/O | 对同一或一段 I/O 点高频反复写（如逆变器有功设定点往复跳变），制造振荡与设备应力 |
| T1693 | Modify Firmware | .001/.002：篡改装置固件以植入错误算法或隐蔽后门（低于组态层的控制权夺取） |

---

## 12. Impact — 影响（TA0105）

> 官方收录 12 项；下表 8 项。

| 技术 ID | 名称 | 电力落地示例 |
|---|---|---|
| T0831 | Manipulation of Control | 直接遥控分合闸/调节出力导致误动、非计划停运；DNP3 一个 11 字节 CROB 即对应一次开关动作 |
| T0832 | Manipulation of View | 篡改上送遥测/状态（MMS Report、DNP3 响应、Modbus 寄存器），使调度端看到与实际不符的工况 |
| T0837 | Loss of Protection | 保护拒动或误动（GOOSE 报文被抑制/伪造、定值被改、保护功能被置于退出态） |
| T0880 | Loss of Safety | SIS/安全联锁功能被破坏（电厂 SIS、燃气/化水安全联锁、储能消防联锁） |
| T0879 | Damage to Property | 变压器/开关/GIS/机组辅机损坏（长期过载、失保护运行、非同期合闸） |
| T0826 | Loss of Availability | 停电、出力受阻、场站脱网、配网大面积不可控 |
| T0828 | Loss of Productivity and Revenue | 发电量损失、供电可靠性指标（SAIDI/SAIFI）恶化、考核罚款 |
| T0882 | Theft of Operational Information | 外带运行数据、点表、SCD/工程文件、录波与定值单（可用于后续攻击或商业情报） |

---

## 13. 电力业务影响分级（映射收敛表）

| 目标系统 | 主要承载协议 | 高相关战术 | 影响上限 |
|---|---|---|---|
| 保护装置 / 合并单元 / 智能终端（变电） | GOOSE `0x88B8`、SV `0x88BA`、MMS 102/tcp | Impair Process Control、Inhibit Response Function、Impact | **Loss of Protection（T0837）→ 设备损坏、人身风险** |
| 安全仪表系统 SIS / 安全联锁（发电） | 厂商专有、Modbus、PROFIBUS/PROFINET | Inhibit Response Function、Impact | **Loss of Safety（T0880）** |
| 变电站自动化后台 / 远动网关 | MMS、IEC 60870-5-104、DNP3、ICCP | Discovery、Collection、Lateral Movement、C2 | 全站监视与控制权失守 |
| 调度主站 / EMS / 前置机 | ICCP/TASE.2、IEC 104、DNP3 | Initial Access、Lateral Movement、Impact | 多站联动、区域级影响 |
| DCS / 厂级监控（发电） | 厂商专有、OPC（DA/UA）、Modbus | Execution、Impair Process Control | 机组停运、设备损坏 |
| 配网自动化主站 / DTU/FTU/TTU | DNP3、IEC 104、Modbus | Execution、Impact | 配电线路可控性丧失 |
| 电能量计量 / 采集终端 | Modbus、DL/T645、IEC 61850 `MMTR` | Collection、Impact（Manipulation of View） | 结算数据失真、经济影响 |
| 新能源场站控制 / AGC/AVC | Modbus、IEC 104、OPC UA | Impair Process Control、Impact | 出力受限/脱网、考核损失 |
| 辅控（输煤/除灰/化水/暖通） | Modbus、S7comm | Initial Access、Persistence、Lateral Movement | 常作为**进入站内网络的跳板** |

---

## 14. 战术覆盖清单（对账用）

| # | 战术 | 战术 ID | 官方技术数 | 本文件收录 |
|---|---|---|---|---|
| 1 | Initial Access 初始访问 | TA0108 | 12 | 8 |
| 2 | Execution 执行 | TA0104 | 10 | 6 |
| 3 | Persistence 持久化 | TA0110 | 5 | 5 |
| 4 | Privilege Escalation 提权 | TA0111 | 2 | 2 |
| 5 | Evasion 规避 | TA0103 | 7 | 6 |
| 6 | Discovery 发现 | TA0102 | 5 | 5 |
| 7 | Lateral Movement 横向移动 | TA0109 | 6 | 6 |
| 8 | Collection 收集 | TA0100 | 11 | 8 |
| 9 | Command and Control 命令与控制 | TA0101 | 3 | 3 |
| 10 | Inhibit Response Function 抑制响应功能 | TA0107 | 13 | 8 |
| 11 | Impair Process Control 破坏过程控制 | TA0106 | 4 | 4 |
| 12 | Impact 影响 | TA0105 | 12 | 8 |
| — | **合计** | — | **90**（含跨战术重复） | **69** |

> 说明：官方“技术数”按矩阵列示条目统计（同一技术出现在多个战术下会重复计数）。
> 本文件按电力场景相关性筛选，**未收录项并非无关**（如 T0895 Autorun Image、T0862 Supply Chain Compromise、
> T0820 Exploitation for Evasion 等），需要时应回官方矩阵补齐。

---

## 15. 关联

- 协议细节：`../protocols/modbus.md`、`../protocols/s7comm.md`、`../protocols/iec61850.md`、`../protocols/dnp3.md`
- 业务资产：`../business-scenarios/power-grid.md`
- 技能：`f2x-power-modbus-attack`、`f2x-power-s7comm-attack`、`f2x-power-iec61850-analysis`、
  `f2x-power-scada-recon`、`f2x-power-traceback`；通用 `f2x-asset-mapping`、`f2x-vuln-discovery`、
  `f2x-exploitation`、`f2x-internal-pentest`
- 数据集：`$REDTEAM_REFS/IEC61850SecurityDataset/`（GOOSE 攻击 trace 可映射到 T1692/T0814/T0831）
- 靶场：`$REDTEAM_REFS/GRFICSv3/`（docker-compose：plc / hmi / ews / simulation / router /
  caldera / wazuh，网段 `192.168.95.0/24`(OT) 与 `192.168.90.0/24`(IT)，可用于技法验证）
