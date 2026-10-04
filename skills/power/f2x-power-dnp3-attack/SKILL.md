---
name: f2x-power-dnp3-attack
description: 电力 OT 靶场 DNP3（IEEE 1815）20000 端口安全评估技能——链路层帧构造与 CRC 校验、设备属性与点位表枚举、Class 0/1/2/3 轮询读取、控制输出（CROB/AO/DO）写操作门禁、可选 Secure Authentication 判定，含 Scapy/pymodbus 实操与隔离靶场纪律。
whenToUse: 目标开放 20000/tcp 或 20000/udp，或已知网内存在 DNP3 主站/从站（调度主站、变电站 RTU、配网 DTU/FTU/TTU、新能源场站控制器），需要判定无认证访问、枚举遥测/遥信点位、评估遥控可写性或核对 Secure Authentication 是否启用时使用。
---

# DNP3 电力 OT 攻击面技能（f2x-power-dnp3-attack）

> **工具可用性与退路（先读这一节）**
> 本技能只依赖本插件自带的 `f2x_orchestrate_*` 工具，**不依赖任何其他插件**。
> 工作流里出现的 `redteam_coverage_mark` / `redteam_finding_register` 是**可选增强**：
> - **成果登记** → `f2x_orchestrate_finding`（本插件自带；`action=update` 到 `verified`
>   强制要求基线/差分/marker 三件套）
> - **覆盖矩阵** → 本插件无此面；用 `f2x_orchestrate_export` 作为覆盖记录，
>   或仅在部署里确实有 `redteam_coverage_mark` 时才回写
> **规则**：目录里没有的工具一律不要调用。开场先跑 `f2x_orchestrate_doctrine` 自检。

> **定位**：本技能只覆盖 **DNP3（IEEE 1815）** 单一协议面。Modbus 见 `f2x-power-modbus-attack`；S7 见 `f2x-power-s7comm-attack`；IEC 61850（站内 MMS/GOOSE/SV）见 `f2x-power-iec61850-analysis`；上位机与网络面见 `f2x-power-scada-recon`；流量回溯与防守视角见 `f2x-power-traceback`。
>
> **协议事实（来源：本包 `refs/power/protocols/dnp3.md`，其素材来自 `$REDTEAM_REFS/awesome-industrial-protocols/`，由配置项 `referenceRoot` 或环境变量 `$REDTEAM_REFS` 解析）**：
> 默认端口 **20000/tcp、20000/udp**（串行为 RS-232/RS-485）；DNP3 over TLS 工程上多用 **19999/tcp**；
> 分层为 应用层 / 传输功能 / 链路层 / 物理层（EPA 三层模型，无会话层与表示层）；
> 模型为 Master（主站）↔ Outstation（从站/RTU），支持**非请求上报**（Unsolicited Response）；
> 链路帧头 10 字节（`0x05 0x64` + Length + Control + Dest(2,LE) + Src(2,LE) + CRC(2,LE)），用户数据分块 ≤16 字节、每块后跟 2 字节 CRC
> （多项式 0x3D65 反射 / 0xA6BC、初值 0x0000、末异或 0xFFFF）；
> 认证**可选**：Secure Authentication（DNP3-SA，IEEE 1815-2012 / IEC 62351-5）——**未启用即完全无认证**；
> 协议本身不加密。工具面：nmap `dnp3-info.nse`、Wireshark `packet-dnp.c`、Scapy 的 DNP3 层。
> 规范为付费标准（IEEE 1815-2012），**不要**承诺"照规范逐条实现"。
>
> **设计前提**：DNP3 与 Modbus 同类——**认证与加密都是可选项**。因此"未授权访问"在本协议面通常也是
> **设计事实**而非配置缺陷；评分价值在于**实际读到的远动/配网生产过程数据**（遥测、遥信、电能计量）
> 与**控制输出可写性对过程的影响**，不在"发现 20000 开放"。

---

## 操作步骤

### 0. 授权与前置门禁（未完成不得进入第 1 步）

1. 用允许清单确认目标在授权范围内：`f2x_orchestrate_scope`（空清单 = **拒绝一切**）。
2. 记住这条铁律：**读优先、写受限**。DNP3 的"读"（Class 0/1/2/3 轮询、积分/事件扫描）在授权范围内可做；
   一切**控制输出**（CROB / Analog Output / Direct Operate / 二进制输出）都可能**真实动作现场设备**。
3. 生产环境默认**只做只读**判定；写操作验证只在**过程为纯仿真的隔离靶场**进行，
   且必须先过 `f2x_orchestrate_audit`（OT 写门禁，需二次确认）。

### 1. 协议识别与链路层握手（只读）

```bash
# 端口与协议指纹（NSE 只做识别，不发控制类报文）
nmap -Pn -sU -sT -p 20000 --script dnp3-info <target>

# 抓包确认链路帧头（0x05 0x64）与源/目的 DNP3 地址
tcpdump -i <iface> -nn 'tcp port 20000 or udp port 20000' -c 20
```

要点：
- **DNP3 地址**（Dest/Src，各 2 字节小端）是后续一切请求的寻址基础——先记下目标地址。
- 若 20000 无响应，试 **19999/tcp**（DNP3 over TLS）与 `dhcp/udp` 之外的端口变体；
  TLS 变体需按 TLS 处理（证书、SNI），不要当明文协议硬打。
- **UDP 与 TCP 都要试**：不少实现在 UDP 上开放而不要求链路层确认。

### 2. 无认证访问判定（只读，本技能的核心得分点）

按顺序取三类证据，**每类都要留原始请求/响应**（`f2x_orchestrate_checkpoint` 记 `confirmed`）：

1. **链路层状态**：发链路状态请求（Link Status / Reset Link），若得到 ACK 且无需任何凭据 → 无链路层认证。
2. **设备属性**（Device Attributes，g0v254 系列对象）：取厂商、型号、固件版本、序列号、配置 ID。
   这一步等价于"拿到设备指纹"，也是后续对 Nday 适配的唯一可靠依据。
3. **点位表枚举**：Class 0 积分轮询（Integrity Poll）一次拉回该从站的全部静态点位
   （遥测 AI/AO、遥信 BI/BO、计数器、电能计量）；再用 Class 1/2/3 事件轮询拉变化。
   能读回**工程量**（电压、电流、功率、开关位置）即证明"无认证 + 真实生产过程数据"。

举证纪律：
- 报告里写 **对象组/变体（group/variation）+ 索引区间 + 读回的解释值**，不要只写"能读"。
- 数据量按点位与时间跨度计（如"Class 0 一次读回 1,842 个点，覆盖 110kV 侧线路遥测"）。
- 敏感数据部分遵循最小化：**不回传、不外传**，只留必要的字段样本作证据。

### 3. Secure Authentication 判定（只读）

DNP3-SA 是**可选项**，必须实测而不是假设：

- 观察是否有 **Challenge/Reply** 交互（SAv2/v5 的挑战-应答）；若从站对 Operate 直接回
  `Success` 而不要求挑战，则 SA **未启用**。
- SA 已启用时，把结论记为"该面受保护"，**不要**尝试绕过或做重放/降级（超出本技能授权口径）。
- 结论写清：`未启用` / `已启用` / `无法判定（证据不足）`，三者不同。

### 4. 控制输出（写）—— **门禁最严的一步**

> 只有在**隔离靶场**且过程为纯仿真时才允许。生产环境一律**不写**：写 CROB/AO 可能真实分合闸、
> 改变出力或越限，属于不可回退的物理影响。

```bash
# 第一步永远是门禁：把动作、目标设备地址、期望影响写清楚，取得二次确认
#   f2x_orchestrate_audit(action=..., target=..., command=..., confirmedBy=...)
```

过门禁后，最小化验证原则：
- 只选**单个可控点位**、**单次**、**可回退**的目标（如仿真环境里的一个指示性输出），
  不做批量、不做保持时间长的设置。
- 用 **Select-Before-Operate（SBO）** 语义：先 Select，确认应允，再 Operate；
  或明确使用 Direct Operate 并在证据里写明用的是哪一种。
- 立即记录：操作前后的点位值对照（基线 → 差分 → 回显），作为三件套证据；
  结束后**恢复原值**并记录恢复动作。

### 5. 证据与成果登记

```text
f2x_orchestrate_checkpoint(level=confirmed, summary=..., evidence=原始请求/响应路径)
f2x_orchestrate_finding(action=add, ...)     # 加成果
f2x_orchestrate_finding(action=update, ...)  # 转 verified（需基线/差分/marker 三件套）
f2x_orchestrate_export()                     # 交接文档
```

**不要**把"20000 端口开放"当成成果：那是资产信息，不是漏洞。成果必须是
"无认证读到 X 个点位 / 读到真实工程量 / 控制输出可写且已证明影响"这三类之一。

---

## 退路（工具缺失时）

| 场景 | 退路 |
|---|---|
| 无 Scapy / pymodbus | 先用 nmap `dnp3-info.nse` 与 Wireshark 抓包判定；必要时手写最小链路帧（10 字节帧头 + CRC，算法见本包 `refs/power/protocols/dnp3.md`） |
| 无 nmap / tcpdump | 用本插件自带的隧道 + 任何可用客户端做端口连通性判定，并在报告里注明"协议级证据缺失" |
| 从站在 DMZ、仅单跳可达 | 先建隧道（`suo5`/`chisel` 技能），再按上表继续；不要为省事在跳板机上落工具 |
| SA 已启用 | 记"受保护"，转下一目标；**不做绕过尝试** |

## 完成判据（缺一不可）

1. 协议与设备身份判定（端口、DNP3 地址、设备属性、固件版本）；
2. 无认证访问的**实测证据**（请求 + 响应原文）；
3. 点位/工程量读回样本（按最小化原则取证）；
4. SA 状态结论（三态之一，有依据）；
5. 若做过写验证：门禁记录 + 三件套 + 恢复记录；
6. 全部落库：checkpoint / finding / export 三处一致。
