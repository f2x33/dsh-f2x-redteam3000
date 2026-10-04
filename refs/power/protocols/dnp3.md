# DNP3（IEEE 1815）— 协议参考

> 定位：**参考手册**（客观描述协议结构与已知安全属性），不是利用教程。
> 适用范围：电力系统远动与配网自动化——调度主站 ↔ 变电站 RTU/测控装置、配网自动化主站 ↔ DTU/FTU/TTU、
> 部分新能源场站与微网控制器，也用于水利/油气。
> 素材来源（只读参考仓库，仅做摘编与索引，未整文件复制）：
> `$REDTEAM_REFS/awesome-industrial-protocols/protocols/dnp3.md`（端口 `20000/tcp, 20000/udp`、安全特性 “Optional authentication, optional encryption with TLS”、nmap `dnp3-info.nse`、Wireshark `packet-dnp.c`）
> `$REDTEAM_REFS/awesome-industrial-protocols/db/protocols.json`（`{"name":"DNP3","port":"20000/tcp, 20000/udp","keywords":["Power grid","Water"]}`）
> 规范依据 IEEE 1815-2012（含 Secure Authentication）与 IEC 62351-5；
> 本文件 CRC 值全部由脚本按 DNP3 CRC（多项式 0x3D65 反射 / 0xA6BC，初值 0x0000，末异或 0xFFFF，
> 校验串 "123456789" → 0xEA82 已验证）实测复算，帧长度字段已逐字节核对。

---

## 1. 概览

| 项 | 值 |
|---|---|
| 名称 | DNP3（Distributed Network Protocol，IEEE 1815） |
| 默认端口 | **20000/tcp**、**20000/udp**；串行为 RS-232/RS-485；部分实现支持 DNP3 over TLS（工程上多用 19999/tcp） |
| 分层 | 应用层 / 传输功能 / 链路层 / 物理层（EPA 三层模型，无会话层/表示层） |
| 通信模型 | Master（主站）↔ Outstation（从站/RTU）；支持**非请求上报**（Unsolicited Response） |
| 规范访问 | 付费（IEEE 1815-2012） |
| 认证 | **可选**：Secure Authentication（DNP3-SA，IEEE 1815-2012 / IEC 62351-5）；**未启用即完全无认证** |
| 加密 | 协议本身不加密；可选 DNP3 over TLS |
| 电力相关性 | **高**：北美与部分亚洲电力远动/配网自动化的主力协议 |

---

## 2. 链路层

### 2.1 帧布局

```
+---------------- 帧头块（10 字节，含 CRC） ----------------+
| 0x05 0x64 | Length | Control | Dest(2, LE) | Src(2, LE) | CRC(2, LE) |
+----------------------------------------------------------+
| 用户数据块 1：≤16 字节数据 + CRC(2)                        |
| 用户数据块 2：≤16 字节数据 + CRC(2)                        |
| ...（最后一块可短于 16 字节）                              |
+----------------------------------------------------------+
```

| 字段 | 长度 | 说明 |
|---|---|---|
| Start | 2 | 固定 `0x05 0x64` |
| **Length** | 1 | 帧内**除起始字节与所有 CRC 之外**的字节数；即 Control(1)+Dest(2)+Src(2)+用户数据；取值 5–255 |
| Control | 1 | 见 §2.2 |
| Destination | 2 | 目的链路地址，**小端** |
| Source | 2 | 源链路地址，**小端** |
| CRC | 2 | 对前 8 字节（`05 64`…`Src`）计算，**低字节先发** |
| 每数据块 CRC | 2 | 对**该块数据**计算（最多 16 字节），低字节先发 |

- CRC-16/DNP：多项式 0x3D65（反射后 0xA6BC），初值 0x0000，末异或 0xFFFF，反射输入/输出。
- 地址：`0x0000`–`0xFFEF` 为常规地址；`0xFFF0` 及以上为保留/特殊（**`0xFFFF` = 广播**，
  另有自地址等特殊值）。链路地址与 IP 无固定映射，需枚举。
- 广播帧（Dest=0xFFFF）从站应执行但**不应答**，是链路层“一发多响”的放大面。

### 2.2 Control 字节

| 位 | 字段 | 说明 |
|---|---|---|
| bit7 | DIR | 1 = 来自 Master，0 = 来自 Outstation |
| bit6 | PRM | 1 = 报文含链路功能码（Primary），0 = 响应（Secondary） |
| bit5 | FCB | 帧计数位（仅 confirmed 用户数据使用） |
| bit4 | FCV/DFC | PRM=1 时为 FCV（帧计数有效），PRM=0 时为 DFC（数据流控） |
| bit3-0 | Function Code | 见下表 |

| PRM | FC | 名称 | 说明 |
|---|---|---|---|
| 1（主） | 0 | RESET_LINK_STATES | 复位链路状态 |
| 1 | 1 | RESET_USER_PROCESS | 复位用户进程 |
| 1 | 2 | TEST_LINK_STATES | 链路测试 |
| 1 | 3 | CONFIRMED_USER_DATA | 需确认的用户数据（可靠传输） |
| 1 | 4 | UNCONFIRMED_USER_DATA | 不确认的用户数据 |
| 1 | 9 | REQUEST_LINK_STATUS | 请求链路状态 |
| 0（从） | 0 | ACK | 确认 |
| 0 | 1 | NACK | 否认 |
| 0 | 11 | LINK_STATUS | 链路状态 |
| 0 | 15 | NOT_SUPPORTED | 功能不支持 |

PRM=1、FC=3（confirmed）时，Control = `0xC0 | 0x03 = 0xC3`；PRM=1、FC=4（unconfirmed）时 = `0xC4`；
PRM=0、FC=0（ACK）时 = `0x00`。

---

## 3. 传输功能（Transport Function）

TCP 之上，链路层用户数据以 **1 字节传输头**分片/重组：

| 位 | 字段 | 说明 |
|---|---|---|
| bit7 | FIN | 1 = 应用层报文的最后一段 |
| bit6-0 | SEQ | 段序号 0–63，循环递增 |

应用层报文（Fragment）被切成多段，每段前加 1 字节传输头（每段仍受链路层 16 字节数据块限制）。
`FIN=1, SEQ=0` → 传输头 = `0xC0`。

---

## 4. 应用层

### 4.1 请求/响应头

```
请求:  Application Control (1) | Function Code (1) | 对象头…
响应:  Application Control (1) | Function Code (1) | IIN (2) | 对象头…
```

Application Control 字节：

| 位 | 字段 | 说明 |
|---|---|---|
| bit7 | FIR | 报文分片的第一片 |
| bit6 | FIN | 报文分片的最后一片 |
| bit5 | CON | 请求是否需要应用层确认 |
| bit4 | UNS | 是否为非请求响应 |
| bit3-0 | SEQ | 应用层序号 0–15，请求与响应配对 |

单分片请求通常 FIR=FIN=1、CON=0、SEQ=0 → Application Control = `0xC0`。

### 4.2 应用层功能码

| 码 | 名称 | 类别 | 说明 |
|---|---|---|---|
| `0x00` | CONFIRM | 确认 | 对 CON=1 请求的确认 |
| `0x01` | READ | 采集 | 按类/按对象读（轮询） |
| `0x02` | WRITE | 写入 | 写对象（含时间、死区等） |
| `0x03` | SELECT | 控制 | 选择（SBO 前半） |
| `0x04` | OPERATE | 控制 | 执行（SBO 后半） |
| `0x05` | DIRECT_OPERATE | 控制 | 直接执行（无选择） |
| `0x06` | DIRECT_OPERATE_NR | 控制 | 直接执行且不需响应 |
| `0x07`–`0x0C` | IMMED_FREEZE / FREEZE_CLEAR / FREEZE_AT_TIME（各含 _NR） | 计量 | 冻结计数器 |
| `0x0D` | COLD_RESTART | 设备管理 | 冷启动 |
| `0x0E` | WARM_RESTART | 设备管理 | 温启动 |
| `0x0F` | INITIALIZE_DATA | 设备管理 | 初始化数据（部分场合清空配置） |
| `0x10` | INITIALIZE_APPL | 设备管理 | 初始化应用层 |
| `0x11` | START_APPL | 设备管理 | 启动应用 |
| `0x12` | STOP_APPL | 设备管理 | **停止应用**（可用性打击） |
| `0x13` | SAVE_CONFIG | 设备管理 | 保存配置 |
| `0x14` | ENABLE_UNSOLICITED | 上报控制 | 使能非请求上报 |
| `0x15` | DISABLE_UNSOLICITED | 上报控制 | 禁止非请求上报 |
| `0x16` | ASSIGN_CLASS | 上报控制 | 分配事件类 |
| `0x17` | DELAY_MEASURE | 时延测量 | — |
| `0x18` | RECORD_CURRENT_TIME | 时间 | 记录当前时间 |
| `0x19`–`0x1E` | OPEN_FILE / CLOSE_FILE / DELETE_FILE / GET_FILE_INFO / AUTHENTICATE_FILE / ABORT_FILE | 文件 | 文件传输与枚举（外带通道） |
| `0x1F` | ACTIVATE_CONFIG | 配置 | 激活配置 |
| `0x20` | AUTHENTICATE_REQ | **DNP3-SA** | 认证请求（需响应） |
| `0x21` | AUTHENTICATE_REQ_NR | **DNP3-SA** | 认证请求（不需响应，aggressive mode） |
| `0x81` | RESPONSE | 响应 | 常规响应 |
| `0x82` | UNSOLICITED_RESPONSE | 响应 | 非请求上报 |
| `0x83` | AUTHENTICATE_RESP | **DNP3-SA** | 认证响应 |

### 4.3 对象头与限定词（Qualifier）

```
对象头 = Group(1) | Variation(1) | Qualifier(1) | Range(0/1/2/4 字节)
```

| Qualifier | 含义 | Range 长度 |
|---|---|---|
| `0x00` | 8 位起止 | 2 |
| `0x01` | 16 位起止 | 4 |
| `0x02` | 32 位起止 | 8 |
| `0x03` | 8 位绝对地址（单个） | 1 |
| `0x04` | 16 位绝对地址 | 2 |
| `0x05` | 32 位绝对地址 | 4 |
| `0x06` | **无范围（全部对象）** | 0 |
| `0x07` | 8 位计数 | 1 |
| `0x08` | 16 位计数 | 2 |
| `0x09` | 32 位计数 | 4 |
| `0x17` | 8 位计数 + 8 位索引 | 2（命令类常用） |
| `0x28` | 16 位计数 + 16 位索引 | 4 |

> `0x06` 是**一次读全表**的关键：`3C 01 06` 即“读全部 Class 0 数据”，
> 对 **DNP3 全点表枚举**极为高效（对应 T0861 / T0877）。

### 4.4 常用对象组（Group）

| Group | 内容 | 常用 Variation |
|---|---|---|
| 1 | 二进制输入 Binary Input | 1（带标志）、2（带绝对时标） |
| 2 | 二进制输入事件 | 1/2/3 |
| 3 / 4 | 双位输入 / 双位输入事件 | — |
| 10 | 二进制输出状态 | 1、2 |
| 11 | 二进制输出事件 | — |
| **12** | **二进制命令（CROB，控制继电器输出块）** | **1** |
| 13 | 二进制命令事件 | — |
| 20 | 计数器 Counter | 1（16 位）、2（32 位带标志）、5/6、8 |
| 21 / 22 / 23 | 冻结计数器 / 计数器事件 / 冻结计数器事件 | — |
| 30 | 模拟输入 Analog Input | 1（16 位）、2（32 位）、5（float32）、6（float64） |
| 31 / 32 / 33 | 冻结模拟量 / 模拟量事件 / 冻结模拟量事件 | — |
| 34 | 模拟量死区 Deadband | 1/2/3 |
| 40 | 模拟输出状态 | 1/2/3/4 |
| **41** | **模拟输出块（Analog Output Block）** | 1（16 位）、2（32 位）、3（float32）、4（float64） |
| 42 / 43 | 模拟输出事件 / 模拟输出命令事件 | — |
| 50 | 时间与日期（含 CTO/LTO 时标对象） | 1–4 |
| 51 / 52 | 时间 CTO / 时延 | — |
| 60 | **类对象 Class 0/1/2/3** | 1/2/3/4 |
| 70 | 文件控制 | — |
| **80** | **内部指示 Internal Indications（IIN）** | 1 |
| 110 / 111 | 八位组字符串 / 事件 | — |
| **120** | **认证对象（DNP3-SA）** | 1–13（见 §6） |

点表模型：每个点在从站内有**唯一点号（index）**，分属 Class 0（静态值）/ Class 1/2/3（事件类）。
主站轮询 Class 0 得全量静态值，轮询 Class 1/2/3 或接收非请求上报得变化事件。

### 4.5 内部指示 IIN（2 字节位域）

| 字节 | 位 | 名称 | 含义 |
|---|---|---|---|
| IIN1 | 0 | ALL_STATIONS | 广播报文 |
| IIN1 | 1 | CLASS_1_EVENTS | 有 Class 1 事件待读 |
| IIN1 | 2 | CLASS_2_EVENTS | 有 Class 2 事件待读 |
| IIN1 | 3 | CLASS_3_EVENTS | 有 Class 3 事件待读 |
| IIN1 | 4 | NEED_TIME | 需要时间同步 |
| IIN1 | 5 | LOCAL_CONTROL | 就地控制已封锁 |
| IIN1 | 6 | DEVICE_TROUBLE | 设备故障 |
| IIN1 | 7 | DEVICE_RESTART | 设备已重启 |
| IIN2 | 0 | FUNC_NOT_SUPPORTED | 功能码不支持 |
| IIN2 | 1 | OBJECT_UNKNOWN | 对象未知 |
| IIN2 | 2 | PARAM_ERROR | 参数错误 |
| IIN2 | 3 | EVENT_BUFFER_OVERFLOW | **事件缓冲溢出（丢事件）** |
| IIN2 | 4 | ALREADY_EXECUTING | 正在执行 |
| IIN2 | 5 | CONFIG_CORRUPT | 配置损坏 |

`EVENT_BUFFER_OVERFLOW` 是攻击后遗留的强指纹：泛洪/风暴导致从站事件缓冲区溢出。

---

## 5. 报文示例（CRC 实测复算，长度字段已核对）

### 5.1 主站轮询：READ Class 0（读取全部静态点）

```
05 64 0B C4 01 00 02 00 69 9E   C0 C0 01 3C 01 06 FF 50
└─┬─┘ │  │  └─┬─┘ └─┬─┘ └─┬─┘  │  │  │  └───┬────┘ └─┬─┘
 起始 │  │  Dest=1 Src=2 CRC    │  │  │   G60 V1 Q=06  CRC
      │  │  （小端）              │  │  └ READ
      │  └ Control=C4              │  └ AppControl=C0(FIR/FIN=1)
      │    (DIR=1,PRM=1,FC=4)       └ Transport=C0(FIN=1,SEQ=0)
      └ Length=0x0B=11 = 1+2+2+6
```

- 链路帧总长 = 10（帧头块）+ 8（6 字节数据 + 2 字节 CRC）= 18 字节。
- 语义：主站以**不确认**方式请求从站返回全部 Class 0 静态数据（全点表）。

### 5.2 主站控制：DIRECT_OPERATE 二进制命令 CROB（遥控出口）

```
05 64 18 C3 01 00 02 00 EA 9C
C0 C0 05 0C 01 17 01 00 41 01 64 00 00 00 64 00 C5 BA
00 00 00 FF FF
```

| 字节 | 值 | 含义 |
|---|---|---|
| `C0` | 传输头 | FIN=1, SEQ=0 |
| `C0` | App Control | FIR=1, FIN=1, CON=0, SEQ=0 |
| `05` | 功能码 | DIRECT_OPERATE（直接执行，无先选择） |
| `0C` | Group | 12（二进制命令） |
| `01` | Variation | 1（CROB） |
| `17` | Qualifier | 8 位计数 + 8 位索引 |
| `01 00` | Range | 计数 = 1，索引 = 0（第 0 号点） |
| `41` | **CROB 控制码** | 见 §5.3 |
| `01` | Count | 执行次数 = 1 |
| `64 00 00 00` | On-time | 100 ms |
| `64 00 00 00` | Off-time | 100 ms |
| `00` | Status | 请求中恒 0 |

- 链路 Length = 0x18 = 24 = 1+2+2+19（用户数据 19 字节 = 传输头 1 + 应用分片 18）。
- 数据块：前 16 字节 + CRC（`C5 BA`），余 3 字节 + CRC（`FF FF`）。

### 5.3 CROB（Group 12 Variation 1）结构与控制码

CROB 共 **11 字节**：Control Code(1) + Count(1) + On-time(4) + Off-time(4) + Status(1)。

控制码位域（工程通用约定，精确位定义以 IEEE 1815 表为准）：

| 位 | 含义 |
|---|---|
| bit0-3 | 操作类型：`0x1` PULSE_ON、`0x2` PULSE_OFF、`0x3` LATCH_ON、`0x4` LATCH_OFF（`0x0` NUL） |
| bit4 | QUEUE（排队） |
| bit5 | CLEAR（清除排队） |
| bit6 | **TC：1 = Trip（跳闸），0 = Close（合闸）** |

常用取值：**`0x41` = PULSE_ON + Trip（跳闸）**、**`0x81` = PULSE_ON + Close（合闸）**。
在电力远动语境中，一个 11 字节的结构体即对应一次开关分/合——这是 DNP3 面**业务影响最直接**的字段。

---

## 6. DNP3 安全认证（DNP3-SA）与未启用时的风险

### 6.1 机制（IEEE 1815-2012 Clause 7 / IEC 62351-5）

| 组成 | 内容 |
|---|---|
| 认证对象 | Group 120：1 Challenge（挑战）、2 Reply（应答）、3 Aggressive Mode Request、4 Session Key Status Request、5 Session Key Status、6 Session Key Change、7 Error、8 User Status Change、9 Update Key Change Request、10 Update Key Change Reply、11 Update Key Change、12 Update Key Change Signature、13 Update Key Change Confirmation |
| 认证功能码 | `0x20` AUTHENTICATE_REQ、`0x21` AUTHENTICATE_REQ_NR、`0x83` AUTHENTICATE_RESP |
| 密钥层次 | 预共享 **Update Key**（每从站唯一）→ 派生 **Session Key**（经密钥变更流程，AES 密钥封装 RFC 3394 分发） |
| 完整性算法 | HMAC（截断 MAC，长度由挑战报文协商），SAv2/SAv5 之间算法套件不同 |
| 模式 | **挑战/响应**（默认，延迟不敏感）与 **Aggressive Mode**（报文内直接带 MAC，用于对时延敏感的遥控） |
| 关键性范围 | 挑战报文中定义哪些功能码为 “Critical”（强制认证），工程上通常包含 CROB / DIRECT_OPERATE / 配置与文件类 |
| 防重放 | 挑战含随机数与序号；CSQ（Challenge Sequence Number）单调；接收方维护窗口 |

### 6.2 未启用（或未覆盖全部关键功能码）时的风险

| 风险 | 说明 |
|---|---|
| 无认证 | 任何能连 20000 端口的主机即可 READ/WRITE/OPERATE |
| 无加密/无完整性 | 明文可嗅探、可篡改、可重放（SELECT/OPERATE 可被重放或篡改） |
| 主站伪造 | 直接以主站身份连接从站（或反向劫持链路） |
| 广播利用 | Dest=0xFFFF 广播写，一次影响全部从站 |
| 可用性 | `0x0D`/`0x0E` 重启、`0x12` STOP_APPL、`0x15` DISABLE_UNSOLICITED（关掉告警上报） |
| 文件面 | `0x19`–`0x1E` 文件服务：目录枚举与外带 |
| 配置面 | `0x0F` INITIALIZE_DATA / `0x1F` ACTIVATE_CONFIG 可致配置损坏（IIN CONFIG_CORRUPT） |
| 部分部署 | SA 仅覆盖 “Critical” 功能码；若工程未把 CROB 标为关键，则认证形同虚设 |
| 密钥管理 | Update Key 常为出厂默认或全网相同 → 认证被旁路（对应 T1694.002 硬编码凭据） |

---

## 7. 已知安全弱点汇总

| 类别 | 弱点 | 电力后果 |
|---|---|---|
| 认证 | 默认无认证；SA 可选且常未启用/未覆盖遥控 | 未授权遥控分合闸 |
| 授权 | 读（Class 0 全表）与控（CROB）同通道同权限 | 无只读隔离 |
| 完整性 | 无签名；SELECT/OPERATE 可被篡改或重放 | 误动（对应 T0831 / T1692.001） |
| 可用性 | 重启/停止应用、DISABLE_UNSOLICITED | 失去监控与告警（T0815 / T0814） |
| 信息泄露 | 全点表枚举、文件目录、配置读取 | 电网拓扑与运行方式外泄（T0861/T0882） |
| 协议实现 | 畸形链路长度、CRC 与分段不一致、超长对象头 | 栈崩溃/异常（各厂商实现差异大） |
| 时间 | 时间同步无认证（Group 50 写） | 事件时标错乱，影响事后定责 |
| UDP | 20000/udp 承载时无连接状态 | 放大/伪造源地址更容易 |

---

## 8. 检测与指纹要点

| 手段 | 值/要点 |
|---|---|
| 端口 | 20000/tcp、20000/udp；DNP3/TLS 工程上多用 19999/tcp |
| nmap | `dnp3-info.nse`（链路层探测 + 设备信息） |
| Wireshark | `dnp3` 过滤器；解析器 `packet-dnp.c`；抓包样例见 ICS-pcap `DNP3/` |
| 工具（参考仓库索引） | `opendnp3`、`dnp3-simulator`、`gec/dnp3`、FreyrSCADA DNP3、Step Function I/O 的 Rust 实现 |
| 正常态基线 | 主站 IP 单一；链路地址集合固定；轮询周期与 Class 分配固定；CROB 仅出现在遥控操作窗口且伴随 SELECT→OPERATE 成对出现；应用层 SEQ 单调 |
| 高危信号 | 直接 DIRECT_OPERATE（无 SELECT 前置）；CROB 控制码 `0x41`/`0x81` 出现在非操作时段；非授权源发起链路 RESET/`0x0E`/`0x12`；`DISABLE_UNSOLICITED`；`3C 01 06` 式全表读高频重复；对象组 120 出现但**未伴随** MAC 校验通过（SA 被旁路）；IIN `EVENT_BUFFER_OVERFLOW`；Dest=0xFFFF 广播写；源 IP 变化但链路地址相同（伪造主站） |
| 交叉校验 | 将实网 CROB 点号与调度端遥控点表比对；将 `0x0F`/`0x1F` 配置类调用与检修工作票比对 |

---

## 9. 关联

- 技能：`f2x-power-scada-recon`（主站/RTU 侦察）、`f2x-power-traceback`（远动报文回溯）、
  `f2x-asset-mapping`、`f2x-exploitation`（跨协议通用）
- 同目录：`modbus.md`、`s7comm.md`、`iec61850.md`
- 上层：`../ics-attack/mitre-ics-mapping.md`（CROB 遥控 → T1692.001 / T0831；
  重启停应用 → T0816/T0814；全点表读 → T0861/T0877）
- 业务：`../business-scenarios/power-grid.md`（输电/配电环节远动通道与影响分级）
- 相关电力协议（参考仓库索引，本知识库未单列）：
  `iec-60870-5-104.md`（2404/tcp，欧洲/中国远动主力）、`iccp.md`（TASE.2，102/tcp，控制中心间）、
  `ieee-c37118.md`（同步相量）
