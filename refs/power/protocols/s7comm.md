# S7comm / S7comm-plus — 协议参考

> 定位：**参考手册**（客观描述协议结构与已知安全属性），不是利用教程。
> 适用范围：西门子 SIMATIC S7-300/400（S7comm）与 S7-1200/1500（S7comm-plus）系列 PLC、
> 以及以 S7 为主控的电力辅控（输煤/除灰/化水/暖通）、新能源场站控制、部分小型 DCS/SCADA 站控层。
> 素材来源（只读参考仓库，仅做摘编与索引，未整文件复制）：
> `$REDTEAM_REFS/awesome-industrial-protocols/protocols/s7comm.md`（端口 102/tcp、nmap `s7-info.nse`/`s7-enumerate.nse`、Wireshark `packet-s7comm.c`）
> `$REDTEAM_REFS/awesome-industrial-protocols/db/protocols.json`（`{"name":"S7comm","port":"102/tcp"}`）
> `$REDTEAM_REFS/awesome-industrial-control-system-security/source/s7-cracker.py`、`s7-brute-offline.py`（S7 口令校验/离线爆破脚本，仅作工具索引，未引用其代码）
> 帧结构依据 ISO-on-TCP（RFC 1006）/ ISO 8073 COTP、S7 通信协议公开逆向资料（GyM《The Siemens S7 Communication》系列）
> 与 Wireshark `packet-s7comm.c` / `packet-cotp.c`；本文件所有十六进制帧均由本文件逐字段推导（长度字段已自校验）。

---

## 1. 概览

| 项 | 值 |
|---|---|
| 名称 | S7comm（别名 S7、S7 Communication）；新一代为 **S7comm-plus** |
| 默认端口 | **102/tcp** |
| 承载 | TPKT（RFC 1006）→ COTP（ISO 8073，ISO-TSAP）→ S7 PDU |
| 规范访问 | 私有协议，无公开规范；字段语义来自逆向与抓包 |
| 认证/加密 | S7comm：**无**（仅“访问保护等级”在应用层做弱口令门）；S7comm-plus（S7-1200/1500）：引入会话与挑战/响应，部分版本对关键操作加密 |
| 连接数 | 由 CPU 连接资源决定（PG/OP/S7 基本通信资源分别计数） |
| 电力相关性 | 中：电力主厂站远动以 IEC 60870-5-104/DNP3 为主，S7 更多出现在**辅控/厂用电/新能源/小型站控**与工程师站侧 |

---

## 2. 封装栈

```
+----------------+   TCP 102
| TPKT (4 字节)   |   version=0x03, reserved=0x00, length(2, 大端, 含头)
+----------------+
| COTP (3+N 字节) |   ISO 8073 连接/数据传输 TPDU
+----------------+
| S7 PDU          |   协议 ID + ROSCTR + 头 + 参数 + 数据
+----------------+
```

### 2.1 TPKT 头（4 字节）

| 偏移 | 长度 | 字段 | 值 |
|---|---|---|---|
| 0 | 1 | Version | `0x03` |
| 1 | 1 | Reserved | `0x00` |
| 2 | 2 | Length | 整个 TPKT 报文长度（含 4 字节头），大端 |

### 2.2 COTP 头

| 字段 | 长度 | 说明 |
|---|---|---|
| Length Indicator (LI) | 1 | **其后 COTP 头字节数**（不含 LI 自身） |
| PDU Type | 1 | 见下表 |
| （类型相关字段） | 变长 | 见下 |

| PDU Type | 名称 | 结构 |
|---|---|---|
| `0xE0` | CR Connection Request | LI, E0, dst-ref(2), src-ref(2), class/options(1), 参数 |
| `0xD0` | CC Connection Confirm | LI, D0, dst-ref(2), src-ref(2), class/options(1), 参数 |
| `0xF0` | DT Data Transfer | LI, F0, TPDU-NR/EOT(1)，其后为数据 |
| `0x80` | ED Expedited Data | 同上 |
| `0x06` | DR Disconnect Request | LI, 06, dst-ref(2), src-ref(2), reason(1) |
| `0x01` | ER TPDU Error | LI, 01, dst-ref(2), reject-cause(1) |
| `0x07` | DC Disconnect Confirm | 少有 |

COTP 连接参数（CR/CC 中，参数码 + 长度 + 值）：

| 参数码 | 名称 | 说明 |
|---|---|---|
| `0xC0` | tpdu-size | 最大 TPDU 尺寸（常见 `0x0A` = 1024 字节） |
| `0xC1` | src-tsap | 源 TSAP（2 字节） |
| `0xC2` | dst-tsap | 目的 TSAP（2 字节） |

**S7 TSAP 语义**：`0x01 00` = PG（编程器）、`0x01 01` = OP/OS（操作员站/HMI）、`0x01 02` = S7 基本通信
（Step7/上位机组态）。TSAP 低位编码机架/槽位：`TSAP = 0x0100 + (rack << 5) + slot`，
故 rack0/slot2 → `0x0102`。扫描器常遍历 rack/slot 组合定位 CPU。

### 2.3 CR 连接请求示例（解码后自校验，总长 22 = 0x16）

```
03 00 00 16 11 e0 00 00 00 01 00 c1 02 01 00 c2 02 01 02 c0 01 0a
│  │  └─┬─┘ │  │  └─┬─┘ └─┬─┘ │  └────┬────┘ └────┬────┘ └──┬──┘
│  │    │   │  │    │     │   │       │           │         └ tpdu-size=1024
│  │    │   │  │    │     │   │       │           └ dst-tsap=0x0102 (S7 基本通信)
│  │    │   │  │    │     │   │       └ src-tsap=0x0100 (PG)
│  │    │   │  │    │     │   └ class/options
│  │    │   │  │    │     └ src-ref = 1
│  │    │   │  │    └ dst-ref = 0
│  │    │   │  └ PDU type = E0 (CR)
│  │    │   └ LI = 0x11 = 其后 17 字节
│  │    └ TPKT length = 22
│  └ reserved
└ version
```

---

## 3. S7 PDU

### 3.1 头结构

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 1 | Protocol Id | S7comm = `0x32`；S7comm-plus = `0x72` |
| 1 | 1 | ROSCTR | `0x01` Job 请求、`0x02` Ack、`0x03` Ack-Data（带数据响应）、`0x07` Userdata |
| 2 | 2 | Redundancy Identification | 通常 `0x0000` |
| 4 | 2 | Protocol Data Unit Reference | 请求/响应配对 |
| 6 | 2 | Parameter Length | 参数区长度 |
| 8 | 2 | Data Length | 数据区长度 |
| 10 | 1 | Error Class | **仅 Ack / Ack-Data** |
| 11 | 1 | Error Code | **仅 Ack / Ack-Data** |

→ Job 头 = 10 字节；Ack / Ack-Data 头 = 12 字节。其后依次为参数区、数据区（均大端）。

协议数据单元长度（PDU Length）在 Setup Communication 中协商，常见 **240 / 480 / 960** 字节。

### 3.2 作业类型（Job 功能码 = 参数区第 1 字节）

| 码 | 名称 | 说明 | 电力/工控语义 |
|---|---|---|---|
| `0xF0` | Setup Communication | 协商 Max AmQ 与 PDU Length | 任何会话第一步 |
| `0x04` | Read Var | 按 S7ANY 地址读变量 | 读遥测/状态/定值 |
| `0x05` | Write Var | 按 S7ANY 地址写变量 | 写命令/定值/输出 |
| `0x1A` | Request Download | 请求下载块 | 程序/组态下载入口 |
| `0x1B` | Download Block | 下载块数据 | — |
| `0x1C` | Download Ended | 下载结束 | — |
| `0x1D` | Start Upload | 开始上传 | 程序回读 |
| `0x1E` | Upload | 上传块数据 | 程序回读 |
| `0x1F` | End Upload | 上传结束 | — |
| `0x28` | PI Service | 程序调用服务（`_INSE`/`_DELE`/`_MODU`/`_GARB`） | 块插入/删除/模式切换 |
| `0x29` | PLC Stop | 使 CPU 进入 STOP | 直接停机（可用性打击） |

`0x07` Userdata（ROSCTR=`0x07`）承载 CPU 功能：函数组 `0x04`（CPU functions），
子功能 `0x04` = **Read SZL**（System Status List）；另有读/写诊断缓冲、时间设置等子功能。

### 3.3 三种作业的完整帧示例（逐字段推导，长度自校验）

**① Setup Communication（协商 PDU 960，总长 25 = 0x19）**

```
03 00 00 19 02 f0 80 32 01 00 00 00 01 00 08 00 00 f0 00 00 01 00 01 03 c0
└─┬─┘ └─┬─┘ └─┬─┘ └─┬─┘ │  └─┬─┘ └─┬─┘ └────┬────┘ │  └────┬────┘
 TPKT  COTP  Job  Redund PDURef ParamLen DataLen  │   PDU len = 0x03C0 = 960
 25B   3B    10B  0x0000  =1    =8      =0        └ MaxAmQ calling=1, called=1
                                    参数区: f0  00 00  01  00 01  03 c0
                                            │   └─┬─┘ └─┬─┘ └──┬──┘
                                            │  MaxAmQ  MaxAmQ  PDU Length
                                            └ 0xF0 Setup Communication
```

**② Read Var：读 DB1.DBB0 起 1 字节（总长 31 = 0x1F）**

```
03 00 00 1f 02 f0 80 32 01 00 00 00 01 00 0e 00 00
04 01
12 0a 10 02 00 01 00 01 84 00 00 00
```

参数区（14 = 0x0E 字节）解码：

| 字节 | 值 | 含义 |
|---|---|---|
| 1 | `0x04` | Read Var |
| 2 | `0x01` | 项数 = 1 |
| 3 | `0x12` | 变量规范类型（S7ANY） |
| 4 | `0x0A` | 其后地址规范长度 = 10 |
| 5 | `0x10` | 语法 ID = S7ANY |
| 6 | `0x02` | 传送尺寸 = BYTE |
| 7-8 | `0x0001` | 长度 = 1 |
| 9-10 | `0x0001` | DB 号 = 1 |
| 11 | `0x84` | 区域 = 数据块 DB |
| 12-14 | `0x000000` | 地址：`(字节地址 << 3) \| 位号` = 0 |

**③ Read Var 响应（Ack-Data，总长 27 = 0x1B，返回值 0x41）**

```
03 00 00 1b 02 f0 80 32 03 00 00 00 01 00 02 00 06 00 00
04 01
ff 04 00 08 41 00
```

头为 12 字节（含 Error Class `0x00`、Error Code `0x00`）；数据区 6 字节 =
返回码 `0xFF`（成功）+ 传送尺寸 `0x04`（字节串）+ 长度 `0x0008`（**位**）+ 数据 `0x41` + 偶数对齐填充 `0x00`。

**④ Write Var：写 DB1.DBB0 = 0x41（总长 37 = 0x25）**

```
03 00 00 25 02 f0 80 32 01 00 00 00 01 00 0e 00 06
05 01
12 0a 10 02 00 01 00 01 84 00 00 00
00 04 00 08 41 00
```

参数区同 Read Var 的项结构（`0x05` = Write Var）；数据区首字节为保留位 `0x00`（请求中恒 0），
后继结构与读响应相同。数据长度须为偶数（不足补 1 字节）。

### 3.4 S7ANY 地址规范

| 字段 | 值/说明 |
|---|---|
| 语法 ID | `0x10` = S7ANY |
| 传送尺寸 | `0x01` BIT、`0x02` BYTE、`0x03` CHAR、`0x04` WORD、`0x05` INT、`0x06` DWORD、`0x07` DINT、`0x08` REAL、`0x09` DATE、`0x0A` TOD、`0x0B` TIME、`0x0C` S5TIME、`0x0E` DATE_AND_TIME、`0x13` STRING、`0x1C` COUNTER、`0x1D` TIMER、`0x1E` IEC_COUNTER、`0x1F` IEC_TIMER |
| 长度 | 位访问按位、字节访问按字节（按具体栈实现，需与响应交叉核对） |
| 区域 Area | `0x81` 输入 I(PE)、`0x82` 输出 Q(PA)、`0x83` 位存储 M(MK)、`0x84` 数据块 DB、`0x85` 实例数据块 DI、`0x86` 局部数据 L、`0x1C` 计数器 C、`0x1D` 定时器 T、`0x1E` IEC 计数器、`0x1F` IEC 定时器、`0x03`/`0x06`/`0x07` SZL 系统信息、`0x05` 直接外设访问 |
| DB 号 | 区域为 DB/DI 时有效 |
| 地址 | 3 字节：`(字节地址 << 3) \| 位号`；位访问时低 3 位为位号，字节地址 = 值 >> 3 |

### 3.5 返回码

| 层级 | 值 | 含义 |
|---|---|---|
| 数据项返回码 | `0xFF` | 成功 |
| | `0x01` | 硬件故障 |
| | `0x03` | 不允许访问（保护等级/口令限制） |
| | `0x05` | 地址越界（无此地址） |
| | `0x06` | 数据类型不支持 |
| | `0x07` | 数据类型不一致 |
| | `0x0A` | 对象不存在（无此 DB/区域） |
| 头 Error Class | `0x00` | 无错 |
| | `0x81` | 应用关系类错误 |
| | `0x82` | 对象定义类错误 |
| | `0x83` | 无资源 |
| | `0x84` | 服务处理错误（如 CPU 处于 STOP） |
| | `0x85` | 供给错误 |
| | `0x87` | 访问错误 |

> `0x03` 与 `0x05`/`0x0A` 的区分是**判断“是否被保护等级挡住”**的关键：
> 返回 `0x03` 说明地址本身存在但当前权限不足；返回 `0x05`/`0x0A` 说明地址/对象不存在。

---

## 4. SZL 读取（设备指纹的核心面）

SZL（System Status List）经 ROSCTR=`0x07`（Userdata）读取，函数组 `0x04`（CPU functions）、
子功能 `0x04`（Read SZL）。Userdata 数据区头部字段序列（均为大端）：

| 字段 | 长度 | 说明 |
|---|---|---|
| Head | 1 | 固定 `0x00` |
| Length | 2 | 其后 Userdata 长度 |
| Method | 1 | 请求/响应标志（常见 `0x04` 请求、`0x08` 响应；以设备实测为准） |
| Function group | 1 | `0x04` = CPU functions |
| Subfunction | 1 | `0x04` = Read SZL |
| Sequence number | 1 | 请求/响应配对 |
| 数据 | 变长 | 请求：SZL-ID(2) + SZL-Index(2)；响应：SZL 记录列表 |

常用 SZL-ID（**取值随 CPU 系列不同而不同，须以目标实测为准**）：

| SZL-ID | 内容 | 用于 |
|---|---|---|
| `0x0000` | 组件部分列表 | 已知 SZL 列表 |
| `0x0011` | 组件标识（Component identification） | 型号/版本/序列号 |
| `0x001C` | 组件标识（S7-300/400 常用） | 订货号、固件版本、序列号、系统名 |
| `0x0131` | 组件标识 | 同上（部分系列） |
| `0x0132` | 组件标识 | 同上（部分系列） |
| `0x0121` | 用户存储区 | 装载/工作/保持内存大小 |
| `0x0111` | CPU 特性 | 功能位（PUT/GET 是否允许等） |

组件标识记录典型内容：索引、20 字符文本（订货号如 `6ES7 315-2AG10-0AB0`）、
CPU 类型（如 `CPU 315-2 PN/DP`）、固件版本（`V2.6.11`）、序列号、系统名、Plant Identification。
这些字段构成**免认证的设备指纹**（型号+固件+序列号），是版本比对与目标定位的基础。

---

## 5. 访问保护与安全机制

| 机制 | 适用系列 | 说明 | 已知弱点 |
|---|---|---|---|
| 访问保护等级 1/2/3 | S7-300/400 | 1=无保护，2=读保护，3=读/写保护 | 口令校验在应用层、无重放保护；`s7-cracker.py`/离线爆破即针对该握手 |
| 访问级别 + PUT/GET | S7-1200/1500 | 访问级别（完全/读/HMI 读/禁止）+ 是否允许 PUT/GET 通信 | **允许 PUT/GET 时，绝对地址读写在无口令情况下成立**（“legacy 通信”遗留面） |
| S7comm-plus 会话 | S7-1200/1500 | 引入会话 ID、序列号；口令校验为挑战/响应，部分版本对关键操作使用加密 | 仍存在降级/兼容路径；服务可被 S7comm 传统帧激活 |
| SZL 读取 | 全系列 | 无需口令即可读组件标识 | 信息泄露（型号/固件/序列号） |
| 时间设置/诊断缓冲 | 全系列 | Userdata 子功能 | 可改时间戳（掩盖痕迹）、读诊断历史 |

### S7comm-plus 结构要点

- 协议 ID **`0x72`**（对比 S7comm 的 `0x32`），OPCode 取代 ROSCTR，头部含协议版本、序列号、
  Field/Function 位域、PDU 长度；载体内含会话 ID。具体字段以 Wireshark `packet-s7comm_plus.c` 为准。
- 会话初始化（Init SSL）以 COTP DT 承载，典型 27 字节帧：

```
03 00 00 1b 02 f0 80 72 01 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00
```

  `0x1B` = 27 字节 TPKT；`72 01 00 00` 后为 16 个填充字节（版本不同尾部可能不同）。
- S7-1200/1500 的获取口令挑战、写入密钥等操作在协议外依赖加密响应；
  相关逆向见参考仓库收录的会议材料（`awesome-industrial-protocols/protocols/s7comm.md` 中列出的
  Black Hat / DEF CON 议题：Rogue7、S7CommPlus 相关、SIMATIC 安全功能模糊测试、从 S7 窃取私钥等）。

---

## 6. 已知安全弱点汇总

| 类别 | 弱点 | 电力语境后果 |
|---|---|---|
| 认证 | S7comm 无认证；保护等级为可离线爆破的弱口令门 | 未授权读写过程变量 |
| 授权 | PUT/GET 开启即等于绝对地址全读写 | 绕过程序逻辑直接改 I/O |
| 完整性 | S7comm 无 MAC/签名，可中间人改写 | 遥测被篡改、命令被替换 |
| 可用性 | Job `0x29` PLC Stop 单帧即可停机 | 辅控/场站控制停摆（T0816/T0814） |
| 程序面 | 下载/上传块作业（`0x1A`–`0x1F`）与 PI 服务 `0x28` | 改逻辑=持久化（T0889/T0843）、程序被外带（T0845） |
| 信息泄露 | SZL 免认证；诊断缓冲可读 | 设备指纹、拓扑与历史行为泄露 |
| 会话 | 连接资源有限，易被占满 | 合法工程师站无法连接（DoS） |
| 降级 | S7comm-plus 设备兼容传统 S7comm 帧 | 新保护机制被旧协议旁路 |
| 站控层 | 工程师站/上位机侧组态工程文件（项目文件）感染面 | 参考 T0873.001（Siemens Project File Format） |

---

## 7. 检测与指纹要点

| 手段 | 值/要点 |
|---|---|
| 端口 | 102/tcp（与 IEC 61850 MMS、ICCP/TASE.2 共用 102，**必须做深度解析区分**） |
| nmap | `s7-info.nse`（经 SZL 输出模块/版本/序列号）、`s7-enumerate.nse`（枚举块） |
| Wireshark | `s7comm`、`cotp`、`tpkt` 过滤器；解析器 `packet-s7comm.c`、`packet-cotp.c` |
| 工具（参考仓库索引） | `python-snap7`/`Snap7`、`s7scan`、`s7-pcaps`（STEP7/WinCC 通信抓包样例） |
| 正常态基线 | 会话来源固定（工程师站 IP）；Setup Communication 的 PDU Length 与 MaxAmQ 固定；写入作业仅出现在组态/调试窗口 |
| 高危信号 | 非授权源出现 `0x05` Write Var / `0x29` PLC Stop / `0x1A`–`0x1F` 下载上传 / `0x28` PI 服务；短时间大量不同 TSAP 的 CR（扫描）；大量 SZL 读取（指纹枚举）；同 IP 反复 CR 打满连接资源 |

---

## 8. 关联

- 技能：`f2x-power-s7comm-attack`（S7 面专项）、`f2x-power-scada-recon`、`f2x-asset-mapping`
- 同目录：`modbus.md`、`iec61850.md`、`dnp3.md`
- 上层：`../ics-attack/mitre-ics-mapping.md`（PLC Stop → T0816；下载/改逻辑 → T0843/T0889；PUT/GET → T1692.001）
- 业务：`../business-scenarios/power-grid.md`（辅控/新能源/小型站控定位）
