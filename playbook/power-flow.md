# Playbook: power-grid (IT/OT) flow

The power-module overlay on `playbook/redteam-flow.md`. Same seven stages, but
each stage now runs **two lanes in parallel** — an IT branch and an OT branch —
whose findings converge on a single blackboard. Additive, never a replacement:
with the power module disabled the general flow is unchanged.

Enable with `f2x_orchestrate_switch { mode: "power", lane: "ot" }`. From that
point the OT gate rules below are enforced by the plugin.

---

## The dual-lane model

```text
                      ┌──────────────────────────────┐
   brief ──► intake ──►│  commander (power persona)   │
                      └───────────┬──────────────────┘
                                  │
              ┌───────────────────┴───────────────────┐
              ▼                                       ▼
      IT lane subagent                        OT lane subagent
   (enterprise / DMZ / HMI)              (control network / field devices)
              │                                       │
              └───────────► f2x_orchestrate_blackboard ◄──────────┘
                       fact / intent / hint, one shared board
                                  │
                                  ▼
                    f2x_orchestrate_checkpoint  ──►  f2x_orchestrate_verify
```

Both lanes register to the same board, so an IT-side discovery ("engineering
workstation `EWS-01` has an SMB share") is visible to the OT side, and vice versa
("that same host runs the SCADA programming client"). Neither lane works from a
private picture, which is the whole point of the overlay.

---

## Stage 0 — intake, and the OT-specific questions

Before any probe:

```text
f2x_orchestrate_doctrine
f2x_orchestrate_scope { targets: [...] }
f2x_orchestrate_start { brief, targets, mode: "power", lane: "ot" }
```

Then answer, on the blackboard, the questions that decide whether the engagement is
safe to run:

| Question | Why it gates the engagement |
|---|---|
| Which devices are in an **active control loop** vs spare/redundant? | A spare PLC can be tested; a live protection relay cannot. |
| Is the process continuous (generation, transmission) or interruptible? | Determines whether "just a write" is recoverable. |
| Which devices are **redundant pairs**? | Writing one of a pair may still disturb failover logic. |
| Where is the IT/OT boundary, and what crosses it? | Defines the pivot path and the visibility boundary. |
| What is the maintenance window, if any? | The only period where an outage-risk test is defensible. |

Record these as `fact` entries (they need evidence pointers) or `intent` entries
(planned directions). An `intent` entry is how "I mean to test the spare PLC"
becomes visible to the commander before it happens.

---

## Stage 1 — recon (IT ∥ OT)

### IT lane
Port scan, web fingerprint, directory enumeration — per
`playbook/redteam-flow.md` stage 1.

### OT lane
Identify ICS protocols and the devices behind them. See
`skills/power/f2x-power-scada-recon/` and the protocol skills.

| Protocol | Port | What identification gives you |
|---|---|---|
| Modbus/TCP | 502 | Unit ids, register map, function codes honoured, write permission |
| S7comm (ISO-TSAP) | 102 | CPU family/model, rack/slot, firmware, protection level, mode |
| IEC 61850 MMS | 102 | IED model, logical devices, data objects |
| IEC 61850 GOOSE / SV | Ethertype `0x88B8` / `0x88BA` | Publisher/subscriber map, `StNum`/`SqNum` state |
| DNP3 | 20000 | Outstation id, point map, whether secure authentication is enabled |
| OPC UA / OPC DA | 4840 / DCOM | Server endpoints, security policy actually negotiated |

Identification is **read-only and low-rate**. `nmap` against a controller runs
`-T2 --max-rate 10` at most; a control network is not a web server farm, and a
flood of SYNs to a 1990s-era PLC stack is an availability incident you caused.

Converge on the board: if recon finds a SCADA web interface (IT-flavoured) and an
exposed Modbus port (OT-flavoured) on the same host, that single fact usually
defines the engagement's cheapest path.

**Gate:** ≥1 `confirmed` checkpoint with a protocol/device identification and its
capture or tool output.

---

## Stage 2 — asset mapping (IT ∥ OT)

### IT lane
Hosts, services, accounts, entry points, technologies.

### OT lane
Five OT-specific entity classes, kept distinct from the IT ledger because their
uniqueness rules differ:

| Class | Identity key | Notes |
|---|---|---|
| Controller (PLC/RTU) | `ip` + protocol + `unit_id`/rack-slot | One IP may host several logical units |
| IED | `ip` + IED name (from SCL) | Protection devices; the SCL file is authoritative |
| HMI / engineering workstation | `hostname` + installed vendor tooling | The pivot point into the control network |
| Gateway / protocol converter | `ip` + both sides' protocols | Where IT meets OT; often the weakest device |
| Historian / data store | `ip` + service | Where process data leaves the control network |

The SCL/SCD file, when obtainable, is the highest-value asset-mapping artifact in
IEC 61850 work: it names every IED, its logical devices, and the GOOSE
publisher/subscriber relationships. See
`skills/power/f2x-power-iec61850-analysis/`.

**Gate:** ≥1 `confirmed`; both lanes' ledgers are on the board, and the coverage
denominator is stated per class.

---

## Stage 3 — vulnerability discovery (IT ∥ OT)

### IT lane
Web flaws, weak credentials, misconfiguration — per the general flow.

### OT lane
| Class | What to establish | Read-only evidence |
|---|---|---|
| Protocol authorization gap | Can a register be written by an unauthenticated client? | Read-back of an attempt is **not** acceptable as proof-of-write; use the protocol's own error/ack response and a documented value comparison |
| Weak/no authentication | Is the device's protection level set to "no protection"? | S7 SZL protection-level read; Modbus has no auth by design — state that as a protocol property, not a finding |
| Firmware / version exposure | Is the firmware version affected by a published advisory? | Identity read + advisory cross-reference |
| Configuration-tamper risk | Are setpoints writable without a program-mode transition? | Read the current value and the access mode |
| Engineering protocol exposure | Is an engineering port reachable from the enterprise zone? | Route/reachability evidence, not a scan flood |

> **Careful with `confirm`:** "the protocol permits a write" is a `partial`
> conclusion. A `confirmed` write finding requires having performed the write (with
> commander confirmation and an audit entry) and read the changed value back, or a
> vendor advisory plus a matching version read.

**Gate:** ≥1 `confirmed`; unconfirmed protocol-permits observations are recorded as
`partial` and are not presented as vulnerabilities.

---

## Stage 4 — exploitation (IT ∥ OT)

The OT lane's write operations are the highest-consequence actions in the whole
plugin. They are gated twice: by the redteam gate at stage level, and by
`f2x_orchestrate_audit` per action.

### Per-action sequence (mandatory order)

```text
1. classify   -> read-only | recoverable write | irreversible/outage risk
2. scope      -> f2x_orchestrate_scope confirms the device is in range
3. plan       -> state the exact operation, the current value, the target value,
                 the expected process effect, and the rollback
4. confirm    -> commander second confirmation; recorded as audit.confirmedBy
5. audit      -> f2x_orchestrate_audit writes the entry BEFORE execution
6. execute    -> perform the operation
7. read back  -> document the resulting state
8. traceback  -> what artifact the action left and what would have detected it
```

Steps 4–5 are not a formality: `f2x_orchestrate_audit` **refuses** an unclassified
write with no `confirmedBy`, and refuses to log it, so an unconfirmed write never
reaches step 6.

### Impact classes

| Class | Examples | Rule |
|---|---|---|
| 🟢 read-only | register read, identity read, SCL upload, passive capture | No confirmation; logged anyway |
| 🟡 recoverable write | register/setpoint write the controller logic will overwrite | Confirmation + original value known + rollback stated |
| 🔴 irreversible | PLC stop, firmware/logic download, GOOSE injection, IED reconfig | Confirmation + operational consequence stated + strongly prefer a spare device |

For a 🔴 action on a device that is not demonstrably spare, the correct output is a
**written plan submitted for approval**, not an executed action.

**Gate:** ≥1 `confirmed` checkpoint referencing the evidence triple, plus a clean
audit trail — every executed OT action has an audit entry that precedes it and
carries an impact class.

---

## Stage 5 — internal pentest, including the OT pivot

### IT lane
Standard internal work: position, credentials, reuse matrix, lateral steps.

### OT lane
The OT-specific question is not "how many hosts can I reach" but **"what does the
control network trust?"**

- **The engineering workstation is the pivot.** It usually has both enterprise
  network access and controller programming access. Reaching it is the standard
  route into the control network, and it is the device whose compromise most
  directly enables a firmware or logic change.
- **Gateway and protocol converters** are shared-trust devices; enumerate both of
  their interfaces.
- **Historian / OPC paths** can carry process data outward without touching a
  controller — often the highest-value, lowest-risk exfiltration route.
- **Engineering protocols do not authenticate by default.** State this as a
  property of the deployment, not as an exploit.

Persistence in the OT lane is **not** installed by default. A persistence
mechanism inside a control network is an operational risk that outlives the
engagement, so it is proposed, never assumed.

**Gate:** ≥1 `confirmed`; no open doctrine violation; every OT step is in the audit
trail.

---

## Stage 6 — traceback (mandatory in power mode)

This is where the power module earns its place. See
`skills/power/f2x-power-traceback/` and the `IEC61850SecurityDataset` attack
captures for replay material.

Deliverables, per executed action:

1. **Artifact** — which device log, capture point, flow record, alarm list.
2. **Detection** — a concrete rule or query. Examples:
   - Modbus write function code (05/06/0F/10) to a unit that is only ever read.
   - S7 CPU mode transition (stop) issued from a host that is not an engineering
     station.
   - GOOSE `StNum` increment with no corresponding protection event — the
     canonical IEC 61850 forgery tell.
   - A new MAC/ARP entry appearing on the station bus.
   - A protection-group or setpoint write outside a maintenance window.
   - OPC/historian read volume from a host that never reads before.
3. **Blind spot** — what the deployed telemetry would have missed, stated honestly
   (e.g. unmanaged switch with no port mirroring; no Modbus deep inspection).
4. **Recommendation** — prioritized and concrete.

**Gate:** ≥1 checkpoint stating a defender-facing detection conclusion. An OT
engagement cannot close on offence alone.

---

## Stage 7 — collection and handover

```text
f2x_orchestrate_verify { stage: "collection" }
f2x_orchestrate_export
```

The handover must contain, in this order: the asset picture (IT and OT), the
findings with evidence level and impact class, the OT audit trail, the traceback /
detection section, the open gaps including failed attempts, and the explicit
statement of which devices were touched by a write and which were not.

An engagement report that does not state which devices received writes is
incomplete regardless of findings.

---

## Hardcoded OT gate rules (summary)

Enforced by the plugin; violating one records a doctrine violation and blocks
stage advancement.

1. **≤3 concurrent tool calls per target.**
2. **Fuzzing is low-rate only** — explicit rate limit on every OT probe; never
   high-frequency scan a PLC, RTU or IED.
3. **Every write needs commander second confirmation**, recorded via
   `f2x_orchestrate_audit`'s `confirmedBy`. Unconfirmed writes are refused.
4. **Every potentially process-affecting action is audit-logged before execution.**
5. **The target allowlist is hardcoded and narrow**; out-of-range operations are
   refused in code.
6. **No DDoS, no brute force.** Offline cracking tools may be referenced in
   reports, never aimed at a live controller.
7. **The defender-facing traceback is mandatory** — no power engagement closes
   without it.
