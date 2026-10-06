---
name: active-scan
description: 主动端口与服务扫描（nmap/masscan），严格遵守授权范围
whenToUse: 需要确认资产存活与开放端口时
role: recon
enabled: true
---

## 前置检查
1. 确认目标 CIDR 在授权范围内。
2. 确认当前时间窗口允许主动扫描。

## 命令
- 快速存活：`nmap -sn <cidr>`
- 全端口（限速）：`nmap -sS -p- --min-rate 1000 -T4 <target> -oX runs/nmap-full.xml`
- 服务版本：`nmap -sV -sC -p <ports> <target> -oX runs/nmap-svc.xml`

## 本地已备好的工具（绝对路径，优先用它们，不要手搓）
| 用途 | 命令 |
| --- | --- |
| 端口扫描 | `nmap` / `masscan` / `$DSH_HOME/redteam/toolkit/naabu/naabu`（SYN 需 root，否则加 `-scan-type c`） |
| 内网综合扫描 | `$DSH_HOME/redteam/toolkit/fscan/fscan`（技能 fscan-intranet） |
| 内网测绘/指纹 | `$DSH_HOME/redteam/toolkit/gogo/gogo`（技能 gogo-intranet） |
| HTTP 探测（ProjectDiscovery） | `pd-httpx`（Kali 官方包名 `httpx-toolkit`，装出来是 `/usr/bin/httpx-toolkit`；**注意：`/usr/bin/httpx` 是 Python httpx 库的 CLI，不是这个**） |
| 子域/解析 | `$DSH_HOME/redteam/toolkit/subfinder/subfinder`、`$DSH_HOME/redteam/toolkit/dnsx/dnsx` |
| POC 扫描 | `nuclei`（模板已在 `~/.local/nuclei-templates`） |
| 目录爆破 | `ffuf`、`$DSH_HOME/redteam/toolkit/dirsearch/dirsearch` |
| 隧道 | `$DSH_HOME/redteam/toolkit/suo5/suo5-linux-amd64`、`$DSH_HOME/redteam/toolkit/chisel/chisel`、`$DSH_HOME/redteam/toolkit/frp/{frpc,frps}` |
| 完整清单 | `$DSH_HOME/redteam/toolkit/清单.md`、`$DSH_HOME/redteam/toolkit/技能工具清单.md` |

> **路径统一口径**：本技能所有工具路径都相对 `$DSH_HOME`（`DSH_HOME` 由宿主注入；本机为 `/root/dsh-data`）。
> 不要写成 `~/.dsh/...` —— 那不是 `DSH_HOME`，多数安装里并不存在。
> 开工前先跑自检：`node <插件根>/scripts/toolkit-check.mjs`，它会逐条实测这些路径并给出缺失清单。

## 落库要求
provenance = `active`，tool = `nmap`/`masscan`，记录 scan_run。
