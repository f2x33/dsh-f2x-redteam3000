# 免责声明 / Disclaimer

**请在使用前完整阅读本文件。下载、安装、加载或使用本项目（`dsh-f2x-redteam3000`，
以下称"本项目"）即表示你已阅读、理解并同意本声明全部内容。若你不同意，请立即停止使用并删除本项目。**

---

## 1. 用途限定：仅限合法授权场景

本项目是**红队/安全测试作业的编排与知识工具**，面向下列场景：

- 已取得**书面授权**的渗透测试、红蓝对抗、攻防演练；
- CTF 竞赛与经许可的靶场；
- 漏洞赏金计划（在项目公开范围内）；
- 安全研究与教学（在隔离环境中）。

**禁止**将本项目用于任何未经授权的活动，包括但不限于：未经授权扫描、探测、入侵、控制他人
系统或数据；拒绝服务攻击；窃取、篡改、破坏数据；规避安全防护；侵害他人隐私。

**你必须自行确认并留存授权证据。** 本项目**不具备**、也**不会**替你判断某项操作是否获得授权：
其内置的授权范围配置（`allowedTargets` / 任务 `allowlist`）只是**技术约束**，用于避免误伤，
**不构成任何授权证明，也不是法律意见**。把某个目标填进配置，不会被解释为"已获授权"。

## 2. 法律后果由使用者自行承担

在中华人民共和国境内，未经授权侵入、干扰计算机信息系统可能触犯《中华人民共和国刑法》
第二百八十五条、第二百八十六条，《中华人民共和国网络安全法》以及《数据安全法》等法律法规；
在其他司法辖区，另有对应的刑事与民事责任规定。

**使用者应自行了解并遵守所在地与目标所在地的全部适用法律。** 因使用本项目（无论是否授权）
引发的任何法律责任、行政责任、民事赔偿、刑事指控或第三方索赔，**均由使用者本人承担**，
本项目作者与贡献者**不承担任何责任**。

## 3. 风险自负，无任何担保

本项目按 **"现状"（AS IS）** 提供，不附带任何明示或默示的担保，包括但不限于适销性、
特定用途适用性、不侵权、以及**无错误或无中断运行**的担保。适用 **MIT License** 的免责与
责任限制条款（"THE SOFTWARE IS PROVIDED AS IS… IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE…"）：

- 作者与贡献者**不对**任何直接、间接、附带、特殊、惩罚性或后果性损害负责，包括数据丢失、
  系统损坏、业务中断、利润损失或第三方索赔；
- 本项目**会真实发起网络流量、上传文件、建立隧道、执行命令**。在非隔离环境中使用，
  可能影响你自己的生产系统、网络出口信誉或他人系统；
- **强烈建议**只在专用、隔离、可随时丢弃的演练环境中运行，不要在存放私钥、真实业务数据
  或日常办公用途的机器上运行。

## 4. 使用者的环境与数据责任

- 本项目内的工具会读写本机文件（台账数据库、经验库、会话记录）。**在使用前自行备份**；
- 你自行提供的密钥、凭据、VPS 访问方式等信息，**由你负责保管与合规使用**；
- 演练产生的数据（含可能接触到的目标侧数据）**由你负责按法律与合同约定处置**，
  包括及时删除与保密义务。

## 5. 无出口管制与制裁用途保证

你声明并保证：你不会将本项目用于任何受适用的出口管制、经济制裁或禁运法律所禁止的用途、
主体或地区；你不在受制裁的司法辖区或以违反上述法律的方式使用本项目。

## 6. 无担保的"得分/评分/成果"含义

本项目中的"得分""成果""报告"等概念**仅用于演练内部评估与记录**，不代表对任何系统安全性、
合法性或合规性的认定，也不构成审计结论。**不得**将其作为对外出具的安全结论使用。

## 7. 第三方内容

本项目包含第三方材料，其版权与许可见 [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md)。
第三方材料由其各自作者提供，本项目作者不对其内容、合法性或适用性作任何保证；
再分发时你必须遵守各第三方许可的条款。

## 8. 本声明的变更与解释

本声明可随版本更新，更新后随包发布即生效。若本声明与 `LICENSE`（MIT）冲突，
就许可授权范围以 `LICENSE` 为准，就使用限定与风险责任以本声明为准。

---

# Disclaimer (English)

**This project is for authorized security work only.** It is provided for penetration
tests, red-team exercises, CTF competitions, bug-bounty programs and security research
**where you hold prior written authorization**, and for use in isolated, disposable
environments.

**Do not use it for any unauthorized activity.** You are solely responsible for
establishing and evidencing your authorization; the built-in target allowlist is a
technical guardrail against accidents, **not** a grant of authorization and **not**
legal advice.

The software is provided **"AS IS"**, without warranty of any kind. To the maximum
extent permitted by law, the authors and contributors **accept no liability** for any
damage, data loss, service disruption, legal consequence or third-party claim arising
from its use (see the MIT License warranty and liability disclaimer). It performs **real network
activity, file uploads, tunnel establishment and command execution** — run it only in
an isolated environment you can discard.

You are responsible for complying with all applicable laws (including unauthorized
access, computer-misuse, data-protection and export-control laws) in your jurisdiction
and in the jurisdiction of any target. Third-party components carry their own licences;
see [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).

*This document states the project's usage terms as understood by its authors. It is not
legal advice; consult a lawyer for commercial redistribution or compliance review.*
