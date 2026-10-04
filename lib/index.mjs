import { F2X_PROVIDER_NAME, bundledPowerSkillDir, bundledRefsDir, bundledSkillDirs, createSkillProvider } from "./skills.mjs";
import { RECOMMENDED, RECOMMENDED_REPOS, installPlugin, prepareRepo, renderInstallText, renderManagerHtml, renderRepoText, resolveManagerEnv, runEnvironmentCheck, verifyInstalled } from "./manager.mjs";
import { closeSync, existsSync, mkdirSync, openSync, statSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { defineTool } from "@deepseek-ai/dsh-tools";
import Schema from "@deepseek-ai/schemastery";
import { mkdir, readFile, rename, stat, unlink, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
//#region src/config.ts
const Config = Schema.object({
	extraSkillDirs: Schema.array(Schema.string()).default([]).description("Additional skill root directories (absolute paths) searched after the bundled roots."),
	allowedTargets: Schema.array(Schema.string()).default([]).description("Authorized target allowlist: IPv4, IPv4/CIDR, hostname, or a leading-dot domain suffix. Empty denies all targets."),
	persistState: Schema.boolean().default(true).description("Persist tasks, blackboard facts and the audit ledger as JSON under the state directory."),
	stateDir: Schema.string().default("").description("State directory; empty resolves to <dshHome>/f2x-redteam3000."),
	referenceRoot: Schema.string().default("").description("Read-only reference tree cited by the power/OT skills; empty resolves to $REDTEAM_REFS, then <dshHome>/redteam-refs when present."),
	enablePowerModule: Schema.boolean().default(true).description("Advertise the power/OT module (power persona, power flow and skills/power)."),
	registerSkillProvider: Schema.boolean().default(true).description("Publish skills/ and vendor/redteam-skills/ globally. Set false when an agent preset supplies them via customSkillDirs."),
	publishPowerSkillsGlobally: Schema.boolean().default(true).description("Also publish skills/power to the global skill layer. Default true for a bare host mount, but a deployment that wires presets/ should set false on the host row and let only the power preset opt in — otherwise every mode advertises the OT skills."),
	maxConcurrencyPerTarget: Schema.number().default(3).description("Doctrine ceiling for concurrent tool calls against a single target (OT gate rule)."),
	maxCheckpointsPerStage: Schema.number().default(12).description("Evidence checkpoints accepted per stage before the stage is considered saturated."),
	gateValidityStages: Schema.number().default(1).description("How many stage advances a redteam gate verdict stays valid.")
});
//#endregion
//#region src/conduct.ts
/**
* Engagement conduct policy: which actions are refused outright, which need a confirmation
* reference, and which may proceed.
*
* Why this is a table of word patterns rather than a flag the caller sets
*
* The audit of this plugin found the OT write gate could be skipped by declaring a write as
* `operation: "register-read"` — the party being constrained supplied its own classification.
* This module takes the opposite stance: **the category is decided from the action text**, so
* describing what you are about to do is what puts you in the right tier. A caller that
* misdescribes its action is not lying to a human, it is lying to the gate, and the gate
* treats a description it cannot classify as the stricter of the two.
*
* What this can and cannot do
*
* It constrains actions that are recorded through this plugin's tools. It does **not**
* intercept a shell, so a command typed straight into a terminal is out of its reach — that
* is a property of running inside the harness, not a tuning issue. What it does guarantee:
* nothing that matches the prohibited list can be *logged as performed*, so the ledger this
* plugin exports will never present a deleted dataset or a dumped customer table as an
* accepted engagement step.
*/
/**
* Positive read-only signal: verbs that name an observation rather than a change.
*
* Why a positive signal exists at all: the classifier is a keyword table, so a declared read-only
* operation whose text used an unlisted verb (`调成`, `change … to 100`, `寄存器 = 100`) was logged
* as `read-only` with no confirmation. Requiring BOTH a declared read-only class AND a recognised
* read verb removes that: an unlisted verb is treated as unclassified, which needs confirmation.
* The cost is the reverse failure an audit also found — a legitimate read whose text matches
* nothing (`nmap -sV` before this list) was refused — so the list is deliberately broad.
*/
const READ_INTENT_RE = new RegExp([
	"\\b(read|reads|reading|scan|scans|scanned|probe|probes|probing|list|lists|listing|enumerate|enumerating|fingerprint|fingerprinting|capture|capturing|browse|browsing|view|viewing|query|querying|fetch|fetching|get|head|dump|inspect|inspecting|identify|identifying|discover|discovery|detect|detecting|check|checking|test|testing|verify|verifying|validate|validating|measure|measuring|monitor|monitoring|lookup|resolve|resolve|trace|tracing|audit|review|survey|map|mapping|collect|collection|grep|find|search|download|export)\\b",
	"\\b(nmap|masscan|httpx|whatweb|wafw00f|nikto|curl|wget|dig|nslookup|whois|subfinder|dnsx|katana|gau|waybackurls|ffuf|feroxbuster|gobuster|dirsearch|tcpdump|tshark|wireshark|strings|objdump|readelf|nm|file|exiftool|binwalk|radare2|strings|semgrep|gitleaks|trufflehog)\\b",
	"(读取|读取器|扫描|探测|枚举|列举|列出|指纹|抓包|捕获|抓取|浏览|查看|查询|获取|识别|发现|检测|检查|核对|验证|测量|监控|解析|审计|复核|收集|采集|检索|导出清单|查看清单)"
].join("|"), "i");
/** Whether the text names an observation, so a declared read-only class can be trusted. */
function declaresReadIntent(action, operation) {
	return READ_INTENT_RE.test(`${action ?? ""} ${operation ?? ""}`);
}
/**
* Actions that are refused with no override.
*
* These are the ones where doing them is the finding: destroying the data you were hired to
* protect, or exfiltrating it wholesale, falls outside any ordinary penetration-test scope,
* and a confirmation prompt would only turn an accident into a decision. `confirmedBy` is
* deliberately NOT accepted for these — the refusal is final.
*/
const PROHIBITED = [{
	tier: "prohibited",
	reason: "Destructive action on a target. Deleting, wiping, dropping, truncating or mass-removing a target's data or system files — or disabling its recovery — is refused in all cases, including with a confirmation reference.",
	patterns: [
		/\brm\b|\brmdir\b|\bunlink\b|\bshred\b|\bwipe\b|\bformat\b|\bmkfs\b|\bdd\s+if=|\btruncate\b|\bpurge\b|\bobliterate\b|\bsecure\s+erase\b|\bbcdedit\b|\bsdelete\b|\bbleachbit\b/i,
		/\bdrop\s+(table|database|schema|index)\b|\bdelete\s+from\b|\bdrop\s+all\b/i,
		/\bvssadmin\s+delete\b|\bwevtutil\s+cl\b|\bhistory\s+-c\b|\bclear\s+-history\b/i,
		"删除",
		"清除日志",
		"清空",
		"抹除",
		"擦除",
		"销毁",
		"破坏数据",
		"格式化",
		"删库",
		"清库",
		"毁尸",
		/(ransom|encrypt\s+for\s+ransom|勒索|加密索要)/i
	]
}, {
	tier: "prohibited",
	reason: "Wholesale data exfiltration of a production database. Dumping an entire database or bulk-exporting customer/business data is refused; take the minimum sample needed to prove the finding (the gate accepts a row count plus a redacted excerpt).",
	patterns: [
		/\b(mysqldump|pg_dump|pg_dumpall|mongodump|sqlcmd\s+-Q\s*.*\bselect|exp(dump)?\s+|ora2pg|import\s+bcp|bcp\s+.*\bout\b)/i,
		/\b(dump|exfiltrat\w*|extract|export)\b[^.]{0,24}\b(database|db|table|schema|user\s*table|customers?|订单|用户表|全量|整库|整表)/i,
		"脱库",
		"拖库",
		"拉库",
		"整库导出",
		"全量导出",
		"导库",
		"导出用户表",
		"导出全部",
		"导出所有",
		"全部记录",
		"所有记录",
		"全表导出"
	]
}];
/**
* Actions that change state or take something. Allowed, but only with a confirmation
* reference, and every one of them is written to the audit log as performed.
*/
const NEEDS_CONFIRMATION = [
	{
		tier: "needs-confirmation",
		reason: "Creating or changing accounts and credentials.",
		patterns: [
			/\b(useradd|adduser|net\s+user\b|usermod|passwd|chpasswd|set\s+password|reset\s+password|alter\s+user)\b/i,
			/\b(create|add|new)\b[^.]{0,40}\b(administrator|admin\s+account|user\s+account|domain\s+admin|privileged\s+account)\b/i,
			/\b(domain\s+administrator|enterprise\s+admin)\b/i,
			"新建账号",
			"新增账号",
			"添加用户",
			"创建用户",
			"提权账号",
			"重置口令",
			"改密码"
		]
	},
	{
		tier: "needs-confirmation",
		reason: "Privilege escalation or security-control changes.",
		patterns: [/\b(sudo|su\s+-|runas|setuid|chmod\s+\+s|privilege|提权|\bprivesc\b|bypass\s+(uac|edr|av|amsi)|关闭(防护|杀软|防火墙)|停用(审计|日志))/i]
	},
	{
		tier: "needs-confirmation",
		reason: "Persistence on a target.",
		patterns: [
			/\b(crontab|\bat\s+\d|systemctl\s+(enable|start)|sc\s+create|schtasks|registry\s+run|run\s+key)\b/i,
			/\b(scheduled\s+task|startup\s+item|autostart|autorun|run\s+key|service\s+install)\b/i,
			"计划任务",
			"定时任务",
			"开机自启",
			"自启动",
			"持久化",
			"驻留",
			"后门账号"
		]
	},
	{
		tier: "needs-confirmation",
		reason: "Credential dumping or password cracking.",
		patterns: [
			/\b(mimikatz|lsass|sekurlsa|secretsdump|hashdump|ntds\.dit|kerberos?ast|asrep|hydra|hashcat|crackstation|responder|ntlmrelayx)\b/i,
			/\b(sam\s+file|offline\s+crack|crack\s+the\s+hash|dump\s+(credentials|hashes)?)\b/i,
			"离线破解",
			"在线爆破",
			"弱口令爆破",
			"抓取哈希",
			"转储凭据",
			"凭据转储",
			"密码喷洒"
		]
	},
	{
		tier: "needs-confirmation",
		reason: "Uploading a payload, web shell or tunnel to a target.",
		patterns: [
			/\b(upload|webshell|web\s+shell|behinder|godzilla|antsword|suo5|neoreg|frp|chisel|stowaway|memshell)/i,
			/\b(drop|deploy|plant|install)\b[^.]{0,24}\b(shell|payload|implant|agent|beacon)\b/i,
			"内存马",
			"上传马",
			"上传载荷",
			"上传webshell",
			"落地载荷",
			"隧道",
			"代理转发",
			"落马"
		]
	},
	{
		tier: "needs-confirmation",
		reason: "Lateral movement onto another host.",
		patterns: [
			/\b(psexec|wmiexec|smbexec|atexec|dcomexec|impacket|winrs|evil-winrm)\b/i,
			/\bssh\s+\S+@/i,
			/pass[-\s]?the[-\s]?hash/i,
			"横向移动",
			"横向渗透",
			"跳板",
			"pth"
		]
	},
	{
		tier: "needs-confirmation",
		reason: "Any write to a controller or process device (OT plane).",
		patterns: [
			/\bplc[\s_-]?(stop|start|write|download|mode)\b|\bregister\s+write\b|\bcoil\s+write\b|\bsetpoint\b|\bgoose\s+(forge|inject)\b|\bied\s+config\b|\bmodbus\s+write\b|\bs7\s+write\b/i,
			/\bfirmware\b[^.]{0,30}\b(write|download|update|flash|upgrade)\b|\b(write|download|update|flash|upgrade)\b[^.]{0,30}\bfirmware\b/i,
			"启停",
			"下装",
			"下发",
			"写寄存器",
			"设定值",
			"固件下装",
			"固件烧写",
			"固件更新",
			"停机",
			"冷启",
			"设为",
			"设置为",
			"改成",
			"改为",
			"置为",
			"置位",
			"初始化为",
			"写入值为",
			"赋值",
			"强制为",
			"调成",
			"调为",
			"调到",
			"调整",
			"调节",
			"设定",
			"设定值",
			"配置为",
			"绑到",
			"映射为",
			"导出为",
			"导出成",
			"另存为",
			"保存为",
			"下载为"
		]
	},
	{
		tier: "needs-confirmation",
		reason: "Interrupting a service or process on a target.",
		patterns: [
			/\b(kill\s+-|pkill|taskkill|stop-process|shutdown|reboot)\b/i,
			/\b(systemctl|service|net)\b[^.]{0,24}\b(stop|disable|restart|reload)\b/i,
			/\b(stop|restart|reload|disable)\b[^.]{0,24}\b(service|daemon|process|server)\b/i,
			"停止服务",
			"关闭服务",
			"重启服务",
			"重启主机",
			"重启进程",
			"服务中断"
		]
	}
];
/**
* Actions described so vaguely that no tier can be chosen.
*
* This exists because a text classifier can be gamed by vagueness: "handle it" and "optimize"
* matched nothing, so they were classified `free`, while an honest description that happened to
* contain a command word could be refused. Requiring a concrete description removes the reward for
* being vague — and the ask is cheap, since the caller knows what it is about to do.
*/
const VAGUE = [{
	tier: "needs-confirmation",
	reason: "The action is described too vaguely to classify (no operation, no object). Say WHAT you are about to run against WHAT — a concrete description is also what makes the audit trail useful later.",
	patterns: [
		"处理一下",
		"优化",
		"继续",
		"推进一下",
		"搞一下",
		"弄一下",
		"看一下",
		"检查一下",
		"试试",
		"handle it",
		"optimize",
		"proceed",
		"continue",
		"do the thing",
		"look into it",
		"check it out"
	]
}];
/** Every rule, most restrictive first. */
const RULES = [
	...PROHIBITED,
	...NEEDS_CONFIRMATION,
	...VAGUE
];
/**
* Classify an action by what its text describes.
*
* @param action - the human-readable action ("PLC stop / mode transition to STOP").
* @param operation - the declared operation id ("register-read", "plc-start-stop", …).
*/
function classifyConduct(action, operation) {
	const text = `${action ?? ""} ${operation ?? ""}`.trim();
	if (text === "") return { tier: "free" };
	const folded = text.toLowerCase();
	for (const rule of RULES) for (const pattern of rule.patterns) {
		const hit = typeof pattern === "string" ? folded.includes(pattern.toLowerCase()) ? pattern : void 0 : pattern.exec(text)?.[0];
		if (hit !== void 0) return {
			tier: rule.tier,
			reason: rule.reason,
			matched: hit
		};
	}
	return { tier: "free" };
}
/** Render the policy for `f2x_orchestrate_doctrine`, so operators can read the rules. */
function renderConductPolicy() {
	const lines = [];
	lines.push("Conduct policy (decided from the action TEXT, not from a self-declared class):");
	lines.push("  PROHIBITED — refused outright, no confirmation can override:");
	for (const rule of PROHIBITED) lines.push(`    · ${rule.reason}`);
	lines.push("  NEEDS CONFIRMATION — allowed with `confirmedBy`, always logged as performed:");
	for (const rule of NEEDS_CONFIRMATION) lines.push(`    · ${rule.reason}`);
	lines.push("  FREE — everything else, including reads, probes and passive capture.");
	lines.push("  Note: this constrains actions recorded through these tools. It does not intercept a shell.");
	return lines;
}
//#endregion
//#region src/scope.ts
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
/** Parse a dotted-quad IPv4 literal, or return `undefined` when it is not one. */
function parseIpv4(input) {
	const match = IPV4_RE.exec(input);
	if (match === null) return void 0;
	if ([
		match[1],
		match[2],
		match[3],
		match[4]
	].some((part) => /^0\d/.test(part ?? ""))) return void 0;
	const octets = [
		match[1],
		match[2],
		match[3],
		match[4]
	].map((part) => Number.parseInt(part ?? "", 10));
	if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return void 0;
	return { octets };
}
/** Convert an IPv4 address to its 32-bit unsigned integer value. */
function ipv4ToInt(address) {
	const [a = 0, b = 0, c = 0, d = 0] = address.octets;
	return (a << 24 >>> 0) + (b << 16) + (c << 8) + d >>> 0;
}
/** Strip a trailing `:port` (or `[v6]:port`) and lowercase the remainder. */
function stripPort(input) {
	const trimmed = input.trim().toLowerCase();
	if (trimmed.startsWith("[")) {
		const close = trimmed.indexOf("]");
		return close === -1 ? trimmed : trimmed.slice(1, close);
	}
	const colon = trimmed.lastIndexOf(":");
	if (colon === -1) return trimmed;
	const tail = trimmed.slice(colon + 1);
	if (/^\d{1,5}$/.test(tail) && trimmed.indexOf(":") === colon) return trimmed.slice(0, colon);
	return trimmed;
}
/**
* Test whether `target` is covered by `entry`.
* @returns a reason code when covered, otherwise `undefined`.
*/
function matchEntry(target, entry) {
	const normalizedTarget = stripPort(target);
	const normalizedEntry = stripPort(entry.trim().toLowerCase());
	if (normalizedEntry === "" || normalizedTarget === "") return void 0;
	if (normalizedEntry === "*") return "wildcard";
	if (normalizedEntry.includes("/")) {
		const [networkPart, prefixPart] = normalizedEntry.split("/", 2);
		const prefix = Number.parseInt(prefixPart ?? "", 10);
		const network = parseIpv4(networkPart ?? "");
		const address = parseIpv4(normalizedTarget);
		if (network === void 0 || address === void 0) return void 0;
		if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return void 0;
		if (prefix === 0) return "cidr-match";
		const mask = prefix === 32 ? 4294967295 : 4294967295 << 32 - prefix >>> 0;
		return (ipv4ToInt(network) & mask) >>> 0 === (ipv4ToInt(address) & mask) >>> 0 ? "cidr-match" : void 0;
	}
	if (normalizedEntry.startsWith(".")) return normalizedTarget.endsWith(normalizedEntry) ? "suffix-match" : void 0;
	return normalizedTarget === normalizedEntry ? "allowlisted" : void 0;
}
/**
* Whether allowlist entry `outer` already covers entry `inner`.
*
* This is range-in-range containment, not host-in-range membership: `matchEntry` answers "is this
* host inside the range", which is the wrong question when the caller passes a range of its own.
* Using it here made a legitimate narrowing (`10.10.0.0/24` inside `10.0.0.0/8`) fail, and the
* natural "fix" for that false failure is to stop checking — which is how the hole reopened.
*
* @param inner - the entry the caller wants to use.
* @param outer - an entry from the operator's configured range.
*/
function entryCovers(outer, inner) {
	const outerEntry = stripPort(outer.trim().toLowerCase());
	const innerEntry = stripPort(inner.trim().toLowerCase());
	if (outerEntry === "" || innerEntry === "") return false;
	if (outerEntry === "*") return true;
	if (innerEntry === "*") return false;
	const parseCidr = (value) => {
		if (!value.includes("/")) return void 0;
		const [networkPart, prefixPart] = value.split("/", 2);
		const network = parseIpv4(networkPart ?? "");
		const prefix = Number.parseInt(prefixPart ?? "", 10);
		if (network === void 0 || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return void 0;
		return {
			network,
			prefix
		};
	};
	const asHost = (entry) => {
		const match = /^(.*)\/(\d+)$/.exec(entry);
		return match !== null && match[2] === "32" ? match[1] ?? "" : entry;
	};
	if (innerEntry.endsWith("/32")) return entryCovers(outerEntry, asHost(innerEntry));
	if (outerEntry.endsWith("/32")) return matchEntry(asHost(outerEntry), innerEntry) !== void 0;
	const outerCidr = parseCidr(outerEntry);
	const innerCidr = parseCidr(innerEntry);
	if (outerCidr !== void 0) {
		if (innerCidr !== void 0) {
			if (innerCidr.prefix < outerCidr.prefix) return false;
			const mask = outerCidr.prefix === 0 ? 0 : 4294967295 << 32 - outerCidr.prefix >>> 0;
			return (ipv4ToInt(innerCidr.network) & mask) >>> 0 === (ipv4ToInt(outerCidr.network) & mask) >>> 0;
		}
		return matchEntry(innerEntry, outerEntry) !== void 0;
	}
	if (innerCidr !== void 0) return false;
	return matchEntry(innerEntry, outerEntry) !== void 0;
}
/**
* Decide whether one target is inside the configured allowlist.
* @param target - the target as supplied by the caller.
* @param allowlist - the hardcoded allowlist from plugin config.
* @returns the verdict; `allowed` is false for every failure mode.
*/
function checkTarget(target, allowlist) {
	const usable = allowlist.map((entry) => entry.trim()).filter((entry) => entry !== "");
	if (stripPort(target) === "") return {
		target,
		allowed: false,
		code: "unparseable",
		reason: "Target is empty after normalization."
	};
	if (usable.length === 0) return {
		target,
		allowed: false,
		code: "empty-allowlist",
		reason: "No authorized target range is configured, so every target is denied. Set `allowedTargets` in the plugin config (or pass `targets` to f2x_orchestrate_start) to authorize a range explicitly."
	};
	for (const entry of usable) {
		const code = matchEntry(target, entry);
		if (code !== void 0) return {
			target,
			allowed: true,
			code,
			matched: entry,
			reason: `Target "${target}" is covered by allowlist entry "${entry}".`
		};
	}
	return {
		target,
		allowed: false,
		code: "out-of-scope",
		reason: `Target "${target}" is outside the authorized range [${usable.join(", ")}]. Out-of-scope operations are refused.`
	};
}
/** Check every target and summarize; `allowed` is true only when all targets pass. */
function checkTargets(targets, allowlist) {
	const verdicts = targets.map((target) => checkTarget(target, allowlist));
	const rejected = verdicts.filter((verdict) => !verdict.allowed).map((verdict) => verdict.target);
	return {
		allowed: rejected.length === 0,
		verdicts,
		rejected
	};
}
//#endregion
//#region src/orchestrate.ts
/** Canonical stage identifiers, mirroring `playbook/redteam-flow.md`. */
const STAGES = [
	"recon",
	"asset-mapping",
	"vuln-discovery",
	"exploitation",
	"internal-pentest",
	"traceback",
	"collection"
];
/** Return the stage after `stage`, or `undefined` at the end of the flow. */
function nextStage(stage) {
	const index = STAGES.indexOf(stage);
	return index === -1 ? void 0 : STAGES[index + 1];
}
/**
* The digest a verdict must carry to be consumable by the check-in gate.
*
* Exported so the gate and the producer cannot drift apart: both sides call this one function.
*/
function verdictToken(verdict) {
	const material = [
		verdict.stage,
		String(verdict.pass),
		verdict.atStage,
		String(verdict.cpCount),
		String(verdict.confirmedCount),
		verdict.openGaps.join("|"),
		verdict.checkedAt
	].join("\0");
	return createHash("sha256").update(material).digest("hex").slice(0, 32);
}
/** Whether a verdict carries a token that matches its own content. */
function verdictIsIntact(verdict) {
	if (verdict === void 0 || typeof verdict.token !== "string") return false;
	const { token, ...rest } = verdict;
	return verdictToken(rest) === token;
}
/** OT operations that require an explicit second confirmation from the commander. */
/**
* Detect write intent in an operation's description, independent of its declared class.
*
* The gate used to trust `operation` alone, so `{ operation: "register-read", action:
* "PLC stop / mode transition to STOP" }` was logged as `impact=read-only` and needed no
* confirmation — the party being constrained supplied the classification. The declared
* class is still honoured, but a write verb in the text forces confirmation even when the
* class claims read-only. Under-detection is the safe direction here: a false positive only
* asks for a confirmation reference, a false negative authorises an irreversible action.
*/
const WRITE_INTENT_RE = new RegExp(["\\b(stop|start|cold[\\s-]?start|warm[\\s-]?start|halt|restart|reboot|reset|write|force|set|override|inject|forge|download|upload|flash|program|erase|delete|kill|disable|enable|trip|close|open|operate|command|control|switch|transition|modif|patch|upgrade|downgrade|persist|install)", "(写入|下装|下发|下载|烧写|刷写|启停|停机|启动|停止|冷启|热启|复位|重启|置位|强制|伪造|注入|封锁|打开|合闸|分闸|跳闸|闭锁|解锁|修改|变更|升级|降级|植入|落地|清除|删除)"].join("|"), "i");
/** The declared classes whose semantics are a write, plus whether the text also says so. */
function declaresWriteIntent(action, operation) {
	const text = `${action ?? ""} ${operation ?? ""}`;
	return WRITE_INTENT_RE.test(text);
}
const WRITE_OPERATIONS = [
	{
		id: "register-write",
		label: "Modbus register / coil write (FC 05/06/0F/10)",
		impact: "reversible"
	},
	{
		id: "setpoint-change",
		label: "Process setpoint change on PLC/RTU",
		impact: "reversible"
	},
	{
		id: "plc-start-stop",
		label: "PLC start / stop mode transition",
		impact: "irreversible"
	},
	{
		id: "firmware-write",
		label: "Controller firmware or logic download",
		impact: "irreversible"
	},
	{
		id: "goose-forge",
		label: "GOOSE / SV message injection or forgery",
		impact: "irreversible"
	},
	{
		id: "ied-config-write",
		label: "IED configuration / SCL download",
		impact: "irreversible"
	}
];
/**
* Categories of OT activity that do not touch device state. Anything not listed
* here is treated as a write and therefore gated behind commander confirmation.
*/
const READ_ONLY_OPERATIONS = [
	{
		id: "protocol-probe",
		label: "Protocol identification / service banner probe"
	},
	{
		id: "device-enumeration",
		label: "Device and unit-id enumeration"
	},
	{
		id: "register-read",
		label: "Register / coil / input read (FC 01-04)"
	},
	{
		id: "identity-read",
		label: "Controller identity and diagnostic (SZL) read"
	},
	{
		id: "traffic-capture",
		label: "Passive traffic capture and offline analysis"
	},
	{
		id: "config-upload",
		label: "Configuration / SCL upload (read direction)"
	},
	{
		id: "web-ui-browse",
		label: "SCADA/HMI web interface browsing (GET only)"
	}
];
/** Whether a parsed JSON value is a plain object (not null and not an array). */
function isRecord(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
/** Create an empty state blob. */
function emptyState() {
	return {
		version: 1,
		mode: "general",
		tasks: Object.create(null),
		blackboard: [],
		audit: [],
		findings: []
	};
}
/** Serialized JSON store shared by every tool in this plugin. */
var StateStore = class {
	file;
	enabled;
	queue = Promise.resolve();
	cache;
	/** mtime of the file when `cache` was loaded, or `-1` for "read once, never written". */
	cacheStamp = -1;
	constructor(stateDir, enabled) {
		this.file = join(stateDir, "state.json");
		this.enabled = enabled;
	}
	/** Absolute path of the backing file (reported to the model for traceability). */
	get path() {
		return this.file;
	}
	/** Whether writes reach disk. */
	get persistent() {
		return this.enabled;
	}
	/**
	* Reload the cache when another instance has written the file since we read it.
	*
	* One plugin process can hold several `StateStore` objects for the same file —
	* the host-plane row and every agent-preset row each register this plugin — and a
	* long-lived cache in each of them made the last writer win, silently discarding
	* the other mode's tasks, blackboard entries and findings. Comparing the file
	* stamp before every mutation is enough to make each write a read-modify-write of
	* the CURRENT file instead of of a stale snapshot.
	*/
	async refresh() {
		if (!this.enabled || this.cache === void 0) return;
		try {
			if ((await stat(this.file)).mtimeMs !== this.cacheStamp) this.cache = void 0;
		} catch {}
	}
	/** Read the state, loading it from disk on first use. */
	async read() {
		if (this.cache !== void 0) return this.cache;
		if (!this.enabled) {
			this.cache = emptyState();
			return this.cache;
		}
		let stamp = -1;
		try {
			stamp = (await stat(this.file)).mtimeMs;
		} catch {}
		try {
			const raw = await readFile(this.file, "utf8");
			const parsed = JSON.parse(raw);
			const base = emptyState();
			this.cache = parsed !== null && typeof parsed === "object" && parsed.version === 1 ? {
				version: 1,
				mode: parsed.mode === "power" ? "power" : "general",
				...typeof parsed.activeTaskId === "string" ? { activeTaskId: parsed.activeTaskId } : {},
				tasks: isRecord(parsed.tasks) ? Object.assign(Object.create(null), parsed.tasks) : base.tasks,
				blackboard: Array.isArray(parsed.blackboard) ? parsed.blackboard : base.blackboard,
				audit: Array.isArray(parsed.audit) ? parsed.audit : base.audit,
				findings: Array.isArray(parsed.findings) ? parsed.findings : base.findings
			} : base;
			this.cacheStamp = stamp;
		} catch {
			this.cache = emptyState();
			this.cacheStamp = -1;
		}
		return this.cache;
	}
	/**
	* Apply `mutate` to the state and persist the result.
	*
	* Mutations are serialized through one promise chain: concurrent tool calls
	* cannot interleave their read-modify-write cycles. The file itself is written
	* atomically, and a file another instance touched since our last read is
	* reloaded first, so two modes (or two processes) sharing the ledger merge
	* instead of overwriting each other.
	*/
	async update(mutate) {
		const run = this.queue.then(async () => {
			if (!this.enabled) return mutate(await this.read());
			await mkdir(dirname(this.file), { recursive: true });
			const release = await acquireLock(`${this.file}.lock`);
			try {
				await this.refresh();
				const state = await this.read();
				const result = mutate(state);
				await writeJsonAtomic(this.file, state);
				try {
					this.cacheStamp = (await stat(this.file)).mtimeMs;
				} catch {
					this.cacheStamp = -1;
				}
				return result;
			} finally {
				await release();
			}
		});
		this.queue = run.then(() => void 0, () => void 0);
		return run;
	}
};
/**
* Write JSON through a sibling temp file and a rename.
*
* A reader must never observe a half-written file: `rename` within one directory is
* atomic, so the ledger either holds the previous document or the next one. Falls
* back to a direct write when the rename is not possible (a filesystem that refuses
* it), which is still better than failing the mutation.
*/
async function writeJsonAtomic(file, value) {
	const text = `${JSON.stringify(value, null, 2)}\n`;
	const temp = `${file}.${process.pid}.${Math.random().toString(36).slice(2, 8)}.tmp`;
	try {
		await writeFile(temp, text, "utf8");
		await rename(temp, file);
	} catch {
		await unlink(temp).catch(() => void 0);
		await writeFile(file, text, "utf8");
	}
}
/** Build the next sequential id for a collection. */
function nextSerial(existing, prefix) {
	let max = 0;
	for (const item of existing) {
		const match = new RegExp(`^${prefix}-(\\d+)$`).exec(item.id);
		if (match === null) continue;
		const value = Number.parseInt(match[1] ?? "0", 10);
		if (Number.isFinite(value) && value > max) max = value;
	}
	return max + 1;
}
/**
* Evaluate the redteam gate for one stage.
*
* The gate is deliberately mechanical and evidence-driven: it counts what the
* stage actually produced and refuses to advance on prose. This is the
* "verification decay" guard — a model cannot talk its way past a gate that only
* reads the ledger.
*/
/**
* Is this checkpoint's evidence a real pointer, or a placeholder?
*
* The gate used to count whatever `level` the caller declared, so
* `{summary:"done", evidence:"n/a", level:"confirmed", advance:true}` satisfied it. A
* checkpoint that names nothing is not evidence, so "confirmed" now requires an evidence
* string that actually points at something. The check is deliberately conservative: it
* rejects empties and known placeholders, and never judges content quality (that is the
* operator's call), so legitimate evidence passes untouched.
*/
const PLACEHOLDER_EVIDENCE = /* @__PURE__ */ new Set([
	"-",
	"--",
	"n/a",
	"na",
	"n.a",
	"n.a.",
	"none",
	"nil",
	"null",
	"tbd",
	"tba",
	"todo",
	"pending",
	"x",
	"xx",
	"n",
	"unknown",
	"unclear",
	"not applicable",
	"not available",
	"see notes",
	"see above",
	"done",
	"ok",
	"okay",
	"yes",
	"no",
	"y",
	"see above",
	"as above",
	"same as before",
	"various",
	"no evidence",
	"none yet",
	"later",
	"to be added",
	"to be defined",
	"无",
	"略",
	"暂无",
	"未知",
	"不清楚",
	"不适用",
	"见备注",
	"见说明",
	"已确认",
	"已完成",
	"同上",
	"见上",
	"待补",
	"待补充",
	"待定",
	"待确认",
	"不详",
	"没有",
	"未提供"
]);
/**
* Whether an evidence pointer is specific enough to support a "confirmed" claim.
*
* Scope, deliberately: this rejects *placeholders*, it does not judge evidence quality. An
* operator writing "done" or "n/a" has named nothing, so the gate treats the checkpoint as
* unconfirmed. Anything that looks like it points somewhere — a file, a URL, an id, a
* command, a capture, a sentence describing what was seen — passes untouched, because
* deciding whether a pointer is *good* is a human judgement, not this function's job.
*/
function isEvidencePointer(evidence) {
	const value = (evidence ?? "").trim().toLowerCase().replace(/^[*_`~\s]+|[.*_`~\s]+$/g, "").replace(/[。．.!！?？,，;；:：]+$/g, "");
	if (value.length < 3) return false;
	if (PLACEHOLDER_EVIDENCE.has(value)) return false;
	return true;
}
function runVerify(input) {
	const { task, stage, limits } = input;
	const checkpoints = task.checkpoints[stage] ?? [];
	const confirmed = checkpoints.filter((item) => item.level === "confirmed" && isEvidencePointer(item.evidence));
	const partial = checkpoints.filter((item) => item.level === "partial");
	const unknown = checkpoints.filter((item) => item.level === "unknown");
	const hollowConfirmed = checkpoints.filter((item) => item.level === "confirmed" && !isEvidencePointer(item.evidence));
	const reasons = [];
	const openGaps = [];
	if (checkpoints.length === 0) openGaps.push(`No evidence checkpoints recorded for stage "${stage}".`);
	if (confirmed.length === 0) openGaps.push(`No "confirmed" checkpoint at stage "${stage}" (partial=${partial.length}, unknown=${unknown.length}).`);
	if (hollowConfirmed.length > 0) openGaps.push(`${hollowConfirmed.length} checkpoint(s) declare level "confirmed" without an evidence pointer (e.g. ${JSON.stringify(hollowConfirmed[0]?.evidence ?? "")}); a declared level is not evidence.`);
	const unresolved = unknown.length;
	if (unresolved > 0) openGaps.push(`${unresolved} checkpoint(s) are marked "unknown" and must be resolved or re-classified.`);
	if (stage === "recon" && task.targets.length === 0) openGaps.push("The task has no targets recorded; recon cannot be attested.");
	if (stage === "vuln-discovery" && checkpoints.length > 0 && confirmed.length === 0) openGaps.push("Vulnerability discovery produced only unconfirmed observations.");
	if (stage === "exploitation") {
		if (checkpoints.filter((item) => /marker|回显|echo/i.test(`${item.summary} ${item.evidence}`)).length === 0) openGaps.push("Exploitation evidence lacks a baseline/diff/marker triple reference.");
	}
	if (stage === "traceback") {
		if (checkpoints.filter((item) => /检测|detect|防守|defen|rule|规则/i.test(`${item.summary} ${item.evidence}`)).length === 0) openGaps.push("Traceback stage requires at least one defender-facing detection conclusion.");
	}
	if (checkpoints.length > limits.maxCheckpointsPerStage) reasons.push(`Stage "${stage}" recorded ${checkpoints.length} checkpoints, above the configured ceiling of ${limits.maxCheckpointsPerStage}; the stage is saturated and should close.`);
	if (task.violations.length > 0) openGaps.push(`Task has ${task.violations.length} recorded doctrine violation(s); resolve them before advancing.`);
	const pass = openGaps.length === 0;
	if (pass) reasons.push(`Stage "${stage}" attested: ${confirmed.length} confirmed checkpoint(s), ${partial.length} partial. Evidence is sufficient to advance.`);
	else reasons.push(`Stage "${stage}" NOT attested: ${openGaps.length} open gap(s).`);
	const body = {
		stage,
		pass,
		reasons,
		openGaps,
		checkedAt: (/* @__PURE__ */ new Date()).toISOString(),
		atStage: task.stage,
		cpCount: checkpoints.length,
		confirmedCount: confirmed.length
	};
	return {
		...body,
		token: verdictToken(body)
	};
}
/**
* Enforce the target allowlist for a task and return the refusal text when it fails.
* @returns `undefined` when every target is authorized.
*/
function scopeRefusal(targets, allowlist) {
	const { allowed, verdicts, rejected } = checkTargets(targets, allowlist);
	if (allowed) return void 0;
	const detail = verdicts.filter((verdict) => !verdict.allowed).map((verdict) => `- ${verdict.target}: ${verdict.reason}`).join("\n");
	return {
		refusal: `Refused: ${rejected.length} target(s) are outside the authorized range. Out-of-scope operations are refused.\n${detail}`,
		verdicts
	};
}
/**
* Cross-process mutual exclusion for the state file.
*
* The in-process promise chain serializes tool calls inside ONE host. Two DSH processes sharing a
* `stateDir` (two modes open at once, or a CLI call beside a running web host) still raced: both
* read the file, both mutated their own copy, and the second rename overwrote the first — an audit
* measured 28-30 of 60 records lost. Creating a lock file with `wx` IS the acquisition (it fails if
* the path exists); the holder's pid lets a waiter clear a lock left by a dead process.
*
* Scope: one machine's filesystem. Not distributed; a very slow holder can be pre-empted after the
* stale timeout, which is acceptable because the critical section is a small read, a mutation and a
* rename.
*/
const LOCK_STALE_MS = 1e4;
/** Modification time in ms, or `undefined` when the path is gone. */
function mtimeOrUndefined(path) {
	try {
		return statSync(path).mtimeMs;
	} catch {
		return;
	}
}
/** Acquire the write lock, waiting up to `timeoutMs`. Resolves to a release function. */
async function acquireLock(lockPath, timeoutMs = 15e3) {
	const deadline = Date.now() + timeoutMs;
	for (;;) try {
		const handle = openSync(lockPath, "wx");
		writeSync(handle, String(process.pid));
		closeSync(handle);
		let released = false;
		return async () => {
			if (released) return;
			released = true;
			await unlink(lockPath).catch(() => void 0);
		};
	} catch (error) {
		if (error.code !== "EEXIST") throw error;
		const age = mtimeOrUndefined(lockPath);
		if (age !== void 0 && Date.now() - age > LOCK_STALE_MS) {
			await unlink(lockPath).catch(() => void 0);
			continue;
		}
		if (Date.now() > deadline) throw new Error(`timed out waiting for the state lock at ${lockPath}`);
		await new Promise((resolve) => setTimeout(resolve, 15 + Math.random() * 35));
	}
}
//#endregion
//#region src/experience.ts
/**
* The deployment's battle-knowledge store — the "experience system".
*
* What it is for
* --------------
* Twelve modes run over each other's leftovers, but nothing here gives them a place
* to leave what they LEARNED. This store is that place: one SQLite file, every mode
* reads and writes the same one, so a lesson recorded in one mode is recalled in the
* next — across targets and across sessions.
*
* What belongs in it
* ------------------
* Lessons, not bookkeeping. Per-target facts already have homes: assets, findings and
* scores live in the vendor ledger, and per-task detail lives in the orchestration
* ledger. A record here should change how the NEXT engagement is run.
*
* Design notes (mechanisms worth keeping)
* ---------------------------------------
* - **Scoped by mode × workspace.** Recall filtering starts from the mode that asks
*   and the directory it works in; a workspace key carries a path hash so two
*   directories with the same basename do not read each other's notes.
* - **FTS5 trigram search.** Multi-term queries are OR-ed, so a term split off from
*   the whole still hits, and CJK substrings of three or more characters are
*   searchable (the default tokenizer swallows a Chinese run into one token).
*   Falls back to a `LIKE` scan when FTS5 is unavailable in the build.
* - **Usage-ranked with a 30-day half-life.** Recalling a record is what earns it a
*   place in the next recall (`get`/`work` counts, a preview listing does not), so
*   the store keeps surfacing what is actually used instead of what arrived first.
* - **Expiry by kind.** Detection intel goes stale; target fingerprints less so.
*   Expired records drop out of automatic recall but stay searchable.
* - **Bounded, with an archive.** Past the per-workspace ceiling the coldest records
*   move to an archive table instead of being deleted.
*/
/** Record kinds, aligned with the sibling campaign-memory plugin so one habit fits both. */
const EXPERIENCE_KINDS = [
	"tactic",
	"fingerprint",
	"tooling",
	"lesson",
	"detect"
];
/** Chinese labels used in the rendered blocks. */
const KIND_LABELS = {
	tactic: "战术打法",
	fingerprint: "目标指纹",
	tooling: "工具可用性",
	lesson: "教训",
	detect: "检测指纹"
};
/** Default time-to-live per kind, in days; `undefined` means "never expires". */
const KIND_TTL_DAYS = {
	tactic: void 0,
	fingerprint: 180,
	tooling: void 0,
	lesson: void 0,
	detect: 30
};
/** Bodies are truncated to this many characters, with the caller told. */
const MAX_BODY_CHARS = 4e3;
/** Marker around the injected block, so it stays recognisable after compaction. */
const INJECT_TAG = "dsh-f2x-experience";
/** Why a write or query was refused. */
var ExperienceError = class extends Error {};
/** `name@hash8` for a working directory; empty for a session without one. */
function workspaceOf(cwd) {
	if (typeof cwd !== "string" || cwd === "") return {
		name: "",
		key: ""
	};
	const name = basename(cwd).slice(0, 60);
	return {
		name,
		key: `${name}@${createHash("sha256").update(cwd).digest("hex").slice(0, 8)}`
	};
}
/** Column list every row reader shares. */
const COLUMNS = `id, kind, title, content, tags, target_kind, mode, workspace, workspace_key,
  usage_count, last_used_at, source_session, expires_at, created_at, updated_at`;
/** Cold-order ranking: weight falls by half every 30 idle days. */
const COLD_ORDER = `ORDER BY (usage_count + 1.0) * pow(0.5, (julianday('now') - julianday(COALESCE(NULLIF(last_used_at, ''), created_at))) / ${String(30)}.0) ASC, updated_at ASC`;
/** Hot-order ranking, the inverse of {@link COLD_ORDER}. */
const HOT_ORDER = `ORDER BY (usage_count + 1.0) * pow(0.5, (julianday('now') - julianday(COALESCE(NULLIF(last_used_at, ''), created_at))) / ${String(30)}.0) DESC, updated_at DESC`;
const SCHEMA = `
CREATE TABLE IF NOT EXISTS experiences (
  id             TEXT PRIMARY KEY,
  kind           TEXT NOT NULL,
  title          TEXT NOT NULL,
  content        TEXT NOT NULL,
  tags           TEXT NOT NULL DEFAULT '',
  target_kind    TEXT NOT NULL DEFAULT '',
  mode           TEXT NOT NULL DEFAULT '',
  workspace      TEXT NOT NULL DEFAULT '',
  workspace_key  TEXT NOT NULL DEFAULT '',
  usage_count    INTEGER NOT NULL DEFAULT 0,
  last_used_at   TEXT DEFAULT '',
  source_session TEXT NOT NULL DEFAULT '',
  expires_at     TEXT,
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS experiences_archive (
  id             TEXT PRIMARY KEY,
  kind           TEXT NOT NULL,
  title          TEXT NOT NULL,
  content        TEXT NOT NULL,
  tags           TEXT NOT NULL DEFAULT '',
  target_kind    TEXT NOT NULL DEFAULT '',
  mode           TEXT NOT NULL DEFAULT '',
  workspace      TEXT NOT NULL DEFAULT '',
  workspace_key  TEXT NOT NULL DEFAULT '',
  usage_count    INTEGER NOT NULL DEFAULT 0,
  last_used_at   TEXT DEFAULT '',
  source_session TEXT NOT NULL DEFAULT '',
  expires_at     TEXT,
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL,
  archived_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS experiences_scope ON experiences(mode, workspace_key);
CREATE INDEX IF NOT EXISTS experiences_dedupe ON experiences(mode, workspace_key, title, target_kind);
`;
/** Seconds-resolution UTC stamp, the form SQLite's date functions read directly. */
function stamp(now) {
	return now.toISOString().replace("T", " ").slice(0, 19);
}
/** Add days to a stamp. */
function plusDays(now, days) {
	return stamp(new Date(now.getTime() + days * 864e5));
}
/** Trim and cap a free-text field. */
function clean(value, max) {
	return String(value ?? "").trim().slice(0, max);
}
/** Comma-joined tags, normalised so a re-write does not duplicate one. */
function normaliseTags(tags) {
	const list = typeof tags === "string" ? tags.split(",") : tags ?? [];
	const seen = /* @__PURE__ */ new Set();
	const out = [];
	for (const tag of list) {
		const trimmed = tag.trim();
		if (trimmed === "") continue;
		const folded = trimmed.toLowerCase();
		if (seen.has(folded)) continue;
		seen.add(folded);
		out.push(trimmed);
	}
	return out.join(", ");
}
/** Split a stored tag string back into a list. */
function splitTags(value) {
	return String(value ?? "").split(",").map((tag) => tag.trim()).filter((tag) => tag !== "");
}
/** Whether a value names a known kind. */
function isExperienceKind(value) {
	return EXPERIENCE_KINDS.includes(value);
}
/** Map a row onto the record shape, tolerating missing columns. */
function toRecord(row) {
	const kind = isExperienceKind(row.kind) ? row.kind : "lesson";
	const lastUsedAt = String(row.last_used_at ?? "");
	const expiresAt = row.expires_at === null || row.expires_at === void 0 ? "" : String(row.expires_at);
	return {
		id: String(row.id),
		kind,
		title: String(row.title ?? ""),
		content: String(row.content ?? ""),
		tags: splitTags(row.tags),
		targetKind: String(row.target_kind ?? ""),
		mode: String(row.mode ?? ""),
		workspace: String(row.workspace ?? ""),
		workspaceKey: String(row.workspace_key ?? ""),
		usageCount: Number(row.usage_count ?? 0),
		...lastUsedAt === "" ? {} : { lastUsedAt },
		sourceSession: String(row.source_session ?? ""),
		...expiresAt === "" ? {} : { expiresAt },
		createdAt: String(row.created_at ?? ""),
		updatedAt: String(row.updated_at ?? "")
	};
}
/**
* One store over one database file.
*
* Instances are cheap and hold no cache between calls: every mode mounts this plugin
* and they all point at the same path, so the file is the only truth. WAL plus a busy
* timeout keeps two `dsh` processes from failing each other's writes, and the two
* processes are the normal case here (a host run and a test harness).
*/
var ExperienceStore = class {
	file;
	enabled;
	db;
	fts = false;
	constructor(stateDir, enabled) {
		this.file = join(stateDir, "experience.db");
		this.enabled = enabled;
	}
	/** Absolute path of the backing file, reported to the model for traceability. */
	get path() {
		return this.file;
	}
	/** Whether writes reach disk. */
	get persistent() {
		return this.enabled;
	}
	/** Whether the full-text index is in use (false means the `LIKE` fallback). */
	get fullText() {
		return this.fts;
	}
	/** Open the store, creating schema and index on first use. */
	open() {
		if (this.db !== void 0) return this.db;
		if (!this.enabled) {
			const memory = new DatabaseSync(":memory:");
			memory.exec(SCHEMA);
			this.db = memory;
			return memory;
		}
		mkdirSync(dirname(this.file), { recursive: true });
		const db = new DatabaseSync(this.file);
		try {
			db.exec("PRAGMA journal_mode = WAL");
			db.exec("PRAGMA busy_timeout = 5000");
		} catch {}
		db.exec(SCHEMA);
		try {
			db.exec(`CREATE VIRTUAL TABLE IF NOT EXISTS experiences_fts USING fts5(
        title, content, tags, content='experiences', content_rowid='rowid', tokenize='trigram')`);
			db.exec(`CREATE TRIGGER IF NOT EXISTS experiences_fts_ai AFTER INSERT ON experiences BEGIN
        INSERT INTO experiences_fts(rowid, title, content, tags) VALUES (new.rowid, new.title, new.content, new.tags); END`);
			db.exec(`CREATE TRIGGER IF NOT EXISTS experiences_fts_ad AFTER DELETE ON experiences BEGIN
        INSERT INTO experiences_fts(experiences_fts, rowid, title, content, tags) VALUES ('delete', old.rowid, old.title, old.content, old.tags); END`);
			db.exec(`CREATE TRIGGER IF NOT EXISTS experiences_fts_au AFTER UPDATE ON experiences BEGIN
        INSERT INTO experiences_fts(experiences_fts, rowid, title, content, tags) VALUES ('delete', old.rowid, old.title, old.content, old.tags);
        INSERT INTO experiences_fts(rowid, title, content, tags) VALUES (new.rowid, new.title, new.content, new.tags); END`);
			db.exec("INSERT INTO experiences_fts(experiences_fts) VALUES ('rebuild')");
			this.fts = true;
		} catch {
			this.fts = false;
		}
		this.db = db;
		return db;
	}
	/** Close the store; a no-op when nothing was opened. */
	close() {
		this.db?.close();
		this.db = void 0;
	}
	/**
	* Insert or refresh one record.
	*
	* The same mode + workspace + title + target kind refreshes the existing record
	* rather than adding a near-duplicate: the store is scoped for recall, and a store
	* that grows a copy per re-learning turns recall into noise. Usage count survives a
	* refresh, and the caller gets the previous body as a receipt so a wrong merge is
	* visible instead of silent.
	*/
	write(input, now = /* @__PURE__ */ new Date()) {
		const title = clean(input.title, 200);
		if (title === "") throw new ExperienceError("experience write requires a title");
		const kind = isExperienceKind(input.kind) ? input.kind : "lesson";
		const raw = String(input.content ?? "");
		const truncated = raw.length > MAX_BODY_CHARS;
		const content = raw.slice(0, MAX_BODY_CHARS);
		const tags = normaliseTags(input.tags);
		const targetKind = clean(input.targetKind, 60);
		const workspace = clean(input.workspace, 60);
		const workspaceKey = clean(input.workspaceKey, 80);
		const ttl = input.expiresDays !== void 0 && Number.isFinite(input.expiresDays) ? input.expiresDays : KIND_TTL_DAYS[kind];
		const expiresAt = ttl === void 0 ? null : plusDays(now, ttl);
		const db = this.open();
		const existing = db.prepare(`SELECT ${COLUMNS} FROM experiences WHERE mode = ? AND workspace_key = ? AND title = ? AND target_kind = ?`).get(input.mode, workspaceKey, title, targetKind);
		const at = stamp(now);
		if (existing === void 0) {
			const count = Number(db.prepare("SELECT COUNT(*) AS n FROM experiences").get().n ?? 0);
			const id = `f2x-exp-${String(nextExperienceSerial(db, count))}`;
			db.prepare(`INSERT INTO experiences (${COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(...[
				id,
				kind,
				title,
				content,
				tags,
				targetKind,
				input.mode,
				workspace,
				workspaceKey,
				0,
				"",
				clean(input.sourceSession, 80),
				expiresAt,
				at,
				at
			].map((value) => value === null || value === void 0 ? null : value));
			const evicted = this.evict(db);
			return {
				record: this.get(id),
				refreshed: false,
				truncated,
				evicted
			};
		}
		const previous = toRecord(existing);
		db.prepare(`UPDATE experiences SET kind = ?, content = ?, tags = ?, expires_at = ?, updated_at = ? WHERE id = ?`).run(kind, content, tags, expiresAt, at, previous.id);
		return {
			record: this.get(previous.id),
			refreshed: true,
			truncated,
			previous: {
				chars: previous.content.length,
				preview: clean(previous.content.split("\n")[0], 80)
			},
			evicted: this.evict(db)
		};
	}
	/** One record by id, or `undefined`. */
	get(id) {
		const row = this.open().prepare(`SELECT ${COLUMNS} FROM experiences WHERE id = ?`).get(id);
		return row === void 0 ? void 0 : toRecord(row);
	}
	/**
	* Search records, best match first.
	*
	* Terms are OR-ed through FTS5 so a split-off word still hits, then blended with the
	* usage ranking: a lexically closer record wins, and among equals the one that has
	* actually been used wins. Expired records are excluded unless asked for.
	*/
	search(query = {}) {
		const db = this.open();
		const limit = Math.max(1, Math.min(query.limit ?? 10, 50));
		const where = [];
		const params = [];
		if (query.kind !== void 0 && isExperienceKind(query.kind)) {
			where.push("e.kind = ?");
			params.push(query.kind);
		}
		if (query.mode !== void 0 && query.mode !== "") {
			where.push("e.mode = ?");
			params.push(query.mode);
		}
		if (query.workspaceKey !== void 0 && query.workspaceKey !== "") {
			where.push("e.workspace_key = ?");
			params.push(query.workspaceKey);
		}
		if (query.targetKind !== void 0 && query.targetKind !== "") {
			where.push("e.target_kind = ?");
			params.push(query.targetKind);
		}
		if (query.includeExpired !== true) where.push("(e.expires_at IS NULL OR e.expires_at = '' OR e.expires_at > datetime('now'))");
		const terms = (query.q ?? "").split(/\s+/).map((term) => term.trim()).filter((term) => term !== "");
		return terms.length > 0 && this.fts ? this.searchFts(db, terms, where, params, limit) : this.searchScan(db, terms, where, params, limit);
	}
	/** FTS5 branch: OR the terms, blend bm25 with the usage rank. */
	searchFts(db, terms, where, params, limit) {
		const match = terms.map((term) => term.startsWith("\"") ? term : `"${term.replaceAll("\"", "\"\"")}"`).join(" OR ");
		const clauses = [...where, "experiences_fts MATCH ?"];
		const sql = `SELECT ${COLUMNS.split(", ").map((column) => `e.${column}`).join(", ")},
        snippet(experiences_fts, 1, '', '', '…', 12) AS snip, bm25(experiences_fts) AS bm
      FROM experiences_fts
      JOIN experiences e ON e.rowid = experiences_fts.rowid
      WHERE ${clauses.join(" AND ")}
      ORDER BY (bm25(experiences_fts) + 12.0) / (1.0 + (e.usage_count + 1.0) * pow(0.5, (julianday('now') - julianday(COALESCE(NULLIF(e.last_used_at, ''), e.created_at))) / ${String(30)}.0))
      LIMIT ?`;
		try {
			return db.prepare(sql).all(...params, match, limit).map((row) => this.toHit(row));
		} catch {
			return this.searchScan(db, terms, where, params, limit);
		}
	}
	/** LIKE branch: every term must appear, used when FTS5 is unavailable. */
	searchScan(db, terms, where, params, limit) {
		const clauses = [...where];
		const local = [];
		const stripped = terms.map((term) => term.replaceAll("%", "").replaceAll("_", ""));
		for (const term of stripped) {
			clauses.push("(e.title LIKE ? OR e.content LIKE ? OR e.tags LIKE ?)");
			local.push(`%${term}%`, `%${term}%`, `%${term}%`);
		}
		const sql = `SELECT ${COLUMNS.split(", ").map((column) => `e.${column}`).join(", ")}, '' AS snip
      FROM experiences e
      ${clauses.length === 0 ? "" : `WHERE ${clauses.join(" AND ")}`}
      ${terms.length > 0 ? HOT_ORDER.replaceAll("usage_count", "e.usage_count").replaceAll("last_used_at", "e.last_used_at").replaceAll("created_at", "e.created_at").replaceAll("updated_at", "e.updated_at") : HOT_ORDER}
      LIMIT ?`;
		return db.prepare(sql).all(...params, ...local, limit).map((row) => this.toHit(row));
	}
	/** Row → hit, deriving the snippet when the query had no FTS window. */
	toHit(row) {
		const record = toRecord(row);
		const rawSnip = String(row.snip ?? "").trim();
		const snippet = rawSnip === "" ? clean(record.content.split("\n")[0], 160) : rawSnip;
		const expiresAt = record.expiresAt;
		return {
			record,
			snippet,
			expired: expiresAt !== void 0 && expiresAt !== "" && expiresAt <= stamp(/* @__PURE__ */ new Date())
		};
	}
	/**
	* Records an automatic recall block should carry for one mode×workspace.
	*
	* Expired records are left out on purpose: a stale detection fingerprint must not
	* be injected as if it still held, and it stays reachable by search when asked for.
	*/
	topForInjection(mode, workspaceKey, limit = 3) {
		return this.open().prepare(`SELECT ${COLUMNS} FROM experiences
         WHERE mode = ? AND workspace_key = ? AND (expires_at IS NULL OR expires_at = '' OR expires_at > datetime('now'))
         ${HOT_ORDER}
         LIMIT ?`).all(mode, workspaceKey, limit).map(toRecord);
	}
	/** List one scope's records, newest first, without touching the usage ranking. */
	list(options = {}) {
		const db = this.open();
		const where = [];
		const params = [];
		if (options.mode !== void 0 && options.mode !== "") {
			where.push("mode = ?");
			params.push(options.mode);
		}
		if (options.workspaceKey !== void 0 && options.workspaceKey !== "") {
			where.push("workspace_key = ?");
			params.push(options.workspaceKey);
		}
		if (options.kind !== void 0 && isExperienceKind(options.kind)) {
			where.push("kind = ?");
			params.push(options.kind);
		}
		const limit = Math.max(1, Math.min(options.limit ?? 20, 200));
		return db.prepare(`SELECT ${COLUMNS} FROM experiences ${where.length === 0 ? "" : `WHERE ${where.join(" AND ")}`} ORDER BY updated_at DESC, id DESC LIMIT ?`).all(...params, limit).map(toRecord);
	}
	/** Count one scope without loading the rows. */
	size(options = {}) {
		const db = this.open();
		const where = [];
		const params = [];
		if (options.mode !== void 0 && options.mode !== "") {
			where.push("mode = ?");
			params.push(options.mode);
		}
		if (options.workspaceKey !== void 0 && options.workspaceKey !== "") {
			where.push("workspace_key = ?");
			params.push(options.workspaceKey);
		}
		const row = db.prepare(`SELECT COUNT(*) AS n FROM experiences ${where.length === 0 ? "" : `WHERE ${where.join(" AND ")}`}`).get(...params);
		return Number(row.n ?? 0);
	}
	/**
	* Record that records were actually read.
	*
	* This is the only thing that raises a record's rank: a listing that was skimmed is
	* not a use, but fetching a record's body is.
	*/
	markUsed(ids, now = /* @__PURE__ */ new Date()) {
		if (ids.length === 0) return 0;
		const db = this.open();
		const at = stamp(now);
		let touched = 0;
		const statement = db.prepare("UPDATE experiences SET usage_count = usage_count + 1, last_used_at = ? WHERE id = ?");
		for (const id of ids) touched += Number(statement.run(at, id).changes ?? 0);
		return touched;
	}
	/** Remove records, moving them to the archive instead of deleting them. */
	archive(ids, now = /* @__PURE__ */ new Date()) {
		if (ids.length === 0) return 0;
		const db = this.open();
		const at = stamp(now);
		let moved = 0;
		for (const id of ids) {
			const row = db.prepare(`SELECT ${COLUMNS} FROM experiences WHERE id = ?`).get(id);
			if (row === void 0) continue;
			db.prepare(`INSERT OR REPLACE INTO experiences_archive (${COLUMNS}, archived_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(...[
				row.id,
				row.kind,
				row.title,
				row.content,
				row.tags,
				row.target_kind,
				row.mode,
				row.workspace,
				row.workspace_key,
				row.usage_count,
				row.last_used_at,
				row.source_session,
				row.expires_at,
				row.created_at,
				row.updated_at,
				at
			].map((value) => value === void 0 ? null : value));
			db.prepare("DELETE FROM experiences WHERE id = ?").run(id);
			moved += 1;
		}
		return moved;
	}
	/** Drop records past their expiry, archiving them first. */
	purgeExpired(now = /* @__PURE__ */ new Date()) {
		const rows = this.open().prepare(`SELECT id FROM experiences WHERE expires_at IS NOT NULL AND expires_at != '' AND expires_at <= ?`).all(stamp(now));
		return this.archive(rows.map((row) => String(row.id)), now);
	}
	/** Archive the coldest records of one workspace past the ceiling; returns how many. */
	evict(db) {
		const scopes = db.prepare(`SELECT mode, workspace_key, COUNT(*) AS n FROM experiences GROUP BY mode, workspace_key HAVING n > ?`).all(400);
		let moved = 0;
		for (const scope of scopes) {
			const excess = Number(scope.n ?? 0) - 400;
			if (excess <= 0) continue;
			const cold = db.prepare(`SELECT id FROM experiences WHERE mode = ? AND workspace_key = ? ${COLD_ORDER} LIMIT ?`).all(String(scope.mode ?? ""), String(scope.workspace_key ?? ""), excess);
			moved += this.archive(cold.map((row) => String(row.id)));
		}
		return moved;
	}
	/** Per-scope record counts, live and archived, for both kinds of scope. */
	stats() {
		const db = this.open();
		const group = (table) => db.prepare(`SELECT mode, workspace_key AS workspace, COUNT(*) AS rows FROM ${table} GROUP BY mode, workspace_key`).all();
		const key = (mode, workspace) => `${String(mode)}\u0000${String(workspace)}`;
		const live = group("experiences");
		const archiveMap = new Map(group("experiences_archive").map((row) => [key(row.mode, row.workspace), Number(row.rows ?? 0)]));
		const liveMap = new Map(live.map((row) => [key(row.mode, row.workspace), Number(row.rows ?? 0)]));
		return [.../* @__PURE__ */ new Set([...liveMap.keys(), ...archiveMap.keys()])].map((scope) => {
			const [mode = "", workspace = ""] = scope.split("\0");
			return {
				mode,
				workspace,
				rows: liveMap.get(scope) ?? 0,
				archived: archiveMap.get(scope) ?? 0
			};
		}).sort((left, right) => right.rows - left.rows || right.archived - left.archived);
	}
};
/** Next sequential record id, past every id the table already holds. */
function nextExperienceSerial(db, _count, prefix = "f2x-exp") {
	const row = db.prepare(`SELECT MAX(CAST(substr(id, ?) AS INTEGER)) AS max FROM experiences WHERE id LIKE ?`).get(prefix.length + 2, `${prefix}-%`);
	const max = Number(row?.max ?? 0);
	return Number.isFinite(max) ? max + 1 : 1;
}
/**
* The automatic recall block for one mode×workspace.
*
* Marker-tagged so it survives compaction recognition, budgeted so it cannot grow
* with the store: over budget the DATA lines are dropped one by one and the guide
* line goes last — a recall block that costs an unbounded number of tokens is worse
* than no recall block. Deterministic: the same store state renders the same text.
*/
/** Neutralise `{{` so a stored note can never be parsed as a prompt variable. */
function promptSafe(text) {
	return text.replaceAll("{{", "{ {");
}
function buildExperienceBlock(mode, workspace, rows, budget = 700) {
	if (rows.length === 0) return "";
	const close = `</${INJECT_TAG}>`;
	const guide = "沉淀/检索：有效打法即时 f2x_exp 写入（同题刷新不重复）；开工、接案或换目标类型先 f2x_exp_search 检索。";
	const build = (kept) => [
		`<${INJECT_TAG} mode="${mode}" workspace="${workspace}" n="${String(kept.length)}">`,
		"本模式本工作区经验（历史沉淀；适用性自判——目标环境可能已变化）：",
		...kept.map((record, index) => `${String(index + 1)}. [${KIND_LABELS[record.kind]}${record.targetKind === "" ? "" : `·${record.targetKind}`}${record.usageCount > 0 ? `·用${String(record.usageCount)}` : ""}] ${record.title}——${clean(record.content.split("\n")[0], 150)}`),
		guide
	].join("\n") + `\n${close}`;
	let kept = rows.slice();
	let text = build(kept);
	while (kept.length > 0 && text.length > budget) {
		kept = kept.slice(0, -1);
		text = build(kept);
	}
	if (text.length > budget) {
		const tail = `…\n${close}`;
		text = text.slice(0, budget - tail.length) + tail;
	}
	const safe = promptSafe(text);
	// A complete {{...}} group left here would be read as a prompt variable by
	// the host and would fail the WHOLE turn, not just this block. Recall is
	// worth less than the session: drop the block instead of poisoning the prompt.
	return /\{\{[^{}]*\}\}/.test(safe) ? "" : safe;
}
/** One line for a listing: what it is, and how to get the rest. */
function renderExperienceLine(record) {
	const meta = [KIND_LABELS[record.kind], ...record.tags.length > 0 ? [record.tags.join("/")] : []].join(" ");
	const target = record.targetKind === "" ? "" : `·${record.targetKind}`;
	const used = record.usageCount > 0 ? ` (用${String(record.usageCount)})` : "";
	const first = clean(record.content.split("\n").find((line) => line.trim() !== "") ?? "", 120);
	return `- ${record.id} [${meta}${target}] ${record.title}${used}${first === "" ? "" : ` — ${first}`}`;
}
/** The whole record, for when a listing line is not enough. */
function renderExperience(record) {
	const expired = record.expiresAt !== void 0 && record.expiresAt !== "" && record.expiresAt <= stamp(/* @__PURE__ */ new Date());
	return [
		`# ${record.title} (${record.id})`,
		`kind: ${record.kind}${record.tags.length > 0 ? ` | tags: ${record.tags.join(", ")}` : ""}${record.targetKind === "" ? "" : ` | target: ${record.targetKind}`}`,
		`mode: ${record.mode} | workspace: ${record.workspaceKey === "" ? "(none)" : record.workspaceKey} | source: ${record.sourceSession === "" ? "(unknown)" : record.sourceSession}`,
		`created: ${record.createdAt} | updated: ${record.updatedAt}${record.usageCount > 0 ? ` | used: ${String(record.usageCount)}x` : ""}${record.expiresAt === void 0 ? "" : ` | expires: ${record.expiresAt}${expired ? " (EXPIRED)" : ""}`}`,
		"",
		record.content.trim() === "" ? "(no body)" : record.content.trim()
	].join("\n");
}
//#endregion
//#region src/console.ts
/** Assemble the console payload from already-resolved inputs. Pure, so it is tested directly. */
function buildConsoleSnapshot(input) {
	const { state } = input;
	const tasks = Object.values(state.tasks);
	return {
		plugin: input.plugin,
		generatedAt: input.now ?? (/* @__PURE__ */ new Date()).toISOString(),
		mode: state.mode,
		activeTaskId: state.activeTaskId ?? null,
		paths: input.paths,
		config: input.config,
		capabilities: input.capabilities,
		counts: {
			tasks: tasks.length,
			blackboard: state.blackboard.length,
			findings: state.findings.length,
			audit: state.audit.length
		},
		tasks,
		blackboard: state.blackboard,
		findings: state.findings,
		audit: state.audit.slice(-100)
	};
}
/** Escape text for interpolation into HTML text and attribute positions. */
function escapeHtml(value) {
	return String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
/**
* Whether a socket address is the loopback interface.
*
* The console is served from the raw web server, which carries no trust fence, so
* the handler enforces its own. The ledger holds live engagement data — targets,
* evidence, and whatever an operator noted on the blackboard — and the host may be
* bound to `0.0.0.0` (`dsh web --host 0.0.0.0`), which would otherwise publish all
* of it to the network with no authentication.
*
* Accepts the IPv4 loopback block `127.0.0.0/8`, IPv6 `::1`, and the IPv4-mapped
* form Node reports for an IPv6 socket (`::ffff:127.0.0.1`).
*/
function isLoopbackAddress(address) {
	if (typeof address !== "string" || address === "") return false;
	const normalised = address.startsWith("::ffff:") ? address.slice(7) : address;
	if (normalised === "::1" || normalised === "localhost") return true;
	const octets = normalised.split(".");
	return octets.length === 4 && octets[0] === "127";
}
/**
* The console page.
*
* Self-contained: no network fetches, no build step, no external assets. The page,
* its JSON payload and the raw-ledger download are all served by the same host
* route. The inline script uses string concatenation only — a template literal
* would be interpolated by the TypeScript template this function returns.
*/
function renderConsoleHtml(title) {
	return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
:root{--bg:#0f1115;--panel:#171a21;--line:#272c37;--fg:#e6e9ef;--dim:#9aa3b2;--ok:#3fb950;--no:#6e7681;--warn:#d29922;--err:#f85149}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{padding:18px 22px;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:10px 18px;align-items:baseline}
h1{margin:0;font-size:18px;font-weight:650}
.tag{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--dim)}
a{color:#58a6ff}
main{padding:18px 22px;display:grid;gap:18px;grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}
section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;min-width:0}
section.wide{grid-column:1/-1}
h2{margin:0 0 10px;font-size:13px;letter-spacing:.06em;text-transform:uppercase;color:var(--dim);font-weight:600;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
input[type=search]{margin-left:auto;background:var(--bg);border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:3px 8px;font:12px ui-monospace,Menlo,monospace;min-width:180px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
th{color:var(--dim);font-weight:600;font-size:12px}
tr:last-child td{border-bottom:0}
code,.mono{font:12px ui-monospace,SFMono-Regular,Menlo,monospace}
.ok{color:var(--ok)}.no{color:var(--no)}.warn{color:var(--warn)}.err{color:var(--err)}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;border:1px solid var(--line);font-size:12px}
.empty{color:var(--dim);margin:0}
.kv{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:13px}
.kv div:nth-child(odd){color:var(--dim)}
.notice{border-color:var(--warn);color:var(--warn);margin-bottom:10px}
.err-box{border-color:var(--err);color:var(--err)}
</style></head>
<body>
<header>
  <h1 id="title">${escapeHtml(title)}</h1>
  <span class="tag" id="meta">加载中…</span>
  <a class="tag" href="/f2x-console/raw" download="f2x-state.json">下载原始台账</a>
</header>
<main id="root"><section class="wide"><p class="empty">读取 /f2x-console/state …</p></section></main>
<script>
var esc = function (v) { return String(v == null ? '' : v); };
var el = function (tag, attrs) {
  var n = document.createElement(tag);
  var a = attrs || {};
  for (var k in a) if (Object.prototype.hasOwnProperty.call(a, k)) n.setAttribute(k, a[k]);
  for (var i = 2; i < arguments.length; i++) {
    var kid = arguments[i];
    if (kid == null) continue;
    if (Array.isArray(kid)) { for (var j = 0; j < kid.length; j++) if (kid[j] != null) n.append(kid[j]); }
    else n.append(kid);
  }
  return n;
};
var text = function (s) { return document.createTextNode(String(s == null ? '' : s)); };
var code = function (s, cls) { return el('span', { 'class': 'mono ' + (cls || '') }, text(s)); };
var cell = function (c) { return el('td', {}, typeof c === 'string' ? text(c) : c); };

/** A section whose rows can be filtered. \`rows\` are already-built cell arrays. */
function filterable(title, headers, rows, emptyText, haystack) {
  var input = el('input', { type: 'search', placeholder: '筛选…' });
  var body = el('tbody', {});
  var table = el('table', {}, el('thead', {}, el('tr', {}, headers.map(function (h) { return el('th', {}, text(h)); }))), body);
  function paint() {
    var needle = input.value.trim().toLowerCase();
    body.replaceChildren();
    var shown = 0;
    for (var i = 0; i < rows.length; i++) {
      if (needle && haystack(rows[i]).toLowerCase().indexOf(needle) === -1) continue;
      body.append(el('tr', {}, rows[i].cells.map(cell)));
      shown++;
    }
    if (!shown) body.append(el('tr', {}, el('td', { colspan: String(headers.length) }, el('span', { 'class': 'empty' }, text(needle ? '无匹配。' : emptyText)))));
  }
  input.addEventListener('input', paint);
  paint();
  return el('section', { 'class': 'wide' }, el('h2', {}, text(title), rows.length ? input : null), table);
}

function render(s) {
  document.getElementById('title').textContent = s.plugin.name;
  document.getElementById('meta').textContent =
    'v' + s.plugin.version + '  ·  ' + s.mode +
    '  ·  生成于 ' + s.generatedAt +
    '  ·  任务 ' + s.counts.tasks + ' / 黑板 ' + s.counts.blackboard +
    ' / 成果 ' + s.counts.findings + ' / 审计 ' + s.counts.audit;

  var root = document.getElementById('root');
  root.replaceChildren();

  var cfg = s.config || {};
  var emptyRange = !cfg.allowedTargets || cfg.allowedTargets.length === 0;

  // ── runtime self-check ─────────────────────────────────────────────────────
  root.append(el('section', { 'class': 'wide' },
    el('h2', {}, text('运行时自检')),
    emptyRange
      ? el('p', { 'class': 'notice' }, text('⚠ 授权范围为空 —— 按默认拒绝策略，任何目标都会被拒绝。开任务时用 f2x_orchestrate_start 的 allowlist 声明授权范围。'))
      : null,
    el('div', { 'class': 'kv' },
      el('div', {}, text('授权范围')),
      el('div', {}, emptyRange ? el('span', { 'class': 'warn' }, text('(空 — 拒绝一切)')) : code(cfg.allowedTargets.join(', '))),
      el('div', {}, text('台账')),
      el('div', {}, code(s.paths.ledger + (s.paths.persistent ? '' : '（仅内存，未持久化）'))),
      el('div', {}, text('素材仓库根')),
      el('div', {}, code(s.paths.referenceRoot + '  '),
        el('span', { 'class': s.paths.referenceRootExists ? 'ok' : 'err' }, text(s.paths.referenceRootExists ? '存在' : '缺失'))),
      el('div', {}, text('知识库')),
      el('div', {}, code(s.paths.knowledgeBase + '  '),
        el('span', { 'class': s.paths.knowledgeBaseExists ? 'ok' : 'err' }, text(s.paths.knowledgeBaseExists ? '存在' : '缺失'))),
      el('div', {}, text('能源/OT 模块')),
      el('div', {}, el('span', { 'class': cfg.enablePowerModule ? 'ok' : 'no' }, text(cfg.enablePowerModule ? 'ON' : 'OFF'))),
      el('div', {}, text('全局技能 provider')),
      el('div', {}, el('span', { 'class': cfg.registerSkillProvider ? 'ok' : 'no' }, text(cfg.registerSkillProvider ? 'ON' : 'OFF'))),
      el('div', {}, text('门禁参数')),
      el('div', {}, code('并发 ≤' + cfg.maxConcurrencyPerTarget + ' / 每阶段检查点 ≤' + cfg.maxCheckpointsPerStage + ' / 门禁有效 ' + cfg.gateValidityStages + ' 阶段'))),
    el('h2', { style: 'margin-top:14px' }, text('可选兄弟能力')),
    el('table', {},
      el('thead', {}, el('tr', {}, ['工具', '说明', '状态'].map(function (h) { return el('th', {}, text(h)); }))),
      el('tbody', {}, (s.capabilities || []).map(function (c) {
        return el('tr', {},
          cell(code(c.tool)),
          cell(text(c.why)),
          cell(el('span', { 'class': c.available ? 'ok' : 'no' }, text(c.available ? 'AVAILABLE' : 'absent'))));
      })))));

  // ── tasks ──────────────────────────────────────────────────────────────────
  var taskRows = (s.tasks || []).map(function (t) {
    var gates = Object.keys(t.gates || {}).filter(function (k) { return t.gates[k] && t.gates[k].pass; });
    return {
      cells: [code(t.id), text(t.mode + '/' + t.lane), text(t.stage), text(t.status),
        text((t.targets || []).join(', ') || '—'), text(gates.join(' | ') || '—')],
      hay: [t.id, t.mode, t.lane, t.stage, t.status, (t.targets || []).join(' '), gates.join(' ')].join(' '),
    };
  });
  root.append(filterable('任务台账', ['id', '平面', '阶段', '状态', '目标', '已过门禁'], taskRows,
    '暂无任务。用 f2x_orchestrate_start 开一个。', function (r) { return r.hay; }));

  // ── blackboard ─────────────────────────────────────────────────────────────
  var bbRows = (s.blackboard || []).map(function (e) {
    return {
      cells: [code(e.id), el('span', { 'class': 'pill' }, text(e.kind)), text(e.title),
        el('div', {}, text(e.body),
          e.evidence ? el('div', { 'class': 'mono', style: 'color:var(--dim);margin-top:4px' }, text('证据: ' + e.evidence)) : null)],
      hay: [e.id, e.kind, e.title, e.body, e.evidence].join(' '),
    };
  });
  root.append(filterable('黑板', ['id', '类型', '标题', '内容'], bbRows, '黑板为空。', function (r) { return r.hay; }));

  // ── findings ───────────────────────────────────────────────────────────────
  var fRows = (s.findings || []).map(function (f) {
    return {
      cells: [code(f.id), text(f.title),
        el('span', { 'class': f.severity === 'critical' || f.severity === 'high' ? 'err' : 'warn' }, text(f.severity)),
        text(f.status),
        el('span', { 'class': f.evidenceLevel === 'confirmed' || f.evidenceLevel === 'impact' ? 'ok' : 'no' }, text(f.evidenceLevel)),
        code(f.target)],
      hay: [f.id, f.title, f.severity, f.status, f.evidenceLevel, f.target, f.type].join(' '),
    };
  });
  root.append(filterable('成果登记', ['id', '标题', '级别', '状态', '证据等级', '目标'], fRows, '尚未登记成果。', function (r) { return r.hay; }));

  // ── audit ──────────────────────────────────────────────────────────────────
  var aRows = (s.audit || []).slice().reverse().map(function (a) {
    return {
      cells: [code(a.ts), code(a.operation || a.op || ''), code(a.target),
        text(a.confirmedBy || '—'), text(a.action || '')],
      hay: [a.ts, a.operation, a.op, a.target, a.confirmedBy, a.action].join(' '),
    };
  });
  root.append(filterable('OT 审计轨迹（最近 ' + (s.audit || []).length + ' 条，共 ' + s.counts.audit + ' 条）',
    ['时间', '操作类', '目标', '二次确认', '动作'], aRows, '暂无审计记录。', function (r) { return r.hay; }));
}

fetch('/f2x-console/state', { headers: { accept: 'application/json' } })
  .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
  .then(render)
  .catch(function (err) {
    document.getElementById('root').replaceChildren(el('section', { 'class': 'wide err-box' },
      el('h2', {}, text('读取失败')), el('p', {}, text(String(err && err.message ? err.message : err)))));
  });
<\/script>
</body></html>
`;
}
//#endregion
//#region src/index.ts
const name = "dsh-f2x-redteam3000";
const inject = [
	"tools",
	"skills",
	"systemPrompt"
];
/** Plugin version reported by the doctrine self-check and the console. Kept in step with package.json by a test. */
const PLUGIN_VERSION = "0.1.0";
/**
* Route prefix of the read-only operator console.
*
* Registered on the raw web server rather than the `/api` connection channel: that
* channel is fenced by the browser-trust/session policy, which would make the page
* unreachable by plain navigation. The console exposes only what `state.json`
* already holds on the operator's own machine.
*/
const CONSOLE_PATH = "/f2x-console";
/** Route of the capability manager page and its two JSON endpoints. */
const MANAGER_PATH = "/f2x-manager";
/** The shared state store, created per plugin instance. */
let store;
/** Resolve the state directory, preferring config over the DSH home default. */
function resolveStateDir(config) {
	if (config.stateDir.trim() !== "") return config.stateDir.trim();
	const home = process.env.DSH_HOME ?? join(homedir(), ".dsh");
	return join(home, "f2x-redteam3000");
}
/**
* Fallback lookup for the read-only reference tree some skills cite.
*
* No absolute path is baked in: a path that exists on the author's machine does not
* exist on the reader's, and "exists=no" in the self-check reads as a broken install
* rather than an optional tree. Resolution order is the `referenceRoot` config key,
* then `$REDTEAM_REFS`, then `<dshHome>/redteam-refs` — which is where an operator who
* wants the tree would put it. When none of them exists the answer is the empty string,
* and the skills that cite the tree say so instead of pointing at a missing directory.
*/
function defaultReferenceRoot() {
	const home = process.env.DSH_HOME ?? join(homedir(), ".dsh");
	const candidate = join(home, "redteam-refs");
	return existsSync(candidate) ? candidate : "";
}
/**
* Resolve the upstream reference tree the power/OT skills cite, preferring an
* explicit config value over `$REDTEAM_REFS` over the WSL default.
*
* The doctrine self-check reports this value *and whether it exists*, because the
* skills hardcode absolute paths: a moved tree would otherwise fail silently the
* first time a skill tried to read its material.
*/
function resolveReferenceRoot(config) {
	const configured = config.referenceRoot.trim();
	if (configured !== "") return configured;
	const fromEnv = process.env.REDTEAM_REFS?.trim();
	if (fromEnv !== void 0 && fromEnv !== "") return fromEnv;
	const fallback = defaultReferenceRoot();
	if (fallback !== "" && process.env.REDTEAM_REFS === void 0) process.env.REDTEAM_REFS = fallback;
	return fallback;
}
/** Render a task ledger row as one human-readable line. */
function renderTaskLine(task) {
	const gates = Object.entries(task.gates).filter(([, verdict]) => verdict.pass).map(([stage]) => stage);
	return `${task.id} [${task.mode}/${task.lane}] stage=${task.stage} status=${task.status} targets=${task.targets.join(",") || "(none)"} gates=${gates.join("|") || "(none)"}`;
}
/**
* Capabilities other plugins may contribute. This plugin never requires any of
* them: it ships its own finding registry and its own ledger, so a deployment
* with nothing else installed still works. They are listed here so an operator
* can see, at the start of a task, whether the richer path is available — and so a
* skill's fallback instruction has something concrete to refer to.
*/
const OPTIONAL_CAPABILITIES = [
	{
		tool: "redteam_finding_register",
		why: "richer finding records with a shared results page"
	},
	{
		tool: "redteam_coverage_mark",
		why: "attack-surface coverage matrix write-back"
	},
	{
		tool: "redteam_atlas_target",
		why: "per-target attack-chain topology"
	},
	{
		tool: "campaign_memory_write",
		why: "cross-session battle-knowledge memory (the experience store)"
	},
	{
		tool: "webshell_connect",
		why: "webshell connection library"
	},
	{
		tool: "stage_gate",
		why: "an alternative stage-gate implementation"
	}
];
/**
* Whether a tool is registered in this deployment.
*
* Detection reads the live tool registry rather than guessing from config, so the
* answer reflects what the model can actually see. Any failure resolves to
* `false`: an unreachable registry must never be reported as an available
* capability.
*/
function hasTool(ctx, toolName) {
	try {
		return ctx.tools.schemas().some((schema) => schema.name === toolName);
	} catch {
		return false;
	}
}
/** Render the blackboard as a compact digest. */
function renderBlackboard(entries, kind) {
	const filtered = kind === void 0 ? entries : entries.filter((entry) => entry.kind === kind);
	if (filtered.length === 0) return kind === void 0 ? "(blackboard empty)" : `(no ${kind} records)`;
	return filtered.map((entry) => `[${entry.kind}/${entry.lane}] ${entry.id} ${entry.title}\n  ${entry.body}${entry.evidence === void 0 ? "" : `\n  evidence: ${entry.evidence}`}`).join("\n");
}
/** Tool definitions are declared once so the plugin body stays readable. */
function registerTools(ctx, config) {
	const activeStore = () => {
		if (store === void 0) store = new StateStore(resolveStateDir(config), config.persistState);
		return store;
	};
	const limits = {
		maxConcurrencyPerTarget: config.maxConcurrencyPerTarget,
		maxCheckpointsPerStage: config.maxCheckpointsPerStage,
		gateValidityStages: config.gateValidityStages
	};
	ctx.tools.register(defineTool({
		name: "f2x_orchestrate_start",
		description: "Open a red-team engagement ledger entry. Validates every target against the hardcoded authorized range and refuses out-of-scope work. mode=power enables the OT lane and its gate rules. Returns the task id used by every other f2x_orchestrate_* tool.",
		parameters: {
			brief: {
				type: "string",
				required: true,
				description: "One-line engagement brief (goal and authorization context)."
			},
			targets: {
				type: "array",
				items: { type: "string" },
				description: "Authorized targets (IPv4, CIDR, hostname). Checked against the plugin allowlist."
			},
			mode: {
				type: "string",
				enum: ["general", "power"],
				description: "Assignment plane; power enables the OT module."
			},
			lane: {
				type: "string",
				enum: ["it", "ot"],
				description: "For power mode: which half of the engagement this task covers."
			},
			allowlist: {
				type: "array",
				items: { type: "string" },
				description: "Additional authorized entries for this task. Union with the configured allowlist."
			}
		},
		output: {
			schema: { type: "string" },
			render: (_args, value) => [{
				type: "text",
				text: value
			}]
		},
		async execute(args) {
			await activeStore().read();
			const mode = args.mode === "power" ? "power" : "general";
			if (mode === "power" && !config.enablePowerModule) return "Refused: the power/OT module is disabled in this plugin configuration (enablePowerModule=false).";
			const lane = mode === "power" ? args.lane === "ot" ? "ot" : "it" : "it";
			const targets = (args.targets ?? []).map((target) => target.trim()).filter((target) => target !== "");
			const configured = config.allowedTargets.map((entry) => entry.trim()).filter((entry) => entry !== "");
			const requested = (args.allowlist ?? []).map((entry) => entry.trim()).filter((entry) => entry !== "");
			if (configured.length === 0) return [
				"Refused: no authorized target range is configured (`allowedTargets` is empty), so no task can start.",
				requested.length === 0 ? "Ask the operator to set `allowedTargets`." : `A task allowlist cannot authorize anything on its own — it may only narrow the operator's range, and that range is empty. Requested: ${requested.join(", ")}.`,
				"This is the deny-by-default boundary: the party being constrained does not get to set it."
			].join("\n");
			const notCovered = requested.filter((entry) => !configured.some((allowed) => entryCovers(allowed, entry)));
			if (notCovered.length > 0) return [
				"Refused: a task allowlist may narrow the operator's range, not widen it.",
				`Configured range: [${configured.join(", ")}]. Not covered by it: ${notCovered.join(", ")}.`,
				"Ask the operator to add the intended entries to `allowedTargets` instead of passing them per task."
			].join("\n");
			const taskScope = requested.length === 0 ? [...configured] : requested;
			const refusal = scopeRefusal(targets, taskScope);
			if (refusal !== void 0) return refusal.refusal;
			const now = (/* @__PURE__ */ new Date()).toISOString();
			return [
				`Started ${await activeStore().update((current) => {
					const id = `f2x-task-${nextSerial(Object.values(current.tasks), "f2x-task")}`;
					current.tasks[id] = {
						id,
						brief: args.brief,
						mode,
						lane,
						stage: "recon",
						status: "open",
						targets,
						allowedTargets: taskScope.filter((entry) => entry.trim() !== ""),
						createdAt: now,
						updatedAt: now,
						gates: {},
						checkpoints: {},
						violations: [],
						notes: []
					};
					current.activeTaskId = id;
					current.mode = mode;
					return id;
				})} (${mode}/${lane}).`,
				`Brief: ${args.brief}`,
				`Targets (all inside the authorized range): ${targets.join(", ") || "(none recorded)"}`,
				`Authorized range in force: ${taskScope.filter((entry) => entry.trim() !== "").join(", ") || "(empty)"}`,
				`Stage: recon. Advance with f2x_orchestrate_checkpoint, then attest the stage with f2x_orchestrate_verify.`,
				mode === "power" ? `OT gate rules active: every write operation needs f2x_orchestrate_audit with commander confirmation. Advisory (not enforced by the plugin): keep to ${limits.maxConcurrencyPerTarget} concurrent calls per target and probe at a low rate — the plugin cannot count a scanner's own concurrency.` : "General red-team flow active.",
				`Ledger: ${activeStore().path}`
			].join("\n");
		}
	}));
	ctx.tools.register(defineTool({
		name: "f2x_orchestrate_status",
		description: "Read the engagement ledger: task rows, current stage, blackboard digest, gate verdicts and any open doctrine violations. Use it after a compaction or when taking over someone else's task.",
		parameters: {
			taskId: {
				type: "string",
				description: "Task id; omit for the active task."
			},
			includeBlackboard: {
				type: "boolean",
				description: "Include the blackboard digest (default true)."
			},
			blackboardKind: {
				type: "string",
				enum: [
					"fact",
					"intent",
					"hint"
				],
				description: "Restrict the blackboard digest to one record kind."
			}
		},
		output: {
			schema: { type: "string" },
			render: (_args, value) => [{
				type: "text",
				text: value
			}]
		},
		async execute(args) {
			const state = await activeStore().read();
			const taskId = args.taskId ?? state.activeTaskId;
			const lines = [];
			if (Object.keys(state.tasks).length === 0) return `No tasks yet. Open one with f2x_orchestrate_start. Ledger: ${activeStore().path}`;
			lines.push(`Active task: ${state.activeTaskId ?? "(none)"} | plugin mode: ${state.mode} | ledger: ${activeStore().path}`);
			for (const task of Object.values(state.tasks)) {
				lines.push(`${task.id === taskId ? "* " : "  "}${renderTaskLine(task)}`);
				if (task.id === taskId) {
					lines.push(`    brief: ${task.brief}`);
					for (const stage of STAGES) {
						const cps = task.checkpoints[stage] ?? [];
						if (cps.length === 0) continue;
						const gate = task.gates[stage];
						lines.push(`    ${stage}: ${cps.length} checkpoint(s) [confirmed=${cps.filter((c) => c.level === "confirmed").length} partial=${cps.filter((c) => c.level === "partial").length} unknown=${cps.filter((c) => c.level === "unknown").length}] gate=${gate === void 0 ? "not run" : gate.pass ? "PASS" : "FAIL"}`);
					}
					if (task.violations.length > 0) lines.push(`    VIOLATIONS: ${task.violations.join(" | ")}`);
				}
			}
			if (args.includeBlackboard !== false) lines.push("", "Blackboard:", renderBlackboard(state.blackboard.filter((entry) => entry.taskId === taskId), args.blackboardKind));
			return lines.join("\n");
		}
	}));
	ctx.tools.register(defineTool({
		name: "f2x_orchestrate_switch",
		description: "Switch the engagement plane between general IT red-team and the power/OT module, updating the active task. Switching to power enforces the OT gate rules and the write-confirmation requirement.",
		parameters: {
			mode: {
				type: "string",
				required: true,
				enum: ["general", "power"],
				description: "Target plane."
			},
			lane: {
				type: "string",
				enum: ["it", "ot"],
				description: "For power mode: target lane."
			},
			taskId: {
				type: "string",
				description: "Task to retarget; omit for the active task."
			},
			reason: {
				type: "string",
				description: "Why the plane is changing (recorded in the ledger)."
			}
		},
		output: {
			schema: { type: "string" },
			render: (_args, value) => [{
				type: "text",
				text: value
			}]
		},
		async execute(args) {
			if (args.mode === "power" && !config.enablePowerModule) return "Refused: the power/OT module is disabled in this plugin configuration (enablePowerModule=false).";
			const state = await activeStore().read();
			const taskId = args.taskId ?? state.activeTaskId;
			if (taskId === void 0 || state.tasks[taskId] === void 0) return `Refused: no task to switch. Open one with f2x_orchestrate_start first.`;
			const mode = args.mode;
			const lane = mode === "power" ? args.lane === "ot" ? "ot" : "it" : "it";
			await activeStore().update((current) => {
				const task = current.tasks[taskId];
				if (task === void 0) return;
				task.mode = mode;
				task.lane = lane;
				task.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
				if (args.reason !== void 0 && args.reason.trim() !== "") task.notes.push(`plane switch: ${args.reason}`);
				current.mode = mode;
			});
			return [
				`Switched ${taskId} to ${mode}/${lane}.`,
				args.reason === void 0 ? "" : `Reason recorded: ${args.reason}`,
				mode === "power" ? `OT gate rules now apply: commander confirmation for every write operation (enforced). Advisory: ${limits.maxConcurrencyPerTarget} concurrent calls per target, low-rate probing — the plugin cannot count a scanner's own concurrency.` : "General red-team flow restored. The power module stays available as an overlay."
			].filter((line) => line !== "").join("\n");
		}
	}));
	ctx.tools.register(defineTool({
		name: "f2x_orchestrate_blackboard",
		description: "Read or write the engagement blackboard: fact (established observation), intent (a direction we mean to pursue) and hint (an unverified lead). OT and IT subagents share one board, so both lanes see the same facts.",
		parameters: {
			action: {
				type: "string",
				required: true,
				enum: ["read", "write"],
				description: "read returns records; write appends one."
			},
			kind: {
				type: "string",
				enum: [
					"fact",
					"intent",
					"hint"
				],
				description: "Record kind; required for write, optional filter for read."
			},
			title: {
				type: "string",
				description: "Short record title (write)."
			},
			body: {
				type: "string",
				description: "Record body (write)."
			},
			evidence: {
				type: "string",
				description: "Evidence pointer (regex allowed): evidence id, pcap, output path."
			},
			lane: {
				type: "string",
				enum: ["it", "ot"],
				description: "Lane that produced the record (default: the task lane)."
			},
			taskId: {
				type: "string",
				description: "Task id; omit for the active task."
			}
		},
		output: {
			schema: { type: "string" },
			render: (_args, value) => [{
				type: "text",
				text: value
			}]
		},
		async execute(args) {
			const state = await activeStore().read();
			const activeTaskId = args.taskId ?? state.activeTaskId;
			if (args.action === "read") return renderBlackboard(activeTaskId === void 0 ? state.blackboard : state.blackboard.filter((entry) => entry.taskId === activeTaskId), args.kind);
			if (args.kind === void 0 || args.title === void 0 || args.body === void 0) return "Refused: blackboard write needs kind, title and body.";
			if (args.kind === "fact" && (args.evidence === void 0 || args.evidence.trim() === "")) return "Refused: a \"fact\" record is an established observation and must carry an evidence pointer. Use kind=hint for unverified leads.";
			const taskId = activeTaskId ?? "(unassigned)";
			const lane = args.lane === "ot" ? "ot" : args.lane === "it" ? "it" : state.tasks[taskId]?.lane ?? "it";
			return `Recorded ${await activeStore().update((current) => {
				const nextId = `bb-${nextSerial(current.blackboard, "bb")}`;
				current.blackboard.push({
					id: nextId,
					taskId,
					kind: args.kind,
					lane,
					title: args.title ?? "",
					body: args.body ?? "",
					...args.evidence === void 0 ? {} : { evidence: args.evidence },
					createdAt: (/* @__PURE__ */ new Date()).toISOString()
				});
				return nextId;
			})} [${args.kind}/${lane}] on ${taskId}: ${args.title}`;
		}
	}));
	ctx.tools.register(defineTool({
		name: "f2x_orchestrate_checkpoint",
		description: "Record one evidence checkpoint at the current stage. This is the only way the ledger learns what a stage produced; the redteam gate reads checkpoints and nothing else. evidence levels: confirmed (reproduced/verified), partial (tool output or indirect), unknown (unresolved).",
		parameters: {
			summary: {
				type: "string",
				description: "What was established, one or two sentences (action=record)."
			},
			evidence: {
				type: "string",
				description: "Evidence pointer: evidence id, request/response capture, output path, pcap (action=record)."
			},
			level: {
				type: "string",
				enum: [
					"confirmed",
					"partial",
					"unknown"
				],
				description: "Evidence grade (action=record)."
			},
			stage: {
				type: "string",
				enum: [...STAGES],
				description: "Stage this checkpoint belongs to (default: the task stage)."
			},
			advance: {
				type: "boolean",
				description: "Advance to the next stage when the gate for this stage passes."
			},
			taskId: {
				type: "string",
				description: "Task id; omit for the active task."
			},
			action: {
				type: "string",
				enum: ["record", "delete"],
				description: "record (default) adds a checkpoint; delete removes one by id, which is the way out when a checkpoint was recorded with placeholder evidence."
			},
			id: {
				type: "string",
				description: "Checkpoint id to delete (with action=delete)."
			}
		},
		output: {
			schema: { type: "string" },
			render: (_args, value) => [{
				type: "text",
				text: value
			}]
		},
		async execute(args) {
			const state = await activeStore().read();
			const taskId = args.taskId ?? state.activeTaskId;
			const task = taskId === void 0 ? void 0 : state.tasks[taskId];
			if (task === void 0) return "Refused: no active task. Open one with f2x_orchestrate_start first.";
			if (args.action === "delete") {
				const wanted = (args.id ?? "").trim();
				if (wanted === "") return "Refused: action=delete needs the checkpoint id.";
				const removed = await activeStore().update((current) => {
					const target = current.tasks[task.id];
					if (target === void 0) return "the task disappeared mid-write";
					for (const [key, list] of Object.entries(target.checkpoints)) {
						const index = list.findIndex((item) => item.id === wanted);
						if (index === -1) continue;
						list.splice(index, 1);
						target.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
						return;
					}
					return `no checkpoint "${wanted}" on ${task.id}`;
				});
				if (removed !== void 0) return `Refused: ${removed}.`;
				await activeStore().update((current) => {
					const target = current.tasks[task.id];
					if (target === void 0) return;
					for (const [key, verdict] of Object.entries(target.gates)) if (!verdict.token) delete target.gates[key];
					target.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
				});
				return `Deleted checkpoint ${wanted} from ${task.id}. Re-run f2x_orchestrate_verify for the affected stage; the previous verdict for that stage was invalidated.`;
			}
			const stage = args.stage ?? task.stage;
			if (!STAGES.includes(stage)) return `Refused: unknown stage "${stage}". Legal stages: ${STAGES.join(", ")}.`;
			const missing = [
				args.summary === void 0 || args.summary.trim() === "" ? "summary" : void 0,
				args.evidence === void 0 || args.evidence.trim() === "" ? "evidence" : void 0,
				args.level === void 0 ? "level" : void 0
			].filter((value) => value !== void 0);
			if (missing.length > 0) return `Refused: action=record needs ${missing.join(", ")}. Supply them, or use action=delete with an id to remove a checkpoint.`;
			const stageList = STAGES;
			const hereNow = stageList.indexOf(task.stage);
			if (stageList.indexOf(stage) !== hereNow) return [`Refused: cannot record a checkpoint for "${stage}" while the task is on "${task.stage}".`, `Evidence is recorded where the work happens: use "${task.stage}", check in, then the next stage becomes current.`].join("\n");
			const placeholder = !isEvidencePointer(args.evidence);
			const requestedLevel = args.level;
			const level = placeholder && requestedLevel === "confirmed" ? "unknown" : requestedLevel;
			const downgradeNote = placeholder && requestedLevel === "confirmed" ? `Evidence "${args.evidence}" is a placeholder, so it is recorded as "unknown" rather than "confirmed" — a declared level is not evidence. Record another checkpoint with a real pointer (path, URL, capture, command output).` : void 0;
			const recorded = await activeStore().update((current) => {
				const target = current.tasks[task.id];
				if (target === void 0) return {
					ok: false,
					message: "Refused: the task disappeared mid-write."
				};
				const list = target.checkpoints[stage] ?? [];
				if (list.length >= limits.maxCheckpointsPerStage) return {
					ok: false,
					message: `Refused: stage "${stage}" already holds ${list.length} checkpoints (ceiling ${limits.maxCheckpointsPerStage}). Close the stage with f2x_orchestrate_verify instead of piling on more evidence.`
				};
				const id = `cp-${nextSerial(list, "cp")}`;
				list.push({
					id,
					stage,
					summary: args.summary ?? "",
					evidence: args.evidence ?? "",
					level,
					createdAt: (/* @__PURE__ */ new Date()).toISOString()
				});
				target.checkpoints[stage] = list;
				target.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
				return {
					ok: true,
					id
				};
			});
			if (!recorded.ok) return recorded.message;
			const lines = [`Recorded ${recorded.id} at stage "${stage}" [${level}]: ${args.summary}`, `evidence: ${args.evidence}`];
			if (downgradeNote !== void 0) lines.push(downgradeNote);
			if (args.advance === true && stage !== task.stage) lines.push(`advance ignored: the task is on "${task.stage}" and this verdict is for "${stage}". Re-attesting an earlier stage records it without moving the task; run advance on the current stage.`);
			if (args.advance === true && stage === task.stage) {
				const updated = (await activeStore().read()).tasks[task.id];
				if (updated === void 0) return lines.join("\n");
				const verdict = runVerify({
					task: updated,
					limits,
					stage
				});
				if (!verdict.pass) {
					lines.push("Gate not passed, stage NOT advanced:");
					lines.push(...verdict.openGaps.map((gap) => `- ${gap}`));
				} else {
					const following = nextStage(stage);
					if (following === void 0) {
						await activeStore().update((current) => {
							const target = current.tasks[task.id];
							if (target === void 0) return;
							target.gates[stage] = verdict;
							target.status = "closed";
							target.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
						});
						lines.push(`Stage "${stage}" attested and it is the final stage — task closed.`);
					} else {
						await activeStore().update((current) => {
							const target = current.tasks[task.id];
							if (target === void 0) return;
							target.gates[stage] = verdict;
							target.stage = following;
							target.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
						});
						lines.push(`Stage "${stage}" attested — advanced to "${following}".`);
					}
				}
			}
			return lines.join("\n");
		}
	}));
	ctx.tools.register(defineTool({
		name: "f2x_orchestrate_verify",
		description: "Run the redteam gate for one stage: it reads the recorded checkpoints and returns PASS or FAIL with explicit open gaps. A gate that never ran is not a pass; a stale verdict does not count. This is the checkpoint discipline that stops verification decay.",
		parameters: {
			stage: {
				type: "string",
				enum: [...STAGES],
				description: "Stage to attest (default: the task stage)."
			},
			advance: {
				type: "boolean",
				description: "Advance the task when the gate passes (default false)."
			},
			taskId: {
				type: "string",
				description: "Task id; omit for the active task."
			}
		},
		output: {
			schema: { type: "string" },
			render: (_args, value) => [{
				type: "text",
				text: value
			}]
		},
		async execute(args) {
			const state = await activeStore().read();
			const taskId = args.taskId ?? state.activeTaskId;
			const task = taskId === void 0 ? void 0 : state.tasks[taskId];
			if (task === void 0) return "Refused: no active task. Open one with f2x_orchestrate_start first.";
			const stage = args.stage ?? task.stage;
			const stages = STAGES;
			const here = stages.indexOf(task.stage);
			const asked = stages.indexOf(stage);
			if (asked === -1) return `Refused: unknown stage "${stage}". Valid stages: ${stages.join(" → ")}.`;
			if (asked > here) return [`Refused: cannot attest "${stage}" while the task is on "${task.stage}".`, `Forward attestation would leave the current stage ungated. Attest "${task.stage}" first; attesting an earlier stage is allowed.`].join("\n");
			const verdict = runVerify({
				task,
				limits,
				stage
			});
			await activeStore().update((current) => {
				const target = current.tasks[task.id];
				if (target === void 0) return;
				target.gates[stage] = verdict;
				target.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
			});
			const lines = [
				`Redteam gate for ${task.id} stage "${stage}": ${verdict.pass ? "PASS" : "FAIL"}`,
				`checkpoints=${verdict.cpCount} confirmed=${verdict.confirmedCount}`,
				...verdict.reasons.map((reason) => `- ${reason}`)
			];
			if (!verdict.pass) {
				lines.push("Open gaps that block advancement:");
				lines.push(...verdict.openGaps.map((gap) => `- ${gap}`));
			}
			if (args.advance === true && stage !== task.stage) lines.push(`advance ignored: the task is on "${task.stage}", this checkpoint is for "${stage}".`);
			if (args.advance === true && stage === task.stage) {
				if (!verdict.pass) lines.push("advance requested but refused: gate did not pass.");
				else {
					const following = nextStage(stage);
					await activeStore().update((current) => {
						const target = current.tasks[task.id];
						if (target === void 0) return;
						target.stage = following ?? stage;
						if (following === void 0) target.status = "closed";
						target.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
					});
					lines.push(following === void 0 ? "Final stage attested — task closed." : `Advanced to "${following}".`);
				}
			}
			return lines.join("\n");
		}
	}));
	ctx.tools.register(defineTool({
		name: "f2x_orchestrate_mark",
		description: "The check-in (打卡) gate: the only path that advances the engagement. It reads the current stage's gate verdict and records a check-in only when that verdict is a PASS for the stage the task is actually on. A task with no gate run, a failed gate, or a stale verdict cannot be checked in.",
		parameters: {
			note: {
				type: "string",
				description: "Short note recorded with the check-in."
			},
			taskId: {
				type: "string",
				description: "Task id; omit for the active task."
			}
		},
		output: {
			schema: { type: "string" },
			render: (_args, value) => [{
				type: "text",
				text: value
			}]
		},
		async execute(args) {
			const state = await activeStore().read();
			const taskId = args.taskId ?? state.activeTaskId;
			const task = taskId === void 0 ? void 0 : state.tasks[taskId];
			if (task === void 0) return "Refused: no active task. Open one with f2x_orchestrate_start first.";
			if (task.status === "closed") return `Refused: ${task.id} is already closed.`;
			const stage = task.stage;
			const verdict = task.gates[stage];
			if (verdict === void 0) return [`Refused: no redteam gate has been run for stage "${stage}".`, `Run f2x_orchestrate_verify { stage: "${stage}" } first — an unattested gate is not a pass.`].join("\n");
			if (!verdict.pass) return [
				`Refused: the redteam gate for "${stage}" did not pass, so ${task.id} cannot check in.`,
				"Open gaps:",
				...verdict.openGaps.map((gap) => `- ${gap}`)
			].join("\n");
			if (!verdictIsIntact(verdict)) return [
				`Refused: the "${stage}" verdict did not come from f2x_orchestrate_verify, or it was edited after it was produced.`,
				"A verdict is only consumable when its integrity token matches its own content.",
				`Run f2x_orchestrate_verify { stage: "${stage}" } to produce a verdict for this stage.`
			].join("\n");
			if (verdict.atStage !== stage) return [`Refused: the "${stage}" verdict is stale — it was produced while the task was on stage "${verdict.atStage}".`, `Re-run f2x_orchestrate_verify { stage: "${stage}" } to attest the current stage.`].join("\n");
			const horizon = Math.max(0, Math.floor(limits.gateValidityStages));
			const order = STAGES;
			const drift = Math.abs(order.indexOf(task.stage) - order.indexOf(verdict.atStage));
			if (drift > horizon) return [`Refused: the "${stage}" verdict is beyond its validity horizon — the task has moved ${drift} stage(s) since it was produced, and gateValidityStages is ${horizon}.`, `Re-run f2x_orchestrate_verify { stage: "${stage}" } for a fresh verdict.`].join("\n");
			const following = nextStage(stage);
			await activeStore().update((current) => {
				const target = current.tasks[task.id];
				if (target === void 0) return;
				target.notes.push(`check-in at ${(/* @__PURE__ */ new Date()).toISOString()}: stage "${stage}" attested${args.note === void 0 ? "" : ` — ${args.note}`}`);
				target.stage = following ?? stage;
				if (following === void 0) target.status = "closed";
				target.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
			});
			return [
				`Checked in ${task.id} on stage "${stage}" (gate PASS, ${verdict.confirmedCount} confirmed checkpoint(s)).`,
				args.note === void 0 ? "" : `Note: ${args.note}`,
				following === void 0 ? "That was the final stage — the task is now closed. Run f2x_orchestrate_export for the handover." : `Stage advanced to "${following}".`
			].filter((line) => line !== "").join("\n");
		}
	}));
	ctx.tools.register(defineTool({
		name: "f2x_orchestrate_scope",
		description: "Check a target (or a list) against the hardcoded authorized range without starting anything. Answers \"am I allowed to touch this?\" with the decisive allowlist entry. Deny-by-default: an empty range denies everything.",
		parameters: {
			targets: {
				type: "array",
				required: true,
				items: { type: "string" },
				description: "Targets to check."
			},
			taskId: {
				type: "string",
				description: "Use this task's authorized range; omit for the plugin configuration."
			}
		},
		output: {
			schema: { type: "string" },
			render: (_args, value) => [{
				type: "text",
				text: value
			}]
		},
		async execute(args) {
			const state = await activeStore().read();
			if (args.taskId !== void 0 && state.tasks[args.taskId] === void 0) return `Refused: no task "${args.taskId}". Omit taskId to check against the plugin configuration, or use a task id from f2x_orchestrate_status.`;
			const activeId = args.taskId ?? state.activeTaskId;
			const task = activeId === void 0 ? void 0 : state.tasks[activeId];
			const allowlist = task?.allowedTargets ?? config.allowedTargets;
			const targets = args.targets ?? [];
			const refusal = scopeRefusal(targets, allowlist);
			return [
				`Authorized range in force (${task === void 0 ? "plugin configuration" : `task ${task.id}${args.taskId === void 0 ? " (active)" : ""}`}): ${allowlist.filter((entry) => entry.trim() !== "").join(", ") || "(empty — everything is denied)"}`,
				refusal === void 0 ? "Verdict: ALL targets are inside the authorized range." : "Verdict: REFUSED — at least one target is out of scope.",
				...refusal === void 0 ? targets.map((target) => `- ${target}: ALLOW`) : refusal.verdicts.map((verdict) => `- ${verdict.target}: ${verdict.allowed ? "ALLOW" : "DENY"} (${verdict.code}) ${verdict.reason}`)
			].join("\n");
		}
	}));
	ctx.tools.register(defineTool({
		name: "f2x_orchestrate_audit",
		description: "The OT audit gate. Every action that could affect a running process must be written here BEFORE it runs. A recognized write operation (register write, setpoint change, PLC start/stop, firmware download, GOOSE forgery, IED config) is refused unless the commander second-confirms it — on any plane, not only in power mode.",
		parameters: {
			action: {
				type: "string",
				required: true,
				description: "Action taken or about to be taken (e.g. \"read holding registers 0-9\")."
			},
			operation: {
				type: "string",
				description: "Operation class. Read-only classes are listed by f2x_orchestrate_doctrine; anything else counts as a write and needs confirmation."
			},
			target: {
				type: "string",
				required: true,
				description: "Device address (ip or ip:port)."
			},
			command: {
				type: "string",
				description: "Exact command line, so the entry is replayable."
			},
			confirmedBy: {
				type: "string",
				description: "Commander confirmation reference for a write operation. Absent means no confirmation."
			},
			taskId: {
				type: "string",
				description: "Task id; omit for the active task."
			}
		},
		output: {
			schema: { type: "string" },
			render: (_args, value) => [{
				type: "text",
				text: value
			}]
		},
		async execute(args) {
			const state = await activeStore().read();
			const taskId = args.taskId ?? state.activeTaskId;
			const task = taskId === void 0 ? void 0 : state.tasks[taskId];
			const write = WRITE_OPERATIONS.find((entry) => entry.id === args.operation);
			const isReadOnly = args.operation !== void 0 && !write && READ_ONLY_OPERATIONS.some((entry) => entry.id === args.operation);
			const mislabelled = isReadOnly && declaresWriteIntent(args.action, args.operation);
			const readOnlyConfirmed = isReadOnly && !mislabelled && declaresReadIntent(args.action, args.operation);
			const unprovenReadOnly = isReadOnly && !mislabelled && !readOnlyConfirmed;
			const conduct = classifyConduct(`${args.action} ${args.command ?? ""}`, args.operation);
			if (conduct.tier === "prohibited") return [
				`Refused: "${args.action}" is on the prohibited list and cannot be performed as an engagement step.`,
				conduct.reason ?? "",
				conduct.matched === void 0 ? "" : `Matched: "${conduct.matched}".`,
				"This rejection does not depend on credentials, confirmation or scope: it is refused in every configuration.",
				"Nothing was written to the audit log. If the finding requires demonstrating destructive access, record the capability (what you could have run, against which target) rather than running it."
			].filter((line) => line !== "").join("\n");
			const unclassified = write === void 0 && conduct.tier === "free" && (!isReadOnly || unprovenReadOnly);
			const needsConfirmation = conduct.tier === "needs-confirmation" || write !== void 0 || mislabelled || unclassified;
			const allowlist = task?.allowedTargets ?? config.allowedTargets;
			const refusal = scopeRefusal([args.target], allowlist);
			if (refusal !== void 0) return `Refused (out of scope, not logged as executed): ${refusal.refusal}`;
			if (needsConfirmation && (args.confirmedBy === void 0 || args.confirmedBy.trim() === "")) return [
				`Refused: "${args.action}" counts as an OT write operation and has no commander confirmation.`,
				conduct.tier === "needs-confirmation" ? `Conduct policy: ${conduct.reason ?? ""} (matched "${conduct.matched ?? ""}"). Supply confirmedBy with the operator's approval reference.` : mislabelled ? `It was declared as the read-only class "${args.operation ?? ""}" but the action text describes changing device state, so the read-only class is not accepted. Declare the real write class or supply confirmedBy.` : write === void 0 ? `Classify it with a read-only operation id (${READ_ONLY_OPERATIONS.map((entry) => entry.id).join(", ")}) if it truly does not change device state, or supply confirmedBy to record the commander's approval.` : `Operation class "${write.id}" (${write.label}) has impact=${write.impact}. Supply confirmedBy with the commander's approval reference.`,
				"Nothing was written to the audit log: an unconfirmed write is not an authorized action."
			].join("\n");
			const semanticWrite = !mislabelled && write === void 0 && declaresWriteIntent(args.action, args.operation);
			const impact = mislabelled ? "reversible" : readOnlyConfirmed && write === void 0 ? "read-only" : semanticWrite ? "reversible" : write?.impact ?? (isReadOnly ? "read-only" : task?.mode === "power" ? "unclassified-write" : "unclassified-write");
			return [
				`Logged ${await activeStore().update((current) => {
					const nextId = `audit-${nextSerial(current.audit, "audit")}`;
					current.audit.push({
						id: nextId,
						taskId: taskId ?? "(unassigned)",
						action: args.action,
						target: args.target,
						impact,
						command: args.command ?? "(not recorded)",
						...args.confirmedBy === void 0 ? {} : { confirmedBy: args.confirmedBy },
						scopeVerdict: "in-scope",
						at: (/* @__PURE__ */ new Date()).toISOString()
					});
					return nextId;
				})} [impact=${impact}] on ${taskId ?? "(unassigned)"}: ${args.action}`,
				`target: ${args.target} | command: ${args.command ?? "(not recorded)"}`,
				args.confirmedBy === void 0 ? "" : `commander confirmation: ${args.confirmedBy}`,
				isReadOnly ? "Read-only class: no confirmation required, entry kept for the audit trail." : ""
			].filter((line) => line !== "").join("\n");
		}
	}));
	ctx.tools.register(defineTool({
		name: "f2x_orchestrate_finding",
		description: "Register, update and read findings in this plugin's own registry, so the skills work in a deployment that has no sibling red-team plugin installed. A finding is registered as pending with its evidence level; the baseline/differential/marker triple is required before a finding may be marked verified at the exploitation stage. actions: add / update / list.",
		parameters: {
			action: {
				type: "string",
				required: true,
				enum: [
					"add",
					"update",
					"list"
				],
				description: "add registers one finding; update moves status or fields; list reads them back."
			},
			title: {
				type: "string",
				description: "Short finding name (add)."
			},
			type: {
				type: "string",
				description: "Finding class, e.g. CWE-89, unauthenticated-access, cpu-info-disclosure (add)."
			},
			severity: {
				type: "string",
				enum: [
					"critical",
					"high",
					"medium",
					"low"
				],
				description: "Severity (add, default medium)."
			},
			target: {
				type: "string",
				description: "Address, device or location the finding is on (add)."
			},
			summary: {
				type: "string",
				description: "One-line statement of the finding (add)."
			},
			evidenceLevel: {
				type: "string",
				enum: [
					"impact",
					"confirmed",
					"partial",
					"unknown"
				],
				description: "Evidence grade (add, default partial). `impact` means the effect was actually demonstrated."
			},
			baseline: {
				type: "string",
				description: "State before the action (the first leg of the evidence triple)."
			},
			diffEvidence: {
				type: "string",
				description: "What changed (second leg)."
			},
			markerEcho: {
				type: "string",
				description: "Marker proving the intended action, not a coincidence (third leg)."
			},
			impact: {
				type: "string",
				description: "Concrete impact statement."
			},
			evidence: {
				type: "string",
				description: "Evidence pointer: file, capture, request/response, pcap."
			},
			fix: {
				type: "string",
				description: "Remediation guidance for this finding."
			},
			id: {
				type: "string",
				description: "Finding id (update)."
			},
			status: {
				type: "string",
				enum: [
					"pending",
					"verified",
					"false-positive",
					"fixed"
				],
				description: "New status (update)."
			},
			note: {
				type: "string",
				description: "Note appended to the finding history (update)."
			},
			taskId: {
				type: "string",
				description: "Task id; omit for the active task."
			}
		},
		output: {
			schema: { type: "string" },
			render: (_args, value) => [{
				type: "text",
				text: value
			}]
		},
		async execute(args) {
			const state = await activeStore().read();
			const taskId = args.taskId ?? state.activeTaskId ?? "(unassigned)";
			if (args.action === "list") {
				const rows = state.findings.filter((finding) => taskId === "(unassigned)" || finding.taskId === taskId);
				if (rows.length === 0) return `No findings registered on ${taskId}.`;
				return rows.map((finding) => `${finding.id} [${finding.severity}/${finding.status}/${finding.evidenceLevel}] ${finding.title} @ ${finding.target}\n  type: ${finding.type}\n  ${finding.summary}`).join("\n");
			}
			if (args.action === "update") {
				if (args.id === void 0) return "Refused: update needs the finding id.";
				if (!state.findings.some((finding) => finding.id === args.id)) return `Refused: no finding "${args.id}" in this ledger.`;
				if (args.status === "verified") {
					const current = state.findings.find((finding) => finding.id === args.id);
					if ([
						args.baseline ?? current?.baseline,
						args.diffEvidence ?? current?.diffEvidence,
						args.markerEcho ?? current?.markerEcho
					].some((leg) => leg === void 0 || leg.trim() === "")) return [`Refused: finding "${args.id}" cannot be marked verified without the evidence triple.`, "Supply baseline, diffEvidence and markerEcho (or register them via action=add), or leave it pending."].join("\n");
				}
				const outcome = await activeStore().update((current) => {
					const finding = current.findings.find((entry) => entry.id === args.id);
					if (finding === void 0) return void 0;
					if (args.status !== void 0) finding.status = args.status;
					if (args.evidenceLevel !== void 0) finding.history.push(`evidenceLevel -> ${args.evidenceLevel}`);
					if (args.note !== void 0) finding.history.push(`note: ${args.note}`);
					finding.history.push(`at ${(/* @__PURE__ */ new Date()).toISOString()}: status -> ${args.status ?? "(unchanged)"}`);
					finding.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
					return finding;
				});
				if (outcome === void 0) return `Refused: no finding "${args.id}" in this ledger.`;
				return `Updated ${outcome.id}: status=${outcome.status} evidenceLevel=${outcome.evidenceLevel}\nhistory: ${outcome.history.join(" | ")}`;
			}
			if (args.title === void 0 || args.target === void 0 || args.summary === void 0) return "Refused: a finding needs title, target and summary.";
			const level = args.evidenceLevel ?? "partial";
			if (level === "impact" && (args.impact === void 0 || args.impact.trim() === "")) return "Refused: evidenceLevel=impact asserts the effect was demonstrated; supply the impact statement.";
			return [
				`Registered ${await activeStore().update((current) => {
					const nextId = `f2x-finding-${nextSerial(current.findings, "f2x-finding")}`;
					current.findings.push({
						id: nextId,
						taskId,
						title: args.title ?? "",
						type: args.type ?? "unclassified",
						severity: args.severity ?? "medium",
						target: args.target ?? "",
						summary: args.summary ?? "",
						status: "pending",
						evidenceLevel: level,
						...args.baseline === void 0 ? {} : { baseline: args.baseline },
						...args.diffEvidence === void 0 ? {} : { diffEvidence: args.diffEvidence },
						...args.markerEcho === void 0 ? {} : { markerEcho: args.markerEcho },
						...args.impact === void 0 ? {} : { impact: args.impact },
						...args.evidence === void 0 ? {} : { evidence: args.evidence },
						...args.fix === void 0 ? {} : { fix: args.fix },
						createdAt: (/* @__PURE__ */ new Date()).toISOString(),
						updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
						history: [`registered at ${(/* @__PURE__ */ new Date()).toISOString()} as pending/${level}`]
					});
					return nextId;
				})} on ${taskId}: ${args.title}`,
				`severity=${args.severity ?? "medium"} status=pending evidenceLevel=${level} type=${args.type ?? "unclassified"}`,
				`target: ${args.target}`,
				`summary: ${args.summary}`,
				args.evidence === void 0 ? "" : `evidence: ${args.evidence}`,
				"Mark it verified with f2x_orchestrate_finding { action: \"update\", status: \"verified\" } once the evidence triple is complete."
			].filter((line) => line !== "").join("\n");
		}
	}));
	ctx.tools.register(defineTool({
		name: "f2x_orchestrate_doctrine",
		description: "Return the engagement doctrine in force: stage flow, gate rules, the OT write-confirmation requirement, the concurrency and rate ceilings, and the authorized target range. Call it when starting work or after taking over a task.",
		parameters: {},
		output: {
			schema: { type: "string" },
			render: (_args, value) => [{
				type: "text",
				text: value
			}]
		},
		async execute() {
			const state = await activeStore().read();
			const range = (state.activeTaskId === void 0 ? void 0 : state.tasks[state.activeTaskId])?.allowedTargets ?? config.allowedTargets;
			const referenceRoot = resolveReferenceRoot(config);
			const knowledgeBase = bundledRefsDir();
			return [
				"# f2x red-team doctrine in force",
				"",
				`Plane: ${state.mode}${state.mode === "power" ? " (OT module enabled)" : ""} | power module available: ${config.enablePowerModule ? "yes" : "no"}`,
				`Active task: ${state.activeTaskId ?? "(none)"}`,
				"",
				`Stage flow: ${STAGES.join(" -> ")}`,
				"Every stage closes only through f2x_orchestrate_verify; a gate that never ran is not a pass.",
				"",
				"Doctrine rules:",
				`- Authorized range (hardcoded, deny-by-default): ${range.filter((entry) => entry.trim() !== "").join(", ") || "(empty — everything is denied)"}. Out-of-scope operations are refused.`,
				`- Max ${limits.maxConcurrencyPerTarget} concurrent tool calls per target.`,
				"- Fuzz testing against OT devices is low-rate only; never high-frequency scan a PLC, RTU or IED.",
				"- No DDoS, no brute force. Offline cracking scripts may be referenced, never run against a live device.",
				`- Max ${limits.maxCheckpointsPerStage} checkpoints per stage; beyond that the stage is saturated and must close.`,
				`- A gate verdict is valid for ${limits.gateValidityStages} stage advance(s) (enforced: a verdict drifts out of validity as the task moves on).`,
				`- maxConcurrencyPerTarget = ${limits.maxConcurrencyPerTarget}: ADVISORY, not enforced — the plugin cannot observe a scanner's own request concurrency.`,
				...renderConductPolicy(),
				"",
				"OT write gate:",
				...WRITE_OPERATIONS.map((entry) => `- ${entry.id} (impact=${entry.impact}): ${entry.label}`),
				`Read-only classes that need no confirmation: ${READ_ONLY_OPERATIONS.map((entry) => entry.id).join(", ")}.`,
				"Every OT action is logged through f2x_orchestrate_audit before it runs.",
				"",
				"# Runtime self-check — which capabilities are actually in this deployment",
				"",
				`This plugin: ${name} v${PLUGIN_VERSION} (tools registered under the f2x_ prefix; skills under f2x-)`,
				`Skill provider: ${config.registerSkillProvider ? `ON (global — every session sees ${config.publishPowerSkillsGlobally ? "all skills incl. power/OT" : "the general skills; power/OT only via the power preset"})` : "OFF (skills come from an agent preset)"}`,
				`Power/OT module: ${config.enablePowerModule ? "ON" : "OFF"}`,
				"Optional sibling capabilities (this plugin does NOT depend on any of them):",
				...OPTIONAL_CAPABILITIES.map((entry) => `- ${entry.tool.padEnd(28)} ${hasTool(ctx, entry.tool) ? "AVAILABLE" : "absent"}  — ${entry.why}`),
				"A skill that mentions an absent capability names this plugin's own tool as the fallback; follow the fallback rather than calling a tool that is not in the catalog.",
				"",
				`Registered f2x_ tools: ${ctx.tools.schemas().filter((schema) => schema.name.startsWith("f2x_")).length}`,
				`Ledger: ${activeStore().path} (persistent=${activeStore().persistent ? "yes" : "no"})`,
				`Experience store: ${new ExperienceStore(resolveStateDir(config), config.persistState).path} — recall with f2x_exp_search; this mode+workspace's lessons are injected automatically.`,
				`Reference root: ${referenceRoot === "" ? "(not configured — optional; the power/OT skills that cite a reference tree will say so)" : `${referenceRoot} (exists=${existsSync(referenceRoot) ? "yes" : "no"})`} — set the referenceRoot config key or $REDTEAM_REFS to point at a read-only copy.`,
				`Knowledge base: ${knowledgeBase} (exists=${existsSync(knowledgeBase) ? "yes" : "no"}) — the skills cite this tree as refs/...; resolve those refs against it, not against the session cwd.`,
				`Console: ${CONSOLE_PATH} on the Web host (same origin as the UI, loopback only) — read-only page over the ledger, blackboard, findings, OT audit trail and this self-check.`
			].join("\n");
		}
	}));
	ctx.tools.register(defineTool({
		name: "f2x_orchestrate_export",
		description: "Export the engagement ledger as a handover document: per-stage checkpoints, gate verdicts, blackboard facts and the OT audit trail, in the order a reviewer reads them. Use it when closing a task or handing the engagement to another session.",
		parameters: { taskId: {
			type: "string",
			description: "Task id; omit for the active task."
		} },
		output: {
			schema: { type: "string" },
			render: (_args, value) => [{
				type: "text",
				text: value
			}]
		},
		async execute(args) {
			const state = await activeStore().read();
			const taskId = args.taskId ?? state.activeTaskId;
			const task = taskId === void 0 ? void 0 : state.tasks[taskId];
			if (task === void 0) return "Refused: no task to export. Open one with f2x_orchestrate_start first.";
			const lines = [
				`# Handover: ${task.id}`,
				"",
				`Brief: ${task.brief}`,
				`Plane: ${task.mode}/${task.lane} | stage: ${task.stage} | status: ${task.status}`,
				`Targets: ${task.targets.join(", ") || "(none)"}`,
				`Authorized range: ${task.allowedTargets.join(", ") || "(empty)"}`,
				`Opened: ${task.createdAt} | updated: ${task.updatedAt}`,
				"",
				"## Stage evidence"
			];
			for (const stage of STAGES) {
				const cps = task.checkpoints[stage] ?? [];
				if (cps.length === 0) continue;
				const gate = task.gates[stage];
				lines.push(`### ${stage} — gate ${gate === void 0 ? "not run" : gate.pass ? "PASS" : "FAIL"} (${cps.length} checkpoints)`);
				for (const cp of cps) lines.push(`- ${cp.id} [${cp.level}] ${cp.summary} :: evidence=${cp.evidence}`);
				if (gate !== void 0 && !gate.pass && gate.openGaps.length > 0) {
					lines.push("  open gaps:");
					for (const gap of gate.openGaps) lines.push(`  - ${gap}`);
				}
			}
			lines.push("", "## Blackboard", renderBlackboard(state.blackboard.filter((entry) => entry.taskId === task.id)));
			const findings = state.findings.filter((entry) => entry.taskId === task.id);
			lines.push("", `## Findings (${findings.length})`);
			if (findings.length === 0) lines.push("- (none registered)");
			for (const finding of findings) {
				lines.push(`- ${finding.id} [${finding.severity}/${finding.status}/${finding.evidenceLevel}] ${finding.title} @ ${finding.target}`, `  type: ${finding.type}`, `  ${finding.summary}`);
				if ([
					finding.baseline,
					finding.diffEvidence,
					finding.markerEcho
				].some((leg) => leg !== void 0)) {
					lines.push(`  baseline: ${finding.baseline ?? "(missing)"}`);
					lines.push(`  diff: ${finding.diffEvidence ?? "(missing)"}`);
					lines.push(`  marker: ${finding.markerEcho ?? "(missing)"}`);
				}
				if (finding.impact !== void 0) lines.push(`  impact: ${finding.impact}`);
				if (finding.evidence !== void 0) lines.push(`  evidence: ${finding.evidence}`);
				if (finding.fix !== void 0) lines.push(`  fix: ${finding.fix}`);
			}
			const audit = state.audit.filter((entry) => entry.taskId === task.id);
			lines.push("", `## OT audit trail (${audit.length} entries)`);
			for (const entry of audit) lines.push(`- ${entry.id} ${entry.at} [${entry.impact}] ${entry.action} -> ${entry.target}${entry.confirmedBy === void 0 ? " (no confirmation)" : ` (confirmed by ${entry.confirmedBy})`}`);
			if (task.violations.length > 0) {
				lines.push("", "## Doctrine violations");
				for (const violation of task.violations) lines.push(`- ${violation}`);
			}
			lines.push("", "## Experience hand-back", "Hand back what this engagement TAUGHT so the next one starts ahead: call", "`f2x_experience_add` for each lesson worth keeping (kind=tactic|fingerprint|tooling|pitfall|result,", `and pass engagement="${task.id}" so it traces back here). Recall is \`f2x_experience_search\`.`, "This document is the ledger; the experience store is the knowledge.");
			return lines.join("\n");
		}
	}));
}
/**
* Which agent-preset mode an agent runs on, or `''` for a session outside the modes.
*
* Read at call time from the caller's own agent rather than captured when the plugin
* mounted: one mount serves every mode, so the mode is a property of the CALL, not of
* the instance. A failure here must not fail the tool — an unresolvable preset reads
* as "not a security mode" and the tool says so.
*/
function presetOfAgent(ctx, agent) {
	if (agent === void 0 || agent.ctx === void 0) return "";
	try {
		const id = ctx.get("agentPresets")?.composedPreset?.(agent.ctx);
		return typeof id === "string" ? id : "";
	} catch {
		return "";
	}
}
/**
* Register the automatic recall block for this scope.
*
* Called once per mounted instance — the host row and each preset row — because the
* prompt registry is layered per scope: a registration made in the host plane would
* otherwise be the ONLY one, and the block would never reach a session whose context
* lives in a preset's realm. A scope that already carries the name drops the second
* registration (the registry throws on a duplicate), which is why this is guarded
* rather than assumed.
*
* One block per scope is also what keeps the cost bounded: the block is mode-aware by
* construction — it resolves the CALLING agent's mode and workspace while it renders —
* so there is nothing to duplicate per mode even if a scope holds several sessions.
*/
/** Escape hatch: `DSH_F2X_EXPERIENCE_INJECT=off` silences the recall block. */
function experienceInjectionEnabled() {
	const flag = String(globalThis.process?.env?.DSH_F2X_EXPERIENCE_INJECT ?? "").trim().toLowerCase();
	return !(flag === "0" || flag === "off" || flag === "false" || flag === "no");
}
function registerExperienceInjection(ctx, config) {
	const store = () => new ExperienceStore(resolveStateDir(config), config.persistState);
	try {
		ctx.systemPrompt.context({
			name: "f2x-experience",
			order: 600,
			text: (assembly) => {
				const agent = assembly?.agent;
				if (agent === void 0) return "";
				const mode = presetOfAgent(ctx, agent);
				if (mode === "") return "";
				if (!experienceInjectionEnabled()) return "";
				const cwd = agent.session?.header?.cwd;
				const workspace = workspaceOf(typeof cwd === "string" ? cwd : void 0);
				try {
					return buildExperienceBlock(mode, workspace.name, store().topForInjection(mode, workspace.key));
				} catch {
					return "";
				}
			}
		});
	} catch {}
}
/**
* The experience tools — this plugin's own battle-knowledge store.
*
* Three tools, not five: every tool definition is paid for on every turn of every
* mode, so `get`/`list`/`remove` share one `work` entry point, and the long-form
* discipline (what belongs here, what the body should contain) lives in the
* automatically injected block and in the modes' own persona text rather than in the
* schemas. Recall that costs more than the work it saves is not worth having.
*
* The store is scoped by the CALLING mode (resolved from the caller's agent preset)
* and by the session's working directory, so the same plugin instance can serve all
* twelve modes from one file without their notes bleeding together.
*/
function registerExperienceTools(ctx, config) {
	const store = () => new ExperienceStore(resolveStateDir(config), config.persistState);
	/** Which mode and workspace this call is on behalf of. */
	const where = (exec) => {
		const agent = exec?.agent;
		const cwd = agent?.session?.header?.cwd;
		const workspace = workspaceOf(typeof cwd === "string" ? cwd : void 0);
		return {
			mode: presetOfAgent(ctx, agent),
			name: workspace.name,
			key: workspace.key,
			session: typeof agent?.session?.id === "string" ? agent.session.id : ""
		};
	};
	ctx.tools.register(defineTool({
		name: "f2x_exp",
		description: "Record what this engagement TAUGHT so the next one starts ahead — a tactic that worked, a fingerprint, a tool that turned out to be unavailable, a trap that cost time, an answer worth reusing. Same title (+target) refreshes instead of duplicating; the refresh returns the previous body so a wrong merge is visible. Evidence of value: a later session recalls it. Stored verbatim for this local machine; per-target bookkeeping belongs in the asset/vuln ledger, not here.",
		parameters: {
			title: {
				type: "string",
				required: true,
				description: "One line naming the lesson; reusing it updates that record."
			},
			content: {
				type: "string",
				required: true,
				description: "What another session needs to reuse it: hit condition / steps / key parameters / verified result."
			},
			kind: {
				type: "string",
				enum: [...EXPERIENCE_KINDS],
				description: "tactic | fingerprint | tooling | lesson | detect."
			},
			tags: {
				type: "string",
				description: "Comma-separated recall tags, e.g. java,后台,弱口令."
			},
			target_kind: {
				type: "string",
				description: "What it applies to (product family, platform, case id); recall filters on it."
			},
			expires_days: {
				type: "number",
				description: "Override the per-kind default (detect 30d, fingerprint 180d, others permanent)."
			}
		},
		output: {
			schema: { type: "string" },
			render: (_args, value) => [{
				type: "text",
				text: value
			}]
		},
		async execute(args, exec) {
			const scope = where(exec);
			if (scope.mode === "") return "Refused: this session is not on a security mode preset (experience is scoped per mode).";
			const active = store();
			const result = active.write({
				title: args.title,
				content: args.content,
				kind: args.kind,
				mode: scope.mode,
				workspace: scope.name,
				workspaceKey: scope.key,
				sourceSession: scope.session,
				...args.tags === void 0 ? {} : { tags: args.tags },
				...args.target_kind === void 0 ? {} : { targetKind: args.target_kind },
				...args.expires_days === void 0 ? {} : { expiresDays: args.expires_days }
			});
			return [
				`${result.refreshed ? "Refreshed" : "Recorded"} ${result.record.id} [${result.record.kind}] ${result.record.title}`,
				`scope: mode=${scope.mode} workspace=${scope.key === "" ? "(none)" : scope.key} | records here: ${String(active.size({
					mode: scope.mode,
					workspaceKey: scope.key
				}))}${result.evicted > 0 ? ` (archived ${String(result.evicted)} coldest)` : ""}`,
				...result.refreshed ? [`receipt: previous body was ${String(result.previous?.chars ?? 0)} chars, starting "「${result.previous?.preview ?? ""}…」" — if that is not the same lesson, use a different title.`] : [],
				...result.truncated ? [`truncated: content exceeded ${String(MAX_BODY_CHARS)} chars and was cut — shorten it or split by target.`] : [],
				`store: ${active.path}${active.persistent ? "" : " (in-memory: persistState=false)"}`
			].join("\n");
		}
	}));
	ctx.tools.register(defineTool({
		name: "f2x_exp_search",
		description: "Recall what earlier engagements learned. Call it before planning: terms are OR-matched over title/body/tags (CJK substrings of 3+ chars included), ranked by match × usage × 30-day decay. Returns one line per record; ask again with id for one full record. Pass all=1 to browse the whole scope instead of searching.",
		parameters: {
			q: {
				type: "string",
				description: "Terms; omit (with all=1) to browse the scope."
			},
			kind: {
				type: "string",
				enum: [...EXPERIENCE_KINDS],
				description: "Restrict to one kind."
			},
			target_kind: {
				type: "string",
				description: "Restrict to one target family/platform."
			},
			id: {
				type: "string",
				description: "Return one record in full (and count it as used)."
			},
			all: {
				type: "number",
				description: "1 = list the whole scope instead of searching."
			},
			limit: {
				type: "number",
				description: "Max lines (default 10, max 50)."
			}
		},
		output: {
			schema: { type: "string" },
			render: (_args, value) => [{
				type: "text",
				text: value
			}]
		},
		async execute(args, exec) {
			const scope = where(exec);
			if (scope.mode === "") return "Refused: this session is not on a security mode preset (experience is scoped per mode).";
			const active = store();
			if (args.id !== void 0) {
				const record = active.get(String(args.id));
				if (record === void 0) return `No record ${String(args.id)}. Store: ${active.path}`;
				active.markUsed([record.id]);
				return renderExperience(record);
			}
			const browse = args.all !== void 0 && Number(args.all) !== 0;
			const hits = active.search({
				...browse ? {} : { q: args.q ?? "" },
				mode: scope.mode,
				workspaceKey: scope.key,
				...args.kind === void 0 ? {} : { kind: args.kind },
				...args.target_kind === void 0 ? {} : { targetKind: args.target_kind },
				limit: args.limit ?? 10
			});
			const here = active.size({
				mode: scope.mode,
				workspaceKey: scope.key
			});
			if (hits.length === 0) return browse ? `No experience recorded for mode=${scope.mode} workspace=${scope.key === "" ? "(none)" : scope.key}. Record the first with f2x_exp.` : `No lesson matched${args.q === void 0 ? "" : ` "${args.q}"`} in this scope (${String(here)} record(s)). Omit q with all=1 to browse, or pass no workspace filter by searching from the directory the note was written in.`;
			return [
				`# Experience recall (${String(hits.length)} of ${String(here)} here) — mode=${scope.mode} workspace=${scope.key === "" ? "(none)" : scope.key}`,
				"",
				hits.map((hit) => `${renderExperienceLine(hit.record)}${hit.expired ? " [expired]" : ""}`).join("\n"),
				"",
				`Full record: f2x_exp_search { id: "<f2x-exp-N>" } — reading one counts as a use and raises its recall rank.`
			].join("\n");
		}
	}));
	ctx.tools.register(defineTool({
		name: "f2x_exp_work",
		description: "Curate the experience store: list one scope, forget a record (archived, not deleted), or purge expired detection intel. Use it when a record is wrong or has been superseded — a store nobody prunes stops being worth recalling.",
		parameters: {
			action: {
				type: "string",
				enum: [
					"list",
					"forget",
					"purge-expired",
					"stats"
				],
				description: "What to do."
			},
			ids: {
				type: "array",
				items: { type: "string" },
				description: "forget: record ids (f2x-exp-N)."
			},
			kind: {
				type: "string",
				enum: [...EXPERIENCE_KINDS],
				description: "list: restrict to one kind."
			},
			scope: {
				type: "string",
				enum: ["workspace", "mode"],
				description: "list/stats scope (default workspace)."
			},
			limit: {
				type: "number",
				description: "list: max rows (default 20)."
			}
		},
		output: {
			schema: { type: "string" },
			render: (_args, value) => [{
				type: "text",
				text: value
			}]
		},
		async execute(args, exec) {
			const scope = where(exec);
			if (scope.mode === "") return "Refused: this session is not on a security mode preset (experience is scoped per mode).";
			const active = store();
			const wide = args.scope === "mode";
			switch (args.action) {
				case "forget": {
					const moved = active.archive(args.ids ?? []);
					return moved === 0 ? "Nothing forgotten: no record with those ids (see f2x_exp_work { action: \"list\" })." : `Archived ${String(moved)} record(s) — recoverable in the archive table of ${active.path}.`;
				}
				case "purge-expired": {
					const purged = active.purgeExpired();
					return purged === 0 ? "Nothing expired." : `Archived ${String(purged)} expired record(s) (detection intel past its half-life).`;
				}
				case "stats": {
					const rows = active.stats();
					if (rows.length === 0) return `Store is empty (${active.path}).`;
					return [`# Experience store (${active.path})`, ...rows.map((row) => `- ${row.mode}/${row.workspace === "" ? "(none)" : row.workspace}: ${String(row.rows)} record(s)${row.archived > 0 ? `, ${String(row.archived)} archived` : ""}`)].join("\n");
				}
				default: {
					const rows = active.list({
						mode: scope.mode,
						...wide ? {} : { workspaceKey: scope.key },
						...args.kind === void 0 ? {} : { kind: args.kind },
						...args.limit === void 0 ? {} : { limit: args.limit }
					});
					if (rows.length === 0) return `No records for mode=${scope.mode}${wide ? "" : ` workspace=${scope.key === "" ? "(none)" : scope.key}`}.`;
					return [
						`# Experience list (mode=${scope.mode}${wide ? "" : ` workspace=${scope.key === "" ? "(none)" : scope.key}`}, ${String(rows.length)} shown)`,
						"",
						rows.map(renderExperienceLine).join("\n")
					].join("\n");
				}
			}
		}
	}));
}
/**
* Cordis plugin entry point.
*
* Three contributions, all effects: the `f2x_*` tools on `ctx.tools`, an optional
* global skill provider on `ctx.skills`, and (through `presets/`) the mode
* definitions an agent preset reads. Disposing the plugin fiber removes the first
* two; the presets are plain files the operator wires in.
*
* The skill provider is optional because there are two valid ways to publish the
* same directories. The global provider makes a single-plugin deployment work out
* of the box. An agent preset using `customSkillDirs` instead scopes each skill to
* its own mode, which is what keeps the power skills out of unrelated sessions —
* set `registerSkillProvider: false` when `presets/` is wired in.
*/
function registerConsole(ctx, config) {
	const activeStore = () => {
		if (store === void 0) store = new StateStore(resolveStateDir(config), config.persistState);
		return store;
	};
	ctx.inject(["webServer"], (webCtx) => {
		const server = webCtx.webServer;
		if (server === void 0) return;
		webCtx.effect(() => server.register({
			kind: "prefix",
			path: CONSOLE_PATH,
			handler: async (req, res) => {
				if (!isLoopbackAddress(req.socket?.remoteAddress)) {
					res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
					res.end("f2x console is served to loopback clients only\n");
					return;
				}
				const url = new URL(req.url ?? "/", "http://localhost");
				if (url.pathname === `/f2x-console/raw`) {
					const state = await activeStore().read();
					res.writeHead(200, {
						"content-type": "application/json; charset=utf-8",
						"content-disposition": "attachment; filename=\"f2x-state.json\"",
						"cache-control": "no-store"
					});
					res.end(JSON.stringify(state, null, 2));
					return;
				}
				if (url.pathname === `/f2x-console/state`) {
					const referenceRoot = resolveReferenceRoot(config);
					const knowledgeBase = bundledRefsDir();
					const capabilities = OPTIONAL_CAPABILITIES.map((entry) => ({
						tool: entry.tool,
						why: entry.why,
						available: hasTool(ctx, entry.tool)
					}));
					const snapshot = buildConsoleSnapshot({
						plugin: {
							name,
							version: PLUGIN_VERSION
						},
						state: await activeStore().read(),
						paths: {
							ledger: activeStore().path,
							persistent: activeStore().persistent,
							referenceRoot,
							referenceRootExists: existsSync(referenceRoot),
							knowledgeBase,
							knowledgeBaseExists: existsSync(knowledgeBase)
						},
						config: {
							allowedTargets: config.allowedTargets,
							enablePowerModule: config.enablePowerModule,
							registerSkillProvider: config.registerSkillProvider,
							persistState: config.persistState,
							maxConcurrencyPerTarget: config.maxConcurrencyPerTarget,
							maxCheckpointsPerStage: config.maxCheckpointsPerStage,
							gateValidityStages: config.gateValidityStages
						},
						capabilities
					});
					res.writeHead(200, {
						"content-type": "application/json; charset=utf-8",
						"cache-control": "no-store"
					});
					res.end(JSON.stringify(snapshot, null, 2));
					return;
				}
				res.writeHead(200, {
					"content-type": "text/html; charset=utf-8",
					"cache-control": "no-store"
				});
				res.end(renderConsoleHtml(`${name} — f2x 控制台`));
			}
		}), "f2x-console.route");
	});
}
/**
* Register the capability manager page and its endpoints.
*
* Same posture as the console: a plain route on the raw web server, loopback clients
* only, because it can install packages into the running profile. A Settings page can
* front the same handlers later; keeping the logic here means it stays verifiable over
* HTTP while that page is built.
*/
function registerManager(ctx) {
	ctx.inject(["webServer"], (webCtx) => {
		const server = webCtx.webServer;
		if (server === void 0) return;
		/** Read a form body, capped: the only field is a short specifier. */
		const readBody = (req) => new Promise((resolveBody) => {
			let raw = "";
			req.on("data", (chunk) => {
				raw += chunk.toString("utf8");
				if (raw.length > 4096) raw = raw.slice(0, 4096);
			});
			req.on("end", () => {
				resolveBody(new URLSearchParams(raw));
			});
			req.on("error", () => {
				resolveBody(new URLSearchParams());
			});
		});
		webCtx.effect(() => server.register({
			kind: "prefix",
			path: MANAGER_PATH,
			handler: async (req, res) => {
				if (!(() => {
					const origin = req.headers.origin;
					const referer = req.headers.referer;
					const host = req.headers.host;
					const hostIsLoopback = typeof host === "string" && /^(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i.test(host.trim());
					const source = typeof origin === "string" ? origin : typeof referer === "string" ? referer : void 0;
					if (source === void 0) return hostIsLoopback;
					try {
						const parsed = new URL(source);
						return hostIsLoopback && /^(localhost|127\.0\.0\.1|\[::1\])$/i.test(parsed.hostname);
					} catch {
						return false;
					}
				})()) {
					res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
					res.end("refused: a state-changing request to the f2x capability manager must come from a loopback page\n");
					return;
				}
				if (!isLoopbackAddress(req.socket?.remoteAddress)) {
					res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
					res.end("the f2x capability manager is served to loopback clients only\n");
					return;
				}
				const profileContext = ctx.get?.("profileContext");
				const env = resolveManagerEnv({
					...profileContext === void 0 ? {} : { profileContext },
					pluginRoot: resolvePackageRoot()
				});
				if (env === void 0) {
					res.writeHead(503, { "content-type": "text/plain; charset=utf-8" });
					res.end("DSH_PROFILE / DSH_PROFILE_DIR are unset, so there is no profile to manage\n");
					return;
				}
				const url = new URL(req.url ?? "/", "http://localhost");
				const send = (status, type, body) => {
					res.writeHead(status, {
						"content-type": `${type}; charset=utf-8`,
						"cache-control": "no-store"
					});
					res.end(body);
				};
				if (url.pathname === `/f2x-manager/install` && req.method === "POST") {
					const specifier = ((await readBody(req)).get("specifier") ?? "").trim();
					if (specifier === "") {
						send(400, "text/plain", "no specifier given\n");
						return;
					}
					const report = await installPlugin(specifier, env);
					const verification = verifyInstalled(specifier, env);
					send(report.ok ? 200 : 502, "text/plain", `${renderInstallText(specifier, report)}\n\n--- 验证 ---\n${verification.notes.join("\n")}\n`);
					return;
				}
				if (url.pathname === `/f2x-manager/repo` && req.method === "POST") {
					const repoUrl = ((await readBody(req)).get("url") ?? "").trim();
					if (repoUrl === "") {
						send(400, "text/plain", "no repository URL given\n");
						return;
					}
					const report = await prepareRepo(repoUrl, env);
					send(report.ok ? 200 : 502, "text/plain", renderRepoText(report));
					return;
				}
				if (url.pathname === `/f2x-manager/state`) {
					const snapshot = await buildSnapshot(env);
					send(200, "application/json", JSON.stringify(snapshot, null, 2));
					return;
				}
				const snapshot = await buildSnapshot(env);
				send(200, "text/html", renderManagerHtml(snapshot));
			}
		}));
	});
	/** Collect the page's data: checks, recommendations, and what is already installed. */
	const buildSnapshot = async (env) => ({
		profile: env.profile,
		profileDir: env.profileDir,
		checks: await runEnvironmentCheck(env),
		recommended: RECOMMENDED,
		installed: RECOMMENDED.map((entry) => verifyInstalled(entry.specifier, env)),
		repos: RECOMMENDED_REPOS
	});
}
/** This package's root, resolved from the built module's location. */
function resolvePackageRoot() {
	return fileURLToPath(new URL("./", new URL("..", import.meta.url)));
}
function apply(ctx, config) {
	store = new StateStore(resolveStateDir(config), config.persistState);
	registerTools(ctx, config);
	registerExperienceTools(ctx, config);
	registerExperienceInjection(ctx, config);
	registerConsole(ctx, config);
	registerManager(ctx);
	const roots = [
		...bundledSkillDirs(),
		...config.publishPowerSkillsGlobally ? [bundledPowerSkillDir()] : [],
		...config.extraSkillDirs.filter((dir) => dir.trim() !== "")
	];
	if (!config.registerSkillProvider) {
		ctx.logger.info(`${name}: registered f2x_* tools; global skill provider disabled (registerSkillProvider=false), expecting skills via an agent preset's customSkillDirs`);
		return;
	}
	const provider = createSkillProvider(roots, ctx.logger);
	ctx.skills.registerProvider(() => provider);
	ctx.logger.info(`${name}: registered f2x_* tools and skill provider "${F2X_PROVIDER_NAME}" over ${roots.length} root(s)`);
}
//#endregion
export { CONSOLE_PATH, Config, MANAGER_PATH, OPTIONAL_CAPABILITIES, PLUGIN_VERSION, apply, defaultReferenceRoot, hasTool, inject, name, presetOfAgent, renderBlackboard, renderTaskLine, resolveReferenceRoot, resolveStateDir };
