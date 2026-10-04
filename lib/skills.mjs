import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { readFile, readdir } from "node:fs/promises";
//#region src/skills.ts
/**
* Local skill provider for the f2x redteam plugin.
*
* Why a provider instead of `customSkillDirs`: that config key belongs to
* `@deepseek-ai/dsh-skill-filesystem`, which is an **agent-preset plane** row —
* a bundle patch cannot reach it, so a plugin cannot register its skill roots
* that way. The documented seam for a plugin that owns skills is
* `ctx.skills.registerProvider()` (see the harness `docs/subsystems/skills.md`):
* the provider lands in the registry's global layer, is visible to every agent,
* and is unregistered automatically with the plugin fiber because registration
* returns a Cordis disposer.
*
* `customSkillDirs` remains a supported alternative for operators who prefer to
* point the preset at these directories; both paths end up loading the same
* `SKILL.md` files.
*/
/** Rank 250 sits between `project-agents` (200) and `custom` (300). */
const F2X_SKILL_RANK = 250;
/** Provider name registered on `ctx.skills`. */
const F2X_PROVIDER_NAME = "f2x-redteam3000";
/** Skill names this plugin must never shadow, because sibling plugins own them. */
const RESERVED_SKILL_NAMES = [
	"ot-ics",
	"firmware-pentest",
	"hardware-security",
	"radio-sdr",
	"protocol-reverse",
	"pentest-playbook",
	"red-team-command-doctrine",
	"redteam-boundary-policy",
	"asset-mapping-playbook",
	"ir-playbook",
	"ctf-playbook",
	"audit-playbook",
	"av-playbook",
	"cloud-playbook",
	"router-playbook",
	"independent-review",
	"ecosystem-cooperation"
];
const SKILL_NAME_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
/**
* The bundled skill roots, resolved relative to this module.
*
* The package layout is `<pkg>/lib/index.mjs` next to `<pkg>/skills`, `<pkg>/refs`
* and `<pkg>/persona`, so one level up from the built module is the package root.
* Both `skills/` and `skills/power/` are published roots; a flat `<name>.md` in
* either is picked up too.
*
* @param from - the module URL to resolve against; overridable for tests.
*/
function bundledSkillDirs(from = import.meta.url) {
	const root = bundledPackageRoot(from);
	return [join(root, "skills"), join(root, "vendor", "redteam-skills")];
}
/**
* The power/OT skill root, kept out of {@link bundledSkillDirs}.
*
* `skills/` and `skills/power/` used to be published as one set from the host row, which
* made the five power skills visible in *every* mode — a code-audit or binary-analysis
* session advertised Modbus, S7comm and IEC 61850 analysis. The root itself only holds
* `skills/power/`, so a preset that opts in gets exactly the power skills and nothing else.
*
* @param from - the module URL to resolve against; overridable for tests.
*/
function bundledPowerSkillDir(from = import.meta.url) {
	return join(bundledPackageRoot(from), "skills", "power");
}
/**
* The package root, one level up from the built module.
*
* The package layout is `<pkg>/lib/index.mjs` next to `<pkg>/skills`, `<pkg>/refs`
* and `<pkg>/persona`.
*
* @param from - the module URL to resolve against; overridable for tests.
*/
function bundledPackageRoot(from = import.meta.url) {
	return fileURLToPath(new URL("./", new URL("..", from)));
}
/**
* Absolute path of the bundled knowledge base (`<pkg>/refs`).
*
* The skills cite this tree relatively (`refs/power/protocols/modbus.md`), which
* only resolves against the package root — not the session cwd. The doctrine
* self-check prints this value so a model never has to guess it.
*
* @param from - the module URL to resolve against; overridable for tests.
*/
function bundledRefsDir(from = import.meta.url) {
	return join(bundledPackageRoot(from), "refs");
}
/** Read a boolean frontmatter key, defaulting to `true` when omitted. */
function readBool(frontmatter, key, fallback) {
	const match = new RegExp(`^${key}:\\s*(.+)$`, "m").exec(frontmatter);
	if (match === null) return fallback;
	const value = (match[1] ?? "").trim().replace(/^["']|["']$/g, "").toLowerCase();
	if (value === "true" || value === "yes" || value === "1") return true;
	if (value === "false" || value === "no" || value === "0") return false;
	return fallback;
}
/** Read a scalar frontmatter key, collapsing folded/literal block scalars. */
function readScalar(frontmatter, key) {
	const lines = frontmatter.split(/\r?\n/);
	for (let index = 0; index < lines.length; index += 1) {
		const line = lines[index] ?? "";
		const match = new RegExp(`^${key}:\\s*(.*)$`).exec(line);
		if (match === null) continue;
		const inline = (match[1] ?? "").trim();
		if (inline === "" || /^[>|][+-]?$/.test(inline)) {
			const collected = [];
			for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
				const next = lines[cursor] ?? "";
				if (next.trim() === "") {
					collected.push("");
					continue;
				}
				if (!/^\s/.test(next)) break;
				collected.push(next.trim());
			}
			const joined = collected.join(" ").replace(/\s+/g, " ").trim();
			return joined === "" ? void 0 : joined;
		}
		return inline.replace(/^["']|["']$/g, "");
	}
}
/**
* Parse one `SKILL.md` body into a skill definition.
* @param raw - the whole file text.
* @param fallbackName - the directory name, used when frontmatter omits `name`.
* @returns the parsed skill, or `undefined` when the file is not a usable skill.
*/
function parseSkillMarkdown(raw, fallbackName) {
	const normalized = raw.replace(/^\uFEFF/, "");
	const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(normalized);
	if (match === null) return void 0;
	const frontmatter = match[1] ?? "";
	const body = (match[2] ?? "").trim();
	const name = readScalar(frontmatter, "name") ?? fallbackName;
	const description = readScalar(frontmatter, "description");
	if (name === void 0 || description === void 0) return void 0;
	if (!SKILL_NAME_RE.test(name)) return void 0;
	if (body === "") return void 0;
	const whenToUse = readScalar(frontmatter, "whenToUse") ?? readScalar(frontmatter, "when-to-use");
	return {
		name,
		description,
		...whenToUse === void 0 ? {} : { whenToUse },
		modelInvocable: readBool(frontmatter, "disable-model-invocation", false) ? false : true,
		userInvocable: readBool(frontmatter, "user-invocable", true),
		content: body
	};
}
/**
* Scan `roots` for `<name>/SKILL.md` bundles and flat `<name>.md` files.
*
* Discovery is intentionally shallow — the harness local provider documents that
* nested `**​/SKILL.md` discovery is not supported, and mirroring that keeps the
* two loading paths equivalent.
*
* @param roots - absolute skill root directories; missing roots are skipped.
* @param logger - optional sink for non-fatal diagnostics.
* @returns discovered skills, sorted by name.
*/
async function discoverSkills(roots, logger) {
	const diagnostics = [];
	const found = [];
	for (const root of roots) {
		if (root.trim() === "") continue;
		let entries;
		try {
			entries = await readdir(root);
		} catch {
			diagnostics.push(`skill root not readable, skipped: ${root}`);
			continue;
		}
		for (const entry of entries.sort()) {
			if (entry.startsWith(".")) continue;
			const asBundle = join(root, entry, "SKILL.md");
			const asFlat = join(root, `${entry}.md`);
			for (const candidatePath of [asBundle, asFlat]) {
				let raw;
				try {
					raw = await readFile(candidatePath, "utf8");
				} catch {
					continue;
				}
				const parsed = parseSkillMarkdown(raw, entry.replace(/\.md$/, ""));
				if (parsed === void 0) {
					const message = `skill file ignored (missing or invalid frontmatter): ${candidatePath}`;
					diagnostics.push(message);
					logger?.warn(message);
					continue;
				}
				if (RESERVED_SKILL_NAMES.includes(parsed.name)) {
					const message = `skill "${parsed.name}" ignored: the name is reserved by another installed plugin (${candidatePath})`;
					diagnostics.push(message);
					logger?.warn(message);
					continue;
				}
				found.push({
					skill: parsed,
					path: candidatePath,
					dir: root
				});
				break;
			}
		}
	}
	const seen = /* @__PURE__ */ new Map();
	for (const item of found) if (!seen.has(item.skill.name)) seen.set(item.skill.name, item);
	return {
		skills: [...seen.values()].sort((left, right) => left.skill.name.localeCompare(right.skill.name)),
		diagnostics
	};
}
/**
* Build the provider object registered on `ctx.skills`.
*
* `list()` re-scans on every call so edits to a `SKILL.md` take effect without a
* host restart; that cost is trivial for a directory holding a few dozen files
* and keeps the plugin honest about hot reload.
*/
/**
* Text prepended to every skill this provider serves.
*
* The skills are procedural manuals: they describe steps, and none of them mentioned this plugin's
* own gates. So an operator could follow a skill end to end and never touch `f2x_orchestrate_*` —
* the staged ledger, the scope check and the write gate would sit unused. Injecting one paragraph
* here is what makes the skills route through the gates, without editing 34 files (and without
* pretending the gates can see a shell, which they cannot).
*/
const SKILL_GATE_PRELUDE = [
	"> **开工前（本插件门禁，先读三行）**",
	"> 1. 用 `f2x_orchestrate_start` 开任务并写清 `targets`/`allowlist`；范围存疑先跑 `f2x_orchestrate_scope`。",
	"> 2. 任何**写操作/控制操作/凭据操作**上报前，必须先过 `f2x_orchestrate_audit` 取得二次确认；",
	">    删除、脱库一类动作被本插件**硬拒**（给确认也没用）。",
	"> 3. `f2x_orchestrate_checkpoint` 记证据（要真实指针，占位符不算）、`_verify` 过门禁、`_mark` 才能推进阶段。",
	">",
	"> **诚实的边界**：以上只约束**经本插件登记**的动作。你在 shell 里直接敲的命令（`nmap`、`hydra`、`sqlmap`…）",
	"> 它**看不到也拦不住**——本插件是编排与记录层，不是沙箱、不是 EDR。请自行控制范围与节奏。"
].join("\n") + "\n\n";
function createSkillProvider(roots, logger) {
	return {
		name: F2X_PROVIDER_NAME,
		async list() {
			const { skills } = await discoverSkills(roots, logger);
			return skills.map(({ skill, dir }) => ({
				name: skill.name,
				description: skill.description,
				...skill.whenToUse === void 0 ? {} : { whenToUse: skill.whenToUse },
				invocation: {
					modelInvocable: skill.modelInvocable,
					userInvocable: skill.userInvocable
				},
				source: "custom",
				provider: F2X_PROVIDER_NAME,
				resourceBase: {
					kind: "directory",
					path: dir
				},
				rank: 250,
				locator: skill.name
			}));
		},
		async get(candidate) {
			const { skills } = await discoverSkills(roots, logger);
			const hit = skills.find((item) => item.skill.name === candidate.name);
			if (hit === void 0) return void 0;
			return {
				name: hit.skill.name,
				description: hit.skill.description,
				...hit.skill.whenToUse === void 0 ? {} : { whenToUse: hit.skill.whenToUse },
				invocation: {
					modelInvocable: hit.skill.modelInvocable,
					userInvocable: hit.skill.userInvocable
				},
				source: "custom",
				provider: F2X_PROVIDER_NAME,
				resourceBase: {
					kind: "directory",
					path: hit.dir
				},
				content: SKILL_GATE_PRELUDE + hit.skill.content
			};
		}
	};
}
//#endregion
export { F2X_PROVIDER_NAME, F2X_SKILL_RANK, RESERVED_SKILL_NAMES, SKILL_GATE_PRELUDE, bundledPackageRoot, bundledPowerSkillDir, bundledRefsDir, bundledSkillDirs, createSkillProvider, discoverSkills, parseSkillMarkdown };
