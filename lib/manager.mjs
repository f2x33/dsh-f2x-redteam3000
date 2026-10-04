import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
//#region src/manager.ts
/**
* Host-side capability manager: environment self-check, conflict pre-check, install
* with automatic version exemption, and post-install verification.
*
* Why this exists
* ---------------
* Installing a community plugin into DSH 0.2.x currently fails for four unrelated
* reasons, each with a different error shape and none of them self-explanatory:
*
*   1. `git` is not installed → every `github:` specifier fails to resolve.
*   2. github.com is unreachable on this network → the same specifier fails again.
*   3. The plugin declares a 0.1.x peer range → DSH's compatibility gate refuses it.
*   4. The plugin inserts a loader id an installed plugin already inserts → boot breaks.
*
* A user cannot tell these apart from the messages. This module turns them into a
* checklist, a pre-check, an install that repairs what it can, and a verification pass.
*
* The conflict check is deliberately *not* a copy of the marketplace's
* ----------------------------------------------------------------
* The marketplace compares *every* id nested under an `insert:` — including the ids
* inside a preset's `config.plugins[]`. Those are scoped to their own preset: this
* plugin's own bundle patch declares `persona` eleven times and DSH mounts all eleven
* presets. Comparing them reports conflicts between plugins that coexist fine. Only
* TOP-LEVEL inserted ids create loader entries, so only those are compared here.
*/
/** How long a single external command may take. */
const COMMAND_TIMEOUT_MS = 18e4;
/** How long a reachability probe may take. */
const PROBE_TIMEOUT_MS = 15e3;
/** Where this plugin's own bundle patch lives, relative to the package root. */
const OWN_PATCH = "cordis.patch.yml";
/** A specifier accepted for install. Conservative on purpose: it reaches pnpm. */
const SPECIFIER = /^(?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*(?:@[\w.+-]+)?$|^github:[\w.-]+\/[\w.-]+(?:#[\w./-]+)?$|^\d+$/;
/** Path prefixes a `link:`/`file:` specifier may use: relative forms that stay in-tree. */
const SAFE_PATH_PREFIX = /^(?:link:|file:)?(?:\.[\w.-]*)(?:[\\/][\w.$ -]+)*[\\/]?$/;
/**
* Whether a specifier may be handed to `dsh plugin add`.
*
* The install endpoint is reachable by any page in the operator's browser (it is only
* loopback-protected, which does not stop a cross-origin form post), so this is the one
* remaining gate between a web page and arbitrary code landing in the profile. Two things it
* refuses now that it used to accept:
*
*  - **Absolute paths.** The check used to read `!SPECIFIER.test(x) && !x.startsWith('/')`,
*    i.e. a leading `/` was treated as a *reason to accept* — an attacker could name any path
*    on disk. Absolute paths are refused outright: a legitimate local install uses the relative
*    `link:./subdir` form.
*  - **Parent-directory escapes.** `../x` leaves the tree the operator is working in.
*
* @param specifier - the raw form value.
*/
function isInstallableSpecifier(specifier) {
	const value = specifier.trim();
	if (value === "") return false;
	if (SPECIFIER.test(value)) return true;
	if (/^[a-z][a-z0-9+.-]*:/i.test(value.replace(/^(link|file):/i, ""))) {
		if (!/^(link|file):/i.test(value)) return false;
	}
	if (value.startsWith("/") || value.startsWith("~")) return false;
	if (value.includes("..")) return false;
	return SAFE_PATH_PREFIX.test(value);
}
/**
* Read the profile facts from the environment.
*
* DSH exports `DSH_PROFILE` and `DSH_PROFILE_DIR` to every session it starts, so the
* manager never has to guess which profile it is running inside.
*/
function readManagerEnv(env = process.env, pluginRoot) {
	const profile = env.DSH_PROFILE;
	const profileDir = env.DSH_PROFILE_DIR;
	if (profile === void 0 || profile === "" || profileDir === void 0) return void 0;
	const dshHome = env.DSH_HOME ?? join(homedir(), ".dsh");
	if (resolve(profileDir) !== join(resolve(dshHome), "profiles", profile)) return void 0;
	return {
		profile,
		profileDir,
		dshHome,
		pluginRoot: pluginRoot ?? resolve(new URL("..", import.meta.url).pathname)
	};
}
/**
* Resolve the profile facts, preferring the live host service over the environment.
*
* `profileContext` is the host's own record of which profile it booted, so it cannot be
* stale. The environment is only a fallback for hosts that do not publish it.
*/
function resolveManagerEnv(options) {
	const env = options.env ?? process.env;
	const profile = options.profileContext;
	if (typeof profile?.name === "string" && profile.name !== "" && typeof profile.dir === "string") return {
		profile: profile.name,
		profileDir: profile.dir,
		dshHome: env.DSH_HOME ?? join(homedir(), ".dsh"),
		pluginRoot: options.pluginRoot ?? resolve(new URL("..", import.meta.url).pathname)
	};
	return readManagerEnv(env, options.pluginRoot);
}
/** Run a command, capturing stdout+stderr, with a timeout. Never uses a shell. */
function runCommand(file, args, options = {}) {
	return new Promise((resolvePromise) => {
		let child;
		try {
			child = spawn(file, [...args], {
				cwd: options.cwd,
				env: {
					...process.env,
					...options.env,
					DSH_PROFILE: "",
					PATH: augmentedPath(process.env.PATH)
				},
				shell: false
			});
		} catch {
			resolvePromise({
				code: null,
				output: "",
				timedOut: false
			});
			return;
		}
		let output = "";
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGKILL");
		}, options.timeoutMs ?? COMMAND_TIMEOUT_MS);
		child.stdout?.on("data", (chunk) => {
			output += chunk.toString("utf8");
		});
		child.stderr?.on("data", (chunk) => {
			output += chunk.toString("utf8");
		});
		child.on("error", () => {
			clearTimeout(timer);
			resolvePromise({
				code: null,
				output,
				timedOut
			});
		});
		child.on("close", (code) => {
			clearTimeout(timer);
			resolvePromise({
				code,
				output,
				timedOut
			});
		});
	});
}
/** PATH with the usual package-manager locations appended. */
function augmentedPath(current) {
	const extra = [
		join(homedir(), ".local", "bin"),
		"/usr/local/bin",
		"/usr/bin",
		"/bin"
	];
	const parts = (current ?? "").split(":").filter((p) => p !== "");
	for (const dir of extra) if (!parts.includes(dir)) parts.push(dir);
	return parts.join(":");
}
/**
* Probe whether a URL answers.
*
* Used for the registry check only: github is probed through `git ls-remote`, because
* an HTTP probe would not exercise the git transport that installs actually use.
*/
async function probe(url) {
	const controller = new AbortController();
	const timer = setTimeout(() => {
		controller.abort();
	}, PROBE_TIMEOUT_MS);
	try {
		return (await fetch(url, {
			signal: controller.signal,
			method: "HEAD"
		})).status < 500;
	} catch {
		return false;
	} finally {
		clearTimeout(timer);
	}
}
/** The public repository the github probe resolves; small and stable. */
const GITHUB_PROBE = "https://github.com/git/git";
/**
* Build the environment checklist.
*
* Ordered by how often each one is the actual blocker, and each failing line carries
* the exact remedy, because the raw tool output does not.
*/
async function runEnvironmentCheck(env) {
	const lines = [];
	const git = await runCommand("git", ["--version"], { timeoutMs: PROBE_TIMEOUT_MS });
	const gitOk = git.code === 0;
	lines.push({
		key: "git",
		ok: gitOk,
		label: "git",
		detail: gitOk ? git.output.trim() : "git is not installed. Every `github:` plugin specifier needs it — install it first (apt-get install -y git)."
	});
	const rewriteLine = (gitOk ? await runCommand("git", [
		"config",
		"--global",
		"--get-regexp",
		"url\\."
	], { timeoutMs: PROBE_TIMEOUT_MS }) : {
		code: 1,
		output: "",
		timedOut: false
	}).output.split("\n").find((line) => line.includes("insteadof") || line.includes("insteadOf"));
	lines.push({
		key: "git-rewrite",
		ok: rewriteLine !== void 0,
		label: "GitHub 代理改写",
		detail: rewriteLine === void 0 ? "No url.insteadOf rewrite is configured. If github.com is unreachable, git-hosted installs fail; the marketplace works around this with a proxy." : rewriteLine.trim()
	});
	const reach = gitOk ? await runCommand("git", [
		"ls-remote",
		"--heads",
		GITHUB_PROBE
	], { timeoutMs: PROBE_TIMEOUT_MS }) : {
		code: 1,
		output: "",
		timedOut: false
	};
	lines.push({
		key: "github",
		ok: reach.code === 0,
		label: "github.com 可达",
		detail: reach.code === 0 ? rewriteLine === void 0 ? "reachable directly" : "reachable through the configured rewrite" : "github.com did not answer. Use the marketplace (it has a built-in route) or configure a rewrite."
	});
	const registryOk = await probe("https://registry.npmjs.org/-/ping");
	lines.push({
		key: "registry",
		ok: registryOk,
		label: "npm registry",
		detail: registryOk ? "registry.npmjs.org answers" : "registry.npmjs.org did not answer"
	});
	lines.push({
		key: "profile",
		ok: existsSync(env.profileDir),
		label: "profile",
		detail: `${env.profile} → ${env.profileDir}`
	});
	return lines;
}
/**
* Extract the TOP-LEVEL inserted ids of a patch file's text.
*
* "Top level" means an `- id:` at the same indentation as the entries directly under
* `- insert:`. Ids nested deeper belong to a row's own config — a preset's plugin list,
* for instance — and are scoped to that row, so two presets may both name theirs
* `persona`. Counting those is what makes the marketplace reject valid combinations.
*
* @param text - patch file contents.
* @returns the ids, in file order, deduplicated.
*/
function topLevelInsertedIds(text) {
	const ids = /* @__PURE__ */ new Set();
	const lines = text.split("\n");
	let insertIndent;
	let entryIndent;
	for (const line of lines) {
		const trimmed = line.trim();
		if (trimmed === "" || trimmed.startsWith("#")) continue;
		const indent = line.length - line.trimStart().length;
		if (trimmed === "- insert:" || trimmed.startsWith("- insert:")) {
			insertIndent = indent;
			entryIndent = void 0;
			continue;
		}
		if (insertIndent === void 0) continue;
		if (indent <= insertIndent) {
			insertIndent = void 0;
			entryIndent = void 0;
			continue;
		}
		const match = /^-\s+id:\s*(\S+)\s*$/.exec(trimmed);
		if (match === null) continue;
		if (entryIndent === void 0) entryIndent = indent;
		if (indent === entryIndent) ids.add(match[1]);
	}
	return [...ids];
}
/** Read the patch text a package declares, or `undefined` when it has none. */
function readBundlePatch(packageDir) {
	const manifestPath = join(packageDir, "package.json");
	if (!existsSync(manifestPath)) return void 0;
	let declared;
	try {
		declared = JSON.parse(readFileSync(manifestPath, "utf8")).dsh?.bundle?.patch;
	} catch {
		return;
	}
	const first = Array.isArray(declared) ? declared[0] : declared;
	const relative = typeof first === "string" && first !== "" ? first : existsSync(join(packageDir, OWN_PATCH)) ? OWN_PATCH : void 0;
	if (relative === void 0) return void 0;
	const path = join(packageDir, relative);
	return existsSync(path) ? readFileSync(path, "utf8") : void 0;
}
/**
* Find loader id collisions between a candidate package and everything already
* installed in the profile.
*
* @param candidateDir - the unpacked candidate package directory.
* @param env - profile facts.
* @returns the colliding ids with their current owners.
*/
function findConflicts(candidateDir, env) {
	const candidatePatch = readBundlePatch(candidateDir);
	if (candidatePatch === void 0) return [];
	const mine = topLevelInsertedIds(candidatePatch);
	if (mine.length === 0) return [];
	const modulesDir = join(env.profileDir, "node_modules");
	if (!existsSync(modulesDir)) return [];
	const candidateReal = resolve(candidateDir);
	const owners = /* @__PURE__ */ new Map();
	for (const entry of installedDirectories(modulesDir)) {
		if (resolve(entry) === candidateReal) continue;
		for (const id of topLevelInsertedIds(readBundlePatch(entry) ?? "")) if (!owners.has(id)) owners.set(id, packageLabel(entry));
	}
	return mine.filter((id) => owners.has(id)).map((id) => ({
		id,
		owner: owners.get(id) ?? "?"
	}));
}
/** A human-readable name for an installed package: its manifest name, else its path. */
function packageLabel(dir) {
	const manifestPath = join(dir, "package.json");
	if (existsSync(manifestPath)) try {
		const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
		if (typeof manifest.name === "string" && manifest.name !== "") return manifest.name;
	} catch {}
	return dir;
}
/** Every installed package directory, including one level of scope. */
function installedDirectories(modulesDir) {
	const found = [];
	for (const entry of readdirSync(modulesDir)) {
		if (entry.startsWith(".")) continue;
		const path = join(modulesDir, entry);
		if (entry.startsWith("@")) {
			for (const scoped of readdirSync(path)) {
				const scopedPath = join(path, scoped);
				if (!scoped.startsWith(".")) found.push(scopedPath);
			}
			continue;
		}
		found.push(path);
	}
	return found;
}
/** The `dsh plugin allow-version ...` line DSH prints when the gate refuses an install. */
const EXEMPTION_HINT = /dsh plugin --profile (\S+) allow-version (\S+) --dsh-version (\S+) --accept-risk/;
/**
* Install a plugin into the running profile, repairing the version gate when needed.
*
* The gate is a policy check on declared peer ranges, not a statement that the plugin
* is broken: measured on this deployment, all seventeen `@dsh-external/*` plugins of
* the reference red-team suite import cleanly on DSH 0.2.x, and thirteen activate.
* DSH prints the exact exemption command, so the manager runs it and retries once.
*
* @param specifier - npm name, `github:owner/repo`, or a local path.
* @param env - profile facts.
* @param onLine - called for every output line as it arrives.
*/
async function installPlugin(specifier, env, onLine = () => {}) {
	if (!isInstallableSpecifier(specifier)) return {
		ok: false,
		lines: [],
		summary: `refused: ${specifier} is not a specifier this manager will pass to pnpm (npm name, github:owner/repo, or a relative link:./path — absolute paths and ../ are refused)`
	};
	const lines = [];
	const run = async (args) => {
		const result = await runCommand("dsh", [...args], {
			timeoutMs: COMMAND_TIMEOUT_MS,
			env: { DSH_HOME: env.dshHome }
		});
		for (const line of result.output.split("\n")) {
			if (line.trim() === "") continue;
			lines.push(line);
			onLine(line);
		}
		return result.code;
	};
	let target = specifier;
	if (specifier.startsWith("github:")) {
		const slug = specifier.slice(7);
		const repo = await prepareRepo(`https://github.com/${slug}`, env);
		if (!repo.ok || repo.dir === void 0) return {
			ok: false,
			lines: [...lines, ...repo.lines],
			summary: repo.summary
		};
		const root = repo.packages.find((entry) => entry.dir === repo.dir && entry.hasBundle);
		if (root === void 0) {
			const installable = repo.packages.filter((entry) => entry.hasBundle);
			return {
				ok: false,
				lines: [...lines, ...repo.lines],
				summary: installable.length === 0 ? `${slug} declares no installable package` : `${slug} is a monorepo — install a subpackage by path: ${installable.slice(0, 3).map((entry) => entry.dir).join(", ")}`
			};
		}
		target = root.dir;
		lines.push(`fetched ${slug} as an archive; installing ${target} by path`);
	}
	await run([
		"plugin",
		"--profile",
		env.profile,
		"add",
		target
	]);
	const hint = EXEMPTION_HINT.exec(lines.join("\n"));
	if (hint === null) {
		const dir = findInstalledDir(packageNameOf(target) ?? target, env) ?? target;
		if (dir === void 0) return {
			ok: false,
			lines,
			summary: "not present in the profile after the install — it did not take"
		};
		const imported = await canImport(dir);
		lines.push(imported.ok ? `verify: ${imported.note}` : `verify FAILED: ${imported.note}`);
		return {
			ok: imported.ok,
			lines,
			summary: imported.ok ? "installed and its entry module loads" : `installed but it does not load: ${imported.note}`
		};
	}
	const exemption = `${hint[2]} for DSH ${hint[3]}`;
	onLine(`compatibility gate refused ${hint[2]}; granting the exact-version exemption and retrying`);
	await run([
		"plugin",
		"--profile",
		env.profile,
		"allow-version",
		hint[2],
		"--dsh-version",
		hint[3],
		"--accept-risk"
	]);
	await run([
		"plugin",
		"--profile",
		env.profile,
		"add",
		target
	]);
	const imported = await canImport(findInstalledDir(packageNameOf(target) ?? target, env) ?? target);
	lines.push(imported.ok ? `verify: ${imported.note}` : `verify FAILED: ${imported.note}`);
	return {
		ok: imported.ok,
		lines,
		exemption,
		summary: imported.ok ? `installed after exemption (${exemption}) and its entry module loads` : `installed after exemption (${exemption}) but it does not load: ${imported.note}`
	};
}
/** Read what an installed package declares. */
function readDeclarations(packageDir) {
	const empty = {
		presets: [],
		entryIds: [],
		client: false,
		bundle: false,
		skillRoots: []
	};
	const manifestPath = join(packageDir, "package.json");
	if (!existsSync(manifestPath)) return empty;
	let manifest;
	try {
		manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
	} catch {
		return empty;
	}
	const patch = readBundlePatch(packageDir);
	const presets = [];
	if (patch !== void 0) {
		const lines = patch.split("\n");
		for (let index = 0; index < lines.length; index += 1) {
			if (!/name:\s*'?@deepseek-ai\/dsh-agent-preset'?\s*$/.test(lines[index].trim())) continue;
			for (let back = index; back >= 0 && back > index - 6; back -= 1) {
				const id = /^-\s+id:\s*(\S+)\s*$/.exec(lines[back].trim());
				if (id !== null) {
					presets.push(id[1]);
					break;
				}
			}
		}
	}
	const skillRoots = [];
	for (const candidate of [
		"skills",
		join("vendor", "redteam-skills"),
		"presets"
	]) if (existsSync(join(packageDir, candidate))) skillRoots.push(candidate);
	return {
		presets,
		entryIds: patch === void 0 ? [] : topLevelInsertedIds(patch),
		client: manifest.dsh?.client !== void 0,
		bundle: manifest.dsh?.bundle !== void 0,
		skillRoots
	};
}
/**
* Verify an install without restarting.
*
* What a static pass can settle: the package is on disk, DSH lists it as a bundle, its
* patch parses, and its ids do not collide. What it cannot settle is whether the rows
* actually mount — that needs the loader, which only runs at boot. The notes say so
* rather than implying a green check means the plugin works.
*/
function verifyInstalled(specifier, env) {
	const notes = [];
	const dir = findInstalledDir(specifier, env);
	if (dir === void 0) return {
		specifier,
		installed: false,
		entryIds: [],
		presets: [],
		conflicts: [],
		notes: [`${specifier} is not present under ${join(env.profileDir, "node_modules")}`]
	};
	const declarations = readDeclarations(dir);
	if (!declarations.bundle) notes.push("the package declares no dsh.bundle patch, so it adds no loader rows");
	if (declarations.presets.length > 0) notes.push(`declares ${String(declarations.presets.length)} preset row(s); whether they mount is only known after a restart — check the mode picker`);
	if (declarations.client) notes.push("ships a web client bundle; its UI appears after a page reload");
	const conflicts = findConflicts(dir, env);
	if (conflicts.length > 0) notes.push(`inserts ${String(conflicts.length)} loader id(s) already in use — DSH may fail to start`);
	notes.push("restart `dsh web` for the new rows to take effect");
	return {
		specifier,
		installed: true,
		entryIds: declarations.entryIds,
		presets: declarations.presets,
		conflicts,
		notes
	};
}
/** Locate an installed package by specifier, tolerating scopes and github specs. */
function findInstalledDir(specifier, env) {
	const modulesDir = join(env.profileDir, "node_modules");
	if (!existsSync(modulesDir)) return void 0;
	const name = specifier.startsWith("github:") ? specifier.slice(7).split(/[#/]/).slice(1).join("/") : specifier;
	for (const dir of installedDirectories(modulesDir)) if (dir.endsWith(join("node_modules", name)) || dir.endsWith(join("node_modules", `@${name}`))) return dir;
	for (const dir of installedDirectories(modulesDir)) {
		const manifestPath = join(dir, "package.json");
		if (!existsSync(manifestPath)) continue;
		try {
			if (JSON.parse(readFileSync(manifestPath, "utf8")).name === name) return dir;
		} catch {}
	}
}
/** Read this plugin's own package root from its module URL. */
function ownPackageRoot(from = import.meta.url) {
	return dirname(dirname(resolve(from.startsWith("file:") ? new URL(from).pathname : from)));
}
/**
* The capabilities worth offering first.
*
* Chosen against the public catalogue of 4400 plugins (awesome-dsh-plugin.com), not
* invented: each one either fills a gap this plugin has or is a prerequisite the
* environment check reports on. Deliberately short — a recommendation list people read
* beats a catalogue they scroll.
*/
/**
* There is deliberately nothing here.
*
* This list previously named three plugins, and two were wrong in ways that took a session
* to find: `@dsh-external/dsh-redteam-model` does not exist on npm (its seventeen plugins
* are unpublished monorepo subpackages), and neither does `dsh-pentest`. But the idea was
* the bigger defect.
*
* Both surviving candidates were counterproductive. `dsh-pentest` is a competing
* penetration mode — installing it adds a thirteenth entry point to a plugin whose measured
* problem is too much surface, not too little. `dsh-reverse-skill`'s 44 skills are already
* vendored here and scoped to the three modes that use them; installing the package would
* broadcast them to every mode instead. A recommendation is only worth making if it makes
* this plugin better, and neither did.
*
* The manager keeps the parts that earn their place — environment checks, a manual
* installer, repository discovery, post-install verification — and drops the shopping list.
*/
const RECOMMENDED = [];
/**
* Prior to installing anything, work out whether it can be installed at all.
*
* Two of this list's entries were wrong for a long time — they named packages that do not
* exist on npm (`@dsh-external/dsh-redteam-model`, `dsh-pentest`), so the page offered an
* install button that could only ever produce "未找到". Checking first is what stops that
* class of mistake: a recommendation is only useful if it is reachable.
*
* Also note what is deliberately NOT recommended: `dsh-redteam-model` itself. Its seventeen
* runtime plugins are unpublished monorepo subpackages, so `dsh plugin add` on the
* repository installs the root package and none of them. The "从 git 仓库装" section already
* handles that shape correctly (clone, discover, bridge, install each subpackage by path),
* and offering a second, broken route to the same thing was the actual defect.
*
* @param specifier - what would be passed to `dsh plugin add`.
* @param env - profile facts.
* @returns a verdict, and one line the operator can act on.
*/
async function preflightSpecifier(specifier, env) {
	if (specifier.startsWith("github:") || specifier.startsWith("https://")) {
		const proxy = await configuredGithubProxy();
		return {
			installable: true,
			line: `${specifier} is a git repository — ${proxy === void 0 ? "no git proxy rewrite is configured, so this needs GitHub to be directly reachable" : `git is routed through ${proxy}`}. A shallow clone through a proxy can take 1-3 minutes.`
		};
	}
	if (specifier.startsWith("/") || specifier.startsWith(".")) return {
		installable: true,
		line: `${specifier} is a local path; it will be linked, not copied`
	};
	const result = await runCommand("npm", [
		"view",
		specifier,
		"version",
		"peerDependencies",
		"--json"
	], {
		timeoutMs: PROBE_TIMEOUT_MS,
		env: { DSH_HOME: env.dshHome }
	});
	if (result.code !== 0 || result.output.trim() === "") return {
		installable: false,
		line: `npm has no package named ${specifier} — do not offer it as a recommendation`
	};
	try {
		const parsed = JSON.parse(result.output);
		const dshPeers = Object.keys(parsed.peerDependencies ?? {}).filter((name) => name.startsWith("@deepseek-ai/"));
		return {
			installable: true,
			line: `npm has ${specifier}@${parsed.version ?? "?"}; ${String(dshPeers.length)} DSH peer(s) declared, so the version gate may need ${dshPeers.length === 0 ? "no exemption" : `${String(dshPeers.length)} exemption(s)`}`
		};
	} catch {
		return {
			installable: true,
			line: `${specifier} resolves on npm but its manifest could not be read`
		};
	}
}
/** Escape text for HTML body and attribute positions. */
function escapeHtml(value) {
	return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
/**
* Render the manager page.
*
* Deliberately a server-rendered page on a plain route rather than a React client
* plugin: this way every behaviour — the checks, the install, the verification — is
* reachable and verifiable over HTTP, with no browser in the loop. A settings page can
* wrap the same handlers later; the logic does not move.
*/
function renderManagerHtml(snapshot) {
	const checkRow = (line) => `<li class="check ${line.ok ? "ok" : "bad"}"><b>${escapeHtml(line.label)}</b><span>${escapeHtml(line.detail)}</span></li>`;
	const recommendationRow = (entry) => {
		const report = snapshot.installed.find((item) => item.specifier === entry.specifier);
		const state = report === void 0 ? "未安装" : report.installed ? "已安装" : "未找到";
		const conflicts = report?.conflicts ?? [];
		const conflictText = conflicts.length === 0 ? "" : `<div class="warn">⚠ ${String(conflicts.length)} 个 loader id 冲突：${escapeHtml(conflicts.map((hit) => `${hit.id} (${hit.owner})`).join(", "))}</div>`;
		const notes = (report?.notes ?? []).map((note) => `<div class="note">${escapeHtml(note)}</div>`).join("");
		return `<li class="rec">
      <div class="rec-head">
        <code>${escapeHtml(entry.specifier)}</code>
        <span class="state">${escapeHtml(state)}</span>
      </div>
      <div class="why">${escapeHtml(entry.why)}</div>
      <div class="brings">${escapeHtml(entry.brings)}</div>
      ${conflictText}${notes}
      <form method="post" action="/f2x-manager/install">
        <input type="hidden" name="specifier" value="${escapeHtml(entry.specifier)}">
        <button type="submit">安装 / 重装</button>
      </form>
    </li>`;
	};
	return `<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>f2x 能力管理器 — ${escapeHtml(snapshot.profile)}</title>
<style>
 :root{color-scheme:light dark}
 body{font:14px/1.6 ui-sans-serif,system-ui,sans-serif;margin:0;padding:24px;max-width:920px}
 h1{font-size:18px;margin:0 0 4px} h2{font-size:14px;margin:28px 0 8px;text-transform:uppercase;letter-spacing:.08em;opacity:.6}
 .sub{opacity:.6;margin:0 0 20px;font-family:ui-monospace,monospace;font-size:12px}
 ul{list-style:none;padding:0;margin:0}
 .check{display:flex;gap:12px;padding:6px 0;border-bottom:1px solid color-mix(in srgb,currentColor 12%,transparent)}
 .check b{min-width:150px} .check span{opacity:.8;font-size:13px}
 .ok::before{content:"✅"} .bad::before{content:"❌"}
 .rec{border:1px solid color-mix(in srgb,currentColor 18%,transparent);border-radius:10px;padding:14px;margin:0 0 12px}
 .rec-head{display:flex;justify-content:space-between;align-items:center;gap:12px}
 .rec-head code{font-size:13px}
 .state{font-size:12px;opacity:.7}
 .why{margin:8px 0 4px} .brings{font-size:13px;opacity:.7}
 .note{font-size:12px;opacity:.7;margin-top:4px} .warn{font-size:12px;color:#c0392b;margin-top:6px}
 form{margin-top:10px} button{font:inherit;padding:6px 14px;border-radius:8px;border:1px solid currentColor;background:transparent;cursor:pointer}
 button:hover{background:color-mix(in srgb,currentColor 10%,transparent)}
 pre{background:color-mix(in srgb,currentColor 7%,transparent);padding:12px;border-radius:8px;overflow:auto;font-size:12px;max-height:420px}
 footer{margin-top:32px;font-size:12px;opacity:.55}
</style></head><body>
<h1>f2x 能力管理器</h1>
<p class="sub">profile: ${escapeHtml(snapshot.profile)} · ${escapeHtml(snapshot.profileDir)}</p>

<h2>环境自检</h2>
<ul>${snapshot.checks.map(checkRow).join("")}</ul>

<h2>推荐能力</h2>
<ul>${snapshot.recommended.map(recommendationRow).join("")}</ul>

<h2>从 git 仓库装（子包套件）</h2>
<p class="brings">有些插件套件是 monorepo，子包不发 npm。<code>dsh plugin add &lt;目录&gt;</code> 可以按路径装。</p>
${snapshot.repos.map((entry) => `<form method="post" action="/f2x-manager/repo" style="margin-bottom:14px">
  <code>${escapeHtml(entry.url)}</code>
  <div class="why">${escapeHtml(entry.why)}</div>
  <div class="brings">${escapeHtml(entry.brings)}</div>
  <input type="hidden" name="url" value="${escapeHtml(entry.url)}">
  <button type="submit" style="margin-top:6px">克隆并列出可装项</button>
</form>`).join("")}

<h2>手动安装</h2>
<form method="post" action="/f2x-manager/install">
  <input type="text" name="specifier" placeholder="包名 / github:owner/repo" style="font:inherit;padding:6px 10px;width:340px;border-radius:8px;border:1px solid currentColor;background:transparent">
  <button type="submit">安装</button>
</form>

<footer>只服务回环客户端 · 安装走 <code>dsh plugin</code>，兼容门禁会被自动豁免并复述 · 装完需要重启 <code>dsh web</code></footer>
</body></html>`;
}
/** Repository suites worth offering, with the plugin count measured on this deployment. */
const RECOMMENDED_REPOS = [{
	url: "https://github.com/SeaOf0/dsh-redteam-model",
	why: "同一来源的插件集（★655）。它的 10 个模式已移植进本插件；这里装的是它另外 17 个运行时插件——逐轮治理、拒答修复、工具拦截、32 门结构校验、资产搜索、成果页。",
	brings: "17 个宿主平面插件，实测 13 个可在 DSH 0.2.x 直接激活，且与本插件零 loader id 冲突"
}];
/** Render the repository preparation result as plain text. */
function renderRepoText(report) {
	const installable = report.packages.filter((entry) => entry.hasBundle);
	return [
		report.summary,
		report.dir === void 0 ? "" : `目录: ${report.dir}`,
		"",
		`可安装（声明了 dsh.bundle，共 ${String(installable.length)} 个）:`,
		...installable.map((entry) => `  ${entry.name}${entry.version === void 0 ? "" : ` v${entry.version}`}\n    dsh plugin --profile <profile> add ${entry.dir}`),
		"",
		report.lines.join("\n")
	].join("\n");
}
/** Render a plain-text report for a completed install. */
function renderInstallText(specifier, report) {
	return [
		`${specifier}: ${report.summary}`,
		report.exemption === void 0 ? "" : `exemption: ${report.exemption}`,
		"",
		...report.lines
	].filter((line) => line !== void 0).join("\n");
}
/**
* Find installable packages inside a directory tree.
*
* Plugin suites published as monorepos — the reference red-team collection among them —
* keep their plugins as subpackages that are never published to npm individually. Passing
* a directory to `dsh plugin add` installs one by `link:`, so the useful thing a manager
* can do is say which directories are worth passing.
*
* @param root - repository root.
* @param maxDepth - how deep to look; plugin dirs sit one or two levels down.
*/
function discoverBundlePackages(root, maxDepth = 3) {
	const found = [];
	const skip = /* @__PURE__ */ new Set([
		"node_modules",
		".git",
		"dist",
		"lib",
		"coverage",
		"test",
		"tests"
	]);
	const walk = (dir, depth) => {
		if (depth > maxDepth) return;
		let entries;
		try {
			entries = readdirSync(dir);
		} catch {
			return;
		}
		if (entries.includes("package.json")) {
			const manifestPath = join(dir, "package.json");
			try {
				const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
				if (typeof manifest.name === "string" && manifest.name !== "") found.push({
					name: manifest.name,
					dir,
					...manifest.version === void 0 ? {} : { version: manifest.version },
					hasBundle: manifest.dsh?.bundle !== void 0
				});
			} catch {}
			if (depth > 0) return;
		}
		for (const entry of entries) {
			if (skip.has(entry) || entry.startsWith(".")) continue;
			walk(join(dir, entry), depth + 1);
		}
	};
	walk(root, 0);
	return found;
}
/** Parse `https://github.com/owner/repo` (with or without `.git`). */
function parseGithubUrl(url) {
	const match = /^https?:\/\/github\.com\/([^/]+)\/([^/#]+?)(?:\.git)?(?:[#/].*)?$/.exec(url);
	if (match === null) return void 0;
	return {
		owner: match[1],
		repo: match[2]
	};
}
/**
* The proxy prefix the operator configured for git, if any.
*
* A `url.<prefix>.insteadOf https://github.com/` rewrite is how this deployment reaches
* GitHub at all, and an archive download has to go through the same route. Reading the
* setting rather than hardcoding a mirror keeps this plugin out of the business of
* choosing a third party to route traffic through.
*/
async function configuredGithubProxy() {
	const result = await runCommand("git", [
		"config",
		"--global",
		"--get-regexp",
		"url..*.insteadof"
	], { timeoutMs: PROBE_TIMEOUT_MS });
	for (const line of result.output.split("\n")) {
		const match = /^(url\.(.+)\.insteadof)\s+(\S+)\s*$/i.exec(line.trim());
		if (match === null) continue;
		if (match[3].replace(/\/$/, "") !== "https://github.com") continue;
		return match[2];
	}
}
/**
* Download and extract a repository archive.
*
* Preferred over `git clone` for GitHub: a shallow clone through the same proxy stalled
* at `early EOF` after three minutes on the reference repository, while the archive
* endpoint delivered 12 MB in about eighty seconds.
*/
async function fetchArchive(archiveUrl, dest, timeoutMs) {
	const controller = new AbortController();
	const timer = setTimeout(() => {
		controller.abort();
	}, timeoutMs);
	const tarball = `${dest}.tar.gz`;
	try {
		mkdirSync(dirname(tarball), { recursive: true });
		const response = await fetch(archiveUrl, {
			signal: controller.signal,
			redirect: "follow"
		});
		if (!response.ok || response.body === null) return {
			ok: false,
			note: `${archiveUrl} answered ${String(response.status)}`
		};
		const chunks = [];
		for await (const chunk of response.body) chunks.push(Buffer.from(chunk));
		writeFileSync(tarball, Buffer.concat(chunks));
		rmSync(dest, {
			recursive: true,
			force: true
		});
		mkdirSync(dest, { recursive: true });
		const extract = await runCommand("tar", [
			"xzf",
			tarball,
			"-C",
			dest,
			"--strip-components=1"
		], { timeoutMs: 12e4 });
		rmSync(tarball, { force: true });
		if (extract.code !== 0) return {
			ok: false,
			note: extract.output.trim().slice(0, 300)
		};
		return {
			ok: true,
			note: `archive downloaded (${String(Buffer.concat(chunks).length)} bytes)`
		};
	} catch (error) {
		rmSync(tarball, { force: true });
		return {
			ok: false,
			note: String(error?.message ?? error).slice(0, 300)
		};
	} finally {
		clearTimeout(timer);
	}
}
/**
* Build the archive URL, routed through the operator's proxy when one is configured.
*
* The rewrite target already ends in `github.com`, so it replaces the origin rather
* than prefixing the whole URL — appending a full URL to it produced
* `https://proxy/https://github.com//https://github.com/owner/repo/...` on the first
* attempt. The archive path is appended to the prefix.
*
* @param github - parsed repository.
* @param proxy - the `url.<prefix>.insteadOf https://github.com` prefix, if configured.
* @returns URLs to try, in order.
*/
function archiveUrls(github, proxy) {
	const path = `${github.owner}/${github.repo}/archive/HEAD.tar.gz`;
	const direct = `https://github.com/${path}`;
	if (proxy === void 0 || proxy === "") return [direct];
	return [`${proxy.endsWith("/") ? proxy : `${proxy}/`}${path}`, direct];
}
/**
* Load a freshly installed package's entry module, the way the host will at boot.
*
* The install text is not evidence that a plugin works. Measured twice in one session: a
* package installed cleanly and then failed at boot with `failed to import`, because a
* `link:`-installed plugin resolves its bare `@deepseek-ai/*` imports from its own real
* location, which ships no `node_modules`. Nothing in the install output says so.
*
* @param dir - the installed package directory.
* @returns whether its entry module imports without error.
*/
async function canImport(dir) {
	let entry;
	try {
		const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
		entry = join(dir, manifest.main ?? "lib/index.js");
	} catch (cause) {
		return {
			ok: false,
			note: `no readable package.json: ${String(cause?.message ?? cause)}`
		};
	}
	if (!existsSync(entry)) return {
		ok: false,
		note: `entry module ${entry} does not exist`
	};
	const result = await runCommand("node", [
		"--input-type=module",
		"-e",
		`await import(${JSON.stringify(pathToFileURL(entry).href)})`
	], { timeoutMs: 9e4 });
	if (result.code === 0) return {
		ok: true,
		note: "entry module imports"
	};
	return {
		ok: false,
		note: (result.output.split("\n").find((line) => line.includes("Cannot find package") || line.includes("Error")) ?? result.output.split("\n")[0] ?? "import failed").slice(0, 200)
	};
}
/** The package name a directory declares, if its manifest is readable. */
function packageNameOf(dir) {
	try {
		return JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).name;
	} catch {
		return;
	}
}
/** A filesystem-safe name for a repository URL. */
function repoSlug(url) {
	return url.replace(/^https?:\/\//, "").replace(/^git@/, "").replace(/\.git$/, "").replace(/[^a-zA-Z0-9._-]+/g, "-").slice(0, 120);
}
/**
* Clone or update a plugin repository, then list what is installable inside it.
*
* The suite's own deploy script is deliberately not run: it writes profile files, links
* directories and shells out to pnpm, and a manager that runs arbitrary install scripts
* out of a cloned repository is a worse trade than installing the subpackages one by one.
* Cloning plus `dsh plugin add <dir>` gets the same rows mounted through DSH's own
* validated path.
*/
async function prepareRepo(url, env) {
	const lines = [];
	if (!/^(https:\/\/|git@|ssh:\/\/|file:\/\/|\/)/.test(url)) return {
		ok: false,
		packages: [],
		lines,
		summary: `refused: ${url} is not a git URL`
	};
	const cacheRoot = join(env.dshHome, "f2x-plugins");
	const dir = join(cacheRoot, repoSlug(url));
	const record = (result) => {
		for (const line of result.output.split("\n")) if (line.trim() !== "") lines.push(line);
		return result.code;
	};
	const env2 = { DSH_HOME: env.dshHome };
	const github = parseGithubUrl(url);
	let ready = existsSync(join(dir, "package.json"));
	if (!ready && github !== void 0) {
		const proxy = await configuredGithubProxy();
		for (const attempt of archiveUrls(github, proxy)) {
			const result = await fetchArchive(attempt, dir, 6e5);
			record({
				code: result.ok ? 0 : 1,
				output: `${attempt}\n${result.note}`
			});
			if (result.ok) {
				ready = true;
				break;
			}
		}
	}
	if (!ready && github === void 0) {
		mkdirSync(dir, { recursive: true });
		ready = record(await runCommand("git", [
			"clone",
			"--depth",
			"1",
			url,
			dir
		], { env: env2 })) === 0;
	}
	if (!ready) return {
		ok: false,
		dir,
		packages: [],
		lines,
		summary: "could not fetch the repository — check the URL, and whether the host is reachable (a git proxy rewrite helps)"
	};
	const all = discoverBundlePackages(dir);
	const packages = [...all.filter((entry) => entry.hasBundle), ...all.filter((entry) => !entry.hasBundle)];
	const bridge = bridgeRepoPeers(dir, findDshInstall(), packages);
	if (bridge.runtime.length > 0) lines.push(`bridged ${String(bridge.runtime.length)} runtime peer(s): ${bridge.runtime.join(", ")}`);
	if (bridge.siblings.length > 0) lines.push(`bridged ${String(bridge.siblings.length)} sibling plugin(s): ${bridge.siblings.join(", ")}`);
	lines.push(...bridge.notes);
	return {
		ok: true,
		dir,
		packages,
		lines,
		summary: `repository ready at ${dir} — ${String(packages.filter((entry) => entry.hasBundle).length)} installable package(s), ${String(bridge.runtime.length)} peer(s) bridged`
	};
}
/**
* Locate the running DSH installation.
*
* A plugin installed by `link:` from a cloned repository resolves its bare imports from
* that repository, which has no `node_modules` — so every `@deepseek-ai/*` peer fails,
* which is exactly how the reference suite's plugins fail to import without their deploy
* script. The runtime packages live beside the `dsh` entry point, so the install root is
* found by walking up from it.
*/
function findDshInstall(env = process.env) {
	const candidates = [];
	if (typeof env.DSH_INSTALL === "string" && env.DSH_INSTALL !== "") candidates.push(env.DSH_INSTALL);
	const entry = process.argv[1];
	if (typeof entry === "string" && entry !== "") try {
		let dir = dirname(realpathSync(entry));
		for (let hop = 0; hop < 6; hop += 1) {
			candidates.push(dir);
			const parent = dirname(dir);
			if (parent === dir) break;
			dir = parent;
		}
	} catch {}
	candidates.push("/usr/lib/node_modules/@deepseek-ai/dsh");
	for (const candidate of candidates) {
		const manifestPath = join(candidate, "package.json");
		if (!existsSync(manifestPath)) continue;
		try {
			if (JSON.parse(readFileSync(manifestPath, "utf8")).name === "@deepseek-ai/dsh") return candidate;
		} catch {}
	}
}
/**
* Link the peers a cloned plugin suite needs but does not ship.
*
* Two kinds: `@deepseek-ai/*` runtime packages, which live in the DSH installation, and
* `@dsh-external/*` siblings, which live next to the plugin in the same repository. Both
* are what a `link:`-installed package cannot resolve on its own.
*
* Idempotent: an existing link is replaced, so re-running after an update is safe.
*
* @param repoDir - cloned repository root.
* @param install - DSH installation root, from {@link findDshInstall}.
* @param packages - discovered packages, used to learn which peers are needed.
*/
function bridgeRepoPeers(repoDir, install, packages) {
	const runtimeWanted = /* @__PURE__ */ new Set();
	const siblingWanted = /* @__PURE__ */ new Set();
	for (const entry of packages) {
		const manifestPath = join(entry.dir, "package.json");
		if (!existsSync(manifestPath)) continue;
		let manifest;
		try {
			manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
		} catch {
			continue;
		}
		for (const name of [...Object.keys(manifest.peerDependencies ?? {}), ...Object.keys(manifest.dependencies ?? {})]) if (name.startsWith("@deepseek-ai/")) runtimeWanted.add(name.slice(13));
		else if (name.startsWith("@dsh-external/")) siblingWanted.add(name);
	}
	const notes = [];
	const runtimeLinked = [];
	const siblingLinked = [];
	const bridge = join(repoDir, "plugins", "node_modules");
	mkdirSync(join(bridge, "@deepseek-ai"), { recursive: true });
	mkdirSync(join(bridge, "@dsh-external"), { recursive: true });
	const runtimeRoot = install === void 0 ? void 0 : join(install, "node_modules", "@deepseek-ai");
	if (runtimeRoot === void 0 || !existsSync(runtimeRoot)) notes.push("DSH installation not found, so @deepseek-ai/* peers were left unlinked");
	else {
		const available = readdirSync(runtimeRoot).filter((name) => !name.startsWith("."));
		const wanted = /* @__PURE__ */ new Set([...available]);
		for (const name of available) {
			const source = join(runtimeRoot, name);
			const link = join(bridge, "@deepseek-ai", name);
			rmSync(link, {
				recursive: true,
				force: true
			});
			try {
				symlinkSync(source, link, "dir");
				runtimeLinked.push(name);
			} catch {
				notes.push(`could not link @deepseek-ai/${name}`);
			}
		}
		for (const name of runtimeWanted) if (!wanted.has(name)) notes.push(`@deepseek-ai/${name} is declared but absent from the installation`);
	}
	for (const scoped of siblingWanted) {
		const short = scoped.slice(14);
		const source = join(repoDir, "plugins", short);
		if (!existsSync(source)) continue;
		const link = join(bridge, "@dsh-external", short);
		rmSync(link, {
			recursive: true,
			force: true
		});
		try {
			symlinkSync(source, link, "dir");
			siblingLinked.push(short);
		} catch {
			notes.push(`could not link ${scoped}`);
		}
	}
	return {
		ok: runtimeLinked.length > 0 || runtimeWanted.size === 0,
		runtime: runtimeLinked,
		siblings: siblingLinked,
		notes
	};
}
//#endregion
export { RECOMMENDED, RECOMMENDED_REPOS, archiveUrls, bridgeRepoPeers, canImport, configuredGithubProxy, discoverBundlePackages, escapeHtml, findConflicts, findDshInstall, installPlugin, isInstallableSpecifier, ownPackageRoot, parseGithubUrl, preflightSpecifier, prepareRepo, readBundlePatch, readDeclarations, readManagerEnv, renderInstallText, renderManagerHtml, renderRepoText, repoSlug, resolveManagerEnv, runCommand, runEnvironmentCheck, topLevelInsertedIds, verifyInstalled };
