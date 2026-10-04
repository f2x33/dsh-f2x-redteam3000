import { SkillProviderControl } from "@deepseek-ai/dsh-skill";
//#region src/skills.d.ts
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
declare const F2X_SKILL_RANK = 250;
/** Provider name registered on `ctx.skills`. */
declare const F2X_PROVIDER_NAME = "f2x-redteam3000";
/**
 * One parsed `SKILL.md`: exactly what the file itself declares.
 *
 * This is deliberately *not* the loaded definition. The registry validates the
 * value returned by `provider.get()` as a complete `SkillDefinition`, which
 * additionally requires `invocation`, `source` and `provider` — a parsed file
 * cannot know those, so `createSkillProvider().get()` assembles them.
 */
interface ParsedSkill {
  readonly name: string;
  readonly description: string;
  readonly whenToUse?: string;
  readonly modelInvocable: boolean;
  readonly userInvocable: boolean;
  readonly content: string;
}
/** Where a skill's relative resources resolve from; the registry and `skill` tool read this. */
type SkillResourceBaseLike = {
  readonly kind: 'directory';
  readonly path: string;
};
/** Minimal shape of the `ctx.skills` seam this module consumes. */
interface SkillCandidateLike {
  readonly name: string;
  readonly description: string;
  readonly whenToUse?: string;
  readonly invocation: {
    readonly modelInvocable: boolean;
    readonly userInvocable: boolean;
  };
  readonly source: string;
  readonly provider: string;
  readonly resourceBase: SkillResourceBaseLike;
  readonly rank: number;
  readonly locator: unknown;
}
/**
 * A complete loaded skill, as `@deepseek-ai/dsh-skill`'s `validateDefinition`
 * enforces it: `name` / `description` / `content` must be strings, `invocation`
 * must carry both booleans, and `source` / `provider` must be strings. Omitting
 * any of these makes the registry throw when an agent loads the skill.
 */
interface SkillDefinitionLike {
  readonly name: string;
  readonly description: string;
  readonly whenToUse?: string;
  readonly invocation: {
    readonly modelInvocable: boolean;
    readonly userInvocable: boolean;
  };
  readonly source: string;
  readonly provider: string;
  readonly resourceBase: SkillResourceBaseLike;
  readonly content: string;
}
/** Minimal provider contract accepted by `ctx.skills.registerProvider`. */
interface F2xSkillProvider {
  readonly name: string;
  readonly list: () => Promise<readonly SkillCandidateLike[]>;
  readonly get: (candidate: SkillCandidateLike) => Promise<SkillDefinitionLike | undefined>;
}
/**
 * The provider as `ctx.skills.registerProvider` wants it.
 *
 * `SkillProviderControl` is the only thing imported from the skill package, and
 * it is a type-only import, so nothing of that package loads at runtime.
 */
type SkillProviderLike = (control: SkillProviderControl) => F2xSkillProvider;
/** Skill names this plugin must never shadow, because sibling plugins own them. */
declare const RESERVED_SKILL_NAMES: readonly string[];
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
declare function bundledSkillDirs(from?: string): string[];
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
declare function bundledPowerSkillDir(from?: string): string;
/**
 * The package root, one level up from the built module.
 *
 * The package layout is `<pkg>/lib/index.mjs` next to `<pkg>/skills`, `<pkg>/refs`
 * and `<pkg>/persona`.
 *
 * @param from - the module URL to resolve against; overridable for tests.
 */
declare function bundledPackageRoot(from?: string): string;
/**
 * Absolute path of the bundled knowledge base (`<pkg>/refs`).
 *
 * The skills cite this tree relatively (`refs/power/protocols/modbus.md`), which
 * only resolves against the package root — not the session cwd. The doctrine
 * self-check prints this value so a model never has to guess it.
 *
 * @param from - the module URL to resolve against; overridable for tests.
 */
declare function bundledRefsDir(from?: string): string;
/**
 * Parse one `SKILL.md` body into a skill definition.
 * @param raw - the whole file text.
 * @param fallbackName - the directory name, used when frontmatter omits `name`.
 * @returns the parsed skill, or `undefined` when the file is not a usable skill.
 */
declare function parseSkillMarkdown(raw: string, fallbackName?: string): ParsedSkill | undefined;
/** One discovered `SKILL.md` on disk. */
interface DiscoveredSkill {
  readonly skill: ParsedSkill;
  readonly path: string;
  readonly dir: string;
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
declare function discoverSkills(roots: readonly string[], logger?: {
  warn: (message: string) => void;
}): Promise<{
  readonly skills: DiscoveredSkill[];
  readonly diagnostics: string[];
}>;
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
declare const SKILL_GATE_PRELUDE: string;
declare function createSkillProvider(roots: readonly string[], logger?: {
  warn: (message: string) => void;
}): F2xSkillProvider;
//#endregion
export { F2X_PROVIDER_NAME, F2X_SKILL_RANK, F2xSkillProvider, ParsedSkill, RESERVED_SKILL_NAMES, SKILL_GATE_PRELUDE, SkillCandidateLike, SkillDefinitionLike, SkillProviderLike, SkillResourceBaseLike, bundledPackageRoot, bundledPowerSkillDir, bundledRefsDir, bundledSkillDirs, createSkillProvider, discoverSkills, parseSkillMarkdown };