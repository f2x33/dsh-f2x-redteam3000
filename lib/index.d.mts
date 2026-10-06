import Schema from "@deepseek-ai/schemastery";
import { Context } from "@deepseek-ai/cordis";
//#region src/config.d.ts
/**
 * Tunable configuration for the f2x redteam plugin. Every key is a Schemastery
 * field so the harness validates it at load time and fails loud on bad values,
 * and every key can be changed from cordis.yml without editing code.
 *
 * Safety-relevant defaults are deliberately restrictive: an empty `allowedTargets`
 * denies every target, so an operator must state the authorized range explicitly
 * before any task can start (`f2x_orchestrate_start`).
 */
interface Config {
  /** Extra skill roots to scan, on top of the bundled `skills/` and `skills/power/`. */
  extraSkillDirs: string[];
  /** Hard target allowlist. Empty means "deny everything" — never "allow everything". */
  allowedTargets: string[];
  /** Write task/blackboard/audit JSON under the DSH data directory (default) or only keep it in memory. */
  persistState: boolean;
  /** Absolute directory for state files; empty means `<dshHome>/f2x-redteam3000`. */
  stateDir: string;
  /**
   * Root of the read-only upstream reference tree (the `redteam-refs` repository)
   * that the power/OT skills cite by absolute path.
   *
   * Empty resolves to `$REDTEAM_REFS`, then to `<dshHome>/redteam-refs` when that
   * directory exists, and otherwise to the empty string. The skills that cite a tree
   * read `$REDTEAM_REFS` (the plugin exports the resolved path for them), so this key
   * is what a deployment sets to point at its own read-only copy.
   */
  referenceRoot: string;
  /** Enable the OT (power) module. When false, power mode and OT skills are not advertised. */
  enablePowerModule: boolean;
  /**
   * Publish this plugin's `skills/` and `skills/power/` through a global skill
   * provider.
   *
   * The default `true` keeps a single-plugin deployment working with no extra
   * configuration. Set it to `false` when an agent preset supplies the same
   * directories through `skill-filesystem`'s `customSkillDirs`: that scopes each
   * skill to its own mode instead of injecting every skill into every session,
   * and it is the recommended setup once `presets/` is wired into
   * `@deepseek-ai/dsh-agent-presets`.
   *
   * Leaving both on is not harmful — the registry resolves a duplicate name to the
   * same file — but the merged catalog is noisier and every session sees the power
   * skills.
   */
  registerSkillProvider: boolean;
  publishPowerSkillsGlobally: boolean;
  /** Max tool invocations per target the doctrine tolerates before flagging the ledger. */
  maxConcurrencyPerTarget: number;
  /** Max accepted evidence checkpoints per stage before the gate closes automatically. */
  maxCheckpointsPerStage: number;
  /** Redteam gate verdicts survive this many stage advances before they must be renewed. */
  gateValidityStages: number;
}
declare const Config: Schema<Config>;
//#endregion
//#region src/orchestrate.d.ts
/**
 * Orchestration state for the f2x redteam plugin: task ledger, blackboard,
 * evidence checkpoints, redteam-gate verdicts and the OT audit log.
 *
 * Everything is plain JSON on disk under the resolved state directory, so a
 * fresh session or a fresh agent can pick the work up again. Writes go through a
 * single serialized promise chain per store, which keeps concurrent tool calls
 * from interleaving read-modify-write cycles.
 */
/** Assignment plane for a task. */
type TaskMode = 'general' | 'power';
/** Which half of a power engagement a task belongs to. */
type TaskLane = 'it' | 'ot';
/** Canonical stage identifiers, mirroring `playbook/redteam-flow.md`. */
declare const STAGES: readonly ["recon", "asset-mapping", "vuln-discovery", "exploitation", "internal-pentest", "traceback", "collection"];
/** One canonical stage identifier. */
type Stage = (typeof STAGES)[number];
/** Lifecycle state of a task. */
type TaskStatus = 'open' | 'gated' | 'closed' | 'aborted';
/** One task in the ledger. */
interface TaskRecord {
  readonly id: string;
  readonly brief: string;
  mode: TaskMode;
  lane: TaskLane;
  stage: Stage;
  status: TaskStatus;
  readonly targets: readonly string[];
  readonly allowedTargets: readonly string[];
  readonly createdAt: string;
  updatedAt: string;
  /** Stage ids that passed the redteam gate at least once. */
  readonly gates: Record<string, GateVerdict>;
  /** Evidence checkpoints keyed by stage. */
  readonly checkpoints: Record<string, Checkpoint[]>;
  /** Doctrine violations recorded by the plugin (never silently dropped). */
  readonly violations: string[];
  readonly notes: string[];
}
/** One evidence checkpoint accepted at a stage. */
interface Checkpoint {
  readonly id: string;
  readonly stage: Stage;
  readonly summary: string;
  readonly evidence: string;
  readonly level: 'confirmed' | 'partial' | 'unknown';
  readonly createdAt: string;
}
/** A redteam-gate verdict produced by `f2x_orchestrate_verify`. */
interface GateVerdict {
  readonly stage: Stage;
  readonly pass: boolean;
  readonly reasons: string[];
  readonly openGaps: string[];
  readonly checkedAt: string;
  /** Task stage at the moment the verdict was produced; a stale verdict does not count. */
  readonly atStage: Stage;
  readonly cpCount: number;
  readonly confirmedCount: number;
  /**
   * Proof that this verdict was produced by `runVerify` and has not been edited since.
   *
   * A hand-written verdict in `state.json` used to satisfy `mark`, so the ledger — which the
   * doctrine calls the evidence source — was also a way to grant yourself a pass. The token
   * is a digest over everything the verdict asserts plus the evidence snapshot it was derived
   * from, so a forged or later-edited verdict no longer matches. This is not a signature: a
   * determined party with write access to the state file can recompute it. It removes the
   * "seed one JSON object and advance" path, which is what a model can actually stumble into.
   */
  readonly token?: string;
}
/** Blackboard entry kinds, borrowed from the voredteam three-record model. */
type BlackboardKind = 'fact' | 'intent' | 'hint';
//#endregion
//#region src/index.d.ts
declare const name = "@dsh-f2x/redteam3000";
declare const inject: string[];
/** Plugin version reported by the doctrine self-check and the console. Kept in step with package.json by `scripts/selfcheck.mjs`. */
declare const PLUGIN_VERSION = "0.1.9";
/**
 * Route prefix of the read-only operator console.
 *
 * Registered on the raw web server rather than the `/api` connection channel: that
 * channel is fenced by the browser-trust/session policy, which would make the page
 * unreachable by plain navigation. The console exposes only what `state.json`
 * already holds on the operator's own machine.
 */
declare const CONSOLE_PATH = "/f2x-console";
/** Route of the capability manager page and its two JSON endpoints. */
declare const MANAGER_PATH = "/f2x-manager";
/** Resolve the state directory, preferring config over the DSH home default. */
declare function resolveStateDir(config: Config): string;
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
declare function defaultReferenceRoot(): string;
/**
 * Resolve the upstream reference tree the power/OT skills cite, preferring an
 * explicit config value over `$REDTEAM_REFS` over the WSL default.
 *
 * The doctrine self-check reports this value *and whether it exists*, because the
 * skills hardcode absolute paths: a moved tree would otherwise fail silently the
 * first time a skill tried to read its material.
 */
declare function resolveReferenceRoot(config: Config): string;
/** Render a task ledger row as one human-readable line. */
declare function renderTaskLine(task: TaskRecord): string;
/**
 * Capabilities other plugins may contribute. This plugin never requires any of
 * them: it ships its own finding registry and its own ledger, so a deployment
 * with nothing else installed still works. They are listed here so an operator
 * can see, at the start of a task, whether the richer path is available — and so a
 * skill's fallback instruction has something concrete to refer to.
 */
declare const OPTIONAL_CAPABILITIES: readonly {
  readonly tool: string;
  readonly why: string;
}[];
/**
 * Whether a tool is registered in this deployment.
 *
 * Detection reads the live tool registry rather than guessing from config, so the
 * answer reflects what the model can actually see. Any failure resolves to
 * `false`: an unreachable registry must never be reported as an available
 * capability.
 */
declare function hasTool(ctx: Context, toolName: string): boolean;
/** Render the blackboard as a compact digest. */
declare function renderBlackboard(entries: readonly {
  kind: BlackboardKind;
  id: string;
  lane: string;
  title: string;
  body: string;
  evidence?: string;
}[], kind?: BlackboardKind): string;
/** The slice of an Agent this plugin reads; kept structural so tests can pass a stub. */
interface AgentLike {
  readonly ctx?: unknown;
  readonly session?: {
    readonly id?: unknown;
    readonly header?: {
      readonly cwd?: unknown;
    };
  };
}
/**
 * Which agent-preset mode an agent runs on, or `''` for a session outside the modes.
 *
 * Read at call time from the caller's own agent rather than captured when the plugin
 * mounted: one mount serves every mode, so the mode is a property of the CALL, not of
 * the instance. A failure here must not fail the tool — an unresolvable preset reads
 * as "not a security mode" and the tool says so.
 */
declare function presetOfAgent(ctx: Context, agent: AgentLike | undefined): string;
declare function apply(ctx: Context, config: Config): void;
//#endregion
export { CONSOLE_PATH, Config, MANAGER_PATH, OPTIONAL_CAPABILITIES, PLUGIN_VERSION, apply, defaultReferenceRoot, hasTool, inject, name, presetOfAgent, renderBlackboard, renderTaskLine, resolveReferenceRoot, resolveStateDir };