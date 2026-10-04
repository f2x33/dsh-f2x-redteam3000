//#region src/manager.d.ts
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
declare function isInstallableSpecifier(specifier: string): boolean;
/** Resolved environment facts the manager needs. */
interface ManagerEnv {
  /** Profile name, e.g. `web`. */
  profile: string;
  /** Absolute profile directory. */
  profileDir: string;
  /** `$DSH_HOME`. */
  dshHome: string;
  /** Package root of this plugin, so its own patch can be read. */
  pluginRoot: string;
}
/**
 * Read the profile facts from the environment.
 *
 * DSH exports `DSH_PROFILE` and `DSH_PROFILE_DIR` to every session it starts, so the
 * manager never has to guess which profile it is running inside.
 */
declare function readManagerEnv(env?: NodeJS.ProcessEnv, pluginRoot?: string): ManagerEnv | undefined;
/** The shape `ctx.get('profileContext')` exposes on the host. */
interface ProfileContextLike {
  name?: string;
  dir?: string;
}
/**
 * Resolve the profile facts, preferring the live host service over the environment.
 *
 * `profileContext` is the host's own record of which profile it booted, so it cannot be
 * stale. The environment is only a fallback for hosts that do not publish it.
 */
declare function resolveManagerEnv(options: {
  profileContext?: ProfileContextLike;
  env?: NodeJS.ProcessEnv;
  pluginRoot?: string;
}): ManagerEnv | undefined;
/** One line of the environment report. */
interface CheckLine {
  /** Stable key, so the UI can group and the tests can assert. */
  key: string;
  /** Whether this prerequisite is satisfied. */
  ok: boolean;
  /** Short human label. */
  label: string;
  /** One sentence of detail: what was found, or what to do. */
  detail: string;
}
/** Run a command, capturing stdout+stderr, with a timeout. Never uses a shell. */
declare function runCommand(file: string, args: readonly string[], options?: {
  timeoutMs?: number;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}): Promise<{
  code: number | null;
  output: string;
  timedOut: boolean;
}>;
/**
 * Build the environment checklist.
 *
 * Ordered by how often each one is the actual blocker, and each failing line carries
 * the exact remedy, because the raw tool output does not.
 */
declare function runEnvironmentCheck(env: ManagerEnv): Promise<CheckLine[]>;
/** One loader id that both the candidate and an installed bundle insert. */
interface ConflictHit {
  id: string;
  /** Package (or plugin name) that already inserts it. */
  owner: string;
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
declare function topLevelInsertedIds(text: string): string[];
/** Read the patch text a package declares, or `undefined` when it has none. */
declare function readBundlePatch(packageDir: string): string | undefined;
/**
 * Find loader id collisions between a candidate package and everything already
 * installed in the profile.
 *
 * @param candidateDir - the unpacked candidate package directory.
 * @param env - profile facts.
 * @returns the colliding ids with their current owners.
 */
declare function findConflicts(candidateDir: string, env: ManagerEnv): ConflictHit[];
/** Outcome of one install attempt. */
interface InstallReport {
  ok: boolean;
  /** Every line the child printed, in order. */
  lines: string[];
  /** The exact-version exemption that was granted, when one was needed. */
  exemption?: string;
  /** One-sentence outcome. */
  summary: string;
}
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
declare function installPlugin(specifier: string, env: ManagerEnv, onLine?: (line: string) => void): Promise<InstallReport>;
/** What an installed package declares. */
interface Declarations {
  /** Agent preset ids the package would register, if its patch mounts. */
  presets: string[];
  /** Every top-level loader id it inserts. */
  entryIds: string[];
  /** Whether the package declares a web client bundle. */
  client: boolean;
  /** Whether the package declares a bundle patch at all. */
  bundle: boolean;
  /** Skill roots it ships, when discoverable from its layout. */
  skillRoots: string[];
}
/** Read what an installed package declares. */
declare function readDeclarations(packageDir: string): Declarations;
/** Result of the post-install verification pass. */
interface VerifyReport {
  specifier: string;
  installed: boolean;
  /** Entry ids the package contributes to the loader tree. */
  entryIds: string[];
  /** Preset row ids it declares. */
  presets: string[];
  /** Conflicts against what is already installed. */
  conflicts: ConflictHit[];
  /** Warnings a human must read: things a static check cannot settle. */
  notes: string[];
}
/**
 * Verify an install without restarting.
 *
 * What a static pass can settle: the package is on disk, DSH lists it as a bundle, its
 * patch parses, and its ids do not collide. What it cannot settle is whether the rows
 * actually mount — that needs the loader, which only runs at boot. The notes say so
 * rather than implying a green check means the plugin works.
 */
declare function verifyInstalled(specifier: string, env: ManagerEnv): VerifyReport;
/** Read this plugin's own package root from its module URL. */
declare function ownPackageRoot(from?: string): string;
/** One entry in the recommended-capabilities list. */
interface Recommendation {
  /** Specifier to install. */
  specifier: string;
  /** Why it is recommended. */
  why: string;
  /** What it is expected to bring, from the catalogue entry this was written against. */
  brings: string;
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
declare const RECOMMENDED: readonly Recommendation[];
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
declare function preflightSpecifier(specifier: string, env: ManagerEnv): Promise<{
  installable: boolean;
  line: string;
}>;
/** Everything the manager page renders. */
interface ManagerSnapshot {
  profile: string;
  profileDir: string;
  checks: CheckLine[];
  recommended: readonly Recommendation[];
  /** Verification reports for the recommendations that are already installed. */
  installed: VerifyReport[];
  /** Repository suites the page offers to clone and enumerate. */
  repos: readonly {
    url: string;
    why: string;
    brings: string;
  }[];
}
/** Escape text for HTML body and attribute positions. */
declare function escapeHtml(value: string): string;
/**
 * Render the manager page.
 *
 * Deliberately a server-rendered page on a plain route rather than a React client
 * plugin: this way every behaviour — the checks, the install, the verification — is
 * reachable and verifiable over HTTP, with no browser in the loop. A settings page can
 * wrap the same handlers later; the logic does not move.
 */
declare function renderManagerHtml(snapshot: ManagerSnapshot): string;
/** Repository suites worth offering, with the plugin count measured on this deployment. */
declare const RECOMMENDED_REPOS: readonly {
  url: string;
  why: string;
  brings: string;
}[];
/** Render the repository preparation result as plain text. */
declare function renderRepoText(report: RepoReport): string;
/** Render a plain-text report for a completed install. */
declare function renderInstallText(specifier: string, report: InstallReport): string;
/** One installable package found inside a repository. */
interface DiscoveredPackage {
  /** Package name from its manifest. */
  name: string;
  /** Absolute directory, which is what `dsh plugin add` takes. */
  dir: string;
  /** Version, when declared. */
  version?: string;
  /** Whether it declares a bundle patch, i.e. whether it adds loader rows. */
  hasBundle: boolean;
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
declare function discoverBundlePackages(root: string, maxDepth?: number): DiscoveredPackage[];
/** A GitHub repository URL, decomposed. */
interface GithubRepo {
  owner: string;
  repo: string;
}
/** Parse `https://github.com/owner/repo` (with or without `.git`). */
declare function parseGithubUrl(url: string): GithubRepo | undefined;
/**
 * The proxy prefix the operator configured for git, if any.
 *
 * A `url.<prefix>.insteadOf https://github.com/` rewrite is how this deployment reaches
 * GitHub at all, and an archive download has to go through the same route. Reading the
 * setting rather than hardcoding a mirror keeps this plugin out of the business of
 * choosing a third party to route traffic through.
 */
declare function configuredGithubProxy(): Promise<string | undefined>;
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
declare function archiveUrls(github: GithubRepo, proxy?: string): string[];
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
declare function canImport(dir: string): Promise<{
  ok: boolean;
  note: string;
}>;
/** Result of preparing a repository for installation. */
interface RepoReport {
  ok: boolean;
  /** Where it was cloned or updated. */
  dir?: string;
  /** Installable packages, bundle-declaring ones first. */
  packages: DiscoveredPackage[];
  /** Command output, for the operator to read. */
  lines: string[];
  /** One-sentence outcome. */
  summary: string;
}
/** A filesystem-safe name for a repository URL. */
declare function repoSlug(url: string): string;
/**
 * Clone or update a plugin repository, then list what is installable inside it.
 *
 * The suite's own deploy script is deliberately not run: it writes profile files, links
 * directories and shells out to pnpm, and a manager that runs arbitrary install scripts
 * out of a cloned repository is a worse trade than installing the subpackages one by one.
 * Cloning plus `dsh plugin add <dir>` gets the same rows mounted through DSH's own
 * validated path.
 */
declare function prepareRepo(url: string, env: ManagerEnv): Promise<RepoReport>;
/**
 * Locate the running DSH installation.
 *
 * A plugin installed by `link:` from a cloned repository resolves its bare imports from
 * that repository, which has no `node_modules` — so every `@deepseek-ai/*` peer fails,
 * which is exactly how the reference suite's plugins fail to import without their deploy
 * script. The runtime packages live beside the `dsh` entry point, so the install root is
 * found by walking up from it.
 */
declare function findDshInstall(env?: NodeJS.ProcessEnv): string | undefined;
/** What a peer bridge did. */
interface BridgeReport {
  ok: boolean;
  /** Runtime packages linked in. */
  runtime: string[];
  /** Sibling plugin packages linked in. */
  siblings: string[];
  /** Notes worth showing. */
  notes: string[];
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
declare function bridgeRepoPeers(repoDir: string, install: string | undefined, packages: readonly DiscoveredPackage[]): BridgeReport;
//#endregion
export { BridgeReport, CheckLine, ConflictHit, Declarations, DiscoveredPackage, InstallReport, ManagerEnv, ManagerSnapshot, ProfileContextLike, RECOMMENDED, RECOMMENDED_REPOS, Recommendation, RepoReport, VerifyReport, archiveUrls, bridgeRepoPeers, canImport, configuredGithubProxy, discoverBundlePackages, escapeHtml, findConflicts, findDshInstall, installPlugin, isInstallableSpecifier, ownPackageRoot, parseGithubUrl, preflightSpecifier, prepareRepo, readBundlePatch, readDeclarations, readManagerEnv, renderInstallText, renderManagerHtml, renderRepoText, repoSlug, resolveManagerEnv, runCommand, runEnvironmentCheck, topLevelInsertedIds, verifyInstalled };