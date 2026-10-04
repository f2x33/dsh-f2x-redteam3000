# Releasing `dsh-f2x-redteam3000`

Every command below has been run against this repository. Nothing here is aspirational.

## 0. What ships

`npm pack` publishes ~1584 files / ~8.2 MB: the built `lib/`, the bundle patch, the twelve
preset sources, the skills, the knowledge base, the personas, the playbooks, the two
maintainer scripts and the README. **It does ship third-party MIT material** — the
vendored trees (`vendor/redteam-*`, `vendor/reverse-skills`, the ported mode refs) are
recorded item by item in `THIRD-PARTY-NOTICES.md`; see §6 for what is deliberately NOT
shipped.

## 0b. The gate (run this first)

```sh
node scripts/release-check.mjs --pack
```

It fails the process — not warns — on the defects that have actually shipped a bad
release somewhere: a manifest whose `repository` / `author` / `homepage` / `bugs` still
holds a `TODO`, a `lib/` older than `src/` (the tarball then carries the previous build
while the tests, which read `src/`, stay green), a missing `dsh.bundle.patch` or
`./vendor/*` export, a preset region out of sync, and a tarball that carries
`node_modules/`, `src/` or `tests/`.

**Fill the four TODO fields before this passes.** `author`, `repository`, `homepage` and
`bugs` are what the npm page links to; a package published without them is a package
nobody can file an issue against.

## 0c. Legal surface (do not skip)

Three documents must ship and must stay consistent with the code:

| File | What it is |
|---|---|
| `LICENSE` | MIT (the project's own licence) |
| `NOTICE` | provenance and attribution: the nature of the project (integration layer, AI-assisted), the bundled MIT material, and the referenced projects |
| `DISCLAIMER.md` | usage terms, risk and liability — authorized use only; the software performs real network activity and is provided AS IS |
| `THIRD-PARTY-NOTICES.md` | every bundled third-party item: licence, copyright holder, **what this project modified**, plus what is deliberately NOT distributed |

**Hard rule: no copyleft content in the package.** `release-check.mjs` scans `presets/`,
`vendor/` and `skills/` for GPL / AGPL / Commons Clause licence text and fails if any
appears — that material would relicense the whole distribution. Two trees were removed
for this reason (semgrep open-source rules: Commons Clause + AGPL; Linux incident-response
handbook: GPL-3.0); the skills that used them now say "obtain it yourself", and
THIRD-PARTY-NOTICES §3 tells the reader where. If you ever want them back, change the
project licence to a compatible copyleft one first — do not ship them under MIT.

Before publishing, re-read `THIRD-PARTY-NOTICES.md` §6 ("待办"): four provenance items
still need your confirmation (upstream URLs and the origin of the two skill collections).

## 0d. Provenance audit

```sh
node scripts/provenance-audit.mjs
```

Walks every path in `package.json#files` and asserts each one is named in
`THIRD-PARTY-NOTICES.md`. It cannot verify that a statement is *true* — only that nothing
shipped is undeclared, which is where an unlicensed copy would otherwise hide.

Then close out `THIRD-PARTY-NOTICES.md` §1.10 (the author attestation). Six items are on
that list; four are upstream URLs and licensing questions, two are "is this yours or
adapted from somewhere?". **`release-check.mjs` fails until the attestation block is
signed and no item is left open.** If any item cannot be resolved, remove that content
from the package — MIT lets you ship your own work, not someone else's of unknown
origin.

## 1. Pre-flight

```sh
cd <checkout>

npx tsc --noEmit                 # types clean
npx tsdown                       # rebuild lib/ (a stale lib ships stale code)
node scripts/sync-presets.mjs --check   # the inlined preset region matches its sources
npx vitest run                   # 169 tests
node scripts/selfcheck.mjs        # 27 checks, incl. publish readiness
node scripts/smoke-live.mjs      # 12 real turns, one per mode (costs model calls)
```

If `sync-presets --check` fails, run `node scripts/sync-presets.mjs` and commit the
result. The region is what makes the modes arrive with the install; a stale region
ships the *previous* modes.

## 2. End-to-end, on the real profile

```sh
node scripts/verify-presets.mjs web
```

Expect `all 12 preset(s) mount cleanly and are selectable.` A preset whose rows
fail to load is **silently filtered out of the UI picker** with no browser error, so
this check is not optional (see `presets/README.md` §3).

## 3. Static check

```sh
npx dsh-plugin-guide check
```

Expect **10 passed, 1 failed, 0 warned**. The one failure is `manifest-peers` and it
is deliberate — the guide pins an exact peer-range string that stops below `0.2.0`,
which would make this plugin unloadable the moment DSH 0.2.0 ships. See the note in
`README.md` and `STATUS.md` §5.

## 4. Pack and verify the artefact

```sh
rm -f dsh-f2x-redteam3000-*.tgz
npm pack --ignore-scripts
tar tzf dsh-f2x-redteam3000-*.tgz | head -50
```

Confirm the tarball contains `package/lib/`, `package/cordis.patch.yml` and
`package/presets/dsh-0.2/*.patch.yml`, and **no** `node_modules/`, `src/`, `tests/`,
`STATUS.md` or `HANDOFF.md`.

## 5. Smoke-test the tarball in a throwaway profile

Never publish an artefact that has only been tested as a `link:` checkout — that is
how you ship a plugin whose modes never appear.

```sh
rm -rf /tmp/f2x-smoke
node --input-type=module -e "
const { initializeProfileFromDefault } = await import('/usr/lib/node_modules/@deepseek-ai/dsh/lib/profile-boot.js')
initializeProfileFromDefault('smoke','web','/tmp/f2x-smoke')"

DSH_HOME=/tmp/f2x-smoke dsh plugin --profile smoke add "$PWD"/dsh-f2x-redteam3000-*.tgz
DSH_HOME=/tmp/f2x-smoke node scripts/verify-presets.mjs smoke
```

Expect the same three `OK` lines. This proves the modes ship **inside the bundle
patch**, so one `dsh plugin add` is enough.

## 6. Publish

```sh
npm publish --access public      # unscoped, so public is the default; the flag is explicit
```

Before you do, re-read the two standing constraints:

- **What is and is not third-party.** This package **does** redistribute third-party
  MIT material (vendored tool packages, skill collections and ported mode references);
  every item, its licence and what this project changed is itemised in
  `THIRD-PARTY-NOTICES.md`, and `scripts/release-check.mjs` fails when a shipped path
  has no declaration or when copyleft text appears anywhere under `presets/`,
  `vendor/` or `skills/`. What is deliberately **NOT** shipped: the semgrep open-source
  rule set (Commons Clause + AGPL-3.0), the NOP Team Linux incident-response handbook
  (GPL-3.0), the `chanzi-rules` knowledge base, and the `@deepseek-ai/*` runtime peers
  (they come from the DSH installation). Keep it that way.
- **Installation goes through `dsh plugin add`, never a bare `npm install`.** DSH
  resolves the `@deepseek-ai/*` peer packages from its own installation; the copies on
  npm are far older than the runtime.

## 7. After publishing

```sh
npm view dsh-f2x-redteam3000 version
```

Then, on a machine with a clean DSH install:

```sh
dsh plugin --profile web add dsh-f2x-redteam3000
dsh web --port <port>
```

Restart, open a **new** chat, and confirm the three modes appear — the picker only
applies to a blank session. The console is at
`http://127.0.0.1:<port>/f2x-console` (loopback clients only).
