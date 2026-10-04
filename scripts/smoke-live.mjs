#!/usr/bin/env node
/**
 * Live smoke test: does every mode this plugin ships actually work end to end?
 *
 * What this proves that the other checks cannot
 * --------------------------------------------
 * `verify-presets.mjs` proves the presets *mount*. Mounting is not working: a mode can
 * mount cleanly while its persona is empty, its skills never resolve, or its tool rows
 * point at packages that are not installed. Only a real turn shows the difference.
 *
 * For each mode this opens a session through the same `sessionController` surface the
 * Web client uses, sends one minimal prompt, and asserts four things from the resulting
 * event stream:
 *
 *   persona  — a `system/message` carries the mode's own instructions (not just the
 *              harness preamble)
 *   skills   — the session's skill catalog was injected
 *   tools    — `f2x_orchestrate_*` appears among the advertised tools, so this plugin's
 *              layer really reached the model
 *   reply    — the model answered, i.e. provider, credentials and streaming all work
 *
 * It costs one short model call per mode, so it is a deliberate, manual gate rather than
 * a unit test. Run it before a release, or after touching the presets.
 *
 * Usage
 * -----
 *   node scripts/smoke-live.mjs                  # every mode
 *   node scripts/smoke-live.mjs pentest redteam  # named modes
 *   PROFILE=web node scripts/smoke-live.mjs      # profile to boot (default: web)
 *
 * Exits non-zero if any mode fails.
 */

import { createRequire } from 'node:module'
import { randomUUID } from 'node:crypto'
import { existsSync, readdirSync, rmSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { MODES as PORTED_MODES } from './port-redteam-modes.mjs'
import { PRESET_ID as DRILL_PRESET } from './port-redteam-mode-preset.mjs'

const DEFAULT_INSTALL = '/usr/lib/node_modules/@deepseek-ai/dsh'

/** Every mode this plugin ships, in roster order. */
export const MODES = ['redteam', 'f2x-power', ...PORTED_MODES.filter((m) => m !== 'redteam'), DRILL_PRESET]

/** The prompt each mode answers. Short on purpose: it is a liveness probe, not a task. */
const PROBE_PROMPT = '只回复两个字：可用'

/** Per-mode wall-clock ceiling. A reasoning model can think for a while. */
const MODE_TIMEOUT_MS = 120_000

function findInstall() {
  const candidates = [process.env.DSH_INSTALL, DEFAULT_INSTALL].filter(
    (entry) => typeof entry === 'string' && entry !== '',
  )
  for (const candidate of candidates) {
    if (existsSync(join(candidate, 'package.json'))) return candidate
  }
  throw new Error(`no DSH installation found (looked at ${candidates.join(', ')})`)
}

/** Boot the profile and return its context. */
async function boot() {
  const install = findInstall()
  const require = createRequire(join(install, 'package.json'))
  const { loadLayeredEnv } = await import(require.resolve('@deepseek-ai/dsh-app-boot'))
  const profile = process.env.PROFILE ?? 'web'
  const { runProfile } = await import(join(install, 'lib', 'profile-boot.js'))
  const { ctx } = await runProfile({
    environment: loadLayeredEnv('dsh'),
    profile,
    patchFiles: [],
    args: ['--port', '0', '--no-open'],
  })
  return { ctx, profile }
}

/** Run one turn in one mode and report what it observed. */
async function probeMode(ctx, preset) {
  const created = await ctx.sessionController.create({ agentPreset: preset })
  const address = { kind: 'session', sessionId: created.sessionId }
  const controller = new AbortController()
  const timer = setTimeout(() => {
    controller.abort()
  }, MODE_TIMEOUT_MS)

  const observed = { sessionId: created.sessionId, persona: false, skills: false, tools: false, reply: '' }
  try {
    await ctx.sessionController.prompt(
      {
        requestId: randomUUID(),
        sessionId: created.sessionId,
        mode: 'queue',
        content: [{ type: 'text', text: PROBE_PROMPT }],
      },
      controller.signal,
    )
    for await (const frame of ctx.sessionController.follow(
      { address, assistantStream: true },
      controller.signal,
    )) {
      const event = frame?.event
      if (event === undefined) continue
      if (event.type === 'system/message') {
        const text = event.data?.message?.content?.[0]?.text ?? ''
        // The harness preamble alone is short; a real mode adds its own instructions.
        if (text.length > 120) observed.persona = true
        if (/f2x_orchestrate_\w+/.test(JSON.stringify(event))) observed.tools = true
      }
      if (
        event.type === 'user/message' &&
        /skills are available in this session/.test(JSON.stringify(event))
      ) {
        observed.skills = true
      }
      if (event.type === 'assistant/message') {
        for (const part of event.data?.message?.content ?? []) {
          if (part.type === 'text') observed.reply += part.text
        }
      }
      if (event.type === 'turn/end' || event.type === 'turn/complete') break
    }
  } finally {
    clearTimeout(timer)
    // Close the stream so its watchers are released before the next mode opens one.
    controller.abort()
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
  return observed
}

/**
 * Remove the sessions a probe run created.
 *
 * A probe session is real state: it lands in the session store and shows up in the
 * operator's sidebar, so a run of twelve modes leaves twelve rows of junk behind. The
 * session API exposes no delete, so this removes the store entries directly — best
 * effort, and never touching anything the run did not create.
 */
function discardSessions(sessionIds) {
  const home = process.env.DSH_HOME ?? join(homedir(), '.dsh')
  const sessionsRoot = join(home, 'sessions')
  const cacheRoot = join(home, 'storages', 'session_projcache', 'sessions')
  if (!existsSync(sessionsRoot)) return
  let removed = 0
  for (const workspace of readdirSync(sessionsRoot)) {
    for (const id of sessionIds) {
      const dir = join(sessionsRoot, workspace, id)
      if (existsSync(dir)) {
        rmSync(dir, { recursive: true, force: true })
        removed += 1
      }
    }
  }
  if (existsSync(cacheRoot)) {
    for (const id of sessionIds) {
      const cached = join(cacheRoot, `${id}.json`)
      if (existsSync(cached)) rmSync(cached, { force: true })
    }
  }
  return removed
}

async function main() {
  const requested = process.argv.slice(2).filter((arg) => !arg.startsWith('-'))
  const modes = requested.length > 0 ? requested : MODES
  for (const mode of modes) {
    if (!MODES.includes(mode)) throw new Error(`unknown mode: ${mode} (known: ${MODES.join(', ')})`)
  }

  const { ctx, profile } = await boot()
  process.stdout.write(`profile "${profile}" — live probe of ${String(modes.length)} mode(s)\n\n`)

  let failed = 0
  const created = []
  for (const mode of modes) {
    const started = Date.now()
    try {
      const observed = await probeMode(ctx, mode)
      if (observed.sessionId !== undefined) created.push(observed.sessionId)
      const ok =
        observed.persona && observed.skills && observed.tools && observed.reply.trim() !== ''
      if (!ok) failed += 1
      const seconds = ((Date.now() - started) / 1000).toFixed(1)
      process.stdout.write(
        `  ${ok ? 'PASS' : 'FAIL'} ${mode.padEnd(18)} ${seconds.padStart(5)}s  ` +
          `persona=${observed.persona ? 'yes' : 'NO '} ` +
          `skills=${observed.skills ? 'yes' : 'NO '} ` +
          `tools=${observed.tools ? 'yes' : 'NO '} ` +
          `reply=${JSON.stringify(observed.reply.trim().slice(0, 12))}\n`,
      )
    } catch (error) {
      failed += 1
      process.stdout.write(
        `  FAIL ${mode.padEnd(18)}       ${String(error?.message ?? error).split('\n')[0]}\n`,
      )
    }
  }

  const removed = discardSessions(created)
  process.stdout.write(`\ncleaned up ${String(removed ?? 0)} probe session(s).\n`)
  process.stdout.write(
    failed === 0
      ? `all ${String(modes.length)} mode(s) answered with their own persona, skills and tools.\n`
      : `${String(failed)} of ${String(modes.length)} mode(s) FAILED.\n`,
  )
  return failed === 0 ? 0 : 1
}

if (process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`) {
  process.exit(await main())
}
