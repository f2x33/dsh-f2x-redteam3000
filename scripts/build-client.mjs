#!/usr/bin/env node
/**
 * Build the Web client bundle (`lib/client.js`).
 *
 * The bundle is a CommonJS module wrapped in the host module loader's registration call,
 * so the browser can mount it without a bundler of its own:
 *
 *     window.__ModuleLoader__.load({ id: "<package>", factory: (require) => {
 *       var module = { exports: {} }; var exports = module.exports;
 *       ...bundle...
 *       return module.exports; } });
 *
 * `react` and the UI primitives are left external: the host supplies them through the
 * module loader's `require`, and bundling a second copy would give the section its own
 * React instance, which breaks hooks.
 *
 * esbuild is optional at build time. A contributor who only touches the host plugin can
 * skip it; the build script says so and exits 0 rather than failing the whole build.
 */

import { existsSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)))
const ENTRY = join(packageRoot, 'src', 'client', 'index.ts')
const OUTFILE = join(packageRoot, 'lib', 'client.js')
const PACKAGE_ID = JSON.parse(
  await import('node:fs').then((fs) => fs.readFileSync(join(packageRoot, 'package.json'), 'utf8')),
).name

/** Resolve esbuild from the package, then from the pnpm store layout. */
async function loadEsbuild() {
  const candidates = [
    'esbuild',
    join(packageRoot, 'node_modules', '.pnpm', 'node_modules', 'esbuild', 'lib', 'main.js'),
  ]
  for (const candidate of candidates) {
    try {
      return await import(candidate)
    } catch {
      // Try the next resolution strategy.
    }
  }
  return undefined
}

const esbuild = await loadEsbuild()
if (esbuild === undefined) {
  process.stdout.write('  esbuild not available — skipped lib/client.js (host plugin is unaffected)\n')
  process.exit(0)
}
if (!existsSync(ENTRY)) {
  process.stdout.write(`  no ${ENTRY} — nothing to bundle\n`)
  process.exit(0)
}

mkdirSync(dirname(OUTFILE), { recursive: true })
await esbuild.build({
  entryPoints: [ENTRY],
  bundle: true,
  format: 'cjs',
  platform: 'browser',
  target: 'es2022',
  outfile: OUTFILE,
  sourcemap: false,
  // Supplied by the host's module loader; a second copy would break React hooks.
  external: ['react', 'react/jsx-runtime', '@deepseek-ai/dsh-client-ui-primitives'],
  define: { 'process.env.NODE_ENV': '"production"' },
  banner: {
    js: [
      `window.__ModuleLoader__.load({ id: ${JSON.stringify(PACKAGE_ID)}, factory: (require) => {`,
      'var module = { exports: {} }; var exports = module.exports;',
    ].join('\n'),
  },
  footer: { js: 'return module.exports; } });' },
})
process.stdout.write(`  wrote ${OUTFILE}\n`)
