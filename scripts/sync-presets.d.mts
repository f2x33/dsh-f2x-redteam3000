/**
 * Types for {@link ./sync-presets.mjs}, which the preset test imports to assert the
 * inlined bundle region still matches its source files.
 */

/** Preset source files, in the order they are inlined. */
export declare const PRESET_FILES: readonly string[]

/** Region markers; the sync script rewrites exactly what lies between them. */
export declare const BEGIN_MARKER: string
export declare const END_MARKER: string

/** The `- insert:` rows of one per-mode patch file. */
export declare function presetRows(relativePath: string): string[]

/** The exact text the marked region must hold. */
export declare function renderRegion(): string
