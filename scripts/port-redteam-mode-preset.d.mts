/**
 * Types for {@link ./port-redteam-mode-preset.mjs}, imported by the preset guards so they
 * know the ported drill mode by name without hardcoding it twice.
 */

/** The agent-preset id this port registers. */
export declare const PRESET_ID: string

/** The loader row id it inserts. */
export declare const ROW_ID: string

/** Roster order the preset takes. */
export declare const ORDER: number

/** The position statement appended to the source persona. */
export declare const RELATION_SUFFIX: readonly string[]

/** Build the ported preset file's text. */
export declare function buildPreset(): string

/** Drop a top-level row and its body. */
export declare function dropRow(
  rows: readonly string[],
  id: string,
): { rows: string[]; removed: number }

/** Append a `suffix:` block to the row that owns a `prefix:` block scalar. */
export declare function addSuffix(rows: readonly string[], suffix: readonly string[]): string[]
