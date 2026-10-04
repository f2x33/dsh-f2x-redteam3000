/**
 * The ledger subset: only the `redteam_*` tools that this package's published skills
 * actually reference, plus the read companions that make the ledger usable.
 *
 * Why not all 53: tool schemas are context that every turn pays for. The full set stays
 * available to `rt-drill` (its sub-agents write to the store through tools its persona
 * never names); every other mode mounts this file instead.
 *
 * The list is derived, not guessed: every name below appears in a `SKILL.md` that a mode
 * actually sees, or is the read side of one that does. `node scripts/check-tool-subsets.mjs`
 * re-derives it and fails when a mounted mode loses a tool its own skills reference.
 */
export const name = 'redteam-tools-ledger'
export const inject = ['redteam', 'tools']

import { applySubset } from './index.js'

/** Tools mounted by every mode except rt-drill: every read tool, plus every write tool
 * that a visible SKILL.md references (42 of 53). */
export const LEDGER_TOOLS = [
  'redteam_access_add',
  'redteam_access_list',
  'redteam_asset_add',
  'redteam_asset_get',
  'redteam_asset_graph',
  'redteam_asset_link',
  'redteam_asset_query',
  'redteam_asset_stats',
  'redteam_asset_test',
  'redteam_asset_timeline',
  'redteam_attack_chain',
  'redteam_attack_file_add',
  'redteam_attack_file_list',
  'redteam_attack_path',
  'redteam_chain',
  'redteam_chain_add',
  'redteam_credential_add',
  'redteam_credential_list',
  'redteam_domain_index',
  'redteam_http_evidence_add',
  'redteam_poc_add',
  'redteam_poc_get',
  'redteam_poc_list',
  'redteam_poc_search',
  'redteam_preflight',
  'redteam_report',
  'redteam_report_targets',
  'redteam_score_hit',
  'redteam_score_list',
  'redteam_score_report',
  'redteam_session_check',
  'redteam_session_info',
  'redteam_sessions',
  'redteam_tunnel_add',
  'redteam_tunnel_list',
  'redteam_tunnel_update',
  'redteam_vuln_add',
  'redteam_vuln_query',
  'redteam_vuln_update',
  'redteam_web_list',
  'redteam_webshell_add',
  'redteam_webshell_list',
]

/** Register the subset. */
export function apply(ctx) {
  return applySubset(ctx, LEDGER_TOOLS)
}
