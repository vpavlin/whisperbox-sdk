// oracle.mjs — invariant checks over raw logs + merged log + folded state.
// SURFACED, NEVER ENFORCED: violations are reported (status card / logs) so a
// broken peer or protocol drift is visible without breaking sync (qaku pattern).

import { EventType } from "../../contract/src/events.mjs";

const lc = (s) => String(s).toLowerCase();

/**
 * @param {Event[][]} rawLogs   per-device logs as received (pre-merge) — lets us
 *        see same-id/different-payload resubmissions the merge collapses.
 * @param {Event[]} mergedLog   HLC-ordered merged log.
 * @param {State} state         computeState output.
 * @returns {{violations: string[], counts: object}}
 */
export function checkInvariants(rawLogs, mergedLog, state) {
  const violations = [];

  // 1. Response↔form referential integrity: responses for forms absent from the
  //    log (orphan sealed blobs — legal while a form is in flight, surfaced so a
  //    permanently-missing form is noticeable).
  if (state.pending.count > 0) {
    const orphans = state.pending.events.filter((e) => e.type === EventType.RESPONSE_SUBMIT);
    if (orphans.length > 0) {
      violations.push(`orphan-responses:${orphans.length} (forms not in local log)`);
    }
  }

  // 2. One live response per respondent: structurally guaranteed by the
  //    deterministic id resp:<formId>:<respondent> under union-by-id merge.
  //    Surface RESUBMISSIONS — same id observed with different payloads in raw
  //    logs (first-in-HLC wins; later attempts are collapsed by the merge).
  const seen = new Map(); // id → canonical payload string
  let resubmissions = 0;
  for (const log of rawLogs) {
    for (const e of log) {
      if (!e.id) continue;
      const canon = JSON.stringify(e.payload);
      const cur = seen.get(e.id);
      if (cur === undefined) seen.set(e.id, canon);
      else if (cur !== canon) resubmissions += 1;
    }
  }
  if (resubmissions > 0) violations.push(`resubmissions:${resubmissions} (first-in-HLC wins)`);

  // 3. No over-confirmation: a form cannot have more confirmations than accepted
  //    responses (each receipt should correspond to one submission).
  for (const f of Object.values(state.forms)) {
    if (f.confirmations.length > f.responseCount) {
      violations.push(`over-confirmed:${f.id} (${f.confirmations.length} confirms > ${f.responseCount} responses)`);
    }
  }

  // 4. Dropped events (admission failures) — always surfaced, never fatal.
  if (state.dropped.count > 0) {
    const parts = Object.entries(state.dropped.reasons).map(([r, n]) => `${r}:${n}`);
    violations.push(`dropped:${parts.join(",")}`);
  }

  // 5. Duplicate confirmations of the SAME id are impossible (merge dedup), but a
  //    creator re-sending a confirmation for an already-confirmed respondent with
  //    a NEW confirmationId is domain-level noise — count it.
  let dupConfirms = 0;
  const confirmCounts = new Map(); // formId → Set(confirmationId)
  for (const e of mergedLog) {
    if (e.type !== EventType.RESPONSE_CONFIRM) continue;
    const k = lc(e.payload.formId);
    if (!confirmCounts.has(k)) confirmCounts.set(k, new Set());
    const set = confirmCounts.get(k);
    if (set.has(e.payload.confirmationId)) dupConfirms += 1; // same pair re-delivered w/ diff hlc? impossible via id — defensive
    set.add(e.payload.confirmationId);
  }
  if (dupConfirms > 0) violations.push(`duplicate-confirmation-events:${dupConfirms}`);

  return {
    violations,
    counts: {
      forms: Object.keys(state.forms).length,
      open: state.feed.length,
      responses: Object.values(state.forms).reduce((n, f) => n + f.responseCount, 0),
      confirmations: Object.values(state.forms).reduce((n, f) => n + f.confirmations.length, 0),
      resubmissions,
    },
  };
}
