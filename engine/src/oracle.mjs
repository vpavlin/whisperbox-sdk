// oracle.mjs — invariant checks over raw logs + merged log + folded state (+
// optional creator view). SURFACED, NEVER ENFORCED: violations are reported
// (status card / logs) so a broken peer or protocol drift is visible without
// breaking sync (qaku pattern).
//
// Privacy note: responses are opaque sealed blobs at the log level — checks that
// need decrypted content (resubmissions per respondent, over-confirmation vs
// accepted responses) run against the CREATOR VIEW when one is supplied.

import { EventType } from "../../contract/src/events.mjs";

const lc = (s) => String(s).toLowerCase();

/**
 * @param {Event[][]} rawLogs   per-device logs as received (pre-merge).
 * @param {Event[]} mergedLog   HLC-ordered merged log.
 * @param {State} state         computeState output.
 * @param {CreatorView} [creatorView]  optional — enables decrypted-content checks.
 * @returns {{violations: string[], counts: object}}
 */
export function checkInvariants(rawLogs, mergedLog, state, creatorView = null) {
  const violations = [];

  // 1. Pending gated events (close/confirm referencing forms not yet in the log).
  //    Legal while a form is in flight; surfaced so a permanently-missing form
  //    is noticeable. (Responses are never pending — opaque pool, no routing.)
  if (state.pending.count > 0) {
    violations.push(`pending-gated:${state.pending.count} (forms not in local log)`);
  }

  // 2. Same-id/different-payload collisions in raw logs. Under content-addressed
  //    response ids this is impossible for responses; possible for form events
  //    (re-publish with edits) — merge keeps min-HLC. Surface when seen.
  const seen = new Map(); // id → canonical payload string
  let conflicts = 0;
  for (const log of rawLogs) {
    for (const e of log) {
      if (!e.id) continue;
      const canon = JSON.stringify(e.payload);
      const cur = seen.get(e.id);
      if (cur === undefined) seen.set(e.id, canon);
      else if (cur !== canon) conflicts += 1;
    }
  }
  if (conflicts > 0) violations.push(`same-id-conflicts:${conflicts} (min-HLC wins)`);

  // 3. Dropped events (admission failures) — always surfaced, never fatal.
  if (state.dropped.count > 0) {
    const parts = Object.entries(state.dropped.reasons).map(([r, n]) => `${r}:${n}`);
    violations.push(`dropped:${parts.join(",")}`);
  }

  // ── Creator-view checks (decrypted content) ────────────────────────────────
  if (creatorView) {
    // 4. Over-confirmation: more confirmations than accepted responses.
    for (const formId of creatorView.forms) {
      const nConf = creatorView.confirmations[formId]?.length ?? 0;
      const nResp = creatorView.responses[formId]?.length ?? 0;
      if (nConf > nResp) {
        violations.push(`over-confirmed:${formId} (${nConf} confirms > ${nResp} responses)`);
      }
    }
    // 5. Creator-view drops (closed-form, sig-invalid, duplicate-respondent).
    if (creatorView.dropped.count > 0) {
      const parts = Object.entries(creatorView.dropped.reasons).map(([r, n]) => `${r}:${n}`);
      violations.push(`creator-dropped:${parts.join(",")}`);
    }
    // 6. Blobs the creator cannot decrypt — expected for other creators' forms;
    //    surfaced as a count only (no violation by itself).
  }

  return {
    violations,
    counts: {
      forms: Object.keys(state.forms).length,
      open: state.feed.length,
      sealedResponses: state.responses.length,
      confirmations: Object.values(state.forms).reduce((n, f) => n + f.confirmations.length, 0),
      accepted: creatorView
        ? Object.values(creatorView.responses).reduce((n, r) => n + r.length, 0)
        : null,
      undecrypted: creatorView ? creatorView.undecrypted : null,
    },
  };
}
