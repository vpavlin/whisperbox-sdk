// merge.mjs — CRDT merge: union event logs by id, order by HLC.
// `mergeEvents`/`mergeOne` are plain-ESM mirrors of loam-sync src/merge.ts
// (lockstep with basecamp/logos_sync/merge.hpp).
//
// `mergeWhisperbox` is a DELIBERATE app-level refinement (documented deviation):
// WhisperBox uses NATURAL event ids (form:<id>, resp:<formId>:<respondent>, …)
// where the same id can legitimately carry DIFFERENT payloads — e.g. a
// respondent resubmitting (first response wins, per whisperbox.org semantics).
// loam-sync's "first in concatenation order wins" is then NOT replica-deterministic
// (it depends on log argument order). Rule here: on id collision keep the copy
// with the MINIMUM HLC; ties are identical payloads. Result is a function of the
// event SET alone — every replica converges to the byte-identical merged log.

import { compareHlc } from "./hlc.mjs";

/** Union any number of logs by id (dedup), then sort by HLC. Pure.
 *  loam-sync semantics: first occurrence in concatenation order wins on id
 *  collision. Use only when same-id ⇒ same-payload (UUIDv4-style ids). */
export function mergeEvents(...logs) {
  const byId = new Map();
  for (const log of logs)
    for (const e of log) if (e.id && !byId.has(e.id)) byId.set(e.id, e);
  return [...byId.values()].sort(totalOrder);
}

/** Merge one event into an already-merged log in place. Returns true if NEW. */
export function mergeOne(log, e) {
  if (!e.id) return false;
  if (log.some((x) => x.id === e.id)) return false; // dedup by id
  let i = log.length;
  while (i > 0 && totalOrder(log[i - 1], e) < 0) i--;
  log.splice(i, 0, e);
  return true;
}

/** Total order: HLC, then event id as a defensive tiebreak. A correct Clock
 *  never emits two identical HLCs from one device (ctr advances), but a buggy
 *  or adversarial peer might — the id tiebreak keeps the merged log a function
 *  of the event SET alone in that case too. */
function totalOrder(a, b) {
  const c = compareHlc(a.hlc, b.hlc);
  if (c !== 0) return c;
  if (a.id !== b.id) return a.id < b.id ? -1 : 1;
  return 0;
}

/** WhisperBox merge: union by id with MIN-HLC conflict rule (see header).
 *  Pure. Deterministic in the multiset of events, independent of log order. */
export function mergeWhisperbox(...logs) {
  const byId = new Map();
  for (const log of logs) {
    for (const e of log) {
      if (!e.id) continue;
      const cur = byId.get(e.id);
      if (!cur) {
        byId.set(e.id, e);
      } else {
        // Same id: keep the earliest-HLC copy. If HLCs are identical the payloads
        // must be identical too (same device stamped the same event twice); keep cur.
        const c = compareHlc(e.hlc, cur.hlc);
        if (c < 0) byId.set(e.id, e);
      }
    }
  }
  return [...byId.values()].sort(totalOrder);
}
