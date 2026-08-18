// engine.mjs — the pure, deterministic fold from a merged WhisperBox event log
// to app state, plus role-based admission. No I/O, no platform deps, no crypto
// (signing is injected; ECIES is P2). This is the REFERENCE implementation:
// whisperbox_core (C++) must reproduce it exactly — golden vectors in
// test/fixtures pin the contract.
//
// Determinism rules (the C++ port MUST match):
//  - Input is the HLC-ordered merged log (mergeWhisperbox). Single pass, in order.
//  - `forms` object keys are inserted in HLC publish order; JSON serialization
//    preserves that order on every replica.
//  - All address comparisons are case-insensitive (lowercased).
//  - No Math.random, no Date.now, no iteration over unordered structures.

import { EventType } from "../../contract/src/events.mjs";
import { compareHlc } from "../../contract/src/hlc.mjs";

const lc = (s) => String(s).toLowerCase();

function drop(dropped, reason) {
  dropped.count += 1;
  dropped.reasons[reason] = (dropped.reasons[reason] ?? 0) + 1;
}

/**
 * Fold a merged event log into app state. Pure.
 *
 * @param {Event[]} mergedLog  HLC-ordered, id-deduped (mergeWhisperbox output).
 * @param {object}  opts
 * @param {string}  [opts.identity]  EVM address whose creator projections to include.
 * @param {(e: Event) => boolean} [opts.verify]  Authenticity hook (P2: secp256k1
 *        ECDSA verify + author recovery). Contract: for SIGNED events it must do
 *        the full check; unsigned events are admitted permissively (transition
 *        semantics — qaku ADR: strict-drop silently hid redelivered copies).
 * @returns {State}
 */
export function computeState(mergedLog, opts = {}) {
  const identity = opts.identity ? lc(opts.identity) : null;
  const verify = typeof opts.verify === "function" ? opts.verify : null;

  const forms = {}; // formId → FormView (inserted in HLC publish order)
  const formHlc = new Map(); // formId → publish event hlc (feed ordering)
  const acceptedResponses = new Map(); // formId → [response entries], fold order
  const acceptedResultsHlc = new Map(); // formId → winning results event hlc (LWW)
  const deferred = []; // events referencing not-yet-folded forms (lenient ordering)
  const dropped = { count: 0, reasons: {} };

  const applyEvent = (e) => {
    const p = e.payload;
    switch (e.type) {
      case EventType.FORM_PUBLISH: {
        const formId = lc(p.id);
        if (forms[formId]) return; // same id ⇒ already folded (defensive)
        forms[formId] = {
          id: formId,
          title: p.title,
          description: p.description,
          creator: lc(p.creator),
          publicKey: p.publicKey,
          createdAt: p.createdAt,
          expiresAt: p.expiresAt ?? null,
          questions: p.questions ?? [],
          whitelist: p.whitelist ?? { type: "none", value: "" },
          status: "open",
          responseCount: 0,
          respondents: [],
          confirmations: [],
          results: null,
        };
        formHlc.set(formId, e.hlc);
        acceptedResponses.set(formId, []);
        // Lenient ordering: replay deferred events for this form in HLC order.
        const mine = [];
        for (let i = deferred.length - 1; i >= 0; i--) {
          if (lc(deferred[i].payload.formId) === formId) mine.unshift(deferred.splice(i, 1)[0]);
        }
        for (const d of mine) applyEvent(d);
        return;
      }
      case EventType.RESPONSE_SUBMIT: {
        // Open event: NEVER dropped for signature problems (qaku lesson).
        const formId = lc(p.formId);
        const f = forms[formId];
        if (!f) { deferred.push(e); return; }          // orphan sealed blob — keep pending
        if (f.status === "closed") { drop(dropped, "form-closed"); return; } // sticky
        f.responseCount += 1;
        f.respondents.push(p.respondent);
        acceptedResponses.get(formId).push({
          respondent: p.respondent,
          submittedAt: p.submittedAt,
          encryptedPayload: p.encryptedPayload,
          signature: p.signature ?? null,
          confirmationId: null, // linked in P2 (creator derives confirmationId per respondent)
        });
        return;
      }
      case EventType.RESPONSE_CONFIRM:
      case EventType.FORM_CLOSE:
      case EventType.FORM_RESULTS: {
        if (verify && e.sig && !verify(e)) { drop(dropped, "sig-invalid"); return; }
        const formId = lc(p.formId);
        const f = forms[formId];
        if (!f) { deferred.push(e); return; }          // lenient: close/results may lead publish
        if (lc(p.author) !== f.creator) { drop(dropped, "not-creator"); return; }
        if (e.type === EventType.RESPONSE_CONFIRM) {
          if (!f.confirmations.includes(p.confirmationId)) f.confirmations.push(p.confirmationId);
        } else if (e.type === EventType.FORM_CLOSE) {
          f.status = "closed";                          // sticky, idempotent
          if (p.expiresAt != null) f.expiresAt = p.expiresAt;
        } else { // FORM_RESULTS — superseding, LWW by full HLC
          const cur = f.results ? acceptedResultsHlc.get(formId) : null;
          if (!cur || compareHlc(e.hlc, cur) > 0) {
            f.results = { resultsJson: p.resultsJson };
            acceptedResultsHlc.set(formId, e.hlc);
          }
        }
        return;
      }
      default:
        drop(dropped, "unknown-type");
    }
  };

  for (const e of mergedLog) applyEvent(e);

  // ── Assemble state ──────────────────────────────────────────────────────────
  const feed = [...formHlc.entries()]
    .sort((a, b) => compareHlc(a[1], b[1]))
    .filter(([id]) => forms[id].status === "open")
    .map(([id]) => id);

  const state = {
    v: 1,
    forms,
    feed,
    creator: null,
    pending: { count: deferred.length, events: deferred.map((e) => ({ id: e.id, type: e.type })) },
    dropped,
  };

  if (identity) {
    const mine = Object.values(forms).filter((f) => f.creator === identity);
    if (mine.length > 0) {
      const responses = {};
      const confirmations = {};
      for (const f of mine) {
        responses[f.id] = acceptedResponses.get(f.id);
        confirmations[f.id] = f.confirmations;
      }
      state.creator = { address: identity, forms: mine.map((f) => f.id), responses, confirmations };
    }
  }

  return state;
}

/** Convenience alias for the snapshot() hot path (core module API name). */
export const snapshot = computeState;
