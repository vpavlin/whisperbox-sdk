// engine.mjs — the pure, deterministic fold from a merged WhisperBox event log to
// app state (computeState), plus the CREATOR VIEW (creatorView) that decrypts and
// interprets sealed responses. No I/O, no platform deps; all crypto is injected.
// This is the REFERENCE implementation: whisperbox_core (C++) must reproduce it
// exactly — golden vectors in test/fixtures pin the contract.
//
// Two layers (privacy ground truth — see events.mjs header):
//   1. LOG FOLD (computeState): syncs opaque events. Responses are sealed blobs;
//      the fold stores them in a global pool, HLC-ordered. It can route/dedup by
//      content hash only — it never sees formId/respondent inside a response.
//   2. CREATOR VIEW (creatorView): given the folded state + an injected `open()`
//      (ECIES decrypt with the creator's key), assigns blobs to forms, enforces
//      one-response-per-respondent (earliest HLC wins), closed-form drops, and
//      whitelist signature checks. Pure & deterministic per replica.
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
 * @param {string}  [opts.identity]  address whose creator projections to include.
 * @param {(e: Event) => boolean} [opts.verify]  Authenticity hook for SIGNED events
 *        (P2: secp256k1 ECDSA verify + author recovery). Contract: for signed
 *        events it must do the full check; unsigned events are admitted
 *        permissively (transition semantics — qaku ADR: strict-drop silently hid
 *        redelivered copies of your own submissions).
 * @returns {State}  { v, forms, feed, responses, creator?, pending, dropped }
 */
export function computeState(mergedLog, opts = {}) {
  const identity = opts.identity ? lc(opts.identity) : null;
  const verify = typeof opts.verify === "function" ? opts.verify : null;

  const forms = {}; // formId → FormView (inserted in HLC publish order)
  const formHlc = new Map(); // formId → publish event hlc (feed ordering)
  const closeHlc = {}; // formId → close event hlc (creator-view drops; in state)
  const responses = []; // global pool of sealed blobs, HLC order: {id,hlc,encryptedPayload}
  const deferred = []; // gated events referencing not-yet-folded forms (lenient ordering)
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
          confirmations: [],
        };
        formHlc.set(formId, e.hlc);
        // Lenient ordering: replay deferred gated events for this form in HLC order.
        const mine = [];
        for (let i = deferred.length - 1; i >= 0; i--) {
          if (lc(deferred[i].payload.formId) === formId) mine.unshift(deferred.splice(i, 1)[0]);
        }
        for (const d of mine) applyEvent(d);
        return;
      }
      case EventType.RESPONSE_SUBMIT: {
        // OPAQUE sealed blob. No form routing, no admission checks at log level —
        // interpretation happens in creatorView after decryption. Never dropped.
        responses.push({ id: e.id, hlc: e.hlc, encryptedPayload: p.encryptedPayload });
        return;
      }
      case EventType.RESPONSE_CONFIRM:
      case EventType.FORM_CLOSE: {
        if (verify && e.sig && !verify(e)) { drop(dropped, "sig-invalid"); return; }
        const formId = lc(p.formId);
        const f = forms[formId];
        if (!f) { deferred.push(e); return; } // lenient: close/confirm may lead publish
        if (lc(p.author) !== f.creator) { drop(dropped, "not-creator"); return; }
        if (e.type === EventType.RESPONSE_CONFIRM) {
          if (!f.confirmations.includes(p.confirmationId)) f.confirmations.push(p.confirmationId);
        } else { // FORM_CLOSE — sticky, idempotent
          f.status = "closed";
          closeHlc[formId] = e.hlc;
          if (p.expiresAt != null) f.expiresAt = p.expiresAt;
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
    responses, // opaque pool, HLC order (fold-level; creatorView interprets)
    closeHlc, // formId → close event hlc (creator-view closed-form drops)
    creator: null,
    pending: { count: deferred.length, events: deferred.map((e) => ({ id: e.id, type: e.type })) },
    dropped,
  };

  if (identity) {
    const mine = Object.values(forms).filter((f) => f.creator === identity);
    if (mine.length > 0) {
      state.creator = { address: identity, forms: mine.map((f) => f.id) };
    }
  }

  return state;
}

/**
 * Creator view: decrypt + interpret the sealed response pool for ONE creator. Pure.
 *
 * @param {State}   state      computeState output (any identity).
 * @param {object}  opts
 * @param {string}  opts.identity        creator address (must own ≥1 form in state).
 * @param {(hex: string) => object|null} opts.open   ECIES open hook. Returns the
 *        decrypted response object {formId, respondent, submittedAt, answers,
 *        signature} or null when the blob is not for this creator / malformed.
 * @param {(e: Event) => boolean} [opts.verifyResponse]  Inner-signature check over
 *        the DECRYPTED content (whitelist != none). Injected so the engine stays
 *        crypto-free; see crypto.mjs verifyEvent for the canonical scheme.
 * @returns {CreatorView}  { address, forms, responses: {formId → [accepted]},
 *   confirmations: {formId → [confirmationId]}, dropped: {count, reasons},
 *   undecrypted: number }
 */
export function creatorView(state, opts) {
  const identity = lc(opts.identity);
  const open = typeof opts.open === "function" ? opts.open : () => null;
  const verifyResponse = typeof opts.verifyResponse === "function" ? opts.verifyResponse : null;

  const mine = Object.values(state.forms).filter((f) => f.creator === identity);
  const view = {
    address: identity,
    forms: mine.map((f) => f.id),
    responses: {},
    confirmations: {},
    dropped: { count: 0, reasons: {} },
    undecrypted: 0,
  };
  for (const f of mine) {
    view.responses[f.id] = [];
    view.confirmations[f.id] = state.forms[f.id].confirmations;
  }

  const seenRespondent = new Map(); // formId → Set(respondent) — earliest HLC wins

  // Pool is HLC-ordered (fold invariant) → first accepted response per respondent
  // is the min-HLC one, on every replica.
  for (const blob of state.responses) {
    let dec = null;
    try { dec = open(blob.encryptedPayload); } catch { dec = null; }
    if (!dec || typeof dec !== "object") { view.undecrypted += 1; continue; }

    const formId = lc(dec.formId ?? "");
    const f = state.forms[formId];
    if (!f || f.creator !== identity) continue; // not mine (can't decrypt anyway)

    // Closed-form drop: blob's HLC after the close event's HLC. Cross-device HLC
    // comparison is approximate (clock skew) — document as best-effort; the
    // original whisperbox had no close at all, so this is our stricter layer.
    if (f.status === "closed") {
      const ch = state.closeHlc?.[formId];
      if (!ch || compareHlc(blob.hlc, ch) >= 0) { drop(view.dropped, "form-closed"); continue; }
    }

    // Whitelist + inner signature (original: enforced only when whitelist != none).
    if (f.whitelist?.type !== "none" && verifyResponse) {
      const pseudo = {
        v: 1, id: blob.id, type: EventType.RESPONSE_SUBMIT, hlc: blob.hlc, dev: "",
        payload: dec, pub: dec.pub ?? null, sig: dec.signature ?? null,
      };
      if (!verifyResponse(pseudo)) { drop(view.dropped, "sig-invalid"); continue; }
    }

    const respondent = lc(dec.respondent ?? "");
    if (!respondent) { drop(view.dropped, "no-respondent"); continue; }
    let seen = seenRespondent.get(formId);
    if (!seen) { seen = new Set(); seenRespondent.set(formId, seen); } // BUGFIX: store back
    if (seen.has(respondent)) { drop(view.dropped, "duplicate-respondent"); continue; }
    seen.add(respondent);

    view.responses[formId].push({
      respondent,
      submittedAt: dec.submittedAt ?? null,
      answers: dec.answers ?? [],
      signature: dec.signature ?? null,
      hlc: blob.hlc,
    });
  }

  return view;
}

/** Convenience alias for the snapshot() hot path (core module API name). */
export const snapshot = computeState;
