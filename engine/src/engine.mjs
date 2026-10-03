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
/** The fields a creator may change with form.update - normalized the same way on
 *  publish and on update (mirror whisperbox_engine.hpp editableFields). */
export function editableFields(p) {
  return {
    title: typeof p.title === "string" ? p.title : "",
    description: typeof p.description === "string" ? p.description : "",
    expiresAt: typeof p.expiresAt === "number" ? p.expiresAt : null,
    questions: Array.isArray(p.questions) ? p.questions : [],
    whitelist: p.whitelist && typeof p.whitelist === "object" ? p.whitelist : { type: "none", value: "" },
    maxResponses: Number.isInteger(p.maxResponses) && p.maxResponses > 0 ? p.maxResponses : null,
    showResponseCount: p.showResponseCount === true,
    thankYou: typeof p.thankYou === "string" ? p.thankYou : "",
    shuffleQuestions: p.shuffleQuestions === true,
    anonymous: p.anonymous === true,   // respondents answer as a per-form identity
    // answer edits: the same (signed) respondent may replace their answer for
    // editWindowMinutes after first sending it, until the creator sends a receipt
    allowEdits: p.allowEdits === true,
    editWindowMinutes: p.allowEdits === true ? (Number.isInteger(p.editWindowMinutes) && p.editWindowMinutes > 0 ? p.editWindowMinutes : 15) : null,
  };
}

export function computeState(mergedLog, opts = {}) {
  const identity = opts.identity ? lc(opts.identity) : null;
  const verify = typeof opts.verify === "function" ? opts.verify : null;
  // opts.prefer: { formId: creatorAddress } - creators pinned by the share links this
  // device opened. Only consulted when a form id is CONTESTED (published by >1 creator).
  const prefer = opts.prefer || {};
  const alts = {}; // formId → { creator → FormView } for contending publishes (id squatting)
  const closeHlcBy = {}; // "formId|creator" → close hlc (per contender)
  const spansBy = {}; // "formId|creator" -> [{from, to|null}] closed periods (close..reopen)
  const receiptHlcBy = {}; // "formId|creator" -> {confirmationId: hlc of the first receipt} (answer-edit lock)

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
        const newView = () => ({
          id: formId,
          creator: lc(p.creator),
          publicKey: p.publicKey,
          createdAt: p.createdAt,
          ...editableFields(p),
          coOwners: [],        // [{address, sealedKey}] - may read answers + send receipts
          version: 1,          // +1 per form.update
          updatedAt: null,     // hlc.wall of the latest update
          status: "open",
          confirmations: [],
        });
        if (forms[formId]) {
          // Same form id from a DIFFERENT creator = id squatting. Every contender is folded
          // on its own; the device later picks which one it shows (own > link-pinned >
          // first) and all of them are flagged contested - clients never seal answers to a
          // contested form unless the link pins that exact creator.
          const c = lc(p.creator);
          if (c !== forms[formId].creator) {
            alts[formId] = alts[formId] || {};
            if (!alts[formId][c]) alts[formId][c] = newView();
            forms[formId].contested = true;
          }
          return;
        }
        forms[formId] = newView();
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
      case EventType.FORM_CLOSE:
      case EventType.FORM_REOPEN:
      case EventType.FORM_UPDATE:
      case EventType.FORM_COOWNER: {
        if (verify && e.sig && !verify(e)) { drop(dropped, "sig-invalid"); return; }
        const formId = lc(p.formId);
        let f = forms[formId];
        if (!f) { deferred.push(e); return; } // lenient: close/confirm may lead publish
        const coOwnerReceipt = e.type === EventType.RESPONSE_CONFIRM && (f.coOwners || []).some((c) => c.address === lc(p.author));
        if (lc(p.author) !== f.creator && !coOwnerReceipt) {
          const alt = alts[formId] && alts[formId][lc(p.author)];
          if (!alt) { drop(dropped, "not-creator"); return; }
          f = alt; // a contender's own close/confirm applies to its own copy
        }
        if (e.type === EventType.FORM_COOWNER) {
          const owner = lc(p.owner || "");
          if (!/^0x[0-9a-f]{40}$/.test(owner) || typeof p.sealedKey !== "string" || !p.sealedKey) { drop(dropped, "bad-coowner"); return; }
          f.coOwners = [...f.coOwners.filter((c) => c.address !== owner), { address: owner, sealedKey: p.sealedKey }];
          return;
        }
        if (e.type === EventType.FORM_UPDATE) {
          // log is HLC-ordered: the latest update wins; status / receipts / closes stay
          Object.assign(f, editableFields(p.form && typeof p.form === "object" ? p.form : {}));
          f.version += 1;
          f.updatedAt = e.hlc?.wall ?? null;
          return;
        }
        if (e.type === EventType.RESPONSE_CONFIRM) {
          // single receipt, or many in one event ("confirm all")
          const ids = Array.isArray(p.confirmationIds) ? p.confirmationIds : [p.confirmationId];
          const rk = formId + "|" + f.creator;
          const rh = receiptHlcBy[rk] || (receiptHlcBy[rk] = {});
          for (const cid of ids) if (typeof cid === "string" && cid && !f.confirmations.includes(cid)) { f.confirmations.push(cid); rh[cid] = e.hlc; }
          return;
        }
        // Close / re-open: the log is HLC-ordered, so the last one wins. Each closed
        // period is kept: answers sealed during ANY of them stay dropped after a re-open.
        const key = formId + "|" + f.creator;
        const spans = spansBy[key] || (spansBy[key] = []);
        const isOpen = !spans.length || spans[spans.length - 1].to !== null;
        if (e.type === EventType.FORM_CLOSE) {
          if (isOpen) spans.push({ from: e.hlc, to: null });
          f.status = "closed";
          if (f === forms[formId]) closeHlc[formId] = spans[spans.length - 1].from;
          closeHlcBy[key] = spans[spans.length - 1].from;
          if (p.expiresAt != null) f.expiresAt = p.expiresAt;
        } else { // FORM_REOPEN
          if (!isOpen) spans[spans.length - 1].to = e.hlc;
          f.status = "open";
          if (f === forms[formId]) delete closeHlc[formId];
          delete closeHlcBy[key];
        }
        return;
      }
      default:
        drop(dropped, "unknown-type");
    }
  };

  for (const e of mergedLog) applyEvent(e);

  // Contested ids: show this device's own copy, else the link-pinned creator's, else the
  // first. The log (and so every replica's set of contenders) is identical everywhere;
  // only this projection is per-device, exactly like creatorView.
  for (const formId of Object.keys(alts)) {
    const first = forms[formId];
    const all = [first, ...Object.values(alts[formId])];
    for (const f of all) f.contested = true;
    const want = (identity && all.find((f) => f.creator === identity))
      || (prefer[formId] && all.find((f) => f.creator === lc(prefer[formId])));
    if (want && want !== first) {
      forms[formId] = want;
      const ch = closeHlcBy[formId + "|" + want.creator];
      if (ch) closeHlc[formId] = ch; else delete closeHlc[formId];
    }
  }
  const receiptHlc = {}; // formId -> {confirmationId: receipt hlc} of the creator shown here
  for (const [formId, f] of Object.entries(forms)) { const r = receiptHlcBy[formId + "|" + f.creator]; if (r && Object.keys(r).length) receiptHlc[formId] = r; }
  const closedSpans = {}; // formId -> closed periods of the creator shown on this device
  for (const [formId, f] of Object.entries(forms)) {
    const sp = spansBy[formId + "|" + f.creator];
    if (sp && sp.length) closedSpans[formId] = sp.map((x) => ({ from: x.from, to: x.to }));
  }

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
    closeHlc, // formId → close event hlc of the CURRENT closed period
    closedSpans, // formId → [{from, to|null}] every closed period (creator-view drops)
    receiptHlc, // formId → {confirmationId: hlc} first receipt per answer (edit lock)
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
/** Parsed address allow-list of a form whitelist {type:"addresses", value:"0xa,0xb"}. */
export function whitelistAddresses(wl) {
  return String(wl?.value ?? "").split(/[,\s]+/).map((a) => lc(a.trim())).filter(Boolean);
}

export function creatorView(state, opts) {
  const identity = lc(opts.identity);
  const open = typeof opts.open === "function" ? opts.open : () => null;
  const verifyResponse = typeof opts.verifyResponse === "function" ? opts.verifyResponse : null;

  // opts.alsoForms: forms this identity co-owns (it holds their key) - same view
  const also = new Set((opts.alsoForms || []).map(lc));
  const mine = Object.values(state.forms).filter((f) => f.creator === identity || also.has(f.id));
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
    if (!f || (f.creator !== identity && !also.has(formId))) continue; // not mine / not co-owned

    // Closed-form drop: blob's HLC after the close event's HLC. Cross-device HLC
    // comparison is approximate (clock skew) — document as best-effort; the
    // original whisperbox had no close at all, so this is our stricter layer.
    // Sealed while the form was closed (any closed period, even if re-opened since).
    const spans = state.closedSpans?.[formId];
    if (spans && spans.length) {
      if (spans.some((s) => compareHlc(blob.hlc, s.from) >= 0 && (s.to === null || compareHlc(blob.hlc, s.to) < 0))) { drop(view.dropped, "form-closed"); continue; }
    } else if (f.status === "closed") {
      const ch = state.closeHlc?.[formId];
      if (!ch || compareHlc(blob.hlc, ch) >= 0) { drop(view.dropped, "form-closed"); continue; }
    }
    // Close-at date (expiresAt, ms): answers stamped after it don't count.
    if (f.expiresAt != null && Number(blob.hlc?.wall) > Number(f.expiresAt)) { drop(view.dropped, "expired"); continue; }

    // Inner signature: members-only forms, and forms that allow edits (an unsigned
    // "edit" could overwrite someone else's answer).
    if ((f.whitelist?.type !== "none" || f.allowEdits) && verifyResponse) {
      const pseudo = {
        v: 1, id: blob.id, type: EventType.RESPONSE_SUBMIT, hlc: blob.hlc, dev: "",
        payload: dec, pub: dec.pub ?? null, sig: dec.signature ?? null,
      };
      if (!verifyResponse(pseudo)) { drop(view.dropped, "sig-invalid"); continue; }
    }

    const respondent = lc(dec.respondent ?? "");
    if (!respondent) { drop(view.dropped, "no-respondent"); continue; }
    // Address allow-list: only listed respondents count (identity proven by the
    // inner signature above). Comma-separated, case-insensitive, whitespace-tolerant.
    if (f.whitelist?.type === "addresses" && !whitelistAddresses(f.whitelist).includes(respondent)) {
      drop(view.dropped, "not-whitelisted"); continue;
    }
    let seen = seenRespondent.get(formId);
    if (!seen) { seen = new Map(); seenRespondent.set(formId, seen); } // BUGFIX: store back
    const prev = seen.get(respondent);
    if (prev) {
      // A later response from the same respondent: an EDIT, if the form allows it, inside
      // the window after their first answer, and before the creator's receipt for it.
      if (!f.allowEdits || !prev.entry) { drop(view.dropped, "duplicate-respondent"); continue; }
      if (Number(blob.hlc?.wall) - prev.firstWall > (f.editWindowMinutes || 15) * 60000) { drop(view.dropped, "edit-too-late"); continue; }
      const rh = state.receiptHlc?.[formId]?.[prev.cid];
      if (rh && compareHlc(blob.hlc, rh) >= 0) { drop(view.dropped, "edit-after-receipt"); continue; }
      Object.assign(prev.entry, { submittedAt: dec.submittedAt ?? null, answers: dec.answers ?? [], signature: dec.signature ?? null, edits: prev.entry.edits + 1 });
      continue;
    }
    const meta = { entry: null, firstWall: Number(blob.hlc?.wall), cid: typeof dec.confirmationId === "string" ? dec.confirmationId : null };
    seen.set(respondent, meta);
    // Answer cap: the first maxResponses (HLC order - identical on every replica) count.
    if (f.maxResponses && view.responses[formId].length >= f.maxResponses) { drop(view.dropped, "over-limit"); continue; }

    const entry = {
      respondent,
      submittedAt: dec.submittedAt ?? null,
      answers: dec.answers ?? [],
      signature: dec.signature ?? null,
      // Respondent-chosen random receipt id (sealed, so the public confirmation
      // can't be linked to an address). null on pre-0.2 responses. Edits keep it.
      confirmationId: meta.cid,
      hlc: blob.hlc,
    };
    if (f.allowEdits) entry.edits = 0;   // only on forms that allow edits (keeps older vectors stable)
    meta.entry = entry;
    view.responses[formId].push(entry);
  }

  return view;
}

/** Convenience alias for the snapshot() hot path (core module API name). */
export const snapshot = computeState;
