// events.mjs — WhisperBox event contract: types, deterministic id helpers, envelope
// constructors.
//
// Event envelope (loam-sync shape): { v:1, id, type, hlc:{wall,ctr,dev}, dev,
// payload } plus optional authenticity layer { pub, sig } (secp256k1 ECDSA low-S
// over the canonical message; see crypto.mjs). The engine never inspects payload
// beyond the fields named here.
//
// Wire topic: /whisperbox/1/all/proto — one shared topic for ALL events.
//
// ── PRIVACY GROUND TRUTH (whisperbox.org src/lib/waku.ts) ────────────────────────
// The ENTIRE response (formId, respondent, submittedAt, answers, signature) is
// ECIES-sealed to the creator's pubkey; the wire event carries ONLY the sealed blob.
// No respondent identity, no form association, no content appears in plaintext.
// Consequently:
//   * response.submit events are OPAQUE to non-creators (and to the fold itself);
//     they are content-addressed: id = resp:<sha256(encryptedPayload)>.
//   * formId/respondent/dedup/closed-form/whitelist checks happen in the CREATOR
//     VIEW (engine.mjs creatorView), after decryption — deterministic per replica.
//   * response.submit must NOT carry an event-level pub/sig: that would leak the
//     respondent's pubkey (→ address) on the wire. The inner signature (over the
//     decrypted content, verified by the creator when whitelist != none) stays sealed.
//   * No form.results event: results are computed locally by the creator from
//     decrypted responses (original whisperbox: client-side CSV export). Publishing
//     aggregates to the topic would leak answer content.

// Portable (Node, browsers, React Native): @noble hashing, no Node built-ins.
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

export const TOPIC = "/whisperbox/1/all/proto";

export const EventType = Object.freeze({
  FORM_PUBLISH: "form.publish",
  RESPONSE_SUBMIT: "response.submit",
  RESPONSE_CONFIRM: "response.confirm",
  FORM_CLOSE: "form.close",
  FORM_REOPEN: "form.reopen",   // 0.3.2+: creator re-opens a closed form
});

// Events only the form's creator may author (gated). Gating: payload.author ==
// form.creator, and (P2+) the event sig must verify AND recover to payload.author.
export const CREATOR_GATED = new Set([
  EventType.RESPONSE_CONFIRM,
  EventType.FORM_CLOSE,
  EventType.FORM_REOPEN,
]);

// Open events: any participant may author; no event-level signature allowed.
export const OPEN_EVENTS = new Set([EventType.RESPONSE_SUBMIT]);

const lc = (s) => String(s).toLowerCase();

// ── Deterministic id helpers ─────────────────────────────────────────────────────
// Redelivery and re-publish are idempotent for free under union-by-id merge.
export const formPublishId = (formId) => `form:${formId}`;
/** Content-addressed: identical sealed blob → identical id (dedup is free); a
 *  resubmission with different answers is a DIFFERENT event (creator view keeps
 *  the earliest-HLC one per respondent). */
export const responseSubmitId = (encryptedPayload) =>
  `resp:${bytesToHex(sha256(utf8ToBytes(String(encryptedPayload))))}`;
export const responseConfirmId = (formId, confirmationId) =>
  `confirm:${lc(formId)}:${confirmationId}`;
// Close/re-open can now happen repeatedly, so each one needs its own id (a repeated
// close:<formId> would be deduplicated away). The bare form is kept for old events.
export const formCloseId = (formId, nonce) => (nonce ? `close:${lc(formId)}:${nonce}` : `close:${lc(formId)}`);
export const formReopenId = (formId, nonce) => `reopen:${lc(formId)}:${nonce}`;
/** One receipt event for many responses ("confirm all"): content-addressed by the ids. */
export const responseConfirmBatchId = (formId, confirmationIds) =>
  `confirm:${lc(formId)}:b:${bytesToHex(sha256(utf8ToBytes([...confirmationIds].sort().join(",")))).slice(0, 16)}`;

// ── Envelope constructors ────────────────────────────────────────────────────────
// Each returns a full Event. hlc + dev come from the local Clock (hlc.mjs).

/** payload: {id,title,description,creator,publicKey,createdAt,expiresAt?,
 *  questions:[{id,type,text,required,options?}],whitelist:{type,value},signature}
 *  Gated: signed by the creator (pub/sig envelope fields; signature field inside
 *  payload is legacy/original compatibility — the envelope sig is authoritative). */
export function evFormPublish({ hlc, dev, form }) {
  return {
    v: 1,
    id: formPublishId(form.id),
    type: EventType.FORM_PUBLISH,
    hlc,
    dev,
    payload: { ...form },
  };
}

/** OPAQUE sealed response. encryptedPayload = hex of the ECIES blob (crypto.mjs
 *  sealToCreator) over the full response JSON:
 *    { formId, respondent, submittedAt, answers:[{questionId,value}], signature }
 *  No other fields on the wire — see privacy ground truth above. */
export function evResponseSubmit({ hlc, dev, encryptedPayload }) {
  return {
    v: 1,
    id: responseSubmitId(encryptedPayload),
    type: EventType.RESPONSE_SUBMIT,
    hlc,
    dev,
    payload: { encryptedPayload },
  };
}

/** Plaintext receipt echo (only formId + confirmationId are public — the original
 *  whisperbox confirmation_response). confirmationId is chosen by the creator
 *  (e.g. a hash over formId+respondent) so re-confirmation is idempotent. */
export function evResponseConfirm({ hlc, dev, formId, confirmationId, author }) {
  return {
    v: 1,
    id: responseConfirmId(formId, confirmationId),
    type: EventType.RESPONSE_CONFIRM,
    hlc,
    dev,
    payload: { formId: lc(formId), confirmationId, author: lc(author) },
  };
}

/** Sticky: once folded, the form is closed (creator view drops later-decrypted
 *  responses; feed removes it). */
export function evFormClose({ hlc, dev, formId, expiresAt, author, nonce }) {
  return {
    v: 1,
    id: formCloseId(formId, nonce),
    type: EventType.FORM_CLOSE,
    hlc,
    dev,
    payload: { formId: lc(formId), expiresAt: expiresAt ?? null, author: lc(author) },
  };
}

/** Re-open a closed form (creator-gated). Answers sealed while it was closed stay dropped. */
export function evFormReopen({ hlc, dev, formId, author, nonce }) {
  return {
    v: 1,
    id: formReopenId(formId, nonce),
    type: EventType.FORM_REOPEN,
    hlc,
    dev,
    payload: { formId: lc(formId), author: lc(author) },
  };
}

/** Receipts for many responses in one event (payload.confirmationIds). */
export function evResponseConfirmBatch({ hlc, dev, formId, confirmationIds, author }) {
  return {
    v: 1,
    id: responseConfirmBatchId(formId, confirmationIds),
    type: EventType.RESPONSE_CONFIRM,
    hlc,
    dev,
    payload: { formId: lc(formId), confirmationIds: [...confirmationIds], author: lc(author) },
  };
}
