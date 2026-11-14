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
  FORM_UPDATE: "form.update",   // 0.3.6+: creator edits a published form (latest wins)
  FORM_COOWNER: "form.coowner", // 0.3.8+: creator shares the form's key with a co-owner
  RESPONSE_REPLY: "response.reply", // 0.3.9+: private reply to one answer (sealed to its reply key)
  // 1.1.3+ (ADR 0026): a BLINDED receipt - unsigned, no form id, no author; only tags
  // sha256("wb-receipt-v2|" + formId + "|" + confirmationId). Only the respondent and the form's
  // owners know the (sealed) confirmation id, so only they can make or recognise a tag.
  RESPONSE_RECEIPT: "response.receipt",
});

// Events only the form's creator may author (gated). Gating: payload.author ==
// form.creator, and (P2+) the event sig must verify AND recover to payload.author.
export const CREATOR_GATED = new Set([
  EventType.RESPONSE_CONFIRM,
  EventType.FORM_CLOSE,
  EventType.FORM_REOPEN,
  EventType.FORM_UPDATE,
  EventType.FORM_COOWNER,
  EventType.RESPONSE_REPLY,
]);

// Open events: any participant may author; no event-level signature allowed.
export const OPEN_EVENTS = new Set([EventType.RESPONSE_SUBMIT, EventType.RESPONSE_RECEIPT]);

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
export const formUpdateId = (formId, nonce) => `update:${lc(formId)}:${nonce}`;
export const formCoOwnerId = (formId, owner) => `coowner:${lc(formId)}:${lc(owner)}`;
export const responseReplyId = (formId, to, nonce) => `reply:${lc(formId)}:${to}:${nonce}`;
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

/** Edit a published form (creator-gated): `form` carries the full new definition
 *  (title, description, questions, whitelist, settings). id / creator / key never change. */
export function evFormUpdate({ hlc, dev, formId, author, form, nonce }) {
  return {
    v: 1,
    id: formUpdateId(formId, nonce),
    type: EventType.FORM_UPDATE,
    hlc,
    dev,
    payload: { formId: lc(formId), author: lc(author), form: { ...form } },
  };
}

/** Share the form's key with a co-owner (creator-gated): sealedKey = ECIES(co-owner pub,
 *  form private key hex). Co-owners can read answers and send receipts; nothing else. */
export function evFormCoOwner({ hlc, dev, formId, author, owner, sealedKey }) {
  return {
    v: 1,
    id: formCoOwnerId(formId, owner),
    type: EventType.FORM_COOWNER,
    hlc,
    dev,
    payload: { formId: lc(formId), author: lc(author), owner: lc(owner), sealedKey },
  };
}

/** Private reply to one answer (creator or co-owner): `to` = the answer's receipt id,
 *  `sealed` = ECIES(the answer's one-off reply key, JSON {message, score?, outOf?}). */
export function evResponseReply({ hlc, dev, formId, author, to, sealed, nonce }) {
  return {
    v: 1,
    id: responseReplyId(formId, to, nonce),
    type: EventType.RESPONSE_REPLY,
    hlc,
    dev,
    payload: { formId: lc(formId), author: lc(author), to, sealed },
  };
}

// ── Blinded receipts and reply addresses (ADR 0026) ─────────────────────────────
/** Tags in one response.receipt event, at most. */
export const MAX_RECEIPT_TAGS = 100;
const tagMemo = new Map();
const tagOf = (kind, formId, cid) => {
  const k = kind + "|" + lc(formId) + "|" + cid;
  let t = tagMemo.get(k);
  if (t === undefined) {
    t = bytesToHex(sha256(utf8ToBytes(k)));
    if (tagMemo.size >= 50000) tagMemo.clear();
    tagMemo.set(k, t);
  }
  return t;
};
/** The public tag of a receipt for one answer: nobody without the sealed confirmation id can link it. */
export const receiptTag = (formId, confirmationId) => tagOf("wb-receipt-v2", formId, confirmationId);
/** The public address of a reply to one answer (response.reply payload.to). */
export const replyTag = (formId, confirmationId) => tagOf("wb-reply-v2", formId, confirmationId);
/** A receipt event's id: content-addressed by its (sorted) tags. */
export const responseReceiptId = (tags) => `rcpt:${bytesToHex(sha256(utf8ToBytes([...tags].sort().join(","))))}`;
export const isReceiptTag = (t) => typeof t === "string" && /^[0-9a-f]{64}$/.test(t);
