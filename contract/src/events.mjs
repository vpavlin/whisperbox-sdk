// events.mjs — WhisperBox event contract: types, deterministic id helpers,
// canonical signature messages, and envelope constructors.
//
// Event envelope (loam-sync shape): { v:1, id, type, hlc:{wall,ctr,dev}, dev,
// payload } plus optional authenticity layer { pub, sig } (secp256k1 ECDSA low-S
// over the canonical message; see identity.mjs / P2). The engine never inspects
// payload beyond the fields named here.
//
// Wire topic: /whisperbox/1/all/proto — one shared topic for ALL events.

export const TOPIC = "/whisperbox/1/all/proto";

export const EventType = Object.freeze({
  FORM_PUBLISH: "form.publish",
  RESPONSE_SUBMIT: "response.submit",
  RESPONSE_CONFIRM: "response.confirm",
  FORM_CLOSE: "form.close",
  FORM_RESULTS: "form.results",
});

// Events only the form's creator may author (gated). Gating in P1 is by
// payload.author == form.creator; P2 adds the cryptographic layer (event sig
// must verify AND recover to payload.author).
export const CREATOR_GATED = new Set([
  EventType.RESPONSE_CONFIRM,
  EventType.FORM_CLOSE,
  EventType.FORM_RESULTS,
]);

// Open events: any participant may author. response.submit carries a respondent
// signature (verified by the creator on decrypt when whitelist != none); a bad or
// missing sig never DROPS it (qaku lesson: strict-drop silently hid redelivered
// copies of your own submission) — it just renders unverified.
export const OPEN_EVENTS = new Set([EventType.RESPONSE_SUBMIT]);

const lc = (s) => String(s).toLowerCase();

// ── Deterministic id helpers (natural domain identities) ─────────────────────
// Redelivery and re-publish are idempotent for free under union-by-id merge.
export const formPublishId = (formId) => `form:${formId}`;
export const responseSubmitId = (formId, respondent) =>
  `resp:${lc(formId)}:${lc(respondent)}`;
export const responseConfirmId = (formId, confirmationId) =>
  `confirm:${lc(formId)}:${confirmationId}`;
export const formCloseId = (formId) => `close:${lc(formId)}`;
export const formResultsId = (formId, wall) => `results:${lc(formId)}:${wall}`;

// ── Canonical signature messages (P2 signs these; secp256k1 ECDSA low-S) ─────
// Deliberately NOT whisperbox.org's locale-dependent `new Date(ts)` strings —
// explicit fields, stable across locales/timezones. The app prefix pins the
// domain (mirrors qaku's sig-v1 scheme).
export const formCreationMessage = (formId, creator, createdAt) =>
  `whisperbox-sig-v1/form-create:${lc(formId)}:${lc(creator)}:${createdAt}`;
export const responseMessage = (formId, respondent, submittedAt) =>
  `whisperbox-sig-v1/response-submit:${lc(formId)}:${lc(respondent)}:${submittedAt}`;

// ── Envelope constructors ─────────────────────────────────────────────────────
// Each returns a full Event. hlc + dev come from the local Clock (hlc.mjs).

/** payload: {id,title,description,creator,publicKey,createdAt,expiresAt?,
 *  questions:[{id,type,text,required,options?}],whitelist:{type,value},signature} */
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

/** The WHOLE answers object is ECIES-sealed to form.publicKey → encryptedPayload.
 *  Envelope metadata (respondent, submittedAt) is plaintext — faithful to
 *  whisperbox.org and required for deterministic ids + creator-side receipts. */
export function evResponseSubmit({ hlc, dev, formId, respondent, submittedAt, encryptedPayload, signature }) {
  return {
    v: 1,
    id: responseSubmitId(formId, respondent),
    type: EventType.RESPONSE_SUBMIT,
    hlc,
    dev,
    payload: {
      formId: lc(formId),
      respondent: lc(respondent),
      submittedAt,
      encryptedPayload,
      signature: signature ?? null,
    },
  };
}

/** Plaintext receipt echo. confirmationId is chosen by the creator (e.g. a hash
 *  over formId+respondent) so re-confirmation is idempotent. */
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

/** Sticky: once folded, the form rejects new responses (fold-level semantics). */
export function evFormClose({ hlc, dev, formId, expiresAt, author }) {
  return {
    v: 1,
    id: formCloseId(formId),
    type: EventType.FORM_CLOSE,
    hlc,
    dev,
    payload: { formId: lc(formId), expiresAt: expiresAt ?? null, author: lc(author) },
  };
}

/** Optional aggregates. Superseding (LWW by full HLC); id embeds hlc.wall so
 *  successive results are distinct events. */
export function evFormResults({ hlc, dev, formId, resultsJson, author }) {
  return {
    v: 1,
    id: formResultsId(formId, hlc.wall),
    type: EventType.FORM_RESULTS,
    hlc,
    dev,
    payload: { formId: lc(formId), resultsJson, author: lc(author) },
  };
}
