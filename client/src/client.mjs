// whisperbox client — the WhisperBox protocol for non-C++ platforms (the Android app).
// A behavioural mirror of whisperbox_core_impl.cpp (desktop/hub): same events, same
// signatures, same admission gates, same sealing, same snapshot shape, same catch-up.
// Transport- and storage-agnostic (both injected), so it runs under Node for the
// cross-implementation tests against the real C++ core, and under React Native/Hermes.
//
// Built from the shared reference packages — nothing protocol-relevant is re-implemented:
//   contract/merge.mjs (min-HLC, signer-keyed dedup), contract/hlc.mjs (Clock),
//   contract/events.mjs (deterministic ids), contract/crypto-portable.mjs (identity,
//   signing, ECIES), engine/engine.mjs (fold + creator view), and loam-sync's RBSR
//   catch-up (fp/ids/need) over event keys.
import { mergeOne, mergeWhisperbox, eventKey } from "../../contract/src/merge.mjs";
import { Clock } from "../../contract/src/hlc.mjs";
import { TOPIC, EventType, formPublishId, responseSubmitId, responseConfirmId, formCloseId, formReopenId, responseConfirmBatchId } from "../../contract/src/events.mjs";
import * as C from "../../contract/src/crypto-portable.mjs";
import { validateAnswers, emptyAnswer as emptyAnswerOf } from "../../contract/src/answers.mjs";
import { computeState, creatorView } from "../../engine/src/engine.mjs";
import { buildInitial, respond } from "../../../third_party/loam-sync/dist/catchup.js";

export { TOPIC };
const lc = (s) => String(s ?? "").toLowerCase();
const isHexAddr = (s) => /^0x[0-9a-f]{40}$/.test(s);
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64decode(s) {
  const out = []; let val = 0, bits = -8;
  for (const ch of s) {
    if (ch === "=") break;
    const v = B64.indexOf(ch); if (v < 0) continue;
    val = (val << 6) | v; bits += 6;
    if (bits >= 0) { out.push((val >> bits) & 0xff); bits -= 8; }
  }
  return Uint8Array.from(out);
}
const confirmIdLegacy = (formId, respondent) => C.sha256Hex(lc(formId) + "|" + lc(respondent)).slice(0, 16);
function confirmIdOf(r, formId) {
  return typeof r.confirmationId === "string" && r.confirmationId ? r.confirmationId : confirmIdLegacy(formId, r.respondent);
}
function emptyAnswer(v) {
  return v === null || v === undefined || (typeof v === "string" && v.trim() === "") || (Array.isArray(v) && v.length === 0);
}
function whitelistAddresses(wl) {
  return String(wl?.value ?? "").split(/[,\s]+/).map((a) => lc(a.trim())).filter(Boolean);
}

/** Parse a share link or bare id → { formId, by } (by = creator pinned by the link). */
export function parseLink(input) {
  const t = String(input || "").trim();
  if (!t.startsWith("whisperbox://")) return t ? { formId: lc(t), by: null } : null;
  const q = t.slice(t.indexOf("?") + 1);
  const params = Object.fromEntries(q.split("&").map((kv) => { const i = kv.indexOf("="); return i < 0 ? [kv, ""] : [kv.slice(0, i), decodeURIComponent(kv.slice(i + 1))]; }));
  if (!params.id) return null;
  const by = lc(params.by || "");
  return { formId: lc(params.id), by: isHexAddr(by) ? by : null };
}

export class WhisperboxClient {
  /**
   * @param {object} o
   * @param {{get(k:string):Promise<string|null>, set(k:string,v:string):Promise<void>}} o.store       durable app data
   * @param {{get(k:string):Promise<string|null>, set(k:string,v:string):Promise<void>}} [o.secrets] identity key (defaults to store)
   * @param {(bytes:Uint8Array)=>Promise<void>} o.send   publish one envelope on TOPIC
   * @param {()=>number} [o.now]
   */
  constructor(o) {
    this.store = o.store; this.secrets = o.secrets || o.store; this.sendRaw = o.send; this.now = o.now || (() => Date.now());
    this.log = []; this.watched = new Set(); this.pins = {}; this.mySubs = {}; // formId → my receipt id ("" = legacy)
    this.identity = null; this.deviceId = ""; this.clock = null; this.cardKeys = new Map();
    this.hidden = new Set(); this.myAnswers = {};
    this.drafts = {}; this.answerDrafts = {}; this.autoReceipts = new Set(); this.lastHousekeep = 0;
    this.seen = {};   // formId -> responses seen ("N new"); first sight = all seen
    this.nodeReady = false; this.listeners = new Set();
    this.diag = { rxRaw: 0, rxNew: 0, rxDup: 0, txTotal: 0, txErr: 0, admDropSig: 0, admDropType: 0, rbsrRx: 0, legacyReseeds: 0 };
    this.syncTries = 0; this.lastSyncAt = 0; this.lastReserveAt = 0; this.unsent = new Set();
  }

  // ── lifecycle ──────────────────────────────────────────────────────────────────
  async init() {
    const priv = await this.secrets.get("wb-identity");
    this.identity = (priv && C.identityFromPriv(priv)) || null;
    if (!this.identity) { this.identity = C.generateIdentity(); await this.secrets.set("wb-identity", C.toHex(this.identity.priv)); }
    let dev = (await this.store.get("wb-device")) || "";
    if (!dev || dev === "whisperbox-core") { dev = "wb-" + C.randomHex(6); await this.store.set("wb-device", dev); }
    this.deviceId = dev;
    this.clock = new Clock(dev);
    const parse = (s, d) => { try { return s ? JSON.parse(s) : d; } catch { return d; } };
    // Same repair as the core: drop unsigned form.publish placeholders, re-sort.
    const raw = parse(await this.store.get("wb-log"), []);
    this.log = mergeWhisperbox((Array.isArray(raw) ? raw : []).filter((e) => e && e.id && !(e.type === EventType.FORM_PUBLISH && !e.sig)));
    for (const e of this.log) this.clock.receive(e.hlc);
    this.watched = new Set(parse(await this.store.get("wb-watched"), []));
    this.pins = parse(await this.store.get("wb-pins"), {});
    this.mySubs = parse(await this.store.get("wb-mysubs"), {});
    this.hidden = new Set(parse(await this.store.get("wb-hidden"), []));
    this.myAnswers = parse(await this.store.get("wb-myanswers"), {});   // formId -> {answers, submittedAt}
    const dr = parse(await this.store.get("wb-drafts"), {});
    this.drafts = dr.forms || {}; this.answerDrafts = dr.answers || {}; this.autoReceipts = new Set(dr.autoReceipts || []);
    this.seen = parse(await this.store.get("wb-seen"), {});
    // Form keys that came from a Keycard (not derivable from the identity): one secret per
    // form ("wb-fk-<formId>"), with the list of ids (not secret) in the plain store.
    this.cardKeys = new Map();
    for (const fid of parse(await this.store.get("wb-fk-index"), [])) {
      const k = C.identityFromPriv((await this.secrets.get("wb-fk-" + fid)) || "");
      if (k) this.cardKeys.set(fid, k);
    }
    this.emit();
  }
  /** Call when the transport is up (and again after any reconnect). */
  onConnected() {
    this.nodeReady = true; this.syncTries = 0; this.lastSyncAt = 0;
    this.requestSync(); this.catchupRound(); this.emit();
  }
  onDisconnected() { this.nodeReady = false; this.emit(); }
  /** Drive from a ~1s timer: catch-up at 3s/10s/25s after connect, then every 60s;
   *  retries sends that failed while offline. */
  tick() {
    try { this._tick(); } catch (e) { this.lastError = String(e?.message || e); }
  }
  _tick() {
    if (!this.nodeReady) return;
    const delays = [3000, 10000, 25000];
    const delay = this.syncTries >= 1 && this.syncTries <= 3 ? delays[this.syncTries - 1] : 60000;
    if (this.now() - this.lastSyncAt >= delay) {
      if (this.syncTries <= 3) this.requestSync(); else { this.lastSyncAt = this.now(); this.syncTries++; }
      this.catchupRound();
    }
    if (this.unsent.size) for (const id of [...this.unsent]) { const e = this.log.find((x) => eventKey(x) === id); this.unsent.delete(id); if (e) this.broadcast(e); }
    if (this.now() - this.lastHousekeep >= 5000) { this.lastHousekeep = this.now(); this.housekeeping(); }
  }
  /** Publish due scheduled drafts; close my forms at their answer cap / end date; send
   *  receipts for forms with automatic receipts. Same rules as the desktop core. */
  housekeeping() {
    for (const d of Object.values(this.drafts)) if (d.publishAt != null && d.publishAt <= this.now()) this.publishDraft(d.id);
    const st = this.state();
    const mine = Object.values(st.forms).filter((f) => f.creator === this.identity.address);
    if (!mine.length) return;
    const cv = this.decrypt(st);
    for (const f of mine) {
      const got = (cv.responses[f.id] || []);
      if (f.status === "open" && ((f.maxResponses && got.length >= f.maxResponses) || (f.expiresAt != null && this.now() > f.expiresAt))) this.closeForm(f.id);
      if (this.autoReceipts.has(f.id) && got.some((r) => !(f.confirmations || []).includes(confirmIdOf(r, f.id)))) this.confirmAll(f.id);
    }
  }
  subscribe(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }
  emit() { for (const fn of this.listeners) { try { fn(); } catch { /* listener */ } } }

  // ── wire ───────────────────────────────────────────────────────────────────────
  async sendEnvelope(obj, key) {
    try { await this.sendRaw(C.utf8Encode(JSON.stringify(obj))); this.diag.txTotal++; return true; }
    catch { this.diag.txErr++; if (key) this.unsent.add(key); return false; }
  }
  broadcast(e) { return this.sendEnvelope({ v: 1, type: "EVENT", event: e }, eventKey(e)); }
  requestSync() {
    this.sendEnvelope({ v: 1, type: "SYNC_REQ", from: this.deviceId, rbsr: true });
    this.lastSyncAt = this.now(); this.syncTries++;
  }
  catchupRound() {
    if (!this.nodeReady) return;
    this.sendEnvelope(buildInitial(this.log.map((e) => ({ id: eventKey(e) })), this.deviceId));
  }

  /** Feed every decode candidate of ONE received message (loam-transport hands these
   *  over). Returns true when one of them was a WhisperBox envelope. */
  ingest(candidates) {
    // Never throw: this runs inside native event callbacks, where an escaping exception
    // would take the app down. A bad message is counted and skipped.
    try { return this._ingest(candidates); }
    catch (e) { this.diag.rxErr = (this.diag.rxErr || 0) + 1; this.lastError = String(e?.message || e); return false; }
  }
  _ingest(candidates) {
    this.diag.rxRaw++;
    for (const cand of candidates || []) {
      let text;
      try { text = C.utf8Decode(cand).trim(); } catch { continue; }
      for (const t of [text, (() => { try { return C.utf8Decode(b64decode(text)).trim(); } catch { return ""; } })()]) {
        if (!t || t[0] !== "{") continue;
        let env; try { env = JSON.parse(t); } catch { continue; }
        if (this.handle(env)) return true;
      }
    }
    return false;
  }
  handle(env) {
    if (!env || typeof env !== "object") return false;
    if (env.v === 2 && (env.t === "fp" || env.t === "ids" || env.t === "need")) {
      const byKey = new Map(this.log.map((e) => [eventKey(e), e]));
      const step = respond([...byKey.keys()].map((id) => ({ id })), env, this.deviceId);
      for (const r of step.replies) this.sendEnvelope(r);
      for (const s of step.serve) { const e = byKey.get(s.id); if (e) this.broadcast(e); }
      this.diag.rbsrRx++;
      return true;
    }
    if (env.type === "SYNC_REQ") {
      if (env.rbsr) return true; // RBSR peers reconcile the exact delta instead
      if (env.from !== this.deviceId && this.now() - this.lastReserveAt >= 3000) {
        this.lastReserveAt = this.now(); this.diag.legacyReseeds++;
        for (const e of this.log) this.broadcast(e);
      }
      return true;
    }
    if (env.type === "EVENT" && env.event && typeof env.event === "object") {
      const e = env.event;
      if (typeof e.id !== "string" || !e.hlc || typeof e.hlc !== "object" || !e.payload || typeof e.payload !== "object") { this.diag.admDropType++; return true; }
      if (!this.admit(e)) return true;
      if (mergeOne(this.log, e)) { this.diag.rxNew++; this.clock.receive(e.hlc); this.saveLog(); this.emit(); }
      else this.diag.rxDup++;
      return true;
    }
    return false;
  }
  // Admission gates (mirror WhisperboxCoreImpl::admitEvent).
  admit(e) {
    if (e.type === EventType.FORM_PUBLISH || e.type === EventType.RESPONSE_CONFIRM || e.type === EventType.FORM_CLOSE || e.type === EventType.FORM_REOPEN) {
      if (!C.verifyEvent(e)) { this.diag.admDropSig++; return false; }
      return true;
    }
    if (e.type === EventType.RESPONSE_SUBMIT) {
      if (e.pub) { this.diag.admDropSig++; return false; } // a signature here would leak the respondent
      if (!e.payload || typeof e.payload.encryptedPayload !== "string") { this.diag.admDropType++; return false; }
      return true;
    }
    this.diag.admDropType++;
    return false;
  }

  // ── persistence ────────────────────────────────────────────────────────────────
  saveLog() { this.store.set("wb-log", JSON.stringify(this.log)).catch?.(() => {}); }
  saveMeta() {
    this.store.set("wb-watched", JSON.stringify([...this.watched]));
    this.store.set("wb-pins", JSON.stringify(this.pins));
    this.store.set("wb-mysubs", JSON.stringify(this.mySubs));
    this.store.set("wb-hidden", JSON.stringify([...this.hidden]));
    this.store.set("wb-myanswers", JSON.stringify(this.myAnswers));
  }
  /** Mark every response of a form as seen (the creator opened it). */
  markSeen(formId) {
    formId = lc(formId);
    const n = (this.decrypt(this.state()).responses[formId] || []).length;
    if (this.seen[formId] !== n) { this.seen[formId] = n; this.store.set("wb-seen", JSON.stringify(this.seen)); this.emit(); }
    return { ok: true, seen: n };
  }
  saveDrafts() {
    return this.store.set("wb-drafts", JSON.stringify({ forms: this.drafts, answers: this.answerDrafts, autoReceipts: [...this.autoReceipts] }));
  }
  // ── drafts (local) + scheduled publishing ──────────────────────────────────────
  /** d = {id?, def, publishAt?(ms)} -> {ok, draftId}. Never leaves this device. */
  saveDraft(d) {
    if (!d || typeof d.def !== "object") return { ok: false, error: "draft needs a def object" };
    const id = d.id || "draft-" + C.randomHex(4);
    this.drafts[id] = { id, def: d.def, updatedAt: this.now(), publishAt: Number.isFinite(d.publishAt) ? d.publishAt : null };
    this.saveDrafts(); this.emit();
    return { ok: true, draftId: id };
  }
  deleteDraft(id) { delete this.drafts[id]; this.saveDrafts(); this.emit(); return { ok: true }; }
  publishDraft(id) {
    const d = this.drafts[id];
    if (!d) return { ok: false, error: "unknown draft" };
    const r = this.createForm(d.def);
    if (r.ok) { delete this.drafts[id]; this.saveDrafts(); this.emit(); }
    return r;
  }
  /** Half-filled answers for a form (restored when it is opened again); [] clears. */
  saveAnswerDraft(formId, answers) {
    formId = lc(formId);
    if (!Array.isArray(answers) || !answers.length) delete this.answerDrafts[formId]; else this.answerDrafts[formId] = answers;
    this.saveDrafts();
    return { ok: true };
  }
  /** Hide from my lists (local only; nothing is deleted, unhideForm brings it back). */
  hideForm(formId) { formId = lc(formId); if (!formId) return { ok: false, error: "formId required" }; this.hidden.add(formId); this.saveMeta(); this.emit(); return { ok: true, formId }; }
  unhideForm(formId) { formId = lc(formId); this.hidden.delete(formId); this.saveMeta(); this.emit(); return { ok: true, formId }; }

  // ── authoring ──────────────────────────────────────────────────────────────────
  buildEvent(type, id, payload, sign) {
    const e = { v: 1, id, type, hlc: this.clock.send(this.now()), dev: this.deviceId, payload };
    return sign ? { ...e, ...C.signEvent(this.identity, e) } : e;
  }
  adopt(e) { if (mergeOne(this.log, e)) { this.clock.receive(e.hlc); this.saveLog(); } this.broadcast(e); this.emit(); }
  state() { return computeState(this.log, { identity: this.identity.address, prefer: this.pins }); }

  newFormId() { return "form-" + C.randomHex(4); }
  /** Store a form key that did not come from the identity (exported from a Keycard). Saved
   *  BEFORE the form is published, so a form is never out there without its key here. */
  async addFormKey(formId, privHex) {
    const fid = lc(formId);
    const k = C.identityFromPriv(privHex || "");
    if (!fid || !k) return { ok: false, error: "invalid form key" };
    const f = this.state().forms[fid];
    if (f && f.publicKey && f.publicKey !== k.pubHex) return { ok: false, error: "this key does not belong to that form (different Keycard?)" };
    await this.secrets.set("wb-fk-" + fid, C.toHex(k.priv));
    this.cardKeys.set(fid, k);
    await this.store.set("wb-fk-index", JSON.stringify([...this.cardKeys.keys()]));
    this.emit();
    return { ok: true, pubHex: k.pubHex };
  }
  /** My forms whose answers I cannot open on this device (e.g. Keycard forms after a reinstall). */
  formsMissingKeys(st = this.state()) {
    const keys = this.formKeys(st);
    return Object.values(st.forms).filter((f) => f.creator === this.identity.address && f.publicKey && !keys.has(f.publicKey)).map((f) => f.id);
  }

  /** opts.publicKey: seal to a key stored with addFormKey (Keycard) instead of the derived one. */
  createForm(def, opts = {}) {
    if (!def || typeof def !== "object") return { ok: false, error: "def must be an object" };
    const formId = lc(def.id) || this.newFormId();
    let publicKey = C.deriveFormKey(this.identity, formId).pubHex;
    if (opts.publicKey) {
      const ck = this.cardKeys.get(formId);
      if (!ck || ck.pubHex !== opts.publicKey) return { ok: false, error: "form key not stored on this device - not publishing a form nobody could read" };
      publicKey = ck.pubHex;
    }
    const p = {
      id: formId, title: def.title || "", description: def.description || "",
      // Sealing key = this form's OWN key: derived from the identity, or exported from a Keycard.
      creator: this.identity.address, publicKey, createdAt: this.now(),
      expiresAt: def.expiresAt ?? null, questions: Array.isArray(def.questions) ? def.questions : [],
      whitelist: def.whitelist || { type: "none", value: "" },
      ...(Number.isInteger(def.maxResponses) && def.maxResponses > 0 ? { maxResponses: def.maxResponses } : {}),
      ...(def.showResponseCount === true ? { showResponseCount: true } : {}),
      ...(typeof def.thankYou === "string" && def.thankYou ? { thankYou: def.thankYou } : {}),
      ...(def.shuffleQuestions === true ? { shuffleQuestions: true } : {}),
      ...(def.allowEdits === true ? { allowEdits: true, editWindowMinutes: Number.isInteger(def.editWindowMinutes) && def.editWindowMinutes > 0 ? def.editWindowMinutes : 15 } : {}),
    };
    const e = this.buildEvent(EventType.FORM_PUBLISH, formPublishId(formId), p, true);
    this.adopt(e);
    return { ok: true, formId };
  }
  closeForm(formId) {
    formId = lc(formId);
    const f = this.state().forms[formId];
    if (!f) return { ok: false, error: "unknown form" };
    if (f.creator !== this.identity.address) return { ok: false, error: "not the creator" };
    this.adopt(this.buildEvent(EventType.FORM_CLOSE, formCloseId(formId, C.randomHex(6)), { formId, expiresAt: null, author: this.identity.address }, true));
    return { ok: true };
  }
  /** Re-open a closed form; answers sealed while it was closed stay dropped. */
  reopenForm(formId) {
    formId = lc(formId);
    const f = this.state().forms[formId];
    if (!f) return { ok: false, error: "unknown form" };
    if (f.creator !== this.identity.address) return { ok: false, error: "not the creator" };
    if (f.status === "open") return { ok: false, error: "form is already open" };
    if (f.expiresAt != null && this.now() > f.expiresAt) return { ok: false, error: "its end date has passed - duplicate it as a new form" };
    if (f.maxResponses && (this.decrypt(this.state()).responses[formId] || []).length >= f.maxResponses) return { ok: false, error: "it reached its answer limit - duplicate it as a new form" };
    this.adopt(this.buildEvent(EventType.FORM_REOPEN, formReopenId(formId, C.randomHex(6)), { formId, author: this.identity.address }, true));
    return { ok: true };
  }
  /** Receipts for every unconfirmed response, 100 per event. */
  confirmAll(formId) {
    formId = lc(formId);
    const st = this.state();
    const f = st.forms[formId];
    if (!f) return { ok: false, error: "unknown form" };
    if (f.creator !== this.identity.address) return { ok: false, error: "not the creator" };
    const todo = (this.decrypt(st).responses[formId] || []).map((r) => confirmIdOf(r, formId)).filter((c) => c && !(f.confirmations || []).includes(c));
    let events = 0;
    for (let i = 0; i < todo.length; i += 100) {
      const ids = todo.slice(i, i + 100);
      this.adopt(this.buildEvent(EventType.RESPONSE_CONFIRM, responseConfirmBatchId(formId, ids), { formId, confirmationIds: ids, author: this.identity.address }, true));
      events++;
    }
    return { ok: true, confirmed: todo.length, events };
  }
  setAutoReceipts(formId, on) {
    formId = lc(formId);
    if (on) this.autoReceipts.add(formId); else this.autoReceipts.delete(formId);
    this.saveDrafts(); this.emit();
    if (on) this.confirmAll(formId);
    return { ok: true, autoReceipts: !!on };
  }
  confirmResponse(formId, respondent) {
    formId = lc(formId); respondent = lc(respondent);
    const st = this.state();
    const f = st.forms[formId];
    if (!f) return { ok: false, error: "unknown form" };
    if (f.creator !== this.identity.address) return { ok: false, error: "not the creator" };
    const r = (this.decrypt(st).responses[formId] || []).find((x) => lc(x.respondent) === respondent);
    if (!r) return { ok: false, error: "no decrypted response from that respondent" };
    const cid = confirmIdOf(r, formId);
    this.adopt(this.buildEvent(EventType.RESPONSE_CONFIRM, responseConfirmId(formId, cid), { formId, confirmationId: cid, author: this.identity.address }, true));
    return { ok: true, confirmationId: cid };
  }
  submitResponse(formId, answers) {
    formId = lc(formId);
    if (!Array.isArray(answers)) return { ok: false, error: "answers must be an array of {questionId,value}" };
    const f = this.state().forms[formId];
    if (!f) return { ok: false, error: "unknown form" };
    if (f.status !== "open") return { ok: false, error: "form is closed" };
    if (f.expiresAt != null && this.now() > f.expiresAt) return { ok: false, error: "this form closed at its end date" };
    // Answer edits (same rule as the creator's view): within the window after the FIRST
    // answer, before the creator's receipt; reuses the receipt id; always signed.
    let isEdit = false, firstAt = 0;
    if (formId in this.mySubs) {
      if (!f.allowEdits) return { ok: false, error: "you already answered this form" };
      firstAt = this.myAnswers[formId]?.firstSubmittedAt ?? this.myAnswers[formId]?.submittedAt ?? 0;
      const cid0 = this.mySubs[formId];
      if (cid0 && (f.confirmations || []).includes(cid0)) return { ok: false, error: "the creator already sent you a receipt - your answer is final" };
      if (!firstAt || this.now() - firstAt > (f.editWindowMinutes || 15) * 60000) return { ok: false, error: "the time to edit your answer is over" };
      isEdit = true;
    }
    if (!f.publicKey) return { ok: false, error: "form not synced yet - try again in a moment" };
    const pin = this.pins[formId] || "";
    if (pin && pin !== f.creator) return { ok: false, error: "this form's creator doesn't match the link you opened - refusing to send answers" };
    if (f.contested && pin !== f.creator) return { ok: false, error: "two different people published a form with this id - open it from the creator's link to answer" };
    const wl = f.whitelist?.type || "none";
    if (wl === "addresses" && !whitelistAddresses(f.whitelist).includes(this.identity.address)) return { ok: false, error: "this form only accepts listed addresses" };
    if (wl !== "none" && wl !== "addresses") return { ok: false, error: `whitelist type '${wl}' is not supported` };
    const byQ = new Map(answers.map((a) => [a?.questionId, a?.value]));
    const bad = validateAnswers(f.questions, answers);   // types, ranges, required (same rules as the core)
    if (bad) return { ok: false, error: bad.error };
    const submittedAt = this.now();
    const confirmationId = isEdit && this.mySubs[formId] ? this.mySubs[formId] : C.randomHex(8);
    const resp = { formId, respondent: this.identity.address, submittedAt, answers };
    const inner = wl !== "none" || f.allowEdits   // editable forms are signed: nobody can "edit" someone else's answer
      ? { signature: C.signInner(this.identity, resp), pub: this.identity.pubHex }
      : { signature: null, pub: null };
    const sealed = C.toHex(C.sealToCreator(null, f.publicKey, JSON.stringify({ ...resp, ...inner, confirmationId })));
    const e = this.buildEvent(EventType.RESPONSE_SUBMIT, responseSubmitId(sealed), { encryptedPayload: sealed }, false);
    this.mySubs[formId] = confirmationId;
    this.myAnswers[formId] = { answers, submittedAt, firstSubmittedAt: isEdit ? firstAt : submittedAt };   // private copy: the sealed blob only opens for the creator
    this.saveMeta();
    if (this.answerDrafts[formId]) { delete this.answerDrafts[formId]; this.saveDrafts(); }
    this.adopt(e);
    return { ok: true, eventId: e.id };
  }
  importForm(input) {
    const l = parseLink(input);
    if (!l || !l.formId) return { ok: false, error: "not a WhisperBox link or form id" };
    const have = !!this.state().forms[l.formId];
    this.watched.add(l.formId);
    if (l.by) this.pins[l.formId] = l.by;
    this.saveMeta();
    if (!have && this.nodeReady) { this.requestSync(); this.catchupRound(); }
    this.emit();
    return { ok: true, formId: l.formId, pending: !have };
  }
  forgetForm(formId) {
    formId = lc(formId); this.watched.delete(formId); delete this.pins[formId]; this.saveMeta(); this.emit();
    return { ok: true };
  }
  shareUri(formId) {
    const f = this.state().forms[lc(formId)];
    if (!f) return { ok: false, error: "unknown form" };
    return { ok: true, uri: `whisperbox://form?id=${f.id}&by=${f.creator}` };
  }
  resync() { if (!this.nodeReady) return { ok: false, error: "not connected" }; this.requestSync(); this.catchupRound(); return { ok: true }; }

  // ── read side (same shape as the core's snapshot) ──────────────────────────────
  // Opening keys for MY forms, by sealing pubkey: the form's own derived key, or the identity
  // key for legacy (0.2.0-and-earlier) forms whose publicKey is the identity pub.
  formKeys(st) {
    const keys = new Map();
    this._derived = this._derived || new Map();
    for (const f of Object.values(st.forms)) {
      if (f.creator !== this.identity.address || !f.publicKey) continue;
      const ck = this.cardKeys.get(f.id);
      if (ck && ck.pubHex === f.publicKey) { keys.set(ck.pubHex, ck); continue; }
      if (f.publicKey === this.identity.pubHex) { keys.set(f.publicKey, this.identity); continue; }
      let k = this._derived.get(f.id);
      if (!k) { k = C.deriveFormKey(this.identity, f.id); this._derived.set(f.id, k); }
      if (k.pubHex === f.publicKey) keys.set(k.pubHex, k);
    }
    return keys;
  }
  // Trial-open against every key (a sealed blob does not say which form it is for - on
  // purpose, that would publish per-form answer counts). Results are cached per blob; a miss
  // is retried only when the key set grows.
  openWith(keys, st, hex) {
    this._opened = this._opened || new Map();
    const c = this._opened.get(hex);
    if (c && (c.dec || c.nKeys === keys.size)) return c.dec;
    let dec = null;
    for (const k of keys.values()) {
      let pt; try { pt = C.eciesOpen(k, hex); } catch { continue; }
      try { dec = JSON.parse(C.utf8Decode(pt)); } catch { dec = null; break; }
      // The key that opened it must be the sealing key of the form it claims to answer.
      const f = dec && st.forms[String(dec.formId ?? "").toLowerCase()];
      if (!f || f.publicKey !== k.pubHex) dec = null;
      break;
    }
    this._opened.set(hex, { dec, nKeys: keys.size });
    return dec;
  }
  decrypt(st) {
    const keys = this.formKeys(st);
    return creatorView(st, {
      identity: this.identity.address,
      open: (hex) => this.openWith(keys, st, hex),
      verifyResponse: (pseudo) => C.verifyInner(pseudo.payload),
    });
  }
  snapshot() {
    const st = this.state();
    let cv = null;
    if (st.creator) {
      cv = this.decrypt(st);
      for (const [fid, list] of Object.entries(cv.responses)) {
        const confs = cv.confirmations[fid] || [];
        for (const r of list) r.confirmed = confs.includes(confirmIdOf(r, fid));
      }
    }
    const missing = new Set(this.formsMissingKeys(st));
    let seenDirty = false, newTotal = 0;
    for (const [fid, f] of Object.entries(st.forms)) {
      const mine = f.creator === this.identity.address;
      const submitted = fid in this.mySubs;
      const cid = submitted ? (this.mySubs[fid] || confirmIdLegacy(fid, this.identity.address)) : "";
      const wl = f.whitelist?.type || "none";
      const allowed = wl === "none" || (wl === "addresses" && whitelistAddresses(f.whitelist).includes(this.identity.address));
      const pin = this.pins[fid] || "";
      const linkMismatch = !!pin && pin !== f.creator;
      const contested = !!f.contested;
      const trusted = !linkMismatch && (!contested || pin === f.creator);
      Object.assign(f, {
        contested, pinnedCreator: pin || null, linkMismatch, mine, mySubmitted: submitted,
        myConfirmed: submitted && (f.confirmations || []).includes(cid), allowed,
        canRespond: trusted && !mine && !submitted && allowed && f.status === "open" && !!f.publicKey,
        // mine, but no key here to open its answers (Keycard form on a new install): tap to restore
        keyMissing: missing.has(fid), keycard: this.cardKeys.has(fid),
        hidden: this.hidden.has(fid), ...(this.myAnswers[fid] ? { myAnswers: this.myAnswers[fid] } : {}),
        ...(submitted && f.allowEdits && this.myAnswers[fid] ? (() => {
          const until = (this.myAnswers[fid].firstSubmittedAt ?? this.myAnswers[fid].submittedAt) + (f.editWindowMinutes || 15) * 60000;
          const confirmedNow = submitted && (f.confirmations || []).includes(cid);
          return { editUntil: until, canEdit: !confirmedNow && f.status === "open" && this.now() < until };
        })() : {}),
        ...(mine ? (() => {   // "N new" since the creator last looked
          const n = (cv?.responses?.[fid] || []).length;
          if (this.seen[fid] === undefined) { this.seen[fid] = n; seenDirty = true; }
          const nw = Math.max(0, n - this.seen[fid]); if (!this.hidden.has(fid)) newTotal += nw;
          return { newResponses: nw };
        })() : {}),
        autoReceipts: this.autoReceipts.has(fid), ...(this.answerDrafts[fid] ? { answerDraft: this.answerDrafts[fid] } : {}),
      });
    }
    if (seenDirty) this.store.set("wb-seen", JSON.stringify(this.seen));
    return {
      v: 1, identity: { address: this.identity.address, pubHex: this.identity.pubHex }, deviceId: this.deviceId, newResponses: newTotal,
      nodeReady: this.nodeReady, state: st, creatorView: cv, watched: [...this.watched],
      pendingForms: [...this.watched].filter((id) => !st.forms[id]), mySubmissions: Object.keys(this.mySubs), hidden: [...this.hidden], drafts: Object.values(this.drafts),
      diagnostics: { ...this.diag, logSize: this.log.length },
    };
  }
  exportCsv(formId) {
    formId = lc(formId);
    const st = this.state(); const f = st.forms[formId];
    if (!f) return { ok: false, error: "unknown form" };
    if (f.creator !== this.identity.address) return { ok: false, error: "not the creator" };
    const cell = (v) => (/[",\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v);
    const opt = (q, x) => (typeof x === "number" && q.options && q.options[x] !== undefined ? String(q.options[x]) : x == null ? "" : typeof x === "boolean" ? (x ? "Yes" : "No") : typeof x === "string" ? x : typeof x === "number" ? String(x) : x && typeof x === "object" && "other" in x ? "Other: " + x.other : JSON.stringify(x));
    const val = (q, v) => (Array.isArray(v) ? v.map((x) => opt(q, x)).join("; ") : opt(q, v));
    const iso = (ms) => (ms > 0 ? new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z") : "");
    const qs = f.questions || [];
    const rows = [["respondent", "submittedAt", "confirmed", ...qs.map((q) => q.text || q.id)]];
    for (const r of this.decrypt(st).responses[formId] || []) {
      const byQ = new Map((r.answers || []).map((a) => [a.questionId, a.value]));
      rows.push([r.respondent, iso(r.submittedAt || 0), (f.confirmations || []).includes(confirmIdOf(r, formId)) ? "yes" : "no",
        ...qs.map((q) => (byQ.has(q.id) ? val(q, byQ.get(q.id)) : ""))]);
    }
    return { ok: true, csv: rows.map((r) => r.map((c) => cell(String(c))).join(",")).join("\n") + "\n" };
  }
}
