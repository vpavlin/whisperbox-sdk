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
import { TOPIC, EventType, formPublishId, responseSubmitId, responseConfirmId, formCloseId } from "../../contract/src/events.mjs";
import * as C from "../../contract/src/crypto-portable.mjs";
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
    this.identity = null; this.deviceId = ""; this.clock = null;
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
    if (e.type === EventType.FORM_PUBLISH || e.type === EventType.RESPONSE_CONFIRM || e.type === EventType.FORM_CLOSE) {
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
  }

  // ── authoring ──────────────────────────────────────────────────────────────────
  buildEvent(type, id, payload, sign) {
    const e = { v: 1, id, type, hlc: this.clock.send(this.now()), dev: this.deviceId, payload };
    return sign ? { ...e, ...C.signEvent(this.identity, e) } : e;
  }
  adopt(e) { if (mergeOne(this.log, e)) { this.clock.receive(e.hlc); this.saveLog(); } this.broadcast(e); this.emit(); }
  state() { return computeState(this.log, { identity: this.identity.address, prefer: this.pins }); }

  createForm(def) {
    if (!def || typeof def !== "object") return { ok: false, error: "def must be an object" };
    const formId = lc(def.id) || "form-" + C.randomHex(4);
    const p = {
      id: formId, title: def.title || "", description: def.description || "",
      // Sealing key = this form's OWN key, derived from the identity (see crypto-portable.mjs).
      creator: this.identity.address, publicKey: C.deriveFormKey(this.identity, formId).pubHex, createdAt: this.now(),
      expiresAt: def.expiresAt ?? null, questions: Array.isArray(def.questions) ? def.questions : [],
      whitelist: def.whitelist || { type: "none", value: "" },
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
    this.adopt(this.buildEvent(EventType.FORM_CLOSE, formCloseId(formId), { formId, expiresAt: null, author: this.identity.address }, true));
    return { ok: true };
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
    if (formId in this.mySubs) return { ok: false, error: "you already answered this form" };
    if (!f.publicKey) return { ok: false, error: "form not synced yet - try again in a moment" };
    const pin = this.pins[formId] || "";
    if (pin && pin !== f.creator) return { ok: false, error: "this form's creator doesn't match the link you opened - refusing to send answers" };
    if (f.contested && pin !== f.creator) return { ok: false, error: "two different people published a form with this id - open it from the creator's link to answer" };
    const wl = f.whitelist?.type || "none";
    if (wl === "addresses" && !whitelistAddresses(f.whitelist).includes(this.identity.address)) return { ok: false, error: "this form only accepts listed addresses" };
    if (wl !== "none" && wl !== "addresses") return { ok: false, error: `whitelist type '${wl}' is not supported` };
    const byQ = new Map(answers.map((a) => [a?.questionId, a?.value]));
    for (const q of f.questions || []) if (q.required && emptyAnswer(byQ.get(q.id))) return { ok: false, error: "required: " + (q.text || q.id) };
    const submittedAt = this.now();
    const confirmationId = C.randomHex(8);
    const resp = { formId, respondent: this.identity.address, submittedAt, answers };
    const inner = wl !== "none"
      ? { signature: C.signInner(this.identity, resp), pub: this.identity.pubHex }
      : { signature: null, pub: null };
    const sealed = C.toHex(C.sealToCreator(null, f.publicKey, JSON.stringify({ ...resp, ...inner, confirmationId })));
    const e = this.buildEvent(EventType.RESPONSE_SUBMIT, responseSubmitId(sealed), { encryptedPayload: sealed }, false);
    this.mySubs[formId] = confirmationId; this.saveMeta();
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
      });
    }
    return {
      v: 1, identity: { address: this.identity.address, pubHex: this.identity.pubHex }, deviceId: this.deviceId,
      nodeReady: this.nodeReady, state: st, creatorView: cv, watched: [...this.watched],
      pendingForms: [...this.watched].filter((id) => !st.forms[id]), mySubmissions: Object.keys(this.mySubs),
      diagnostics: { ...this.diag, logSize: this.log.length },
    };
  }
  exportCsv(formId) {
    formId = lc(formId);
    const st = this.state(); const f = st.forms[formId];
    if (!f) return { ok: false, error: "unknown form" };
    if (f.creator !== this.identity.address) return { ok: false, error: "not the creator" };
    const cell = (v) => (/[",\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v);
    const opt = (q, x) => (typeof x === "number" && q.options && q.options[x] !== undefined ? String(q.options[x]) : x == null ? "" : typeof x === "string" ? x : JSON.stringify(x));
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
