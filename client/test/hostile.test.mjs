// A hostile peer on the topic (review 2026-10-22: WB-1/3/5/9/10/11). The same frames as the C++
// e2e "hostile peer" scenario: the phone must drop them before they reach its log or its clock,
// so the phone and the desktop keep the same event set.
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient, parseLink, MAX_CLOCK_LEAD_MS, wellFormedFormFields } from "../src/client.mjs";
import { MAX_HLC_CTR } from "../../contract/src/hlc.mjs";
import * as C from "../../contract/src/crypto-portable.mjs";
import { responseSubmitId } from "../../contract/src/events.mjs";

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); }, m }; };
const bytes = (s) => new TextEncoder().encode(s);

const FRAMES = [
  `{"v":2,"t":"fp"}`,
  `{"v":2,"t":"ids","from":"x","ids":[1,2]}`,
  `{"v":1,"type":"EVENT","event":{"type":1}}`,
  `{"v":1,"type":"SYNC_REQ","from":1}`,
  `{"v":1,"type":"EVENT","event":{"v":1,"id":"resp:x","type":"response.submit","hlc":1,"dev":"x","payload":{"encryptedPayload":"ab"}}}`,
  `{"v":1,"type":"EVENT","event":{"v":1,"id":"resp:bad","type":"response.submit","hlc":{"wall":1,"ctr":0,"dev":"x"},"dev":"x","payload":{"encryptedPayload":123}}}`,
  `{"v":1,"type":"EVENT","event":{"v":1,"id":"form:bad","type":"form.publish","hlc":{"wall":1700000000000,"ctr":0,"dev":"d"},"dev":"d","payload":{"id":1,"creator":"0x1298004b9c5f01583a855dc3f693769b1289a762","questions":[]},"pub":"035b","sig":"43bd"}}`,
  `{"v":1,"type":"EVENT","event":{"v":1,"id":"resp:shadow","type":"response.submit","hlc":{"wall":1,"ctr":0,"dev":"x"},"dev":"x","payload":{"encryptedPayload":"00"}}}`,
];

test("hostile frames are dropped before the log, the clock and the store", async () => {
  const store = mem();
  const a = new WhisperboxClient({ store, send: async () => {} });
  await a.init(); a.onConnected();
  const fid = a.createForm({ title: "victim", questions: [{ id: "q1", type: "text", text: "?", required: true }] }).formId;
  const before = a.log.length;
  for (const f of FRAMES) a.ingest([bytes(f)]);
  assert.strictEqual(a.log.length, before, "nothing malformed is merged");
  assert.ok(a.snapshot().state.forms[fid], "the client still folds its state");
  const saved = String(await store.get("wb-log") || "");
  assert.ok(!/resp:bad|form:bad|resp:shadow/.test(saved), "nothing malformed is saved");

  // a far-future clock is refused and never adopted (WB-3)
  const far = "00ff";
  const ev = { v: 1, id: responseSubmitId(far), type: "response.submit", hlc: { wall: 9999999999999, ctr: 0, dev: "x" }, dev: "x", payload: { encryptedPayload: far } };
  a.ingest([bytes(JSON.stringify({ v: 1, type: "EVENT", event: ev }))]);
  assert.ok(!a.log.some((e) => e.id === ev.id), "an event 300 years ahead is refused");
  const f2 = a.createForm({ title: "clock", questions: [{ id: "q1", type: "text", text: "?" }] });
  const own = a.log.find((e) => e.id === "form:" + f2.formId);
  assert.ok(own.hlc.wall < Date.now() + MAX_CLOCK_LEAD_MS, "the next local event still carries real time");
});

test("a stored log poisoned by an older version loads without the bad event", async () => {
  const store = mem();
  const a = new WhisperboxClient({ store, send: async () => {} });
  await a.init(); a.onConnected();
  a.createForm({ title: "keep me", questions: [{ id: "q1", type: "text", text: "?" }] });
  const log = JSON.parse(await store.get("wb-log"));
  log.push(JSON.parse(`{"v":1,"id":"resp:bad","type":"response.submit","hlc":{"wall":1,"ctr":0,"dev":"x"},"dev":"x","payload":{"encryptedPayload":123}}`));
  await store.set("wb-log", JSON.stringify(log));
  const b = new WhisperboxClient({ store, send: async () => {} });
  await b.init();
  assert.ok(!b.log.some((e) => e.id === "resp:bad"), "the malformed event is skipped");
  assert.strictEqual(Object.keys(b.snapshot().state.forms).length, 1, "the good events load");
});

test("answer tags are random, links that can't be valid are refused", async () => {
  const wire = [];
  const a = new WhisperboxClient({ store: mem(), send: async (x) => { wire.push(x); } });
  const b = new WhisperboxClient({ store: mem(), send: async (x) => { wire.push(x); } });
  await a.init(); await b.init(); a.onConnected(); b.onConnected();
  const pump = () => { while (wire.length) { const m = wire.shift(); a.ingest([m]); b.ingest([m]); } };
  const fid = a.createForm({ title: "tags", questions: [{ id: "q1", type: "text", text: "?", required: true }] }).formId;
  a.catchupRound(); b.catchupRound(); pump();
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);   // answers need the creator a link names (FR-3)
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "x" }]).ok); pump();
  const resp = a.log.find((e) => e.type === "response.submit");
  assert.ok(resp, "a got b's answer");
  assert.notStrictEqual(resp.dev, C.responseDevTag(b.deviceId, fid), "the tag isn't sha256(deviceId|formId)");
  assert.strictEqual(parseLink("whisperbox://form?id=%"), null, "malformed escape");
  assert.strictEqual(parseLink("whisperbox://form?id=../../etc&by=0xnothex"), null, "bad id and creator");
  assert.strictEqual(parseLink("../../etc"), null, "bare id that can't be one");
  assert.deepStrictEqual(parseLink("whisperbox://form?id=form-ab12&by=0x" + "a".repeat(40)), { formId: "form-ab12", by: "0x" + "a".repeat(40) });
});

// open-review 2026-10-29: the same vectors as the C++ e2e block
test("deep JSON, huge HLC counters, off-curve form keys are refused; the clock stays valid", async () => {
  const store = mem();
  const a = new WhisperboxClient({ store, send: async () => {} });
  await a.init(); a.onConnected();
  const before = a.log.length;
  // FR-1: 50,000 nested arrays
  const deep = "[".repeat(50000) + "]".repeat(50000);
  a.ingest([bytes(`{"v":1,"type":"EVENT","event":{"v":1,"id":"close:x:n","type":"form.close","hlc":{"wall":1,"ctr":0,"dev":"x"},"dev":"x","payload":{"formId":"x","author":"0x0","x":${deep}}}}`)]);
  assert.ok((a.diag.rxBad || 0) >= 1, "the deep frame is refused before parsing");
  // FR-2: a counter far past the bound
  const sealed = "01" + "a".repeat(140);
  const big = { v: 1, id: responseSubmitId(sealed), type: "response.submit", hlc: { wall: Date.now() + 60000, ctr: Number.MAX_SAFE_INTEGER, dev: "x" }, dev: "x", payload: { encryptedPayload: sealed } };
  a.ingest([bytes(JSON.stringify({ v: 1, type: "EVENT", event: big }))]);
  assert.strictEqual(a.log.length, before, "nothing merged");
  const f = a.createForm({ title: "after", questions: [{ id: "q1", type: "text", text: "?" }] });
  const own = a.log.find((e) => e.id === "form:" + f.formId);
  assert.ok(own.hlc.ctr >= 0 && own.hlc.ctr <= MAX_HLC_CTR, "the next local stamp has a valid counter");
  // FR-4: a signed form whose publicKey isn't a point
  const x = C.identityFromPriv(C.sha256Hex ? C.sha256Hex("fr4") : "11".repeat(32));
  const payload = { id: "fr4-badkey", creator: x.address, publicKey: "02" + "0".repeat(64), title: "bad", questions: [], whitelist: { type: "none", value: "" }, createdAt: 1 };
  const fe = { v: 1, id: "form:fr4-badkey", type: "form.publish", hlc: { wall: Date.now(), ctr: 0, dev: "x" }, dev: "x", payload };
  Object.assign(fe, C.signEvent(x, fe));
  a.ingest([bytes(JSON.stringify({ v: 1, type: "EVENT", event: fe }))]);
  assert.ok(!a.snapshot().state.forms["fr4-badkey"], "an off-curve form key is refused");
  assert.strictEqual(C.validPubPoint("02" + "0".repeat(64)), false);
  assert.strictEqual(C.validPubPoint(x.pubHex), true);
});

test("an empty ids frame, repeated, serves each event once (FR-3)", async () => {
  const sent = [];
  let t = 1_800_000_000_000;
  const a = new WhisperboxClient({ store: mem(), send: async (m) => { sent.push(m); }, now: () => t });
  await a.init(); a.onConnected();
  for (let i = 0; i < 3; i++) a.createForm({ title: "f" + i, questions: [{ id: "q1", type: "text", text: "?" }] });
  sent.length = 0;
  for (let i = 0; i < 20; i++) a.ingest([bytes('{"v":2,"t":"ids","from":"evil","ids":[]}')]);
  const events = sent.map((m) => { try { return JSON.parse(new TextDecoder().decode(m)); } catch { return null; } }).filter((x) => x && x.type === "EVENT");
  assert.ok(events.length > 0 && events.length <= a.log.length, `served ${events.length} for 20 frames, log ${a.log.length}`);
  assert.ok(a.diag.serveSkipped > 0);
  t += 3000; sent.length = 0;
  a.ingest([bytes('{"v":2,"t":"ids","from":"peer","ids":[]}')]);
  assert.ok(sent.length > 0, "after the window a new asker is served again");
});

test("a stored log with an unsigned close loads without it (FR-7)", async () => {
  const store = mem();
  const a = new WhisperboxClient({ store, send: async () => {} });
  await a.init(); a.onConnected();
  const f = a.createForm({ title: "stays open", questions: [{ id: "q1", type: "text", text: "?" }] });
  const log = JSON.parse(await store.get("wb-log"));
  log.push({ v: 1, id: "close:" + f.formId + ":forged", type: "form.close", hlc: { wall: Date.now() + 1000, ctr: 0, dev: "x" }, dev: "x", payload: { formId: f.formId, author: a.identity.address } });
  await store.set("wb-log", JSON.stringify(log));
  const b = new WhisperboxClient({ store, send: async () => {} });
  await b.init();
  assert.strictEqual(b.snapshot().state.forms[f.formId].status, "open");
});

// open-review 2026-10-30 (the 0.5.1 re-review): the decrypted path, numbers, bare ids
test("a sealed deep answer, a 1e300 limit and a bare-id answer are refused (FR-1/2/3)", async () => {
  const wire = [];
  const a = new WhisperboxClient({ store: mem(), send: async (x) => { wire.push(["a", x]); } });
  const b = new WhisperboxClient({ store: mem(), send: async (x) => { wire.push(["b", x]); } });
  await a.init(); await b.init(); a.onConnected(); b.onConnected();
  const pump = () => { while (wire.length) { const [from, m] = wire.shift(); (from === "a" ? b : a).ingest([m]); } };
  const fid = a.createForm({ title: "deep target", questions: [{ id: "q1", type: "text", text: "?" }] }).formId;
  a.catchupRound(); b.catchupRound(); pump(); pump();
  const pub = a.snapshot().state.forms[fid].publicKey;
  // FR-1: sealed to the form's public key, 50,000 deep inside
  const pt = `{"formId":"${fid}","respondent":"0x${"9".repeat(40)}","answers":[],"signature":null,"x":${"[".repeat(50000)}${"]".repeat(50000)}}`;
  const sealed = C.toHex(C.sealToCreator(null, pub, pt));
  const ev = { v: 1, id: responseSubmitId(sealed), type: "response.submit", hlc: { wall: Date.now(), ctr: 0, dev: "x" }, dev: "x", payload: { encryptedPayload: sealed } };
  a.ingest([bytes(JSON.stringify({ v: 1, type: "EVENT", event: ev }))]);
  const snap = a.snapshot();
  assert.ok(snap && !(snap.creatorView.responses[fid] || []).length, "the deep answer is dropped, the view still works");
  // FR-2: maxResponses 1e300 fails the shape check
  assert.strictEqual(wellFormedFormFields({ title: "x", questions: [], maxResponses: 1e300 }), false);
  assert.strictEqual(wellFormedFormFields({ title: "x", questions: [], editWindowMinutes: 9.2e18 }), false);
  // FR-3: b knows the form from catch-up only: no creator pinned, no answering
  const bf = b.snapshot().state.forms[fid];
  assert.ok(bf.needsLink && !bf.canRespond, "needs the creator's link");
  assert.strictEqual(b.submitResponse(fid, [{ questionId: "q1", value: "x" }]).ok, false);
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  assert.ok(b.snapshot().state.forms[fid].canRespond, "with the link it can");
});
