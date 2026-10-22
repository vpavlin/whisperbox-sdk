// A hostile peer on the topic (review 2026-10-22: WB-1/3/5/9/10/11). The same frames as the C++
// e2e "hostile peer" scenario: the phone must drop them before they reach its log or its clock,
// so the phone and the desktop keep the same event set.
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient, parseLink, MAX_CLOCK_LEAD_MS } from "../src/client.mjs";
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
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "x" }]).ok); pump();
  const resp = a.log.find((e) => e.type === "response.submit");
  assert.ok(resp, "a got b's answer");
  assert.notStrictEqual(resp.dev, C.responseDevTag(b.deviceId, fid), "the tag isn't sha256(deviceId|formId)");
  assert.strictEqual(parseLink("whisperbox://form?id=%"), null, "malformed escape");
  assert.strictEqual(parseLink("whisperbox://form?id=../../etc&by=0xnothex"), null, "bad id and creator");
  assert.strictEqual(parseLink("../../etc"), null, "bare id that can't be one");
  assert.deepStrictEqual(parseLink("whisperbox://form?id=form-ab12&by=0x" + "a".repeat(40)), { formId: "form-ab12", by: "0x" + "a".repeat(40) });
});
