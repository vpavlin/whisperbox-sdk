// ADR 0024 (wire v2) on the phone side: the RLN budget, answer retries until the receipt, ASK served
// only by the creator. Same rules as the C++ core's "ADR 0024 (wire v2)" e2e section.
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient, wireTopicFor } from "../src/client.mjs";

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); } }; };
const q = { title: "v2", questions: [{ id: "q1", type: "text", text: "?", required: true }] };

// peers on a fake topic bus: a frame reaches the others unless the sender or receiver is offline
async function net(n, opts = {}) {
  let t = 1_800_000_000_000;
  const peers = [], wire = [];
  for (let i = 0; i < n; i++) {
    const p = new WhisperboxClient({ store: mem(), now: () => t, minuteMs: 60000, ...opts,
      send: async (bytes, topic) => { if (p.offline) throw new Error("offline"); wire.push({ from: p, bytes, topic }); } });
    await p.init(); p.onConnected(); peers.push(p);
  }
  const pump = () => { while (wire.length) { const m = wire.shift(); for (const o of peers) if (o !== m.from && !o.offline) o.ingest([m.bytes]); } };
  const advance = (ms) => { for (let s = 0; s < ms; s += 5000) { t += 5000; for (const p of peers) p.tick(); pump(); } };
  return { peers, wire, pump, advance, now: () => t };
}

test("the RLN budget: 3 per epoch, the answer first", async () => {
  const { peers: [a, b], pump } = await net(2, { msgsPerEpoch: 3 });
  const sent0 = a.diag.txTotal;
  const made = [];
  for (let i = 0; i < 6; i++) made.push(a.createForm(q).formId);
  assert.ok(a.diag.txTotal - sent0 <= 3, "only 3 forms out this epoch");
  const fid = made[0];   // the first one went out within the budget
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);   // only opened forms are kept (Václav 2026-11-13)
  pump();
  for (let i = 0; i < 6; i++) b.createForm(q);   // b's own forms fill its budget
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "urgent" }]).ok);
  const best = b.outQ.reduce((x, y) => (y.prio < x.prio ? y : x), b.outQ[0]);
  assert.ok(best && best.prio === 1, "the waiting answer goes before the waiting forms");
});

test("an answer the creator missed goes out again until the receipt, then stops", async () => {
  const { peers: [a, b], pump, advance } = await net(2);
  const fid = a.createForm(q).formId;
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);   // only opened forms are kept
  pump();
  a.offline = true;
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "late" }]).ok); pump();
  assert.strictEqual((a.decrypt(a.state()).responses[fid] || []).length, 0, "the creator missed it");
  a.offline = false;
  advance(11 * 60000);   // the 10-minute retry
  assert.strictEqual(a.decrypt(a.state()).responses[fid].length, 1, "the retry delivered it");
  assert.ok(a.confirmAll(fid).ok); pump();
  assert.ok(b.snapshot().state.forms[fid].myConfirmed, "the respondent has its receipt");
  const tx = b.diag.txTotal; advance(3 * 60 * 60000);
  assert.strictEqual(b.diag.txTotal, tx, "no more retries after the receipt");
});

test("ASK: only the creator side answers; a bystander sends nothing", async () => {
  const { peers: [a, b, c], wire, pump, advance } = await net(3);
  b.offline = true;
  const fid = a.createForm(q).formId;
  c.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);   // c holds the form too (opened first: only opened forms are kept)
  pump();   // b missed the publish (and there is no Store here)
  b.offline = false;
  const cTx = c.diag.txTotal;
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  advance(30000);   // b's first ASK after 20 s
  assert.ok(b.state().forms[fid], "the creator answered b's ASK with the form");
  assert.strictEqual(c.diag.txTotal, cTx, "a respondent holding the form never answers an ASK");
  assert.ok(wireTopicFor(fid).startsWith("/whisperbox/2/form-"));
  void wire;
});

// Václav, 2026-11-13: "we should not store forms and answers we do not care about" (audit W2-2).
// Two forms in ONE bucket, two creators, two respondents, everyone hears everything.
test("a node keeps only its own forms and answers, though it hears the whole bucket", async () => {
  const { peers: [a, d, c, e], pump } = await net(4);
  const ids = []; for (let i = 0; ids.length < 2 && i < 5000; i++) { const id = "form-k" + i.toString(16); if (!ids.length || wireTopicFor(id) === wireTopicFor(ids[0])) ids.push(id); }
  const [f1, f2] = ids;
  assert.strictEqual(wireTopicFor(f1), wireTopicFor(f2), "same bucket");
  assert.ok(a.createForm({ ...q, id: f1 }).ok && d.createForm({ ...q, id: f2 }).ok);
  c.importForm(`whisperbox://form?id=${f1}&by=${a.identity.address}`);
  e.importForm(`whisperbox://form?id=${f2}&by=${d.identity.address}`);
  pump();
  assert.ok(c.state().forms[f1] && !c.state().forms[f2], "c keeps the form it opened, not its bucket neighbour");
  assert.ok(a.state().forms[f1] && !a.state().forms[f2], "a creator doesn't keep another creator's form");
  assert.ok(c.submitResponse(f1, [{ questionId: "q1", value: "for a" }]).ok);
  assert.ok(e.submitResponse(f2, [{ questionId: "q1", value: "for d" }]).ok);
  pump();
  const answers = (x) => x.log.filter((ev) => ev.type === "response.submit").length;
  assert.strictEqual(answers(a), 1, "a keeps the one answer it can open");
  assert.strictEqual(a.decrypt(a.state()).responses[f1].length, 1);
  assert.strictEqual(answers(d), 1, "d keeps the one answer it can open");
  assert.strictEqual(answers(c), 1, "c keeps only its own answer");
  assert.strictEqual(answers(e), 1, "e keeps only its own answer");
  assert.ok(a.diag.admDropUnwanted > 0 && c.diag.admDropUnwanted > 0, "the rest was dropped on arrival");
  assert.ok(a.confirmAll(f1).ok); pump();
  assert.ok(c.snapshot().state.forms[f1].myConfirmed, "the receipt still reaches the respondent");
  assert.ok(!e.log.some((ev) => ev.type === "response.confirm"), "...and nobody else keeps it");
});

test("forgetting a form drops its events; a log saved before the filter is pruned on start", async () => {
  const { peers: [a, g], pump } = await net(2);
  const fid = a.createForm(q).formId;
  g.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`); pump();
  assert.ok(g.state().forms[fid]);
  assert.ok(g.forgetForm(fid).ok);
  assert.ok(!g.state().forms[fid] && !g.log.length, "forgotten: its events are gone");
  assert.ok(!g.joined.has(wireTopicFor(fid)), "...and its bucket isn't pulled any more");
  // an old log holding a stranger's form (as every node in a bucket used to): pruned when it loads
  const m = new Map(); m.set("wb-log", JSON.stringify(a.log));
  const store = { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); } };
  const h = new WhisperboxClient({ store, send: async () => {} });
  await h.init();
  assert.strictEqual(h.log.length, 0, "a stranger's form isn't kept after the update");
  assert.strictEqual(JSON.parse(m.get("wb-log")).length, 0, "...on disk either");
});

// Václav 2026-11-13: "we should keep receipts minimal!" (audit W2-5: every receipt re-sent the whole state)
test("receipts go out alone and small; the form state carries none; a lost receipt comes back on the retry", async () => {
  const { peers: [a, ...rs], wire, pump, advance } = await net(6, { msgsPerEpoch: 1e6 });
  const fid = a.createForm(q).formId;
  for (const r of rs) r.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  pump();
  a.setAutoReceipts(fid, true);
  const frames = [], push = wire.push.bind(wire);
  wire.push = (m) => { if (m.from === a) frames.push(JSON.parse(new TextDecoder().decode(m.bytes))); return push(m); };   // what a sends, as it sends it
  for (const r of rs) { assert.ok(r.submitResponse(fid, [{ questionId: "q1", value: "hi" }]).ok); pump(); advance(5000); }
  for (const r of rs) assert.ok(r.snapshot().state.forms[fid].myConfirmed, "every respondent has its receipt");
  const evs = frames.flatMap((f) => (f.type === "EVENTS" ? f.events : []));
  const rcpt = frames.filter((f) => f.type === "EVENTS" && f.events.every((e) => e.type === "response.receipt"));
  assert.ok(rcpt.length >= 1 && evs.filter((e) => e.type === "form.publish").length === 0, "receipt frames carry receipts only, never the form again");
  // blinded (ADR 0026): no form id, no author, no signature, not the creator's device id
  const rs0 = rcpt.flatMap((f) => f.events);
  assert.ok(rs0.every((e) => !e.pub && !e.sig && Object.keys(e.payload).join() === "tags" && e.dev !== a.deviceId && e.hlc.dev === e.dev), "receipts name no form, author or device");
  // the hourly state: the form, no receipts
  frames.length = 0; a.publishFormState(fid, 5); a.drain();
  const st = frames.slice();
  assert.ok(st.length && st.every((f) => f.events.every((e) => e.type !== "response.receipt")), "the form's state carries no receipts");
  wire.length = 0;
  // a receipt that never arrived: the respondent retries its answer, the creator sends that receipt again
  const r0 = rs[0];
  const held = r0.log.filter((e) => e.type === "response.receipt").length;
  r0.log = r0.log.filter((e) => e.type !== "response.receipt"); r0.recountLog(); r0._int = null; r0._rint = null;   // as if the receipt never came
  r0.myAnswers[fid].sent = true; r0.myAnswers[fid].retries = 0;
  assert.ok(held > 0 && !r0.snapshot().state.forms[fid].myConfirmed, "r0 lost its receipt");
  advance(11 * 60000);
  assert.ok(r0.snapshot().state.forms[fid].myConfirmed, "the retried answer brought the receipt back");
});
