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
  for (let i = 0; i < 6; i++) a.createForm(q);
  assert.ok(a.diag.txTotal - sent0 <= 3, "only 3 forms out this epoch");
  pump();
  const fid = Object.keys(a.state().forms).find((f) => b.state().forms[f]);
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  for (let i = 0; i < 6; i++) b.createForm(q);   // b's own forms fill its budget
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "urgent" }]).ok);
  const best = b.outQ.reduce((x, y) => (y.prio < x.prio ? y : x), b.outQ[0]);
  assert.ok(best && best.prio === 1, "the waiting answer goes before the waiting forms");
});

test("an answer the creator missed goes out again until the receipt, then stops", async () => {
  const { peers: [a, b], pump, advance } = await net(2);
  const fid = a.createForm(q).formId; pump();
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
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
  const fid = a.createForm(q).formId; pump();   // b missed the publish (and there is no Store here)
  c.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);   // c holds the form too
  b.offline = false;
  const cTx = c.diag.txTotal;
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  advance(30000);   // b's first ASK after 20 s
  assert.ok(b.state().forms[fid], "the creator answered b's ASK with the form");
  assert.strictEqual(c.diag.txTotal, cTx, "a respondent holding the form never answers an ASK");
  assert.ok(wireTopicFor(fid).startsWith("/whisperbox/2/form-"));
  void wire;
});
