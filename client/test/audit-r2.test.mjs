// Audit round 2 (proteus/auditor, 2026-11-13): the phone side of the R2 fixes; the C++ e2e
// "round 2" block tests the same on the desktop core.
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient, wireTopicFor } from "../src/client.mjs";
import * as C from "../../contract/src/crypto-portable.mjs";
import { responseSubmitId, responseConfirmId } from "../../contract/src/events.mjs";

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); } }; };
const bytes = (s) => new TextEncoder().encode(s);
const frame = (ev) => bytes(JSON.stringify({ v: 1, type: "EVENT", event: ev }));
const q = { title: "r2", questions: [{ id: "q1", type: "textarea", text: "?", required: true }] };

async function net(n, opts = {}) {
  let t = 1_800_000_000_000;
  const peers = [], wire = [];
  for (let i = 0; i < n; i++) {
    const p = new WhisperboxClient({ receiptDelayMs: 0, store: mem(), now: () => t, minuteMs: 60000, msgsPerEpoch: 1e6, ...opts,
      send: async (b, topic) => { wire.push({ from: p, bytes: b, topic }); } });
    await p.init(); p.onConnected(); peers.push(p);
  }
  const pump = () => { while (wire.length) { const m = wire.shift(); for (const o of peers) if (o !== m.from) o.ingest([m.bytes]); } };
  const advance = (ms) => { for (let s = 0; s < ms; s += 5000) { t += 5000; for (const p of peers) p.tick(); pump(); } };
  return { peers, wire, pump, advance, now: () => t };
}
const sealed = (pub, plain) => C.toHex(C.sealToCreator(null, pub, JSON.stringify(plain)));
const answerEv = (hex, wall) => ({ v: 1, id: responseSubmitId(hex), type: "response.submit", hlc: { wall, ctr: 0, dev: "x" }, dev: "x", payload: { encryptedPayload: hex } });

test("R2-1: a co-owner grant is an invitation: nothing until accepted; leaving drops the answers", async () => {
  const { peers: [a, r, b], pump } = await net(3);
  const fid = a.createForm(q).formId;
  for (const p of [r, b]) p.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  pump();
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "from b" }]).ok); pump();
  assert.ok(a.addCoOwner(fid, r.identity.pubHex).ok, "a names r co-owner, unasked"); pump();
  assert.deepStrictEqual(r.snapshot().coInvites.map((x) => x.formId), [fid], "r sees an invitation");
  assert.ok(!r.snapshot().state.forms[fid].coOwner && !(r.snapshot().creatorView?.responses?.[fid] || []).length, "...not a co-owner; no answers opened");
  assert.ok(r.acceptCoOwner(fid).ok && r.snapshot().state.forms[fid].coOwner, "accepted: a co-owner");
  b.myAnswers[fid].sent = true;
  assert.ok(r.leaveCoOwner(fid).ok && !r.snapshot().state.forms[fid].coOwner && !r.snapshot().coInvites.length, "left: not a co-owner, no invitation");
  assert.ok(!r.log.some((e) => e.type === "response.submit"), "...and no answers kept");
});

test("R2-2: a signed event for a form I keep, by someone who may not write it, isn't kept", async () => {
  const { peers: [a, r], pump } = await net(2);
  const fid = a.createForm(q).formId;
  r.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`); pump();
  const z = C.identityFromPriv(C.toHex(C.utf8Encode("junk".padEnd(32, "z"))).slice(0, 64));
  const ev = { v: 1, id: `update:${fid}:junk`, type: "form.update", hlc: { wall: Date.now(), ctr: 0, dev: "z" }, dev: "z", payload: { formId: fid, author: z.address, form: { title: "J".repeat(40000) } } };
  const junk = { ...ev, ...C.signEvent(z, ev) };
  const n0 = r.log.length;
  r.ingest([frame(junk)]);
  assert.strictEqual(r.log.length, n0, "not stored");
  assert.ok((r.diag.admDropUnwanted || 0) > 0);
});

test("R2-3: one form stops at its own answer cap; another form still takes answers", async () => {
  const { peers: [a] } = await net(1, { maxAnswersPerForm: 5 });
  const f1 = a.createForm(q).formId, f2 = a.createForm(q).formId;
  const st = a.state(), now = Date.now();
  for (let i = 0; i < 8; i++) a.ingest([frame(answerEv(sealed(st.forms[f1].publicKey, { formId: f1, n: i }), now))]);
  a.ingest([frame(answerEv(sealed(st.forms[f2].publicKey, { formId: f2 }), now))]);
  assert.strictEqual(a.respPerForm[f1], 5, "f1 stops at 5");
  assert.strictEqual(a.respPerForm[f2], 1, "f2 still takes its answer");
});

test("R2-7 (as amended by ADR 0027): a retried answer gets its receipt again, byte-identical", async () => {
  const { peers: [a, b, c], wire, pump } = await net(3);
  const fid = a.createForm(q).formId;
  for (const p of [b, c]) p.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  pump();
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "1" }]).ok && c.submitResponse(fid, [{ questionId: "q1", value: "2" }]).ok); pump();
  a.snapshot();   // the creator view opens them
  assert.ok(a.confirmAll(fid).ok); pump();
  const mine = b.log.find((e) => e.type === "response.submit");
  const cid = b.myAnswers[fid].confirmationId;
  wire.length = 0;
  a.ingest([frame(mine)]);   // b's retry
  a.drain();
  const sent = wire.filter((m) => m.from === a).flatMap((m) => JSON.parse(new TextDecoder().decode(m.bytes)).events || []);
  // the stored receipt event again, byte-identical: a fresh one with new decoys would show which entry is
  // real (anoncomms on v3); the re-send cap bounds the cost of re-sending a batch (R6-9)
  const tag = b.answerSecret(b.state(), fid, cid, null).tag;
  const stored = a.log.find((e) => e.type === "response.receipt" && e.payload.r.some((x) => x.t === tag));
  assert.ok(sent.length === 1 && JSON.stringify(sent[0]) === JSON.stringify(stored), "the same receipt event: " + JSON.stringify(sent.map((e) => e.id)));
  assert.ok(stored.payload.r.length >= 8, "padded to at least 8 entries");
});

test("R2-8: with my answers' record missing, the prune keeps answers it can't place", async () => {
  const { peers: [a, b], pump } = await net(2);
  const fid = a.createForm(q).formId;
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`); pump();
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "mine" }]).ok);
  const before = b.log.filter((e) => e.type === "response.submit").length;
  b.myAnswers = {};   // wb-myanswers lost or behind wb-mysubs
  b.pruneUnwanted();
  assert.strictEqual(b.log.filter((e) => e.type === "response.submit").length, before, "my own answer survives");
});

test("R2-5 (as amended by R5-3/R8-3): only a time agreeing with the answer's HLC counts, the earliest; never over a live time", async () => {
  const { peers: [a] } = await net(1);
  const fid = a.createForm(q).formId;
  const pub = a.state().forms[fid].publicKey, now = 1_800_000_000_000;
  const h = now - 600_000;   // the answer's (10-minute) HLC
  const e1 = answerEv(sealed(pub, { formId: fid, n: 1 }), h), e2 = answerEv(sealed(pub, { formId: fid, n: 2 }), now);
  a.ingest([frame(e1)], { tsMs: now - 3_600_000, source: "history" });   // a Store an hour off: ignored
  assert.strictEqual(a.netTimes[e1.id], undefined);
  a.ingest([frame(e1)], { tsMs: h + 240_000, source: "history" });       // agrees
  a.ingest([frame(e1)], { tsMs: h + 480_000, source: "history" });       // agrees, later: no change
  assert.strictEqual(a.netTimes[e1.id], h + 240_000, "the earliest agreeing Store time");
  a.ingest([frame(e2)], { tsMs: now });                                  // seen live
  a.ingest([frame(e2)], { tsMs: now - 60_000, source: "history" });      // a Store claims earlier
  assert.strictEqual(a.netTimes[e2.id], now, "a live time isn't moved by a Store");
});
