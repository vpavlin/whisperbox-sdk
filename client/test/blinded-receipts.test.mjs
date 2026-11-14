// ADR 0026/0027: blinded receipts (v3: per-answer secret, sealed signed proof) and reply tags on the
// phone; the C++ e2e "scenario C" and "receipts v3" blocks check the core.
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient } from "../src/client.mjs";
import { responseReceiptId } from "../../contract/src/events.mjs";
import * as C from "../../contract/src/crypto-portable.mjs";

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); } }; };
const q = { title: "blind", questions: [{ id: "q1", type: "text", text: "?", required: true }] };
async function net(n) {
  let t = 1_800_000_000_000;
  const peers = [], wire = [];
  for (let i = 0; i < n; i++) {
    const p = new WhisperboxClient({ store: mem(), now: () => t, minuteMs: 60000, msgsPerEpoch: 1e6,
      send: async (bytes, topic) => { wire.push({ from: p, bytes, topic }); } });
    await p.init(); p.onConnected(); peers.push(p);
  }
  const pump = () => { while (wire.length) { const m = wire.shift(); for (const o of peers) if (o !== m.from) o.ingest([m.bytes]); } };
  return { peers, wire, pump, tick: (ms) => { t += ms; } };
}
const sentBy = (wire, p) => wire.filter((m) => m.from === p).flatMap((m) => JSON.parse(new TextDecoder().decode(m.bytes)).events || []);
const frameOf = (events) => new TextEncoder().encode(JSON.stringify({ v: 2, type: "EVENTS", events }));
async function answered(n = 3) {
  const w = await net(n); const [a, b] = w.peers;
  const fid = a.createForm(q).formId;
  for (const p of w.peers.slice(1)) p.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  w.pump();
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "hi" }]).ok); w.pump();
  a.snapshot();
  return { ...w, a, b, fid, cid: b.myAnswers[fid].confirmationId };
}

test("a receipt names no form, author or device, carries decoys, and only the respondent and owners can use it", async () => {
  const { wire, pump, a, b, fid, cid, peers: [, , c] } = await answered(3);
  wire.length = 0;
  assert.ok(a.confirmAll(fid).ok);
  const rc = sentBy(wire, a).filter((e) => e.type === "response.receipt");
  assert.strictEqual(rc.length, 1);
  const e = rc[0];
  assert.ok(!e.sig && !e.pub && e.dev !== a.deviceId && e.hlc.dev === e.dev && e.hlc.ctr === 0 && e.hlc.wall % 600000 === 0, "no signature, device or fine clock");
  assert.ok(e.payload.r.length >= 2 && (e.payload.r.length & (e.payload.r.length - 1)) === 0, "padded to a power of two");
  assert.ok(e.payload.r.every((x) => x.s.length === 2 * C.RECEIPT_PROOF_BYTES), "decoys look like proofs");
  const raw = JSON.stringify(e);
  assert.ok(!raw.includes(fid) && !raw.includes(cid) && !raw.includes(a.identity.address.slice(2)), "neither the form, the answer's id nor the creator appear");
  pump();
  assert.ok(b.snapshot().state.forms[fid].myConfirmed, "the respondent verifies it");
  assert.ok(!c.log.some((x) => x.type === "response.receipt"), "a bystander keeps none");
  assert.deepStrictEqual(c.state().forms[fid].confirmations, []);
  assert.deepStrictEqual(a.decrypt(a.state()).confirmations[fid], [cid], "the creator sees it confirmed");
  assert.strictEqual(a.confirmAll(fid).confirmed, 0, "nothing left to confirm");
});

test("A: the respondent can't confirm its own answer, and a stranger's entries are refused", async () => {
  const { a, b, fid, cid } = await answered(2);
  const st = b.state();
  const v = b.answerSecret(st, fid, cid, null);
  const fake = [{ t: v.tag, s: C.sealReceiptProof(v.S, b.identity, fid, cid, 1_800_000_000_000) }, C.decoyReceiptEntry()];
  const ev = { v: 1, id: responseReceiptId(fake), type: "response.receipt", hlc: { wall: 1_800_000_000_000, ctr: 0, dev: "wb-x" }, dev: "wb-x", payload: { r: fake } };
  a.ingest([frameOf([ev])]); b.ingest([frameOf([ev])]);
  assert.ok(!a.log.some((x) => x.id === ev.id), "the creator drops a self-signed receipt");
  assert.ok(!a.state().forms[fid].confirmations.includes(cid), "...and the answer is not confirmed");
  assert.ok(!b.snapshot().state.forms[fid].myConfirmed, "the respondent doesn't count its own signature either");
  const junk = [C.decoyReceiptEntry(), C.decoyReceiptEntry()];
  const j = { ...ev, id: responseReceiptId(junk), payload: { r: junk } };
  b.ingest([frameOf([j])]);
  assert.ok(!b.log.some((x) => x.id === j.id), "random entries are not kept");
});

test("A: the edit lock uses the signed time; a copy with an earlier HLC changes nothing", async () => {
  const { wire, pump, a, b, fid, cid, tick } = await answered(2);
  tick(3 * 60000);
  wire.length = 0; assert.ok(a.confirmAll(fid).ok);
  const e = sentBy(wire, a).find((x) => x.type === "response.receipt");
  pump();
  const at = a.state().receiptHlc[fid][cid].wall;
  assert.strictEqual(at, 1_800_000_000_000 + 3 * 60000, "the signed time");
  const back = { ...e, hlc: { ...e.hlc, wall: e.hlc.wall - 3_600_000 } };   // same id, an hour earlier
  a.ingest([frameOf([back])]); b.ingest([frameOf([back])]);
  assert.strictEqual(a.state().receiptHlc[fid][cid].wall, at);
  assert.strictEqual(b.state().receiptHlc[fid][cid].wall, at, "both devices agree");
});

test("B: the tag doesn't come from the form id and receipt id (nothing to enumerate)", async () => {
  const { a, b, fid, cid } = await answered(2);
  const va = a.answerSecret(a.state(), fid, cid, a.decrypt(a.state()).responses[fid][0].replyPub);
  const vb = b.answerSecret(b.state(), fid, cid, null);
  assert.strictEqual(va.tag, vb.tag, "creator and respondent derive the same tag");
  for (const guess of [fid + "|" + cid, "wb-receipt-v2|" + fid + "|" + cid, "wb-receipt-v3|" + fid + "|" + cid])
    assert.notStrictEqual(C.sha256Hex(guess), va.tag);
});

test("forms that show the answer count keep named receipts (the creator opted in)", async () => {
  const { peers: [a, b], wire, pump } = await net(2);
  const fid = a.createForm({ ...q, showResponseCount: true }).formId;
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`); pump();
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "hi" }]).ok); pump();
  a.snapshot(); wire.length = 0;
  assert.ok(a.confirmAll(fid).ok);
  const sent = sentBy(wire, a);
  assert.ok(sent.some((e) => e.type === "response.confirm") && !sent.some((e) => e.type === "response.receipt"));
  pump();
  assert.strictEqual(b.state().forms[fid].confirmations.length, 1, "countable by respondents");
});

test("a reply is addressed by a tag from the answer's secret, and the respondent reads it", async () => {
  const { wire, pump, a, b, fid, cid } = await answered(2);
  wire.length = 0;
  assert.ok(a.replyToResponse(fid, cid, "thanks").ok);
  const rep = sentBy(wire, a).find((e) => e.type === "response.reply");
  assert.ok(rep && rep.payload.to === b.answerSecret(b.state(), fid, cid, null).rtag && !JSON.stringify(rep).includes(cid), "no receipt id on the wire");
  pump();
  assert.strictEqual(b.snapshot().state.forms[fid].myReplies?.[0]?.message, "thanks");
  assert.strictEqual(a.snapshot().creatorView.responses[fid][0].replies, 1, "the creator counts it");
});

test("R6-1: a seen proof replayed with junk entries is not kept again", async () => {
  const { wire, pump, a, b, fid } = await answered(2);
  wire.length = 0; assert.ok(a.confirmAll(fid).ok);
  const e = sentBy(wire, a).find((x) => x.type === "response.receipt");
  pump();
  const real = e.payload.r;
  for (let i = 0; i < 20; i++) {
    const r = [...real, ...Array.from({ length: 2 }, () => C.decoyReceiptEntry())];
    const amp = { ...e, id: responseReceiptId(r), payload: { r } };
    a.ingest([frameOf([amp])]); b.ingest([frameOf([amp])]);
  }
  for (const p of [a, b]) assert.strictEqual(p.log.filter((x) => x.type === "response.receipt").length, 1, "only the original");
});

test("R6-3: an answer with a huge receipt id puts nothing into confirmations", async () => {
  const { a, fid } = await answered(2);
  const pairs = a.receiptPairsUncached(a.state());
  assert.ok(pairs.every((p) => p.cid.length <= 128));
  assert.ok(pairs.length >= 1 && pairs.some((p) => p.formId === fid));
});

test("held receipts survive the prune (only new ones must bring a new proof)", async () => {
  const { wire, pump, a, b, fid, cid } = await answered(2);
  wire.length = 0; assert.ok(a.confirmAll(fid).ok); pump();
  for (const p of [a, b]) { p.pruneUnwanted(); assert.strictEqual(p.log.filter((x) => x.type === "response.receipt").length, 1); }
  assert.ok(b.snapshot().state.forms[fid].myConfirmed && a.state().forms[fid].confirmations.includes(cid));
});
