// ADR 0026: blinded receipts and reply addresses on the phone; the C++ e2e "scenario C" checks the core
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient } from "../src/client.mjs";
import { receiptTag, replyTag, responseReceiptId } from "../../contract/src/events.mjs";

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
  return { peers, wire, pump };
}
const sentBy = (wire, p) => wire.filter((m) => m.from === p).flatMap((m) => JSON.parse(new TextDecoder().decode(m.bytes)).events || []);

test("a receipt names no form, author or device; the respondent recognises it, a bystander keeps nothing", async () => {
  const { peers: [a, b, c], wire, pump } = await net(3);
  const fid = a.createForm(q).formId;
  for (const p of [b, c]) p.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  pump();
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "hi" }]).ok); pump();
  a.snapshot();
  wire.length = 0;
  assert.ok(a.confirmAll(fid).ok);
  a.drain?.();
  const rc = sentBy(wire, a).filter((e) => e.type === "response.receipt");
  const cid = b.myAnswers[fid].confirmationId;
  assert.strictEqual(rc.length, 1);
  assert.deepStrictEqual(rc[0].payload, { tags: [receiptTag(fid, cid)] });
  assert.ok(!rc[0].sig && !rc[0].pub && rc[0].dev !== a.deviceId && rc[0].id === responseReceiptId(rc[0].payload.tags));
  assert.ok(!JSON.stringify(rc[0]).includes(fid) && !JSON.stringify(rc[0]).includes(a.identity.address.slice(2)), "neither the form id nor the creator appear");
  pump();
  assert.ok(b.snapshot().state.forms[fid].myConfirmed, "the respondent sees its receipt");
  assert.ok(!c.log.some((e) => e.type === "response.receipt"), "a bystander keeps no receipt");
  assert.deepStrictEqual(c.state().forms[fid].confirmations, [], "...and counts none");
  assert.deepStrictEqual(a.decrypt(a.state()).confirmations[fid], [cid], "the creator sees it confirmed");
  assert.strictEqual(a.confirmAll(fid).confirmed, 0, "nothing left to confirm");
});

test("a stranger's receipt with made-up tags is dropped; without the sealed id nobody can confirm an answer", async () => {
  const { peers: [a, b], pump } = await net(2);
  const fid = a.createForm(q).formId;
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`); pump();
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "hi" }]).ok); pump();
  const tags = [receiptTag(fid, "0000000000000000")];
  const fake = { v: 1, id: responseReceiptId(tags), type: "response.receipt", hlc: { wall: 1_800_000_000_000, ctr: 0, dev: "wb-x" }, dev: "wb-x", payload: { tags } };
  b.ingest([new TextEncoder().encode(JSON.stringify({ v: 2, type: "EVENTS", events: [fake] }))]);
  assert.ok(!b.log.some((e) => e.id === fake.id) && !b.snapshot().state.forms[fid].myConfirmed);
  const signed = { ...fake, pub: "02" + "11".repeat(32), sig: "00" };
  b.ingest([new TextEncoder().encode(JSON.stringify({ v: 2, type: "EVENTS", events: [signed] }))]);
  assert.ok(!b.log.some((e) => e.id === fake.id), "a signed receipt is refused (it would name its sender)");
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

test("a reply is addressed by a tag, and the respondent reads it", async () => {
  const { peers: [a, b], wire, pump } = await net(2);
  const fid = a.createForm(q).formId;
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`); pump();
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "hi" }]).ok); pump();
  a.snapshot(); wire.length = 0;
  const cid = b.myAnswers[fid].confirmationId;
  assert.ok(a.replyToResponse(fid, cid, "thanks").ok);
  const rep = sentBy(wire, a).find((e) => e.type === "response.reply");
  assert.ok(rep && rep.payload.to === replyTag(fid, cid) && !JSON.stringify(rep).includes(cid), "the reply doesn't carry the receipt id");
  pump();
  assert.strictEqual(b.snapshot().state.forms[fid].myReplies?.[0]?.message, "thanks");
  assert.strictEqual(a.decrypt(a.state()).responses[fid].length, 1);
});
