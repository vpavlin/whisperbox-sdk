// Audit round 3 (proteus/auditor, 2026-11-13): the phone side of the R3 fixes; the C++ e2e "round 3" block
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient, netMsOf } from "../src/client.mjs";
import * as C from "../../contract/src/crypto-portable.mjs";
import { responseSubmitId } from "../../contract/src/events.mjs";

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); } }; };
const bytes = (s) => new TextEncoder().encode(s);
const frame = (ev) => bytes(JSON.stringify({ v: 1, type: "EVENT", event: ev }));
const q = { title: "r3", questions: [{ id: "q1", type: "textarea", text: "?", required: true }] };
async function net(n) {
  const peers = [], wire = [];
  for (let i = 0; i < n; i++) {
    const p = new WhisperboxClient({ store: mem(), msgsPerEpoch: 1e6, send: async (b) => { wire.push({ from: p, bytes: b }); } });
    await p.init(); p.onConnected(); peers.push(p);
  }
  const pump = () => { while (wire.length) { const m = wire.shift(); for (const o of peers) if (o !== m.from) o.ingest([m.bytes]); } };
  return { peers, pump };
}
const signed = (id, ev) => ({ ...ev, ...C.signEvent(id, ev) });
const keyOf = (s) => C.identityFromPriv(C.toHex(C.utf8Encode(s.padEnd(32, "z"))).slice(0, 64));

test("R3-1: a co-owner grant signed by someone who isn't the creator is no invitation", async () => {
  const { peers: [a, r], pump } = await net(2);
  const fid = a.createForm(q).formId;
  r.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`); pump();
  const x = keyOf("x");
  r.ingest([frame(signed(x, { v: 1, id: `coowner:${fid}:${r.identity.address}`, type: "form.coowner", hlc: { wall: Date.now(), ctr: 0, dev: "x" }, dev: "x",
    payload: { formId: fid, author: x.address, owner: r.identity.address, sealedKey: "00" } }))]);
  assert.ok(!r.snapshot().coInvites.some((i) => i.formId === fid), "not shown");
  assert.ok(!r.acceptCoOwner(fid).ok, "and can't be accepted");
});

test("R3-7: a declined invitation can be accepted later; leaving a form never offered is refused", async () => {
  const { peers: [a, r], pump } = await net(2);
  const fid = a.createForm(q).formId;
  r.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`); pump();
  assert.ok(a.addCoOwner(fid, r.identity.pubHex).ok); pump();
  assert.ok(r.leaveCoOwner(fid).ok && !r.snapshot().coInvites.length, "declined");
  assert.ok(r.acceptCoOwner(fid).ok && r.snapshot().state.forms[fid].coOwner, "...accepted after all");
  assert.ok(!r.leaveCoOwner("form-0dead0be").ok, "never offered: refused");
});

test("R3-5: no creator known (bare id): a signed update by anyone isn't kept", async () => {
  const { peers: [r] } = await net(1);
  r.importForm("form-0badc0de");
  const z = keyOf("bare");
  const n0 = r.log.length;
  r.ingest([frame(signed(z, { v: 1, id: "update:form-0badc0de:j", type: "form.update", hlc: { wall: Date.now(), ctr: 0, dev: "z" }, dev: "z", payload: { formId: "form-0badc0de", author: z.address, form: { title: "junk" } } }))]);
  assert.strictEqual(r.log.length, n0);
});

test("R3-3/R3-4: Store times are clamped (never future, never before the 6 h window); the first live time is final", async () => {
  const now = 1_800_000_000_000;
  assert.strictEqual(netMsOf({ tsMs: 1041379200000, source: "history" }, now), now - 6 * 3600000, "2003 -> the window's start");
  assert.strictEqual(netMsOf({ tsMs: now + 240000, source: "history" }, now), now, "+4 min -> now");
  const { peers: [a] } = await net(1);
  const fid = a.createForm(q).formId, pub = a.state().forms[fid].publicKey;
  const hex = C.toHex(C.sealToCreator(null, pub, JSON.stringify({ formId: fid })));
  const ev = { v: 1, id: responseSubmitId(hex), type: "response.submit", hlc: { wall: Date.now(), ctr: 0, dev: "x" }, dev: "x", payload: { encryptedPayload: hex } };
  const t = Date.now();
  a.ingest([frame(ev)], { tsMs: t });
  a.ingest([frame(ev)], { tsMs: t - 240000 });   // a replay claiming 4 min earlier
  assert.strictEqual(a.netTimes[ev.id], t, "the first live time stays");
});
