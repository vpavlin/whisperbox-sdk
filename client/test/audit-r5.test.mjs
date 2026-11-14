// Audit round 5 (proteus/auditor, 2026-11-14): R5-1..R5-4 on the phone; the C++ e2e "round 5" block
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient } from "../src/client.mjs";
import * as C from "../../contract/src/crypto-portable.mjs";
import { responseSubmitId } from "../../contract/src/events.mjs";

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); } }; };
const frame = (ev) => new TextEncoder().encode(JSON.stringify({ v: 1, type: "EVENT", event: ev }));
const q = { title: "r5", questions: [{ id: "q1", type: "textarea", text: "?", required: true }] };
const signed = (id, ev) => { const { sig, pub, ...rest } = ev; return { ...rest, ...C.signEvent(id, rest) }; };
const keyOf = (s) => C.identityFromPriv(C.toHex(C.utf8Encode(s.padEnd(32, "z"))).slice(0, 64));
async function client() { const c = new WhisperboxClient({ store: mem(), msgsPerEpoch: 1e6, send: async () => {} }); await c.init(); c.onConnected(); return c; }
const evOf = (c, type, fid) => c.log.find((e) => e.type === type && (e.payload?.formId === fid || e.payload?.id === fid));
const grant = (who, fid, owner, wall) => signed(who, { v: 1, id: `coowner:${fid}:${owner}:${who.address.slice(2, 8)}`, type: "form.coowner",
  hlc: { wall, ctr: 0, dev: "x" }, dev: "x", payload: { formId: fid, author: who.address, owner, sealedKey: "00" } });

test("R5-2: a stranger's grant neither hides nor blocks the creator's invitation", async () => {
  const p = await client(), r = await client();
  const fid = p.createForm(q).formId;
  assert.ok(p.addCoOwner(fid, r.identity.pubHex).ok);
  r.ingest([frame(evOf(p, "form.coowner", fid))]); r.ingest([frame(evOf(p, "form.publish", fid))]);
  assert.strictEqual(r.snapshot().coInvites.find((i) => i.formId === fid)?.from, p.identity.address, "P's invitation is shown");
  r.ingest([frame(grant(keyOf("stranger"), fid, r.identity.address, Date.now() + 1))]);
  assert.ok(r.snapshot().coInvites.some((i) => i.formId === fid), "still shown after a stranger's grant");
  assert.ok(r.acceptCoOwner(fid).ok, "...and acceptable");
});

test("R5-1: a stranger's backdated copy makes the invitation contested; accepting needs the creator's link", async () => {
  const p = await client(), r = await client(), x = keyOf("attacker");
  const fid = p.createForm(q).formId;
  assert.ok(p.addCoOwner(fid, r.identity.pubHex).ok);
  const real = evOf(p, "form.publish", fid);
  const fake = signed(x, { ...real, hlc: { ...real.hlc, wall: real.hlc.wall - 60_000 }, payload: { ...real.payload, creator: x.address, title: "FAKE" } });
  r.ingest([frame(grant(x, fid, r.identity.address, Date.now()))]); r.ingest([frame(evOf(p, "form.coowner", fid))]);
  r.ingest([frame(fake)]); r.ingest([frame(real)]);
  const inv = r.snapshot().coInvites.find((i) => i.formId === fid);
  assert.ok(inv && inv.contested, "shown as contested");
  assert.ok(!r.acceptCoOwner(fid).ok, "can't be accepted without a link");
  r.importForm(`whisperbox://form?id=${fid}&by=${p.address ?? p.identity.address}`);
  assert.ok(r.acceptCoOwner(fid).ok, "with the creator's link it can");
  assert.strictEqual(r.state().forms[fid].creator, p.identity.address, "and the form shown is the creator's");
});

test("R5-3: a network time far from the answer's HLC is ignored; the earliest agreeing Store time wins", async () => {
  const a = await client();
  const fid = a.createForm(q).formId, pub = a.state().forms[fid].publicKey;
  const hex = C.toHex(C.sealToCreator(null, pub, JSON.stringify({ formId: fid })));
  const now = Date.now(), h = now - 3_600_000;
  const ev = { v: 1, id: responseSubmitId(hex), type: "response.submit", hlc: { wall: h, ctr: 0, dev: "x" }, dev: "x", payload: { encryptedPayload: hex } };
  a.ingest([frame(ev)], { tsMs: now - 60_000, source: "history" });
  assert.strictEqual(a.netTimes[ev.id], undefined, "a Store's time an hour from the HLC is ignored");
  a.ingest([frame(ev)], { tsMs: h + 300_000, source: "history" });
  assert.strictEqual(a.netTimes[ev.id], h + 300_000, "an agreeing one counts");
  a.ingest([frame(ev)], { tsMs: h + 60_000, source: "history" });
  assert.strictEqual(a.netTimes[ev.id], h + 60_000, "an earlier agreeing Store time corrects it");
  a.ingest([frame(ev)], { tsMs: h + 120_000, source: "history" });
  assert.strictEqual(a.netTimes[ev.id], h + 60_000, "a later one doesn't");
});

test("R5-4: with first-seen times lost too, at most 2,000 unsure answers are kept, mine among them", async () => {
  const a = await client(), b = await client();
  const fid = a.createForm(q).formId;
  const st = a.state();
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  b.ingest(a.log.map((e) => frame(e)));
  for (let i = 0; i < 2500; i++) {
    const hex = C.toHex(C.sealToCreator(null, st.forms[fid].publicKey, JSON.stringify({ formId: fid, n: i })));
    b.log.unshift({ v: 1, id: responseSubmitId(hex), type: "response.submit", hlc: { wall: 1, ctr: i, dev: "x" }, dev: "x", payload: { encryptedPayload: hex } });
  }
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "mine" }]).ok);
  const mine = b.myAnswers[fid].eventId;
  b.myAnswers = {}; b.firstSeen = {};
  b.pruneUnwanted();
  assert.ok(b.log.some((e) => e.id === mine), "my answer is kept");
  assert.ok(b.log.filter((e) => e.type === "response.submit").length <= 2000, "at most 2,000 unsure answers");
});
