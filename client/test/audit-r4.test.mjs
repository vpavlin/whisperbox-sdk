// Audit round 4 (proteus/auditor, 2026-11-13): R4-1, R4-3, R4-5 on the phone; the C++ e2e "round 4" block
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient } from "../src/client.mjs";
import * as C from "../../contract/src/crypto-portable.mjs";
import { responseSubmitId } from "../../contract/src/events.mjs";

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); } }; };
const frame = (ev) => new TextEncoder().encode(JSON.stringify({ v: 1, type: "EVENT", event: ev }));
const q = { title: "r4", questions: [{ id: "q1", type: "textarea", text: "?", required: true }] };
const signed = (id, ev) => ({ ...ev, ...C.signEvent(id, ev) });
const keyOf = (s) => C.identityFromPriv(C.toHex(C.utf8Encode(s.padEnd(32, "z"))).slice(0, 64));
async function client() { const c = new WhisperboxClient({ store: mem(), msgsPerEpoch: 1e6, send: async () => {} }); await c.init(); c.onConnected(); return c; }

test("R4-1/R6-5: an invitation without the creator's link is only listed, not acceptable, and pins no one", async () => {
  const r = await client();
  const x = keyOf("stranger"), fid = "form-b0b0b0b0";
  r.ingest([frame(signed(x, { v: 1, id: `coowner:${fid}:${r.identity.address}`, type: "form.coowner", hlc: { wall: Date.now(), ctr: 0, dev: "x" }, dev: "x",
    payload: { formId: fid, author: x.address, owner: r.identity.address, sealedKey: "00" } }))]);
  assert.ok(r.snapshot().coInvites.find((i) => i.formId === fid)?.needsLink, "listed as needing the creator's link (R6-5)");
  assert.ok(!r.acceptCoOwner(fid).ok, "...and not acceptable without it (R5-1, R6-5)");
  assert.ok(!r.pins[fid], "nothing pinned");
});

test("R4-3: a live copy never re-dates an answer a Store already dated", async () => {
  const a = await client();
  const fid = a.createForm(q).formId, pub = a.state().forms[fid].publicKey;
  const hex = C.toHex(C.sealToCreator(null, pub, JSON.stringify({ formId: fid })));
  const t = Date.now();
  const ev = { v: 1, id: responseSubmitId(hex), type: "response.submit", hlc: { wall: t - 3_600_000, ctr: 0, dev: "x" }, dev: "x", payload: { encryptedPayload: hex } };
  a.ingest([frame(ev)], { tsMs: t - 3_600_000, source: "history" });
  a.ingest([frame(ev)], { tsMs: t + 240_000 });   // a live replay, 64 min later
  assert.strictEqual(a.netTimes[ev.id], t - 3_600_000);
});

test("R4-5: with my answers' record lost, my answer survives a log full of strangers' answers", async () => {
  const a = await client(), b = await client();
  const fid = a.createForm(q).formId;
  const st = a.state();
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);   // opened first: only opened forms are kept
  b.ingest(a.log.map((e) => frame(e)));
  // strangers' answers, as an older version stored them (received from the network: first-seen times)
  for (let i = 0; i < 2100; i++) {
    const hex = C.toHex(C.sealToCreator(null, st.forms[fid].publicKey, JSON.stringify({ formId: fid, n: i })));
    const ev = { v: 1, id: responseSubmitId(hex), type: "response.submit", hlc: { wall: 1, ctr: i, dev: "x" }, dev: "x", payload: { encryptedPayload: hex } };
    b.log.push(ev); b.firstSeen[ev.id] = Date.now();
  }
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "mine" }]).ok);
  const mine = b.myAnswers[fid].eventId;
  b.myAnswers = {};   // the record of my answers is lost
  b.pruneUnwanted();
  assert.ok(b.log.some((e) => e.id === mine), "my answer is kept");
  assert.ok(b.log.filter((e) => e.type === "response.submit").length < 100, "the strangers' answers are not");
});
