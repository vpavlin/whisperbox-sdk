// open-review 2026-11-03 (the 0.5.4 re-review, fixed in 0.5.5): the phone side of the fixes the C++
// e2e tests in its "open-review 2026-11-03" block.
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient } from "../src/client.mjs";
import * as C from "../../contract/src/crypto-portable.mjs";
import { responseSubmitId } from "../../contract/src/events.mjs";

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); }, m }; };
const bytes = (s) => new TextEncoder().encode(s);
const frame = (ev) => bytes(JSON.stringify({ v: 1, type: "EVENT", event: ev }));

async function creator() {
  const a = new WhisperboxClient({ store: mem(), send: async () => {} });
  await a.init(); a.onConnected();
  const fid = a.createForm({ title: "r5", questions: [{ id: "q", type: "text", text: "?" }] }).formId;
  return { a, fid };
}

test("FR-3: an answer with no network time first seen after the close doesn't count, whatever its HLC", async () => {
  const { a, fid } = await creator();
  assert.ok(a.closeForm(fid).ok);
  const hex = C.toHex(C.sealToCreator(null, a.state().forms[fid].publicKey, JSON.stringify({ formId: fid, respondent: "0x" + "3".repeat(40), answers: [], signature: null })));
  a.ingest([frame({ v: 1, id: responseSubmitId(hex), type: "response.submit", hlc: { wall: Date.now() - 3600000, ctr: 0, dev: "x" }, dev: "x", payload: { encryptedPayload: hex } })]);
  const v = a.decrypt(a.state());
  assert.strictEqual((v.responses[fid] || []).length, 0);
  assert.ok(v.dropped.reasons["form-closed"] >= 1);
});

test("FR-3: a held answer is never replaced by a copy with another HLC", async () => {
  const { a, fid } = await creator();
  const hex = C.toHex(C.sealToCreator(null, a.state().forms[fid].publicKey, JSON.stringify({ formId: fid, respondent: "0x" + "4".repeat(40), answers: [], signature: null })));
  const ev = { v: 1, id: responseSubmitId(hex), type: "response.submit", hlc: { wall: Date.now(), ctr: 0, dev: "x" }, dev: "x", payload: { encryptedPayload: hex } };
  a.ingest([frame(ev)]);
  a.ingest([frame({ ...ev, hlc: { wall: 1, ctr: 0, dev: "x" } })]);
  assert.strictEqual(a.log.find((e) => e.id === ev.id).hlc.wall, ev.hlc.wall);
});

test("FR-1: a signed event replaced by a larger, earlier copy is charged its size", async () => {
  const { a } = await creator();
  const z = C.identityFromPriv(C.toHex(C.utf8Encode("r5".padEnd(32, "z"))).slice(0, 64));
  const base = { v: 1, id: "update:ghost5:n", type: "form.update", dev: "z", payload: { formId: "ghost5", author: z.address, form: { title: "s" } } };
  const sign = (ev) => ({ ...ev, ...C.signEvent(z, ev) });
  const now = Date.now();
  a.importForm(`whisperbox://form?id=ghost5&by=${z.address}`);   // a form a opened: only those are kept (Václav 2026-11-13)
  const small = sign({ ...base, hlc: { wall: now, ctr: 9, dev: "z" } });
  const big = sign({ ...base, hlc: { wall: now, ctr: 1, dev: "z" }, payload: { ...base.payload, form: { title: "s", description: "L".repeat(60000) } } });
  a.ingest([frame(small)]); a.ingest([frame(big)]);
  const sum = a.log.reduce((n, e) => n + JSON.stringify(e).length, 0);
  assert.ok(a.log.some((e) => JSON.stringify(e).length > 60000), "the earlier copy replaced it");
  assert.strictEqual(a.logBytes, sum);
});

test("FR-6: forged signatures cost budget before they are verified", async () => {
  const { a } = await creator();
  const z = C.identityFromPriv(C.toHex(C.utf8Encode("r6".padEnd(32, "z"))).slice(0, 64));
  const sig0 = a.diag.admDropSig;
  for (let i = 0; i < 800; i++) {
    a.ingest([frame({ v: 1, id: `close:forged${i}:n`, type: "form.close", hlc: { wall: Date.now(), ctr: i, dev: "z" }, dev: "z",
      payload: { formId: `forged${i}`, author: z.address }, pub: z.pubHex, sig: "1".repeat(128) })]);
  }
  assert.ok(a.diag.admDropBudget > 0 && a.diag.admDropSig - sig0 < 800, JSON.stringify(a.diag));
});
