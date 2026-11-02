// open-review 2026-11-01 (the 0.5.2 re-review): the phone side of the fixes the C++ e2e tests in its
// "open-review 2026-11-01" block. Same rules on both engines, so they keep the same event set and view.
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient, netMsOf, wellFormedQuestion, MAX_CLOCK_LEAD_MS } from "../src/client.mjs";
import { sanitizeAnswers } from "../../engine/src/engine.mjs";
import * as C from "../../contract/src/crypto-portable.mjs";
import { responseSubmitId } from "../../contract/src/events.mjs";

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); }, m }; };
const bytes = (s) => new TextEncoder().encode(s);

async function pair() {
  const wire = [];
  const a = new WhisperboxClient({ store: mem(), send: async (x) => { wire.push(["a", x]); } });
  const b = new WhisperboxClient({ store: mem(), send: async (x) => { wire.push(["b", x]); } });
  await a.init(); await b.init(); a.onConnected(); b.onConnected();
  const pump = () => { while (wire.length) { const [from, m] = wire.shift(); (from === "a" ? b : a).ingest([m]); } };
  const fid = a.createForm({ title: "r3", questions: [{ id: "q", type: "text", text: "?" }] }).formId;
  a.catchupRound(); b.catchupRound(); pump(); pump();
  return { a, b, fid, pump };
}
// an unsigned answer sealed to the form's key, as any peer can send one
const forged = (a, fid, plain) => {
  const hex = C.toHex(C.sealToCreator(null, a.state().forms[fid].publicKey, JSON.stringify(plain)));
  const ev = { v: 1, id: responseSubmitId(hex), type: "response.submit", hlc: { wall: Date.now(), ctr: 0, dev: "x" }, dev: "x", payload: { encryptedPayload: hex } };
  return { hex, ev, frame: bytes(JSON.stringify({ v: 1, type: "EVENT", event: ev })) };
};

test("FR-2: malformed decrypted answer rows are dropped; the CSV still exports", async () => {
  const { a, fid } = await pair();
  a.ingest([forged(a, fid, { formId: fid, respondent: "0x" + "6".repeat(40), signature: null,
    answers: [5, { questionId: 7 }, { questionId: "q", value: { a: { b: 1 } } }, { questionId: "q", value: "kept" }] }).frame]);
  const r = a.decrypt(a.state()).responses[fid];
  assert.strictEqual(r.length, 1);
  assert.deepStrictEqual(r[0].answers, [{ questionId: "q", value: "kept" }]);
  const csv = a.exportCsv(fid);
  assert.ok(csv.ok && csv.csv.includes("kept"));
  assert.deepStrictEqual(sanitizeAnswers("x"), []);
  assert.strictEqual(sanitizeAnswers([{ questionId: "é".repeat(65), value: 1 }]).length, 0, "the id limit is in bytes, as the core");
});

test("FR-3: the snapshot counts the sealed answers instead of carrying them", async () => {
  const { a, fid } = await pair();
  a.ingest([forged(a, fid, { formId: fid, respondent: "0x" + "1".repeat(40), answers: [], signature: null }).frame]);
  const s = a.snapshot();
  assert.ok(!("responses" in s.state));
  assert.strictEqual(s.state.responseCount, 1);
});

test("FR-5: a second link naming another creator doesn't replace the pin", async () => {
  const { a, b, fid } = await pair();
  assert.ok(b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`).ok);
  const r = b.importForm(`whisperbox://form?id=${fid}&by=0x${"5".repeat(40)}`);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(b.pins[fid], a.identity.address);
  b.forgetForm(fid);
  assert.ok(b.importForm(`whisperbox://form?id=${fid}&by=0x${"5".repeat(40)}`).ok, "after removing the form, a new link pins again");
});

test("FR-6: a network time further than 5 minutes from our clock, either way, is no time", () => {
  const N = 1_800_000_000_000;
  assert.strictEqual(netMsOf({ tsMs: N - 3600_000 }, N), 0);
  assert.strictEqual(netMsOf({ tsMs: N - MAX_CLOCK_LEAD_MS + 1000 }, N), N - MAX_CLOCK_LEAD_MS + 1000);
  assert.strictEqual(netMsOf({ tsMs: 1_000_000_000_001 }, N), 0, "2001");
});

test("FR-7: a scale is whole numbers, min <= max, at most 100 steps", () => {
  const q = (min, max) => ({ id: "s", type: "scale", min, max });
  assert.ok(wellFormedQuestion(q(0, 10)) && wellFormedQuestion({ id: "s", type: "scale" }));
  assert.ok(!wellFormedQuestion(q(0, 1_000_000)));
  assert.ok(!wellFormedQuestion(q(5, 1)));
  assert.ok(!wellFormedQuestion(q(0.5, 3)));
  assert.ok(wellFormedQuestion({ id: "n", type: "number", min: 0, max: 1_000_000 }), "number questions keep their range");
});

test("FR-8: an unsigned answer claiming an address gets no receipt", async () => {
  const { a, b, fid } = await pair();
  a.ingest([forged(a, fid, { formId: fid, respondent: b.identity.address, answers: [], signature: null, confirmationId: "fakecid" }).frame]);
  const r = a.confirmResponse(fid, b.identity.address);
  assert.strictEqual(r.ok, false);
  assert.ok(/isn't signed/.test(r.error));
  assert.ok(!(a.state().forms[fid].confirmations || []).includes("fakecid"));
});

test("FR-10: an upper-case copy of a sealed answer is refused", async () => {
  const { a, fid } = await pair();
  const { hex } = forged(a, fid, { formId: fid, respondent: "0x" + "2".repeat(40), answers: [], signature: null });
  const up = hex.toUpperCase();
  const ev = { v: 1, id: responseSubmitId(up), type: "response.submit", hlc: { wall: Date.now(), ctr: 0, dev: "x" }, dev: "x", payload: { encryptedPayload: up } };
  const before = a.log.length;
  a.ingest([bytes(JSON.stringify({ v: 1, type: "EVENT", event: ev }))]);
  assert.strictEqual(a.log.length, before);
});

test("FR-3: answers from the network have a budget", async () => {
  const { a, fid } = await pair();
  const pub = a.state().forms[fid].publicKey;
  for (let i = 0; i < 650; i++) {
    const hex = C.toHex(C.sealToCreator(null, pub, JSON.stringify({ formId: fid, n: i })));
    const ev = { v: 1, id: responseSubmitId(hex), type: "response.submit", hlc: { wall: Date.now(), ctr: 0, dev: "x" }, dev: "x", payload: { encryptedPayload: hex } };
    a.ingest([bytes(JSON.stringify({ v: 1, type: "EVENT", event: ev }))]);
  }
  assert.ok(a.diag.admDropBudget > 0, JSON.stringify({ d: a.diag, n: a.logResponses, e: a.lastError }));
  assert.ok(a.logResponses < 650, "fewer than all 650 taken (600 at once, then 10 a second)");
});
