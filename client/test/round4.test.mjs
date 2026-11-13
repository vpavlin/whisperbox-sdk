// open-review 2026-11-02 (the 0.5.3 re-review, fixed in 0.5.4): the phone side of the fixes the C++
// e2e tests in its "open-review 2026-11-02" block.
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient } from "../src/client.mjs";
import { validConfirmationId } from "../../engine/src/engine.mjs";
import * as C from "../../contract/src/crypto-portable.mjs";
import { responseSubmitId } from "../../contract/src/events.mjs";

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); }, m }; };
const bytes = (s) => new TextEncoder().encode(s);

async function pair() {
  // a fake Store: every frame sent stays here; opening a link pulls it (a node keeps only forms it opened)
  const wire = [], kept = [];
  const pull = (c) => () => { for (const m of kept) c.ingest([m], { source: "history" }); };
  const a = new WhisperboxClient({ store: mem(), send: async (x) => { wire.push(["a", x]); kept.push(x); }, pull: () => pull(a)() });
  const b = new WhisperboxClient({ store: mem(), send: async (x) => { wire.push(["b", x]); kept.push(x); }, pull: () => pull(b)() });
  await a.init(); await b.init(); a.onConnected(); b.onConnected();
  const pump = () => { while (wire.length) { const [from, m] = wire.shift(); (from === "a" ? b : a).ingest([m]); } };
  const fid = a.createForm({ title: "r4", questions: [{ id: "q", type: "textarea", text: "?" }] }).formId;
  /* wire v2: the creator sent the form state on create */ pump(); pump();
  return { a, b, fid, pump, wire };
}
const answerFrame = (a, fid, plain) => {
  const hex = C.toHex(C.sealToCreator(null, a.state().forms[fid].publicKey, JSON.stringify(plain)));
  const ev = { v: 1, id: responseSubmitId(hex), type: "response.submit", hlc: { wall: Date.now(), ctr: 0, dev: "x" }, dev: "x", payload: { encryptedPayload: hex } };
  return bytes(JSON.stringify({ v: 1, type: "EVENT", event: ev }));
};

test("FR-12: the inner message is JSON.stringify's text (same literal as the C++ e2e)", () => {
  const msg = C.innerMessage({ formId: "f", respondent: "0xab", submittedAt: 1, answers: [{ questionId: "q", value: 1e-7 }, { questionId: "r", value: 1e20 }] });
  assert.strictEqual(msg, 'whisperbox-inner-v1|{"formId":"f","respondent":"0xab","submittedAt":1,"answers":[{"questionId":"q","value":1e-7},{"questionId":"r","value":100000000000000000000}]}');
});

test("FR-9: a receipt id over 128 bytes is dropped from the answer", async () => {
  assert.ok(validConfirmationId("c".repeat(128)) && !validConfirmationId("c".repeat(129)) && !validConfirmationId("") && !validConfirmationId(5));
  const { a, fid } = await pair();
  a.ingest([answerFrame(a, fid, { formId: fid, respondent: "0x" + "1".repeat(40), answers: [], signature: null, confirmationId: "c".repeat(100000) })]);
  const r = a.decrypt(a.state()).responses[fid];
  assert.strictEqual(r.length, 1);
  assert.strictEqual(r[0].confirmationId, null);
});

test("FR-6: a replayed answer counts against the budget", async () => {
  const { a, fid } = await pair();
  const f = answerFrame(a, fid, { formId: fid, respondent: "0x" + "2".repeat(40), answers: [], signature: null });
  for (let i = 0; i < 700; i++) a.ingest([f]);
  assert.ok(a.diag.rxDup > 0 && a.diag.admDropBudget > 0, JSON.stringify(a.diag));
});

test("FR-4 / ADR 0024: v1 catch-up frames are ignored; EVENTS frames have a frame budget", async () => {
  const { a } = await pair();
  const sent0 = a.diag.txTotal;
  for (let i = 0; i < 200; i++) a.ingest([bytes(JSON.stringify({ v: 2, t: "fp", from: "flood", bounds: [], fps: ["00000000000000000000000000000000"] }))]);
  assert.strictEqual(a.diag.txTotal, sent0, "nothing answered");
  const ev = bytes(JSON.stringify({ v: 2, type: "EVENTS", events: [] }));
  for (let i = 0; i < 200; i++) a.ingest([ev]);
  assert.ok((a.diag.ctlDropBudget || 0) > 0, "a flood of bundle frames runs out of the frame budget");
});

test("FR-5/FR-7: the snapshot carries only the forms this device shows", async () => {
  const { a, b, fid } = await pair();
  // Václav 2026-11-13: a form this device never opened isn't even stored (it used to be held, unshown)
  assert.ok(!b.state().forms[fid], "b doesn't keep a form it never opened, though it came over the topic");
  assert.ok(!b.snapshot().state.forms[fid] && !b.snapshot().state.feed.includes(fid), "...and doesn't show it");
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  assert.ok(b.snapshot().state.forms[fid].canRespond, "opened: shown");
});

test("FR-10/FR-11: oversized answers and link-breaking ids are refused", async () => {
  const { a, b, fid } = await pair();
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  const r = b.submitResponse(fid, [{ questionId: "q", value: "y".repeat(300000) }]);
  assert.strictEqual(r.ok, false);
  assert.ok(/too long/.test(r.error));
  assert.ok(!b.snapshot().state.forms[fid].mySubmitted, "not kept as sent");
  assert.strictEqual(a.createForm({ id: "x&y", title: "amp", questions: [{ id: "q", type: "text", text: "?" }] }).ok, false);
});

test("FR-13: forgetting a form drops its pin, so the right link opens it", async () => {
  const { a, b, fid } = await pair();
  b.importForm(`whisperbox://form?id=${fid}&by=0x${"7".repeat(40)}`);
  assert.ok(b.snapshot().state.forms[fid].linkMismatch);
  assert.ok(b.forgetForm(fid).ok);
  assert.ok(b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`).ok);
  assert.ok(b.snapshot().state.forms[fid].canRespond && !b.snapshot().state.forms[fid].linkMismatch);
});
