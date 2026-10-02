// The phone's JS engine (Hermes) has no Node globals. Run the client's whole flow with them
// REMOVED, then with exactly the polyfills the app installs (mobile/index.ts), so a Node-only
// dependency fails here instead of crashing on a phone (it did: loam-sync used Buffer).
import test from "node:test";
import assert from "node:assert";

const saved = { Buffer: globalThis.Buffer, TextDecoder: globalThis.TextDecoder };
delete globalThis.Buffer;
delete globalThis.TextDecoder;
// mobile/index.ts polyfills (crypto.getRandomValues exists in Node already):
const { Buffer: BufferPoly } = await import("buffer");
globalThis.Buffer = BufferPoly;
const { WhisperboxClient } = await import("../src/client.mjs");

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); } }; };

test("client flows run with only the app's polyfills (Hermes-like globals)", async () => {
  assert.strictEqual(globalThis.TextDecoder, undefined, "TextDecoder really removed");
  const wire = [];
  const a = new WhisperboxClient({ store: mem(), send: async (b) => { wire.push(b); } });
  const b = new WhisperboxClient({ store: mem(), send: async (x) => { wire.push(x); } });
  await a.init(); await b.init(); a.onConnected(); b.onConnected();
  const pump = () => { while (wire.length) { const m = wire.shift(); a.ingest([m]); b.ingest([m]); } };
  const fid = a.createForm({ title: "Ünïcode ✓", questions: [{ id: "q1", type: "text", text: "?", required: true }] }).formId;
  a.catchupRound(); b.catchupRound(); pump();                  // RBSR fingerprints (the crash site)
  assert.ok(b.snapshot().state.forms[fid], "b reconciled a's form via RBSR");
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "žluťoučký" }]).ok); pump();
  assert.strictEqual(a.snapshot().creatorView.responses[fid][0].answers[0].value, "žluťoučký");
  assert.ok(a.confirmResponse(fid, b.identity.address).ok); pump();
  assert.ok(b.snapshot().state.forms[fid].myConfirmed);
  // hide (local) + my own answers kept
  assert.ok(b.hideForm(fid).ok && b.snapshot().state.forms[fid].hidden && b.snapshot().hidden.includes(fid));
  assert.ok(!a.snapshot().state.forms[fid].hidden, "hiding is local");
  assert.strictEqual(b.snapshot().state.forms[fid].myAnswers.answers[0].value, "žluťoučký");
  assert.ok(b.unhideForm(fid).ok && !b.snapshot().state.forms[fid].hidden);
  // 0.3.2: drafts, scheduled publish, answer drafts, cap auto-close, automatic receipts
  const d = a.saveDraft({ def: { title: "Later", questions: [{ id: "q1", type: "boolean", text: "?", required: true }] }, publishAt: a.now() - 1 });
  assert.ok(d.ok && a.snapshot().drafts.length === 1);
  a.lastHousekeep = 0; a.tick(); pump();
  assert.strictEqual(a.snapshot().drafts.length, 0, "due scheduled draft published by tick");
  const later = Object.values(b.snapshot().state.forms).find((f) => f.title === "Later");
  assert.ok(later, "scheduled form reached the other device");
  b.saveAnswerDraft(later.id, [{ questionId: "q1", value: true }]);
  assert.strictEqual(b.snapshot().state.forms[later.id].answerDraft[0].value, true);
  const capped = a.createForm({ title: "Cap 1", maxResponses: 1, questions: [{ id: "q1", type: "boolean", text: "?", required: true }] }).formId;
  a.setAutoReceipts(capped, true); pump();
  assert.ok(b.submitResponse(capped, [{ questionId: "q1", value: false }]).ok); pump();
  a.lastHousekeep = 0; a.tick(); pump();
  assert.strictEqual(b.snapshot().state.forms[capped].status, "closed", "auto-closed at the cap");
  assert.ok(b.snapshot().state.forms[capped].myConfirmed, "automatic receipt");
  for (const c of [a, b]) c.tick();
  assert.strictEqual((a.lastError || "") + (b.lastError || ""), "", "no swallowed errors");
});

test.after(() => { globalThis.Buffer = saved.Buffer; globalThis.TextDecoder = saved.TextDecoder; });
