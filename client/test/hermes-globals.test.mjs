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
  for (const c of [a, b]) c.tick();
  assert.strictEqual((a.lastError || "") + (b.lastError || ""), "", "no swallowed errors");
});

test.after(() => { globalThis.Buffer = saved.Buffer; globalThis.TextDecoder = saved.TextDecoder; });
