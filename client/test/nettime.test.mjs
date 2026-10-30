// ADR 0019: a creator judges close/expiry/cap by the network's timestamp of an answer (the earliest
// copy it saw), not by the HLC the respondent's device chose.
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient, netMsOf } from "../src/client.mjs";

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); }, m }; };
const N = 1_800_000_000_000;

test("netMsOf: ns or ms, nothing for none, nonsense or far future", () => {
  assert.strictEqual(netMsOf({ ts: (N + 5) * 1e6 }, N), N + 5);
  assert.strictEqual(netMsOf({ ts: 0, tsMs: N }, N), N);
  assert.strictEqual(netMsOf({ ts: 0 }, N), 0);
  assert.strictEqual(netMsOf(undefined, N), 0);
  assert.strictEqual(netMsOf({ tsMs: 12345 }, N), 0);
  assert.strictEqual(netMsOf({ tsMs: N + 3600_000 }, N), 0);
});

test("a backdated answer the network saw after the close is out; an earlier copy brings it back", async () => {
  let tA = N, tB = N;
  const wire = [];
  const store = mem();
  const a = new WhisperboxClient({ store, send: async (x) => { wire.push(["a", x]); }, now: () => tA });
  const b = new WhisperboxClient({ store: mem(), send: async (x) => { wire.push(["b", x]); }, now: () => tB });
  await a.init(); await b.init(); a.onConnected(); b.onConnected();
  const pump = (meta) => { const out = []; while (wire.length) { const [from, m] = wire.shift(); if (from === "a") b.ingest([m]); else { out.push(m); a.ingest([m], meta); } } return out; };
  const fid = a.createForm({ title: "deadline", questions: [{ id: "q1", type: "text", text: "?", required: true }] }).formId;
  b.joinForm?.(fid); a.catchupRound(); b.catchupRound(); pump(); pump();
  assert.ok(b.state().forms[fid], "b has the form");

  tA = N + 10_000; assert.ok(a.closeForm(fid).ok);   // b is offline: never sees the close
  wire.length = 0;
  tB = N + 5_000;                                    // b's device claims "before the close"
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);   // answers need the creator a link names (FR-3)
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "late" }]).ok);
  const sent = pump({ ts: (N + 20_000) * 1e6, source: "live", bearer: "delivery" });   // the network had it at +20 s
  assert.ok(sent.length >= 1);
  const view = () => a.decrypt(a.state());
  assert.strictEqual((view().responses[fid] || []).length, 0, "dropped: the network saw it after the close");
  assert.strictEqual(view().dropped.reasons["form-closed"], 1);

  // the store's copy of the original publish: earlier
  for (const m of sent) a.ingest([m], { ts: 0, tsMs: N + 8_000, source: "history" });
  const r = view().responses[fid];
  assert.strictEqual(r.length, 1, "the earlier network time puts it before the close");
  assert.strictEqual(r[0].timeVerified, true); assert.strictEqual(r[0].receivedAt, N + 8_000);
  // a later copy (re-served during catch-up) doesn't move it back
  for (const m of sent) a.ingest([m], { tsMs: N + 60_000 });
  assert.strictEqual(view().responses[fid][0].receivedAt, N + 8_000);
  assert.ok(String(await store.get("wb-nettime")).includes(String(N + 8_000)), "kept across restarts");
});

test("without network time the answer keeps its HLC and is marked unverified time", async () => {
  const wire = [];
  const a = new WhisperboxClient({ store: mem(), send: async (x) => { wire.push(["a", x]); } });
  const b = new WhisperboxClient({ store: mem(), send: async (x) => { wire.push(["b", x]); } });
  await a.init(); await b.init(); a.onConnected(); b.onConnected();
  const pump = () => { while (wire.length) { const [from, m] = wire.shift(); (from === "a" ? b : a).ingest([m]); } };
  const fid = a.createForm({ title: "ble", questions: [{ id: "q1", type: "text", text: "?", required: true }] }).formId;
  a.catchupRound(); b.catchupRound(); pump(); pump();
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);   // answers need the creator a link names (FR-3)
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "x" }]).ok); pump();
  const r = a.decrypt(a.state()).responses[fid];
  assert.strictEqual(r.length, 1); assert.strictEqual(r[0].timeVerified, false); assert.strictEqual(r[0].receivedAt, null);
});
