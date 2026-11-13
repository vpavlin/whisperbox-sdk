// Audit of wire v2 (proteus/auditor, 2026-11-13): the phone side of the fixes; the C++ e2e
// "audit 2026-11-13 (wire v2)" block tests the same on the desktop core.
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient, wireTopicFor, netMsOf, utf8Bytes, wellFormedEvent, MAX_WIRE_EVENT_BYTES } from "../src/client.mjs";
import { wellFormedFormFields } from "../src/client.mjs";

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); } }; };
const bytes = (s) => new TextEncoder().encode(s);
const q = { title: "w2", questions: [{ id: "q1", type: "textarea", text: "?", required: true }] };

async function net(n, opts = {}) {
  let t = 1_800_000_000_000;
  const peers = [], wire = [];
  for (let i = 0; i < n; i++) {
    const p = new WhisperboxClient({ store: mem(), now: () => t, minuteMs: 60000, msgsPerEpoch: 1e6, ...opts,
      send: async (b, topic) => { if (p.offline) throw new Error("offline"); wire.push({ from: p, bytes: b, topic }); } });
    await p.init(); p.onConnected(); peers.push(p);
  }
  const pump = () => { while (wire.length) { const m = wire.shift(); for (const o of peers) if (o !== m.from && !o.offline) o.ingest([m.bytes]); } };
  const advance = (ms) => { for (let s = 0; s < ms; s += 5000) { t += 5000; for (const p of peers) p.tick(); pump(); } };
  return { peers, wire, pump, advance, now: () => t };
}

test("W2-1: nothing larger than Delivery can carry is made or sent", async () => {
  const { peers: [a, b], wire, pump } = await net(2);
  const r = a.createForm({ ...q, description: "d".repeat(60000), thankYou: "t".repeat(30000) });
  assert.ok(!r.ok && /too large to send/.test(r.error), "refused with a reason, not lost: " + JSON.stringify(r));
  const fid = a.createForm({ ...q, description: "m".repeat(65000) }).formId;
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  const sizes = wire.map((m) => Math.ceil(Math.ceil(m.bytes.length / 3) * 4 / 3) * 4);   // the transport's base64, once more
  pump();
  assert.ok(b.state().forms[fid], "a 65 KB form arrives");
  assert.ok(sizes.every((n) => n <= 153600), "every frame fits 150 KiB after base64 twice: " + Math.max(...sizes));
  assert.ok(!b.submitResponse(fid, [{ questionId: "q1", value: "a".repeat(60000) }]).ok, "an answer too large to send is refused");
  assert.strictEqual(MAX_WIRE_EVENT_BYTES, 80000);
});

test("W2-6/W2-3: an ASK from Store is never acted on; live ASKs cost the frame budget", async () => {
  const { peers: [a], wire } = await net(1);
  const fid = a.createForm(q).formId;
  wire.length = 0; a.askAnsweredAt = {};
  const ask = bytes(JSON.stringify({ v: 2, type: "ASK", formId: fid }));
  a.ingest([ask], { source: "history" });
  a.drain?.();
  assert.strictEqual(wire.length, 0, "a Store copy of an ASK makes the creator send nothing");
  const c0 = a.diag.ctlDropBudget || 0;
  for (let i = 0; i < 200; i++) a.ingest([ask]);
  assert.ok((a.diag.ctlDropBudget || 0) > c0, "a flood of live ASKs runs out of the frame budget");
});

test("W2-7: a squatted form id doesn't stop the respondent asking; the real form wins", async () => {
  const { peers: [a, x, r], pump, advance } = await net(3);
  a.offline = true;
  assert.ok(a.createForm({ ...q, id: "form-5a5a5a5a" }).ok, "the real creator (offline) makes the form");
  r.importForm(`whisperbox://form?id=form-5a5a5a5a&by=${a.identity.address}`);
  assert.ok(x.createForm({ ...q, id: "form-5a5a5a5a" }).ok, "a squatter publishes the same id");
  pump();
  assert.strictEqual(r.state().forms["form-5a5a5a5a"]?.creator, x.identity.address, "only the squatter's form so far");
  a.offline = false;
  advance(30 * 60000);
  const f = r.snapshot().state.forms["form-5a5a5a5a"];
  assert.ok(f && f.creator === a.identity.address && f.canRespond, "it kept asking; the real creator answered: " + JSON.stringify(f?.creator));
});

test("W2-8: lengths are UTF-8 bytes and the close bounds match the core", () => {
  assert.strictEqual(utf8Bytes("é"), 2); assert.strictEqual(utf8Bytes("✓"), 3); assert.strictEqual(utf8Bytes("😀"), 4);
  assert.ok(wellFormedFormFields({ title: "é".repeat(30000), questions: [] }), "60,000 bytes: accepted (as C++)");
  assert.ok(!wellFormedFormFields({ title: "é".repeat(40000), questions: [] }), "80,000 bytes: refused (as C++)");
  const close = (x) => ({ v: 1, id: "close:f:1", type: "form.close", hlc: { wall: 1, ctr: 0, dev: "d" }, dev: "d", payload: { formId: "f", author: "0x" + "a".repeat(40), expiresAt: x } });
  assert.ok(wellFormedEvent(close(0)) && !wellFormedEvent(close(-1)) && !wellFormedEvent(close(100000000000001)), "expiresAt 0..1e14, as C++");
});

test("W2-11: deadlines use the network time; a Store copy keeps its publish time", () => {
  const now = 1_800_000_000_000;
  assert.strictEqual(netMsOf({ tsMs: now - 3600000, source: "history" }, now), now - 3600000, "a Store copy an hour old: its network time");
  assert.strictEqual(netMsOf({ tsMs: now - 3600000 }, now), 0, "a live frame an hour old: not believed");
  assert.strictEqual(netMsOf({ tsMs: now + 3600000, source: "history" }, now), 0, "never in the future");
});

test("W2-11: an answer backdated in its payload, sent after the close, is judged by its Store time", async () => {
  let tA = 1_800_000_000_000, tB = tA;
  const wire = [];
  const a = new WhisperboxClient({ store: mem(), send: async (x) => { wire.push(["a", x]); }, now: () => tA });
  const b = new WhisperboxClient({ store: mem(), send: async (x) => { wire.push(["b", x]); }, now: () => tB });
  await a.init(); await b.init(); a.onConnected(); b.onConnected();
  const fid = a.createForm(q).formId;
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  while (wire.length) { const [from, m] = wire.shift(); if (from === "a") b.ingest([m]); }
  tA += 10_000; assert.ok(a.closeForm(fid).ok); wire.length = 0;   // closed at +10 s; b never hears
  tB = tA - 5_000;                                                 // b's clock claims "before the close"
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "late" }]).ok);
  const sent = wire.filter(([f]) => f === "b").map(([, m]) => m);
  tA += 3_600_000;                                                 // the creator pulls it from Store an hour later
  for (const m of sent) a.ingest([m], { tsMs: tA - 3_600_000 + 20_000, source: "history" });   // Store: published at +20 s
  const v = a.decrypt(a.state());
  assert.strictEqual((v.responses[fid] || []).length, 0, "out: the network published it after the close");
});
