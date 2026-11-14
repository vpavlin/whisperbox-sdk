// Privacy review F4 (proteus/anoncomms 2026-11-14): answer retries are jittered (+/-30%), and on
// anonymous forms they stop after 5 (about an hour). Same rules as the C++ core.
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient } from "../src/client.mjs";

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); } }; };
async function net(n) {
  let t = 1_800_000_000_000;
  const peers = [], wire = [];
  for (let i = 0; i < n; i++) {
    const p = new WhisperboxClient({ store: mem(), now: () => t, minuteMs: 60000, msgsPerEpoch: 1e6,
      send: async (bytes, topic) => { if (p.offline) throw new Error("offline"); wire.push({ from: p, bytes, topic }); } });
    await p.init(); p.onConnected(); peers.push(p);
  }
  const pump = () => { while (wire.length) { const m = wire.shift(); for (const o of peers) if (o !== m.from && !o.offline) o.ingest([m.bytes]); } };
  const advance = (ms) => { for (let s = 0; s < ms; s += 30000) { t += 30000; for (const p of peers) p.tick(); pump(); } };
  return { peers, wire, pump, advance, now: () => t };
}
const answerSends = (wire, p) => wire.filter((m) => m.from === p).flatMap((m) => JSON.parse(new TextDecoder().decode(m.bytes)).events || []).filter((e) => e.type === "response.submit").length;

for (const anonymous of [false, true]) test(`retries are jittered${anonymous ? " and stop after 5 on anonymous forms" : ""}`, async () => {
  const { peers: [a, b], wire, pump, advance, now } = await net(2);
  const fid = a.createForm({ title: "f4", anonymous, questions: [{ id: "q1", type: "text", text: "?", required: true }] }).formId;
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`); pump();
  a.offline = true;   // the creator never sends a receipt
  const log = []; const push = wire.push.bind(wire); wire.push = (m) => { if (m.from === b) log.push(m); return push(m); };
  assert.ok(b.submitResponse(fid, [{ questionId: "q1", value: "hi" }]).ok);
  advance(30000);
  const first = b.myAnswers[fid].nextAt - now();
  assert.ok(first >= 0.7 * 10 * 60000 - 30000 && first <= 1.3 * 10 * 60000, "the first retry is 7-13 min away: " + first);
  advance(8 * 3600000);
  const n = answerSends(log, b);
  if (anonymous) assert.ok(n <= 6, "1 send + at most 5 retries: " + n);
  else assert.ok(n >= 9, "the long schedule continues: " + n);
});
