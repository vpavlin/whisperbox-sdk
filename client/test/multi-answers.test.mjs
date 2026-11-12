// ADR 0022: several answers per respondent - the phone side of the C++ e2e "Several answers per person" block.
import test from "node:test";
import assert from "node:assert";
import { WhisperboxClient } from "../src/client.mjs";

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); }, m }; };

async function pair() {
  const peers = [];
  const mk = async () => {
    const c = new WhisperboxClient({ store: mem(), send: async (b) => { for (const p of peers) if (p !== c) p.ingest([b]); } });
    await c.init(); c.onConnected(); peers.push(c); return c;
  };
  const a = await mk(), b = await mk();
  return { a, b };
}
const ans = (v) => [{ questionId: "q1", value: v }];
const settle = () => new Promise((r) => setTimeout(r, 30));

test("a form taking 2 answers per person: two entries, own receipts, third refused", async () => {
  const { a, b } = await pair();
  assert.ok(!a.createForm({ title: "x", maxPerRespondent: 2, allowEdits: true }).ok, "several answers + edits is refused");
  const fid = a.createForm({ title: "Feedback", questions: [{ id: "q1", type: "boolean", text: "ok?", required: true }], maxPerRespondent: 2 }).formId;
  await settle();
  assert.ok(b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`).ok);
  await settle();
  assert.strictEqual(b.state().forms[fid].maxPerRespondent, 2);
  assert.ok(b.submitResponse(fid, ans(true)).ok);
  let f = b.snapshot().state.forms[fid];
  assert.ok(f.canRespond && f.myAnswerCount === 1, "may send another");
  assert.ok(b.submitResponse(fid, ans(false)).ok);
  f = b.snapshot().state.forms[fid];
  assert.ok(!f.canRespond && f.myAnswerCount === 2, "both used");
  const third = b.submitResponse(fid, ans(true));
  assert.ok(!third.ok && /at most 2/.test(third.error));
  await settle();
  const rs = a.decrypt(a.state()).responses[fid];
  assert.strictEqual(rs.length, 2);
  assert.strictEqual(rs[0].respondent, rs[1].respondent);
  assert.deepStrictEqual(rs.map((r) => r.answerNo), [1, 2]);
  assert.notStrictEqual(rs[0].confirmationId, rs[1].confirmationId);
  assert.ok(a.confirmAnswer(fid, rs[1].confirmationId).ok);
  assert.ok(!a.confirmAnswer(fid, "nope").ok);
  await settle();
  assert.strictEqual(b.snapshot().state.forms[fid].myReceipts, 1);
  assert.strictEqual((b.myAnswers[fid].earlier || []).length, 1);
});

test("unlimited (0): keeps accepting", async () => {
  const { a, b } = await pair();
  const fid = a.createForm({ title: "Ideas", questions: [{ id: "q1", type: "boolean", text: "ok?" }], maxPerRespondent: 0 }).formId;
  await settle();
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  await settle();
  for (let i = 0; i < 4; i++) assert.ok(b.submitResponse(fid, ans(i % 2 === 0)).ok);
  assert.ok(b.snapshot().state.forms[fid].canRespond);
  await settle();
  assert.strictEqual(a.decrypt(a.state()).responses[fid].length, 4);
});

test("an ordinary form is unchanged: one answer, no new fields", async () => {
  const { a, b } = await pair();
  const fid = a.createForm({ title: "One", questions: [{ id: "q1", type: "boolean", text: "ok?" }] }).formId;
  await settle();
  b.importForm(`whisperbox://form?id=${fid}&by=${a.identity.address}`);
  await settle();
  assert.ok(!("maxPerRespondent" in b.state().forms[fid]));
  assert.ok(b.submitResponse(fid, ans(true)).ok);
  const f = b.snapshot().state.forms[fid];
  assert.ok(!f.canRespond && !("myAnswerCount" in f));
  assert.ok(!b.submitResponse(fid, ans(false)).ok);
});

test("ADR 0023: form files - export, open offline, refuse tampered or padded files", async () => {
  const { a } = await pair();
  const fid = a.createForm({ title: "Shipped", questions: [{ id: "q1", type: "boolean", text: "ok?", required: true }] }).formId;
  const ex = a.exportForm(fid);
  assert.ok(ex.ok && JSON.parse(ex.file).events[0].type === "form.publish");
  const lone = new WhisperboxClient({ store: mem(), send: async () => {} });
  await lone.init();
  const fj = JSON.parse(ex.file);
  const tam = JSON.parse(ex.file); tam.events[0].payload.title = "evil";
  assert.ok(!lone.importFormFile(JSON.stringify(tam)).ok, "tampered");
  const pad = JSON.parse(ex.file); pad.events.push({ ...fj.events[0], type: "response.submit" });
  assert.ok(!lone.importFormFile(JSON.stringify(pad)).ok, "padded");
  assert.ok(!lone.importFormFile("{}").ok);
  const im = lone.importFormFile(ex.file);
  assert.ok(im.ok && !im.pending && im.formId === fid);
  const f = lone.snapshot().state.forms[fid];
  assert.ok(f.pinnedCreator === a.identity.address && f.canRespond);
  assert.ok(lone.submitResponse(fid, ans(true)).ok);
});
