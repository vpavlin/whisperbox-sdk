// Cross-implementation interop: the JS client (what the Android app runs) against the REAL
// C++ whisperbox_core (what Basecamp and the hub run), over the fake delivery bus.
// Build the bridge first: whisperbox_core/test/run-bridge-build.sh (scripts/test.sh does).
import test from "node:test";
import assert from "node:assert";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { WhisperboxClient } from "../src/client.mjs";

const BRIDGE = process.env.WB_BRIDGE || "/tmp/wb-bridge";

function memStore() { const m = new Map(); return { get: async (k) => (m.has(k) ? m.get(k) : null), set: async (k, v) => { m.set(k, v); }, m }; }
function candidates(b64) {
  const once = Buffer.from(b64, "base64"); const out = [new Uint8Array(once)];
  try { const twice = Buffer.from(once.toString("utf8"), "base64"); if (twice.length) out.push(new Uint8Array(twice)); } catch { /* single */ }
  return out;
}

class Bridge {
  constructor(layers) {
    this.p = spawn(BRIDGE, [], { stdio: ["pipe", "pipe", "ignore"] });
    this.waiters = new Map(); this.nextId = 1; this.clients = []; this.layers = layers;
    createInterface({ input: this.p.stdout }).on("line", (l) => {
      let j; try { j = JSON.parse(l); } catch { return; }
      if (j.rx) for (const c of this.clients) c.ingest(candidates(j.rx));
      if (j.id !== undefined && this.waiters.has(j.id)) { this.waiters.get(j.id)(j.result); this.waiters.delete(j.id); }
      if (j.pumped !== undefined && this.pumpDone) { const f = this.pumpDone; this.pumpDone = null; f(); }
    });
  }
  send(o) { this.p.stdin.write(JSON.stringify(o) + "\n"); }
  call(m, args = [], peer = "A") { const id = this.nextId++; return new Promise((r) => { this.waiters.set(id, r); this.send({ call: m, args, peer, id }); }); }
  pump(ms) { return new Promise((r) => { this.pumpDone = r; this.send({ pump: ms }); }); }
  async client() {
    const c = new WhisperboxClient({ store: memStore(), send: async (bytes) => this.send({ tx: Buffer.from(bytes).toString("base64"), layers: this.layers }) });
    await c.init(); this.clients.push(c); c.onConnected(); return c;
  }
  close() { this.p.stdin.end(); }
}
async function until(b, pred, ms = 6000) { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await pred()) return true; await b.pump(150); for (const c of b.clients) c.tick(); } return !!(await pred()); }

// layers=1 is loam-transport's actual wire contract (FFI decodes one of its two b64 layers);
// layers=0 (raw envelope bytes) is the other payload shape the desktop core accepts.
for (const layers of [1, 0]) {
  test(`phone (JS) <-> desktop core (C++), wire payload ${layers ? "base64(envelope)" : "raw envelope"}`, async () => {
    const b = new Bridge(layers);
    try {
      await b.pump(1500);
      const phone = await b.client();
      const snapA = await b.call("snapshot"); const addrA = snapA.identity.address;

      // 1. desktop creates, phone sees the signed form and answers; desktop decrypts + receipts
      const fA = (await b.call("createForm", [JSON.stringify({ title: "From desktop", questions: [
        { id: "q1", type: "radioButtons", text: "Pick", required: true, options: ["a", "b", "c"] },
        { id: "q2", type: "text", text: "Why?", required: false }] })])).formId;
      assert.ok(await until(b, () => !!phone.snapshot().state.forms[fA]), "phone receives the desktop's signed form");
      assert.strictEqual(phone.diag.admDropSig, 0, "phone admits the desktop's signature");
      const ans = [{ questionId: "q1", value: 2 }, { questionId: "q2", value: "žluťoučký kůň ✓" }];
      assert.ok(phone.submitResponse(fA, ans).ok);
      assert.ok(await until(b, async () => ((await b.call("getDecryptedResponses", [fA])).responses || []).length === 1), "desktop decrypts the phone's answer");
      const rA = (await b.call("getDecryptedResponses", [fA])).responses[0];
      assert.strictEqual(rA.respondent, phone.identity.address); assert.deepStrictEqual(rA.answers, ans);
      assert.ok((await b.call("confirmResponse", [fA, phone.identity.address])).ok);
      assert.ok(await until(b, () => phone.snapshot().state.forms[fA].myConfirmed), "phone sees the desktop's receipt");

      // 2. phone creates (portable signing), desktop admits + answers, phone decrypts + receipts
      const fP = phone.createForm({ title: "From phone", questions: [{ id: "q1", type: "checkbox", text: "Which", required: true, options: ["x", "y"] }] }).formId;
      assert.ok(await until(b, async () => !!(await b.call("snapshot")).state.forms[fP]), "desktop admits the phone's signed form");
      assert.strictEqual((await b.call("snapshot")).diagnostics.admDropSig, 0);
      assert.ok((await b.call("submitResponse", [fP, JSON.stringify([{ questionId: "q1", value: [0, 1] }])])).ok);
      assert.ok(await until(b, () => (phone.snapshot().creatorView?.responses[fP] || []).length === 1), "phone decrypts the desktop's answer");
      assert.strictEqual(phone.snapshot().creatorView.responses[fP][0].respondent, addrA);
      assert.ok(phone.confirmResponse(fP, addrA).ok);
      assert.ok(await until(b, async () => (await b.call("snapshot")).state.forms[fP].myConfirmed), "desktop sees the phone's receipt");
      assert.match(phone.exportCsv(fP).csv, /,yes,x; y\n$/, "phone CSV renders option text + receipt");

      // 3. members-only form listing the phone: inner signature made in JS, verified in C++
      const fW = (await b.call("createForm", [JSON.stringify({ title: "Members", questions: [{ id: "q1", type: "text", text: "Hi", required: true }],
        whitelist: { type: "addresses", value: phone.identity.address } })])).formId;
      assert.ok(await until(b, () => !!phone.snapshot().state.forms[fW]?.canRespond), "listed phone may answer");
      assert.ok(phone.submitResponse(fW, [{ questionId: "q1", value: "hello" }]).ok);
      assert.ok(await until(b, async () => ((await b.call("getDecryptedResponses", [fW])).responses || []).length === 1), "desktop accepts the JS inner signature");

      // 4. close from the phone, seen by the desktop
      assert.ok(phone.closeForm(fP).ok);
      assert.ok(await until(b, async () => (await b.call("snapshot")).state.forms[fP].status === "closed"), "desktop sees the phone's close");

      // 5. a brand-new phone catches up from the desktop via RBSR (signed keys included)
      const fresh = await b.client();
      const want = (await b.call("snapshot")).diagnostics;
      assert.ok(await until(b, () => fresh.log.length === phone.log.length, 10000), `fresh phone reconciles the full log (${fresh.log.length}/${phone.log.length})`);
      assert.ok(fresh.diag.rbsrRx > 0, "via RBSR");
      assert.strictEqual(fresh.diag.legacyReseeds + (want.legacyReseeds || 0), 0, "no whole-log reseeds");

      // 6. 0.3.2 lifecycle across implementations: desktop closes + re-opens, phone answers
      //    a yes/no question after the re-open, desktop confirms ALL in one batch event;
      //    phone caps its own form and confirms all the desktop's way.
      const fL = (await b.call("createForm", [JSON.stringify({ title: "Lifecycle", maxResponses: 5, showResponseCount: true,
        questions: [{ id: "q1", type: "boolean", text: "Coming?", required: true }] })])).formId;
      assert.ok(await until(b, () => !!phone.snapshot().state.forms[fL]));
      assert.strictEqual(phone.snapshot().state.forms[fL].maxResponses, 5, "cap travels C++ -> JS");
      assert.ok((await b.call("closeForm", [fL])).ok);
      assert.ok(await until(b, () => phone.snapshot().state.forms[fL].status === "closed"), "phone sees close");
      assert.ok((await b.call("reopenForm", [fL])).ok);
      assert.ok(await until(b, () => phone.snapshot().state.forms[fL].status === "open"), "phone sees re-open (C++ form.reopen admitted + folded by JS)");
      assert.ok(phone.submitResponse(fL, [{ questionId: "q1", value: false }]).ok);
      assert.ok(await until(b, async () => ((await b.call("getDecryptedResponses", [fL])).responses || []).length === 1), "post-re-open answer counts in C++");
      assert.strictEqual((await b.call("getDecryptedResponses", [fL])).responses[0].answers[0].value, false, "boolean false round-trips");
      assert.strictEqual((await b.call("confirmAll", [fL])).events, 1);
      assert.ok(await until(b, () => phone.snapshot().state.forms[fL].myConfirmed), "phone sees its receipt from a C++ batch event");
      const fQ = phone.createForm({ title: "Phone lifecycle", questions: [{ id: "q1", type: "boolean", text: "Ok?", required: true }] }).formId;
      assert.ok(await until(b, async () => !!(await b.call("snapshot")).state.forms[fQ]));
      assert.ok(phone.closeForm(fQ).ok && phone.reopenForm(fQ).ok);
      assert.ok(await until(b, async () => (await b.call("snapshot")).state.forms[fQ].status === "open"), "desktop folds the phone's close + re-open");
      assert.ok((await b.call("submitResponse", [fQ, JSON.stringify([{ questionId: "q1", value: true }])])).ok);
      assert.ok(await until(b, () => (phone.snapshot().creatorView?.responses[fQ] || []).length === 1));
      assert.strictEqual(phone.confirmAll(fQ).events, 1);
      assert.ok(await until(b, async () => (await b.call("snapshot")).state.forms[fQ].myConfirmed), "desktop sees its receipt from a JS batch event");

      // 7. edit after publishing, both directions
      assert.ok((await b.call("updateForm", [fL, JSON.stringify({ title: "Lifecycle v2", questions: [{ id: "q1", type: "boolean", text: "Coming? (v2)", required: true }] })])).ok);
      assert.ok(await until(b, () => phone.snapshot().state.forms[fL].title === "Lifecycle v2" && phone.snapshot().state.forms[fL].version === 2), "phone folds the desktop's form.update");
      assert.ok(phone.updateForm(fQ, { title: "Phone lifecycle v2", questions: [{ id: "q1", type: "boolean", text: "Ok? (v2)", required: true }] }).ok);
      assert.ok(await until(b, async () => (await b.call("snapshot")).state.forms[fQ].title === "Phone lifecycle v2"), "desktop folds the phone's form.update");

      // 8. share links are identical on both sides
      assert.strictEqual(phone.shareUri(fA).uri, (await b.call("shareUri", [fA])).uri);
    } finally { b.close(); }
  });
}
