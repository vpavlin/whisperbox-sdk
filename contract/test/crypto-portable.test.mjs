// Portable crypto (crypto-portable.mjs, used by the phone) must be byte-identical to the
// Node reference (crypto.mjs) and the golden fixtures that the C++ core is also tested on.
import test from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as P from "../src/crypto-portable.mjs";
import * as N from "../src/crypto.mjs";
import { responseSubmitId } from "../src/events.mjs";
import { createHash } from "node:crypto";

const fx = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const load = (f) => JSON.parse(readFileSync(join(fx, f), "utf8"));
const ids = Object.fromEntries(load("crypto-identities.json").identities.map((i) => [i.name, i]));

test("identities derive the same address", () => {
  for (const i of Object.values(ids)) {
    const p = P.identityFromPriv(i.privHex);
    assert.strictEqual(p.pubHex, i.pubHex); assert.strictEqual(p.address, i.address);
  }
});

test("golden sealed blobs: open + byte-identical re-seal", () => {
  for (const s of load("crypto-sealed.json").seals) {
    const c = P.identityFromPriv(ids[s.creatorName].privHex);
    assert.strictEqual(P.utf8Decode(P.eciesOpen(c, s.sealedHex)), s.plaintext, s.id);
    const re = P.sealToCreator(null, c.pubHex, s.plaintext, { ephPriv: s.ephPrivHex, deterministic: true });
    assert.strictEqual(P.toHex(re), s.sealedHex, s.id + " re-seal");
    const other = P.identityFromPriv(ids[s.respondentName].privHex);
    assert.throws(() => P.eciesOpen(other, s.sealedHex), /aead/);
  }
});

test("golden signed events verify; tamper fails", () => {
  const doc = load("crypto-signed-events.json");
  const events = doc.events || doc.signed || doc;
  let n = 0;
  for (const item of Array.isArray(events) ? events : Object.values(events)) {
    const e = item.event || item;
    if (!e || !e.sig) continue;
    n++;
    assert.ok(P.verifyEvent(e), "verify " + e.id);
    const t = JSON.parse(JSON.stringify(e)); t.payload.title = (t.payload.title || "") + "x"; t.payload.formId = (t.payload.formId || "") + "x";
    assert.ok(!P.verifyEvent(t), "tamper " + e.id);
  }
  assert.ok(n > 0, "fixtures contained signed events");
});

test("cross: portable <-> node reference, both directions", () => {
  const a = P.identityFromPriv(ids.alice.privHex), nb = N.identityFromPriv(Buffer.from(ids.bob.privHex, "hex"));
  const blob = P.sealToCreator(null, nb.pubHex, "portable → node");
  assert.strictEqual(N.eciesOpen(nb, Buffer.from(blob)).toString("utf8"), "portable → node");
  const blob2 = N.sealToCreator(N.identityFromPriv(Buffer.from(ids.alice.privHex, "hex")), a.pubHex, "node → portable");
  assert.strictEqual(P.utf8Decode(P.eciesOpen(a, new Uint8Array(blob2))), "node → portable");
  const ev = { v: 1, id: "form:x", type: "form.publish", hlc: { wall: 5, ctr: 0, dev: "d" }, dev: "d",
               payload: { id: "x", creator: a.address, title: "Ünïcode ✓", questions: [{ id: "q1", type: "text" }] } };
  Object.assign(ev, P.signEvent(a, ev));
  assert.ok(N.verifyEvent(ev), "node verifies portable signature");
  const ev2 = { ...ev }; delete ev2.pub; delete ev2.sig;
  Object.assign(ev2, N.signEvent(N.identityFromPriv(Buffer.from(ids.alice.privHex, "hex")), ev2));
  assert.ok(P.verifyEvent(ev2), "portable verifies node signature");
});

test("inner response signature round-trips; wrong respondent fails", () => {
  const a = P.identityFromPriv(ids.alice.privHex);
  const r = { formId: "f1", respondent: a.address, submittedAt: 1700000000000, answers: [{ questionId: "q1", value: 2 }, { questionId: "q2", value: ["x"] }] };
  const s = { ...r, pub: a.pubHex, signature: P.signInner(a, r) };
  assert.ok(P.verifyInner(s));
  assert.ok(!P.verifyInner({ ...s, respondent: "0x" + "0".repeat(40) }));
});

test("responseSubmitId is sha256 of the hex blob (matches node:crypto)", () => {
  const hex = "01abcdef";
  assert.strictEqual(responseSubmitId(hex), "resp:" + createHash("sha256").update(hex, "utf8").digest("hex"));
});

test("per-form keys: portable == node reference == golden; sealed-to-form opens only with the form key", () => {
  const doc = JSON.parse(readFileSync(join(fx, "crypto-formkeys.json"), "utf8"));
  const idDoc = JSON.parse(readFileSync(join(fx, "crypto-identities.json"), "utf8"));
  const byName = Object.fromEntries(idDoc.identities.map((i) => [i.name, P.identityFromPriv(i.privHex)]));
  for (const k of doc.formKeys) {
    const d = P.deriveFormKey(byName[k.owner], k.formId);
    assert.strictEqual(d.pubHex, k.pubHex, `${k.owner}/${k.formId}`);
    assert.strictEqual(P.toHex(d.priv), k.privHex);
    assert.strictEqual(P.keycardFormKeyPath(k.formId), k.keycardPath);
    assert.notStrictEqual(d.pubHex, byName[k.owner].pubHex, "form key != identity key");
    assert.match(k.keycardPath, /^m\/43'\/60'\/1581'(\/\d+'){4}$/, "EIP-1581 subtree, 4 hardened indices");
  }
  assert.strictEqual(P.deriveFormKey(byName.bob, "FORM-UPPER").pubHex, P.deriveFormKey(byName.bob, "form-upper").pubHex, "case-insensitive form id");
  const fk = P.deriveFormKey(byName.bob, doc.formSeal.formId);
  assert.strictEqual(P.utf8Decode(P.eciesOpen(fk, doc.formSeal.sealedHex)), doc.formSeal.plaintext);
  assert.throws(() => P.eciesOpen(byName.bob, doc.formSeal.sealedHex), "identity key cannot open a form-key seal");
  assert.throws(() => P.eciesOpen(P.deriveFormKey(byName.bob, "form-639a2554"), doc.formSeal.sealedHex), "another form's key cannot");
});

test("keycard form-key path = the Loam domain-path convention (independent re-implementation)", () => {
  // scala/mobile/src/lib/loam-keycard/paths.ts domainToKeyPath(domain), re-done from the spec:
  const spec = (domain) => {
    const h = createHash("sha256").update("logos-" + domain).digest();
    return "m/43'/60'/1581'/" + [0, 4, 8, 12].map((o) => (h.readUInt32BE(o) & 0x7fffffff) + "'").join("/");
  };
  for (const id of ["form-639a2554", "Form-ABC", "form-žluť"]) {
    assert.strictEqual(P.keycardFormKeyPath(id), spec("whisperbox-form:" + id.toLowerCase()));
    assert.strictEqual(N.keycardFormKeyPath(id), P.keycardFormKeyPath(id));
  }
  // and the value Python's hashlib gives for the first id:
  assert.strictEqual(P.keycardFormKeyPath("form-639a2554"), "m/43'/60'/1581'/11022128'/1577926826'/1799408082'/489631137'");
});
