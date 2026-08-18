// convergence.test.mjs — the property that justifies the whole design:
// N devices author events offline; folding the union in MANY shuffled arrival
// orders (with duplicate redelivery) always yields the IDENTICAL merged log,
// folded state, AND creator view. Responses are real ECIES-sealed blobs; the
// fold treats them as opaque, the creator view decrypts them. Run:
// node test/convergence.test.mjs

import assert from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

import { mergeWhisperbox } from "../../contract/src/merge.mjs";
import { compareHlc } from "../../contract/src/hlc.mjs";
import {
  EventType,
  evFormPublish,
  evResponseSubmit,
  evResponseConfirm,
  evFormClose,
} from "../../contract/src/events.mjs";
import { identityFromPriv, sealToCreator, eciesOpen, toHex } from "../../contract/src/crypto.mjs";
import { computeState, creatorView } from "../src/engine.mjs";
import { checkInvariants } from "../src/oracle.mjs";
import { mulberry32, generateWorld, partitionLogs, addr } from "./_world.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const ri = (rng, n) => Math.floor(rng() * n); // int in [0, n)
const sha = (s) => createHash("sha256").update(s).digest();

// ── Arrival permutations of the device logs ───────────────────────────────────
function permutations(rng, logs, k = 5) {
  const out = [];
  const idx = logs.map((_, i) => i);
  for (let t = 0; t < k; t++) {
    const order = [...idx];
    for (let i = order.length - 1; i > 0; i--) {
      const j = ri(rng, i + 1);
      [order[i], order[j]] = [order[j], order[i]];
    }
    out.push(order.map((i) => logs[i]));
  }
  // Plus: everything in ONE flat log (shuffled).
  const flat = [];
  for (const l of logs) flat.push(...l);
  for (let i = flat.length - 1; i > 0; i--) {
    const j = ri(rng, i + 1);
    [flat[i], flat[j]] = [flat[j], flat[i]];
  }
  out.push([flat]);
  return out;
}

// Creator-view open hook for a fixed identity (real ECIES).
function openHook(identity) {
  return (hex) => {
    try {
      return JSON.parse(eciesOpen(identity, hex).toString("utf8"));
    } catch {
      return null;
    }
  };
}

// ── The property: every arrival order ⇒ byte-identical merged log + state + view ─
function assertConverges(seed, trial) {
  const rng = mulberry32(seed * 7919 + trial);
  const { creators, creatorObjs, events } = generateWorld(rng, seed);
  if (events.length === 0) return;
  const logs = partitionLogs(rng, events);
  const perms = permutations(rng, logs);

  const identityObj = creatorObjs[0];
  const identity = creators[0];
  const open = openHook(identityObj);
  let firstMerged = null;
  let firstState = null;
  let firstView = null;
  for (const perm of perms) {
    const merged = mergeWhisperbox(...perm);
    const state = computeState(merged, { identity });
    if (firstMerged === null) {
      firstMerged = JSON.stringify(merged);
      firstState = JSON.stringify(state);
      firstView = JSON.stringify(creatorView(state, { identity, open }));
    } else {
      assert.strictEqual(JSON.stringify(merged), firstMerged,
        `seed ${seed} trial ${trial}: merged log differs across arrival orders`);
      assert.strictEqual(JSON.stringify(state), firstState,
        `seed ${seed} trial ${trial}: folded state differs across arrival orders`);
      assert.strictEqual(JSON.stringify(creatorView(state, { identity, open })), firstView,
        `seed ${seed} trial ${trial}: creator view differs across arrival orders`);
    }
  }

  // HLC total order sanity: merged log strictly ordered (no equal HLCs).
  const merged = JSON.parse(firstMerged);
  for (let i = 1; i < merged.length; i++) {
    assert.ok(compareHlc(merged[i - 1].hlc, merged[i].hlc) < 0,
      `seed ${seed} trial ${trial}: merged log not strictly HLC-ordered at ${i}`);
  }

  // Oracle runs clean (no crash) on the converged state + view.
  const inv = checkInvariants(logs, merged, JSON.parse(firstState), JSON.parse(firstView));
  assert.ok(Array.isArray(inv.violations));
}

// ── Unit checks: fold + creator-view semantics the property test can't isolate ──
function unitChecks() {
  // Identities for the hand-built scenarios (real keys → real seals).
  const creator = identityFromPriv(sha("unit-creator"));
  const respA = identityFromPriv(sha("unit-resp-a"));
  const respB = identityFromPriv(sha("unit-resp-b"));
  const otherCreator = identityFromPriv(sha("unit-other-creator"));

  const mkForm = (id, creatorId, whitelist) => evFormPublish({
    hlc: { wall: 100, ctr: 0, dev: "d" }, dev: "d",
    form: {
      id, title: "t", description: "", creator: creatorId.address, publicKey: creatorId.pubHex,
      createdAt: 100, questions: [{ id: "q0a", type: "text", text: "n?", required: true }],
      whitelist: whitelist ?? { type: "none", value: "" }, signature: null,
    },
  });
  const seal = (respondentId, creatorId, formId, answers, ephTag) => toHex(sealToCreator(
    respondentId, creatorId.pubHex,
    JSON.stringify({ formId, respondent: respondentId.address, submittedAt: null, answers, signature: "sig" }),
    { ephPriv: sha("unit-eph|" + ephTag), deterministic: true },
  ));

  // 1. min-HLC conflict rule is concat-order independent (form re-publish with edits).
  const pubA = mkForm("f", creator, undefined);
  const pubB = { ...mkForm("f", creator, undefined) };
  pubB.hlc = { wall: 50, ctr: 0, dev: "d" };
  pubB.payload.title = "EARLIER";
  for (const [la, lb] of [[pubA, pubB], [pubB, pubA]]) {
    const m = mergeWhisperbox([la], [lb]);
    assert.strictEqual(m.length, 1);
    assert.strictEqual(m[0].payload.title, "EARLIER", "min-HLC must win");
  }

  // 2. Sticky close at the FOLD level: status flips, feed drops it; responses are
  //    opaque pool entries (no log-level routing).
  const pub = mkForm("f1", creator);
  const close = evFormClose({ hlc: { wall: 200, ctr: 0, dev: "d" }, dev: "d", formId: "f1", author: creator.address });
  const blobBefore = evResponseSubmit({ hlc: { wall: 150, ctr: 0, dev: "d" }, dev: "d", encryptedPayload: seal(respA, creator, "f1", [{ questionId: "q0a", value: "before" }], "b") });
  const blobAfter = evResponseSubmit({ hlc: { wall: 300, ctr: 0, dev: "d" }, dev: "d", encryptedPayload: seal(respB, creator, "f1", [{ questionId: "q0a", value: "after" }], "a") });
  const s = computeState(mergeWhisperbox([pub, close, blobBefore, blobAfter]), { identity: creator.address });
  assert.strictEqual(s.forms.f1.status, "closed");
  assert.strictEqual(s.responses.length, 2, "both blobs pooled (log level is opaque)");
  // Creator view: pre-close accepted, post-close dropped.
  const v = creatorView(s, { identity: creator.address, open: openHook(creator) });
  assert.strictEqual(v.responses.f1.length, 1, "pre-close response accepted");
  assert.deepStrictEqual(v.dropped.reasons, { "form-closed": 1 }, "post-close response dropped in view");

  // 3. Deferred replay: close stamped BEFORE publish → form lands closed.
  const s2 = computeState(mergeWhisperbox([close, pub]), {});
  assert.strictEqual(s2.forms.f1.status, "closed", "deferred close applied when form lands");

  // 4. Not-creator gated event dropped; unsigned gated event admitted (permissive).
  const rogue = evFormClose({ hlc: { wall: 400, ctr: 0, dev: "d" }, dev: "d", formId: "f1", author: addr(9) });
  const s4 = computeState(mergeWhisperbox([pub, rogue]), {});
  assert.deepStrictEqual(s4.dropped.reasons, { "not-creator": 1 });

  // 5. Verify hook: signed gated event failing verification is dropped; unsigned admitted.
  const badSig = evResponseConfirm({ hlc: { wall: 500, ctr: 0, dev: "d" }, dev: "d", formId: "f1", confirmationId: "c1", author: creator.address });
  badSig.sig = "badsig";
  const okNoSig = evResponseConfirm({ hlc: { wall: 501, ctr: 0, dev: "d" }, dev: "d", formId: "f1", confirmationId: "c2", author: creator.address });
  const s5 = computeState(mergeWhisperbox([pub, badSig, okNoSig]), { identity: creator.address, verify: () => false });
  assert.deepStrictEqual(s5.dropped.reasons, { "sig-invalid": 1 }, "signed+fail → dropped");
  assert.ok(s5.forms.f1.confirmations.includes("c2"), "unsigned → permissive admit");

  // 6. Orphan sealed blob (form never in log) → stays in pool, never lost; the
  //    creator view ignores it (undecryptable/unknown form).
  const orphan = evResponseSubmit({ hlc: { wall: 600, ctr: 0, dev: "d" }, dev: "d", encryptedPayload: seal(respA, otherCreator, "ghost", [{ questionId: "q0a", value: "x" }], "o") });
  const s6 = computeState(mergeWhisperbox([orphan]), {});
  assert.strictEqual(s6.pending.count, 0, "responses are never pending");
  assert.strictEqual(s6.responses.length, 1, "blob pooled");
  const v6 = creatorView(computeState(mergeWhisperbox([pub, orphan]), { identity: creator.address }), { identity: creator.address, open: openHook(creator) });
  assert.strictEqual(v6.undecrypted, 1, "foreign blob counted undecrypted");

  // 7. Feed excludes closed forms, ordered by publish HLC.
  const pub2 = mkForm("f0", creator);
  pub2.hlc = { wall: 50, ctr: 0, dev: "d" };
  const s7 = computeState(mergeWhisperbox([pub2, pub, close]), {});
  assert.deepStrictEqual(s7.feed, ["f0"], "closed f1 out of feed; f0 (earlier) first");

  // 8. Resubmission: same respondent, different answers → two content-addressed
  //    events; creator view keeps the min-HLC one per respondent.
  const r1 = evResponseSubmit({ hlc: { wall: 120, ctr: 0, dev: "d" }, dev: "d", encryptedPayload: seal(respA, creator, "f9", [{ questionId: "q0a", value: "first" }], "r1") });
  const r2 = evResponseSubmit({ hlc: { wall: 130, ctr: 0, dev: "d" }, dev: "d", encryptedPayload: seal(respA, creator, "f9", [{ questionId: "q0a", value: "second" }], "r2") });
  const pub9 = mkForm("f9", creator);
  const s8 = computeState(mergeWhisperbox([pub9, r1, r2]), { identity: creator.address });
  assert.strictEqual(s8.responses.length, 2, "both resubmission blobs pooled");
  const v8 = creatorView(s8, { identity: creator.address, open: openHook(creator) });
  assert.strictEqual(v8.responses.f9.length, 1, "one live response per respondent");
  assert.deepStrictEqual(v8.responses.f9[0].answers, [{ questionId: "q0a", value: "first" }], "min-HLC answer wins");
  assert.deepStrictEqual(v8.dropped.reasons, { "duplicate-respondent": 1 });

  // 9. Whitelist form: missing inner signature → creator-view sig-invalid drop.
  const pubW = mkForm("fw", creator, { type: "addresses", value: respA.address });
  const noSigBlob = evResponseSubmit({
    hlc: { wall: 140, ctr: 0, dev: "d" }, dev: "d",
    encryptedPayload: toHex(sealToCreator(respA, creator.pubHex,
      JSON.stringify({ formId: "fw", respondent: respA.address, submittedAt: null, answers: [], signature: null }),
      { ephPriv: sha("unit-eph|w"), deterministic: true })),
  });
  const s9 = computeState(mergeWhisperbox([pubW, noSigBlob]), { identity: creator.address });
  const v9 = creatorView(s9, {
    identity: creator.address, open: openHook(creator),
    verifyResponse: (pseudo) => pseudo.payload.signature != null, // stand-in for ECDSA check
  });
  assert.deepStrictEqual(v9.dropped.reasons, { "sig-invalid": 1 }, "whitelist form rejects unsigned response");
}

// ── Golden vectors: seed 164 must reproduce the committed fixtures byte-for-byte ─
function goldenCheck() {
  const seed = 164;
  const rng = mulberry32(seed * 7919 + 0);
  const { creators, creatorObjs, events } = generateWorld(rng, seed);
  const logs = partitionLogs(rng, events, 3);
  const merged = mergeWhisperbox(...logs);
  const state = computeState(merged, { identity: creators[0] });
  const view = creatorView(state, { identity: creators[0], open: openHook(creatorObjs[0]) });

  const fmt = (x) => JSON.stringify(x, null, 2) + "\n";
  const wantMerged = readFileSync(join(here, "fixtures", "golden-merged.json"), "utf8");
  const wantState = readFileSync(join(here, "fixtures", "golden-state.json"), "utf8");
  const wantView = readFileSync(join(here, "fixtures", "golden-creatorview.json"), "utf8");
  assert.strictEqual(fmt(merged), wantMerged, "golden merged log drifted — regenerate fixtures (test/gen-fixtures.mjs)");
  assert.strictEqual(fmt(state), wantState, "golden state drifted — regenerate fixtures (test/gen-fixtures.mjs)");
  assert.strictEqual(fmt(view), wantView, "golden creator view drifted — regenerate fixtures (test/gen-fixtures.mjs)");
}

// ── Main ──────────────────────────────────────────────────────────────────────
const TRIALS = 200;
let t0 = Date.now();
unitChecks();
console.log(`unit checks: OK (${Date.now() - t0}ms)`);
t0 = Date.now();
for (let trial = 0; trial < TRIALS; trial++) {
  assertConverges(1, trial);
}
console.log(`convergence: ${TRIALS} trials × 6 arrival orders OK (${Date.now() - t0}ms)`);
t0 = Date.now();
goldenCheck();
console.log(`golden vectors (seed 164): byte-identical to fixtures (${Date.now() - t0}ms)`);
console.log("ALL GREEN");
