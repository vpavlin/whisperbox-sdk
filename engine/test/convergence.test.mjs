// convergence.test.mjs — the property that justifies the whole design:
// N devices author events offline; folding the union in MANY shuffled arrival
// orders (with duplicate redelivery and same-id resubmissions) always yields
// the IDENTICAL merged log AND folded state. Pure algorithm check — no
// transport, no crypto (the verify hook is a mock). Run: node test/convergence.test.mjs

import assert from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { mergeWhisperbox } from "../../contract/src/merge.mjs";
import { compareHlc } from "../../contract/src/hlc.mjs";
import {
  EventType,
  evFormPublish,
  evResponseSubmit,
  evResponseConfirm,
  evFormClose,
  evFormResults,
} from "../../contract/src/events.mjs";
import { computeState } from "../src/engine.mjs";
import { checkInvariants } from "../src/oracle.mjs";
import { mulberry32, generateWorld, partitionLogs, addr } from "./_world.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const ri = (rng, n) => Math.floor(rng() * n); // int in [0, n)

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

// ── The property: every arrival order ⇒ byte-identical merged log + state ────
function assertConverges(seed, trial) {
  const rng = mulberry32(seed * 7919 + trial);
  const { creators, events } = generateWorld(rng, seed);
  if (events.length === 0) return;
  const logs = partitionLogs(rng, events);
  const perms = permutations(rng, logs);

  const identity = creators[0];
  let firstMerged = null;
  let firstState = null;
  for (const perm of perms) {
    const merged = mergeWhisperbox(...perm);
    if (firstMerged === null) {
      firstMerged = JSON.stringify(merged);
      firstState = JSON.stringify(computeState(merged, { identity }));
    } else {
      assert.strictEqual(JSON.stringify(merged), firstMerged,
        `seed ${seed} trial ${trial}: merged log differs across arrival orders`);
      assert.strictEqual(JSON.stringify(computeState(merged, { identity })), firstState,
        `seed ${seed} trial ${trial}: folded state differs across arrival orders`);
    }
  }

  // HLC total order sanity: merged log strictly ordered (no equal HLCs).
  const merged = JSON.parse(firstMerged);
  for (let i = 1; i < merged.length; i++) {
    assert.ok(compareHlc(merged[i - 1].hlc, merged[i].hlc) < 0,
      `seed ${seed} trial ${trial}: merged log not strictly HLC-ordered at ${i}`);
  }

  // Oracle runs clean (no crash) on the converged state.
  const inv = checkInvariants(logs, merged, JSON.parse(firstState));
  assert.ok(Array.isArray(inv.violations));
}

// ── Unit checks: fold semantics the property test can't isolate ───────────────
function unitChecks() {
  // 1. min-HLC conflict rule is concat-order independent.
  const mk = (wall, payload) => ({ v: 1, id: "resp:f:x", type: EventType.RESPONSE_SUBMIT, hlc: { wall, ctr: 0, dev: "d" }, dev: "d", payload });
  const a = [mk(200, { formId: "f", respondent: "x", submittedAt: 200, encryptedPayload: "late", signature: null })];
  const b = [mk(100, { formId: "f", respondent: "x", submittedAt: 100, encryptedPayload: "first", signature: null })];
  for (const [la, lb] of [[a, b], [b, a]]) {
    const m = mergeWhisperbox(la, lb);
    assert.strictEqual(m.length, 1);
    assert.strictEqual(m[0].payload.encryptedPayload, "first", "min-HLC must win");
  }

  // 2. Sticky close: response after close dropped; before close kept.
  const pub = evFormPublish({ hlc: { wall: 100, ctr: 0, dev: "d" }, dev: "d", form: { id: "f1", title: "t", description: "", creator: addr(1), publicKey: "pk", createdAt: 100, questions: [], whitelist: { type: "none", value: "" } } });
  const close = evFormClose({ hlc: { wall: 200, ctr: 0, dev: "d" }, dev: "d", formId: "f1", author: addr(1) });
  const respBefore = evResponseSubmit({ hlc: { wall: 150, ctr: 0, dev: "d" }, dev: "d", formId: "f1", respondent: addr(2), submittedAt: 150, encryptedPayload: "s1", signature: null });
  const respAfter = evResponseSubmit({ hlc: { wall: 300, ctr: 0, dev: "d" }, dev: "d", formId: "f1", respondent: addr(3), submittedAt: 300, encryptedPayload: "s2", signature: null });
  const s = computeState(mergeWhisperbox([pub, close, respBefore, respAfter]), { identity: addr(1) });
  assert.strictEqual(s.forms.f1.status, "closed");
  assert.strictEqual(s.forms.f1.responseCount, 1, "pre-close response kept");
  assert.deepStrictEqual(s.dropped.reasons, { "form-closed": 1 }, "post-close response dropped");

  // 3. Deferred replay: close stamped BEFORE publish → form lands closed, in HLC order.
  const s2 = computeState(mergeWhisperbox([close, pub]), {});
  assert.strictEqual(s2.forms.f1.status, "closed", "deferred close applied when form lands");

  // 4. LWW results: later HLC supersedes.
  const r1 = evFormResults({ hlc: { wall: 150, ctr: 0, dev: "d" }, dev: "d", formId: "f1", resultsJson: '{"n":1}', author: addr(1) });
  const r2 = evFormResults({ hlc: { wall: 250, ctr: 0, dev: "d" }, dev: "d", formId: "f1", resultsJson: '{"n":2}', author: addr(1) });
  const s3 = computeState(mergeWhisperbox([pub, r2, r1]), {}); // out-of-order input — merge fixes it
  assert.strictEqual(s3.forms.f1.results.resultsJson, '{"n":2}', "LWW by HLC");

  // 5. Not-creator gated event dropped; unsigned gated event admitted (permissive).
  const rogue = evFormClose({ hlc: { wall: 400, ctr: 0, dev: "d" }, dev: "d", formId: "f1", author: addr(9) });
  const s4 = computeState(mergeWhisperbox([pub, rogue]), {});
  assert.deepStrictEqual(s4.dropped.reasons, { "not-creator": 1 });

  // 6. Verify hook: signed gated event failing verification is dropped; unsigned admitted.
  const badSig = evResponseConfirm({ hlc: { wall: 500, ctr: 0, dev: "d" }, dev: "d", formId: "f1", confirmationId: "c1", author: addr(1) });
  badSig.sig = "badsig";
  const okNoSig = evResponseConfirm({ hlc: { wall: 501, ctr: 0, dev: "d" }, dev: "d", formId: "f1", confirmationId: "c2", author: addr(1) });
  const s5 = computeState(mergeWhisperbox([pub, badSig, okNoSig]), { identity: addr(1), verify: () => false });
  assert.deepStrictEqual(s5.dropped.reasons, { "sig-invalid": 1 }, "signed+fail → dropped");
  assert.ok(s5.forms.f1.confirmations.includes("c2"), "unsigned → permissive admit");

  // 7. Orphan response (form never in log) → pending, not lost, not a form.
  const orphan = evResponseSubmit({ hlc: { wall: 600, ctr: 0, dev: "d" }, dev: "d", formId: "nope", respondent: addr(2), submittedAt: 600, encryptedPayload: "s", signature: null });
  const s6 = computeState(mergeWhisperbox([orphan]), {});
  assert.strictEqual(s6.pending.count, 1);
  assert.strictEqual(Object.keys(s6.forms).length, 0);

  // 8. Feed excludes closed forms, ordered by publish HLC.
  const pub2 = evFormPublish({ hlc: { wall: 50, ctr: 0, dev: "d" }, dev: "d", form: { id: "f0", title: "t0", description: "", creator: addr(1), publicKey: "pk", createdAt: 50, questions: [], whitelist: { type: "none", value: "" } } });
  const s7 = computeState(mergeWhisperbox([pub2, pub, close]), {});
  assert.deepStrictEqual(s7.feed, ["f0"], "closed f1 out of feed; f0 (earlier) first");
}

// ── Golden vectors: seed 164 must reproduce the committed fixtures byte-for-byte ─
function goldenCheck() {
  const seed = 164;
  const rng = mulberry32(seed * 7919 + 0);
  const { creators, events } = generateWorld(rng, seed);
  const logs = partitionLogs(rng, events, 3);
  const merged = mergeWhisperbox(...logs);
  const state = computeState(merged, { identity: creators[0] });

  const fmt = (x) => JSON.stringify(x, null, 2) + "\n";
  const wantMerged = readFileSync(join(here, "fixtures", "golden-merged.json"), "utf8");
  const wantState = readFileSync(join(here, "fixtures", "golden-state.json"), "utf8");
  assert.strictEqual(fmt(merged), wantMerged, "golden merged log drifted — regenerate fixtures (test/gen-fixtures.mjs)");
  assert.strictEqual(fmt(state), wantState, "golden state drifted — regenerate fixtures (test/gen-fixtures.mjs)");
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
