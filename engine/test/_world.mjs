// _world.mjs — seeded world generation shared by convergence.test.mjs and
// gen-fixtures.mjs (single source of truth for the random-world model).

import { evFormPublish, evResponseSubmit, evResponseConfirm, evFormClose, evFormResults } from "../../contract/src/events.mjs";

export function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const ri = (rng, n) => Math.floor(rng() * n); // int in [0, n)
const pick = (rng, arr) => arr[ri(rng, arr.length)];

// Fake identities (no real keys in P1 — addresses are opaque strings).
export const addr = (n) => "0x" + n.toString(16).padStart(40, "0");

/** Builds a random world of events with deliberate edge cases:
 *  - resubmissions (same id, different payload → min-HLC conflict rule)
 *  - responses/closes/results stamped BEFORE the form's publish HLC (deferred)
 *  - not-creator gated events (dropped)
 *  - responses after close (dropped 'form-closed')
 *  - duplicate results (LWW supersede) */
export function generateWorld(rng, seed) {
  const nCreators = 1 + ri(rng, 3);
  const creators = Array.from({ length: nCreators }, (_, i) => addr(0x100 + i));
  const respondents = Array.from({ length: 3 + ri(rng, 6) }, (_, i) => addr(0x500 + i));
  const devices = ["dev-a", "dev-b", "dev-c"];

  // Realistic clock model: one real-time line advancing 0..49ms per event; each
  // device stamps with its own skewed wall clock (fixed random offset, -100..+99ms).
  // Per-device HLCs are unique by construction (ctr advances when the reading does
  // not move forward — exactly loam-sync's Clock.send). Cross-device INVERSIONS
  // arise naturally from skew: a response can carry an earlier wall than the form
  // it answers. This is what the fold's lenient ordering must absorb.
  const skew = {};
  for (const d of devices) skew[d] = ri(rng, 200) - 100;
  let now = 1_700_000_000_000 + seed; // base epoch, distinct per seed
  const clocks = {};
  const stamp = (dev) => {
    now += ri(rng, 50);
    const t = now + skew[dev];
    const c = (clocks[dev] ??= { wall: 0, ctr: 0 });
    if (t > c.wall) { c.wall = t; c.ctr = 0; } else { c.ctr += 1; }
    return { wall: c.wall, ctr: c.ctr, dev };
  };

  const events = [];
  const forms = [];
  const nForms = 1 + ri(rng, 4);
  for (let i = 0; i < nForms; i++) {
    const creator = pick(rng, creators);
    const formId = `f-${seed}-${i}`;
    const form = {
      id: formId,
      title: `Form ${i} (${seed})`,
      description: "desc",
      creator,
      publicKey: "02" + formId.replace(/[^a-z0-9]/gi, "").padEnd(64, "ab").slice(0, 64),
      createdAt: now + 1,
      expiresAt: rng() < 0.3 ? now + 86_400_000 : undefined,
      questions: [
        { id: `q${i}a`, type: "text", text: "name?", required: true },
        { id: `q${i}b`, type: rng() < 0.5 ? "radioButtons" : "checkbox", text: "pick", required: false, options: ["x", "y"] },
      ],
      whitelist: pick(rng, [
        { type: "none", value: "" },
        { type: "addresses", value: respondents[0] + "," + (respondents[1] ?? "") },
      ]),
      signature: rng() < 0.8 ? "sig-form-" + formId : null, // some unsigned (permissive admit)
    };
    const hlc = stamp(pick(rng, devices));
    events.push(evFormPublish({ hlc, dev: hlc.dev, form }));
    forms.push({ formId, creator, publishHlc: hlc });

    // Responses from a random subset of respondents (real-time order; skew may
    // invert their HLCs relative to the publish — that's the point).
    const nResp = ri(rng, respondents.length + 1);
    for (let r = 0; r < nResp; r++) {
      const respondent = pick(rng, respondents);
      const rhlc = stamp(pick(rng, devices));
      const payload = {
        formId, respondent, submittedAt: rhlc.wall,
        encryptedPayload: "sealed:" + formId + ":" + respondent + ":" + r,
        signature: rng() < 0.7 ? "sig-resp-" + formId + "-" + respondent : null,
      };
      events.push(evResponseSubmit({ hlc: rhlc, dev: rhlc.dev, ...payload }));
      // Resubmission edge case: ~15% → same id, different payload, later HLC.
      if (rng() < 0.15) {
        const rhlc2 = stamp(rhlc.dev); // same device, strictly later HLC
        events.push(evResponseSubmit({
          hlc: rhlc2, dev: rhlc2.dev, formId, respondent, submittedAt: rhlc2.wall,
          encryptedPayload: "sealed:RESUB:" + formId + ":" + respondent, signature: null,
        }));
      }
    }

    // Confirmations (creator only; one per some responses).
    if (rng() < 0.8) {
      const nConf = ri(rng, 3);
      for (let c = 0; c < nConf; c++) {
        const chlc = stamp(pick(rng, devices));
        events.push(evResponseConfirm({ hlc: chlc, dev: chlc.dev, formId, confirmationId: `conf-${seed}-${i}-${c}`, author: creator }));
      }
    }

    // Close (sticky) — ~40% of forms.
    if (rng() < 0.4) {
      const chlc = stamp(pick(rng, devices));
      events.push(evFormClose({ hlc: chlc, dev: chlc.dev, formId, expiresAt: rng() < 0.3 ? now + 999_999 : undefined, author: creator }));
      // Late response (real-time after the close; skew may reorder — both
      // outcomes must converge). Dedicated device keeps its HLC unique.
      if (rng() < 0.5) {
        const respondent = pick(rng, respondents);
        const lateDev = `dev-late-${seed}-${i}`;
        const rhlc = stamp(lateDev);
        events.push(evResponseSubmit({ hlc: rhlc, dev: rhlc.dev, formId, respondent, submittedAt: rhlc.wall, encryptedPayload: "sealed:late", signature: null }));
      }
    }

    // Results — ~30% of forms; ~50% of those get a SECOND (superseding) result.
    if (rng() < 0.3) {
      const r1 = stamp(pick(rng, devices));
      events.push(evFormResults({ hlc: r1, dev: r1.dev, formId, resultsJson: JSON.stringify({ n: 1 }), author: creator }));
      if (rng() < 0.5) {
        const r2 = stamp(r1.dev); // same device, strictly later HLC → LWW winner
        events.push(evFormResults({ hlc: r2, dev: r2.dev, formId, resultsJson: JSON.stringify({ n: 2 }), author: creator }));
      }
    }
  }

  // Adversarial edge case: a gated event from a NON-creator (must be dropped).
  if (forms.length > 0) {
    const f = pick(rng, forms);
    const hlc = stamp(pick(rng, devices));
    events.push(evFormClose({ hlc, dev: hlc.dev, formId: f.formId, author: addr(0x999) })); // not the creator
  }

  return { creators, events };
}

/** Partition a world into per-device logs with shuffled order + redelivery. */
export function partitionLogs(rng, events, nDevices = 3) {
  const logs = Array.from({ length: nDevices }, () => []);
  for (const e of events) logs[ri(rng, nDevices)].push(e);
  for (const log of logs) {
    // Shuffle arrival order within each device log.
    for (let i = log.length - 1; i > 0; i--) {
      const j = ri(rng, i + 1);
      [log[i], log[j]] = [log[j], log[i]];
    }
    // Duplicate redelivery: ~20% of events appear twice in some log.
    for (const e of [...log]) if (rng() < 0.2) log.push(e);
  }
  return logs;
}

