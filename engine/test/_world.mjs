// _world.mjs — seeded world generation shared by convergence.test.mjs and
// gen-fixtures.mjs (single source of truth for the random-world model).
//
// P2: responses are REAL ECIES-sealed blobs (crypto.mjs) addressed to the form's
// creator — deterministic via fixed ephPriv + derived nonce, so golden vectors
// reproduce byte-for-byte. The fold sees them as opaque; creatorView tests open
// them with the creator's key.

import { createHash } from "node:crypto";
import { evFormPublish, evResponseSubmit, evResponseConfirm, evFormClose } from "../../contract/src/events.mjs";
import { identityFromPriv, sealToCreator, toHex } from "../../contract/src/crypto.mjs";

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
const sha = (s) => createHash("sha256").update(s).digest();

// Fake address (no key material — for non-creator adversarial events).
export const addr = (n) => "0x" + n.toString(16).padStart(40, "0");

/** Fixed test identities: stable across runs & seeds (golden-vector friendly). */
const IDENTITY_POOL = [];
function identityAt(i) {
  if (!IDENTITY_POOL[i]) {
    IDENTITY_POOL[i] = identityFromPriv(sha("whisperbox-world-identity-" + i));
  }
  return IDENTITY_POOL[i];
}

/** Builds a random world of events with deliberate edge cases:
 *  - resubmissions (same respondent, different answers → new content-addressed id;
 *    creator view keeps min-HLC per respondent)
 *  - responses/closes stamped BEFORE the form's publish HLC (deferred gated replay)
 *  - not-creator gated events (dropped)
 *  - responses after close (creator-view 'form-closed' drops)
 *  - undecryptable blobs for the queried creator (other creators' forms) */
export function generateWorld(rng, seed) {
  const nCreators = 1 + ri(rng, 3);
  const creatorIds = Array.from({ length: nCreators }, (_, i) => identityAt(0x100 + i));
  const respondentIds = Array.from({ length: 3 + ri(rng, 6) }, (_, i) => identityAt(0x500 + i));
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

  // Seal a response to the form creator — deterministic per (seed, form, respondent, r).
  const sealResponse = (creatorId, respondentId, formId, r, resub = false) => {
    const ephPriv = sha("eph|" + seed + "|" + formId + "|" + respondentId.address + "|" + r);
    const body = JSON.stringify({
      formId,
      respondent: respondentId.address,
      submittedAt: null, // filled by caller with the event wall (kept in answers for realism)
      answers: [
        { questionId: "q0a", value: resub ? "RESUB" : "answer-" + r },
        { questionId: "q0b", value: resub ? 1 : 0 },
      ],
      signature: rng() < 0.7 ? "sig-resp-" + formId + "-" + r : null,
    });
    return toHex(sealToCreator(respondentId, creatorId.pubHex, body, { ephPriv, deterministic: true }));
  };

  const events = [];
  const forms = [];
  const nForms = 1 + ri(rng, 4);
  for (let i = 0; i < nForms; i++) {
    const creatorId = pick(rng, creatorIds);
    const formId = `f-${seed}-${i}`;
    const whitelistOn = rng() < 0.5;
    const form = {
      id: formId,
      title: `Form ${i} (${seed})`,
      description: "desc",
      creator: creatorId.address,
      publicKey: creatorId.pubHex, // REAL compressed pubkey — seals address to it
      createdAt: now + 1,
      expiresAt: rng() < 0.3 ? now + 86_400_000 : undefined,
      questions: [
        { id: "q0a", type: "text", text: "name?", required: true },
        { id: "q0b", type: rng() < 0.5 ? "radioButtons" : "checkbox", text: "pick", required: false, options: ["x", "y"] },
      ],
      whitelist: whitelistOn
        ? { type: "addresses", value: respondentIds[0].address + "," + (respondentIds[1]?.address ?? "") }
        : { type: "none", value: "" },
      signature: rng() < 0.8 ? "sig-form-" + formId : null, // some unsigned (permissive admit)
    };
    const hlc = stamp(pick(rng, devices));
    events.push(evFormPublish({ hlc, dev: hlc.dev, form }));
    forms.push({ formId, creator: creatorId.address, publishHlc: hlc });

    // Responses from a random subset of respondents (real-time order; skew may
    // invert their HLCs relative to the publish — that's the point).
    const nResp = ri(rng, respondentIds.length + 1);
    for (let r = 0; r < nResp; r++) {
      const respondentId = pick(rng, respondentIds);
      const rhlc = stamp(pick(rng, devices));
      const encryptedPayload = sealResponse(creatorId, respondentId, formId, r);
      events.push(evResponseSubmit({ hlc: rhlc, dev: rhlc.dev, encryptedPayload }));
      // Resubmission edge case: ~15% → same respondent, DIFFERENT answers → new
      // content-addressed id; creator view keeps the min-HLC one per respondent.
      if (rng() < 0.15) {
        const rhlc2 = stamp(rhlc.dev); // same device, strictly later HLC
        events.push(evResponseSubmit({
          hlc: rhlc2, dev: rhlc2.dev,
          encryptedPayload: sealResponse(creatorId, respondentId, formId, r, true),
        }));
      }
    }

    // Confirmations (creator only; one per some responses).
    if (rng() < 0.8) {
      const nConf = ri(rng, 3);
      for (let c = 0; c < nConf; c++) {
        const chlc = stamp(pick(rng, devices));
        events.push(evResponseConfirm({ hlc: chlc, dev: chlc.dev, formId, confirmationId: `conf-${seed}-${i}-${c}`, author: creatorId.address }));
      }
    }

    // Close (sticky) — ~40% of forms.
    if (rng() < 0.4) {
      const chlc = stamp(pick(rng, devices));
      events.push(evFormClose({ hlc: chlc, dev: chlc.dev, formId, expiresAt: rng() < 0.3 ? now + 999_999 : undefined, author: creatorId.address }));
      // Late response (real-time after the close; skew may reorder — both
      // outcomes must converge). Dedicated device keeps its HLC unique.
      if (rng() < 0.5) {
        const respondentId = pick(rng, respondentIds);
        const lateDev = `dev-late-${seed}-${i}`;
        const rhlc = stamp(lateDev);
        events.push(evResponseSubmit({
          hlc: rhlc, dev: rhlc.dev,
          encryptedPayload: sealResponse(creatorId, respondentId, formId, 900 + i),
        }));
      }
    }
  }

  // Adversarial edge case: a gated event from a NON-creator (must be dropped).
  if (forms.length > 0) {
    const f = pick(rng, forms);
    const hlc = stamp(pick(rng, devices));
    events.push(evFormClose({ hlc, dev: hlc.dev, formId: f.formId, author: addr(0x999) })); // not the creator
  }

  return { creators: creatorIds.map((c) => c.address), creatorObjs: creatorIds, respondentIds, events };
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
