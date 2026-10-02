// gen-fixtures.mjs — regenerate the golden vectors from seed 164 (same world
// model as convergence.test.mjs). Run: node test/gen-fixtures.mjs
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

import { mergeWhisperbox } from "../../contract/src/merge.mjs";
import { eciesOpen } from "../../contract/src/crypto.mjs";
import { computeState, creatorView } from "../src/engine.mjs";
import { mulberry32, generateWorld, partitionLogs, goldenCreator } from "./_world.mjs";
import { toHex, identityFromPriv, signEvent, sealToCreator } from "../../contract/src/crypto.mjs";
import { evFormPublish, evFormClose, evResponseConfirm, evFormReopen, evResponseConfirmBatch, evResponseSubmit } from "../../contract/src/events.mjs";
import { mergeOne } from "../../contract/src/merge.mjs";

const here = dirname(fileURLToPath(import.meta.url));
mkdirSync(join(here, "fixtures"), { recursive: true });

const seed = 164;
const rng = mulberry32(seed * 7919 + 0);
const { creators, creatorObjs, events } = generateWorld(rng, seed);
const logs = partitionLogs(rng, events, 3);
const merged = mergeWhisperbox(...logs);
const gc = goldenCreator(merged, creatorObjs);
const state = computeState(merged, { identity: gc.address });

const open = (hex) => {
  try { return JSON.parse(eciesOpen(gc, hex).toString("utf8")); } catch { return null; }
};
const view = creatorView(state, { identity: gc.address, open });

const fmt = (x) => JSON.stringify(x, null, 2) + "\n";
writeFileSync(join(here, "fixtures", "golden-merged.json"), fmt(merged));
writeFileSync(join(here, "fixtures", "golden-state.json"), fmt(state));
writeFileSync(join(here, "fixtures", "golden-creatorview.json"), fmt(view));
// For the C++ golden check (whisperbox_core/test/engine_golden_test.cpp).
writeFileSync(join(here, "fixtures", "golden-meta.json"), fmt({ seed, identity: gc.address, privHex: toHex(gc.priv) }));
console.log(`wrote fixtures: ${merged.length} merged events, ${Object.keys(state.forms).length} forms, ${state.responses.length} sealed blobs`);

// ── Squat golden: a contested form id (back-dated squat + forged close + genuine
// close/confirm). C++ must reproduce all three per-device projections.
{
  const sh = (t) => createHash("sha256").update(t).digest();
  const C = identityFromPriv(sh("squat-creator")), X = identityFromPriv(sh("squat-attacker"));
  const sign = (id, e) => ({ ...e, ...signEvent(id, e) });
  const pub = (id, wall, title) => sign(id, evFormPublish({ hlc: { wall, ctr: 0, dev: "d" }, dev: "d",
    form: { id: "fs", title, description: "", creator: id.address, publicKey: id.pubHex, createdAt: wall, questions: [], whitelist: { type: "none", value: "" }, signature: null } }));
  const evs = [
    pub(C, 100, "genuine"), sign(C, evFormClose({ hlc: { wall: 300, ctr: 0, dev: "d" }, dev: "d", formId: "fs", author: C.address })),
    sign(C, evResponseConfirm({ hlc: { wall: 310, ctr: 0, dev: "d" }, dev: "d", formId: "fs", confirmationId: "c1", author: C.address })),
    pub(X, 50, "squat"), sign(X, evFormClose({ hlc: { wall: 200, ctr: 0, dev: "d" }, dev: "d", formId: "fs", author: X.address })),
  ];
  const log = []; for (const e of evs) mergeOne(log, e);
  writeFileSync(join(here, "fixtures", "golden-squat.json"), fmt({
    creator: C.address, attacker: X.address, log,
    asCreator: computeState(log, { identity: C.address }),
    pinned: computeState(log, { prefer: { fs: C.address } }),
    browsing: computeState(log, {}),
  }));
}

// ── Lifecycle golden (0.3.2): close -> re-open -> close, answers sealed in each period,
// answer cap, close-at date, receipts one-by-one AND in one batch event. C++ must
// reproduce state + creator view for any arrival order.
{
  const sh = (t) => createHash("sha256").update(t).digest();
  const C = identityFromPriv(sh("life-creator"));
  const sign = (e) => ({ ...e, ...signEvent(C, e) });
  const at = (wall) => ({ hlc: { wall, ctr: 0, dev: "d" }, dev: "d" });
  const form = (id, extra) => sign(evFormPublish({ ...at(100), form: { id, title: id, description: "", creator: C.address, publicKey: C.pubHex,
    createdAt: 100, questions: [{ id: "q1", type: "boolean", text: "ok?", required: true }], whitelist: { type: "none", value: "" }, signature: null, ...extra } }));
  const resp = (fid, who, wall) => {
    const pt = JSON.stringify({ formId: fid, respondent: who, submittedAt: wall, answers: [{ questionId: "q1", value: wall % 2 === 0 }], signature: null, pub: null, confirmationId: "c-" + fid + "-" + wall });
    return evResponseSubmit({ ...at(wall), encryptedPayload: toHex(sealToCreator(null, C.pubHex, pt, { ephPriv: sh("eph" + fid + wall), deterministic: true })) });
  };
  const addr = (i) => "0x" + String(i).padStart(40, "0");
  const evs = [
    form("life"), form("capped", { maxResponses: 2, showResponseCount: true }), form("dated", { expiresAt: 500 }),
    resp("life", addr(1), 150),                                                            // open: counts
    sign(evFormClose({ ...at(200), formId: "life", author: C.address, nonce: "n1" })),
    resp("life", addr(2), 250),                                                            // closed: dropped
    sign(evFormReopen({ ...at(300), formId: "life", author: C.address, nonce: "n2" })),
    resp("life", addr(3), 350),                                                            // re-opened: counts
    sign(evFormClose({ ...at(400), formId: "life", author: C.address, nonce: "n3" })),
    resp("life", addr(4), 450),                                                            // closed again: dropped
    resp("capped", addr(5), 150), resp("capped", addr(6), 160), resp("capped", addr(7), 170),   // 3rd: over-limit
    resp("dated", addr(8), 450), resp("dated", addr(9), 550),                              // 2nd: after expiresAt
    sign(evResponseConfirm({ ...at(600), formId: "capped", confirmationId: "c-capped-150", author: C.address })),
    sign(evResponseConfirmBatch({ ...at(610), formId: "life", confirmationIds: ["c-life-150", "c-life-350"], author: C.address })),
  ];
  const log = []; for (const e of evs) mergeOne(log, e);
  const st = computeState(log, { identity: C.address });
  const openC = (hex) => { try { return JSON.parse(eciesOpen(C, hex).toString("utf8")); } catch { return null; } };
  writeFileSync(join(here, "fixtures", "golden-lifecycle.json"), fmt({
    creator: C.address, privHex: toHex(C.priv), log, state: st, view: creatorView(st, { identity: C.address, open: openC }),
  }));
}
