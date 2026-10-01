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
import { toHex, identityFromPriv, signEvent } from "../../contract/src/crypto.mjs";
import { evFormPublish, evFormClose, evResponseConfirm } from "../../contract/src/events.mjs";
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
