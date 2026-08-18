// gen-fixtures.mjs — regenerate the golden vectors from seed 164 (same world
// model as convergence.test.mjs). Run: node test/gen-fixtures.mjs
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

import { mergeWhisperbox } from "../../contract/src/merge.mjs";
import { eciesOpen } from "../../contract/src/crypto.mjs";
import { computeState, creatorView } from "../src/engine.mjs";
import { mulberry32, generateWorld, partitionLogs } from "./_world.mjs";

const here = dirname(fileURLToPath(import.meta.url));
mkdirSync(join(here, "fixtures"), { recursive: true });

const seed = 164;
const rng = mulberry32(seed * 7919 + 0);
const { creators, creatorObjs, events } = generateWorld(rng, seed);
const logs = partitionLogs(rng, events, 3);
const merged = mergeWhisperbox(...logs);
const state = computeState(merged, { identity: creators[0] });

const open = (hex) => {
  try { return JSON.parse(eciesOpen(creatorObjs[0], hex).toString("utf8")); } catch { return null; }
};
const view = creatorView(state, { identity: creators[0], open });

const fmt = (x) => JSON.stringify(x, null, 2) + "\n";
writeFileSync(join(here, "fixtures", "golden-merged.json"), fmt(merged));
writeFileSync(join(here, "fixtures", "golden-state.json"), fmt(state));
writeFileSync(join(here, "fixtures", "golden-creatorview.json"), fmt(view));
console.log(`wrote fixtures: ${merged.length} merged events, ${Object.keys(state.forms).length} forms, ${state.responses.length} sealed blobs`);
