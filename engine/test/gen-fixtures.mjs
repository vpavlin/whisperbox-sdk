// gen-fixtures.mjs — regenerate the golden vectors from seed 164 (same world
// generation as convergence.test.mjs). Run ONLY when the contract/fold changes
// deliberately:  node test/gen-fixtures.mjs   (then review the diff + commit).

import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { mulberry32, generateWorld, partitionLogs } from "./_world.mjs";
import { mergeWhisperbox } from "../../contract/src/merge.mjs";
import { computeState } from "../src/engine.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const seed = 164;
const rng = mulberry32(seed * 7919 + 0);
const { creators, events } = generateWorld(rng, seed);
const logs = partitionLogs(rng, events, 3);
const merged = mergeWhisperbox(...logs);
const state = computeState(merged, { identity: creators[0] });

const fmt = (x) => JSON.stringify(x, null, 2) + "\n";
writeFileSync(join(here, "fixtures", "golden-merged.json"), fmt(merged));
writeFileSync(join(here, "fixtures", "golden-state.json"), fmt(state));
console.log(`wrote fixtures: ${merged.length} merged events, ${Object.keys(state.forms).length} forms`);
