// gen-crypto-fixtures.mjs — golden vectors for the C++ parity test (whisperbox_core).
// Fixed identities + signed events + deterministic ECIES seals. Run:
// node test/gen-crypto-fixtures.mjs   → writes test/fixtures/crypto-*.json
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

import { identityFromPriv, signEvent, sealToCreator, toHex } from "../src/crypto.mjs";
import { evFormPublish, evResponseConfirm, evFormClose } from "../src/events.mjs";

const here = dirname(fileURLToPath(import.meta.url));
mkdirSync(join(here, "fixtures"), { recursive: true });
const sha = (s) => createHash("sha256").update(s).digest();

// ── Fixed identities ───────────────────────────────────────────────────────────────
const names = ["alice", "bob", "carol"];
const ids = {};
for (const n of names) ids[n] = identityFromPriv(sha("whisperbox-test-" + n));

writeFileSync(join(here, "fixtures", "crypto-identities.json"), JSON.stringify({
  identities: names.map((n) => ({ name: n, privHex: toHex(ids[n].priv), pubHex: ids[n].pubHex, address: ids[n].address })),
}, null, 2) + "\n");

// ── Signed events (C++ must verify; tamper check uses the first one) ──────────────
const alice = ids.alice, bob = ids.bob;
const ev1 = evFormPublish({
  hlc: { wall: 1_700_000_000_000, ctr: 3, dev: "bosgame" },
  dev: "bosgame",
  form: {
    id: "parity-f1", title: "Parity form — čůtek 🤖", description: "desc with \"quotes\" and \\backslash\\",
    creator: alice.address, publicKey: bob.pubHex, createdAt: 1_700_000_000_000,
    questions: [
      { id: "q1", type: "text", text: "name?", required: true },
      { id: "q2", type: "radioButtons", text: "pick", required: false, options: ["x", "y"] },
    ],
    whitelist: { type: "addresses", value: bob.address },
    signature: null,
  },
});
Object.assign(ev1, signEvent(alice, ev1));

const ev2 = evResponseConfirm({ hlc: { wall: 1_700_000_000_500, ctr: 0, dev: "crib" }, dev: "crib", formId: "parity-f1", confirmationId: "conf-parity-1", author: alice.address });
Object.assign(ev2, signEvent(alice, ev2));

const ev3 = evFormClose({ hlc: { wall: 1_700_000_001_000, ctr: 7, dev: "pi5" }, dev: "pi5", formId: "parity-f1", expiresAt: null, author: alice.address });
Object.assign(ev3, signEvent(alice, ev3));

writeFileSync(join(here, "fixtures", "crypto-signed-events.json"), JSON.stringify({ events: [ev1, ev2, ev3] }, null, 2) + "\n");

// ── Deterministic ECIES seals (C++ opens AND re-seals byte-identically) ───────────
const plaintexts = [
  "hello whisperbox",
  "čůtek — ěšč 🤖 unicode round-trip",
  "",
  "x".repeat(500),
  JSON.stringify({ formId: "parity-f1", respondent: bob.address, submittedAt: 1_700_000_000_500, answers: [{ questionId: "q1", value: "Václav" }], signature: "sig-parity" }),
];
const sealed = plaintexts.map((pt, i) => {
  const ephPriv = sha("parity-eph-" + i);
  return {
    id: "seal-" + i,
    creatorName: "bob",
    respondentName: "alice",
    ephPrivHex: toHex(ephPriv),
    plaintext: pt,
    sealedHex: toHex(sealToCreator(alice, bob.pubHex, pt, { ephPriv, deterministic: true })),
  };
});
writeFileSync(join(here, "fixtures", "crypto-sealed.json"), JSON.stringify({ seals: sealed }, null, 2) + "\n");

console.log(`wrote crypto fixtures: ${names.length} identities, 3 signed events, ${sealed.length} sealed blobs`);
