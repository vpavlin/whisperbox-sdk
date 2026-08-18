// crypto.test.mjs — TS reference self-tests for identity/ECDSA/ECIES.
// Run: node test/crypto.test.mjs   (or npm test in packages/contract)
import assert from "node:assert";
import { createHash } from "node:crypto";
import {
  identityFromPriv, generateIdentity, toHex, fromHex, cjson,
  signDigest, verifyDigest, signEvent, verifyEvent, canonicalMessage,
  sealToCreator, eciesOpen, ecdhX, SECP256K1_N,
} from "../src/crypto.mjs";
import { evFormPublish } from "../src/events.mjs";

const sha = (s) => createHash("sha256").update(s).digest();
let n = 0;
const t0 = Date.now();
const ok = (label) => { n++; };

// ── 1. Identity: deterministic derivation, qaku address convention ────────────────
{
  const alice = identityFromPriv(sha("whisperbox-test-alice"));
  assert.ok(alice, "alice identity derives");
  assert.equal(alice.pub.length, 33);
  assert.ok(alice.pub[0] === 0x02 || alice.pub[0] === 0x03, "compressed point prefix");
  assert.match(alice.address, /^0x[0-9a-f]{40}$/);
  // Deterministic: re-derive → identical
  const again = identityFromPriv(sha("whisperbox-test-alice"));
  assert.equal(toHex(again.pub), alice.pubHex);
  assert.equal(again.address, alice.address);
  // Different key → different address
  const bob = identityFromPriv(sha("whisperbox-test-bob"));
  assert.notEqual(bob.address, alice.address);
  ok("identity derivation");
}

// ── 2. cjson: sorted keys, nested, compact — matches C++ cjson() ─────────────────
{
  const v = { b: 1, a: [true, null, "x\"y\\z"], c: { z: 0, a: "čůtek" } };
  assert.equal(cjson(v), '{"a":[true,null,"x\\"y\\\\z"],"b":1,"c":{"a":"čůtek","z":0}}');
  ok("cjson canonical form");
}

// ── 3. ECDSA: sign/verify round-trip + tamper rejection ───────────────────────────
{
  const alice = identityFromPriv(sha("whisperbox-test-alice"));
  const digest = sha("some message");
  const sig = signDigest(alice, digest);
  assert.equal(sig.length, 64, "compact r||s");
  // low-S invariant
  const sBig = BigInt("0x" + toHex(sig.subarray(32)));
  assert.ok(sBig <= SECP256K1_N / 2n, "low-S normalized");
  assert.ok(verifyDigest(alice.pubHex, digest, toHex(sig)), "verify accepts own sig");

  const bob = identityFromPriv(sha("whisperbox-test-bob"));
  assert.ok(!verifyDigest(bob.pubHex, digest, toHex(sig)), "rejects wrong key");
  assert.ok(!verifyDigest(alice.pubHex, sha("other message"), toHex(sig)), "rejects wrong digest");
  const tampered = Buffer.from(sig); tampered[10] ^= 1;
  assert.ok(!verifyDigest(alice.pubHex, digest, toHex(tampered)), "rejects tampered sig");
  ok("ecdsa sign/verify + rejection");
}

// ── 4. Event signing: canonical message binds envelope+payload ────────────────────
{
  const alice = identityFromPriv(sha("whisperbox-test-alice"));
  const bob = identityFromPriv(sha("whisperbox-test-bob"));
  const ev = evFormPublish({
    hlc: { wall: 1_700_000_000_000, ctr: 3, dev: alice.address },
    dev: alice.address,
    form: {
      id: "f-42", title: "Test form", description: "", creator: alice.address,
      publicKey: bob.pubHex, createdAt: 1_700_000_000_000,
      questions: [{ id: "q1", type: "text", text: "name?", required: true }],
      whitelist: { type: "none", value: "" }, signature: null,
    },
  });
  const { pub, sig } = signEvent(alice, ev);
  assert.equal(pub, alice.pubHex);
  const signed = { ...ev, pub, sig };
  assert.ok(verifyEvent(signed), "signed event verifies");

  // Tamper any field → verification fails (that's the point of full binding)
  const t1 = JSON.parse(JSON.stringify(signed));
  t1.payload.title = "HACKED";
  assert.ok(!verifyEvent(t1), "tampered payload rejected");
  const t2 = JSON.parse(JSON.stringify(signed));
  t2.hlc.wall += 1;
  assert.ok(!verifyEvent(t2), "tampered hlc rejected");
  const t3 = JSON.parse(JSON.stringify(signed));
  t3.pub = bob.pubHex;
  assert.ok(!verifyEvent(t3), "swapped pubkey rejected (address check)");
  ok("event signing full binding");
}

// ── 5. ECIES: seal/open round-trip, determinism (test mode), rejection ─────────
{
  const alice = identityFromPriv(sha("whisperbox-test-alice")); // respondent
  const bob = identityFromPriv(sha("whisperbox-test-bob"));     // creator
  const carol = identityFromPriv(sha("whisperbox-test-carol")); // other creator

  for (const pt of ["hello whisperbox", "čůtek — ěšč 🤖", "", "x".repeat(1000)]) {
    const sealed = sealToCreator(alice, bob.pubHex, pt);
    assert.equal(sealed[0], 0x01, "version byte");
    assert.ok(sealed.length >= 1 + 33 + 12 + 16, "blob shape");
    const opened = eciesOpen(bob, sealed);
    assert.equal(opened.toString("utf8"), pt, "round-trip: " + JSON.stringify(pt.slice(0, 20)));
  }

  // Deterministic mode (fixed ephPriv + derived nonce) → reproducible blobs.
  const eph = sha("test-eph");
  const a1 = toHex(sealToCreator(alice, bob.pubHex, "same message", { ephPriv: eph, deterministic: true }));
  const a2 = toHex(sealToCreator(alice, bob.pubHex, "same message", { ephPriv: eph, deterministic: true }));
  assert.equal(a1, a2, "deterministic seal (golden-vector mode)");
  const a3 = toHex(sealToCreator(alice, carol.pubHex, "same message", { ephPriv: eph, deterministic: true }));
  assert.notEqual(a1, a3, "different creator → different blob");
  // Note: the blob is a pure function of (ephPriv, creatorPub, pt) — respondent
  // long-term identity is NOT bound in (the ephemeral key carries confidentiality).
  const eph2 = sha("test-eph-2");
  const a4 = toHex(sealToCreator(alice, bob.pubHex, "same message", { ephPriv: eph2, deterministic: true }));
  assert.notEqual(a1, a4, "different ephemeral → different blob");

  // Random mode (production): same inputs → different blobs (fresh ephemeral).
  const b1 = toHex(sealToCreator(alice, bob.pubHex, "same message"));
  const b2 = toHex(sealToCreator(alice, bob.pubHex, "same message"));
  assert.notEqual(b1, b2, "random ephemeral → non-repeating blobs");

  // Wrong creator cannot open (tag fails).
  let failed = false;
  try { eciesOpen(carol, sealToCreator(alice, bob.pubHex, "secret")); } catch { failed = true; }
  assert.ok(failed, "wrong creator rejected");

  // Tamper ciphertext → tag fails.
  const sealed = Buffer.from(sealToCreator(alice, bob.pubHex, "tamper me"));
  sealed[50] ^= 1;
  failed = false;
  try { eciesOpen(bob, sealed); } catch { failed = true; }
  assert.ok(failed, "tampered blob rejected");

  // Tamper ephPub → ECDH mismatch → tag fails.
  const sealed2 = Buffer.from(sealToCreator(alice, bob.pubHex, "swap me"));
  sealed2[5] ^= 0x01; // flip a byte of ephPub X
  failed = false;
  try { eciesOpen(bob, sealed2); } catch { failed = true; }
  assert.ok(failed, "swapped ephPub rejected");

  // ECDH symmetry: sender-side and creator-side derive the same shared X.
  const ephK = identityFromPriv(sha("test-eph-key"));
  const x1 = toHex(ecdhX(ephK.priv, bob.pubHex));
  const x2 = toHex(ecdhX(bob.priv, ephK.pubHex));
  assert.equal(x1, x2, "ECDH shared X symmetric");
  ok("ecies seal/open + determinism + rejection");
}

// ── 6. generateIdentity sanity ────────────────────────────────────────────────────
{
  const id = generateIdentity();
  assert.ok(id && id.address.startsWith("0x"));
  ok("generateIdentity");
}

console.log(`crypto self-tests: ${n} groups OK (${Date.now() - t0}ms)`);
