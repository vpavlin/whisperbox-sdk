// whisperbox contract — identity + ECIES sealing (TS reference; @noble/curves + node:crypto).
// BYTE-PARITY with whisperbox_core/src/whisperbox_identity.hpp + whisperbox_crypto.hpp.
//
// ── Identity (qaku convention; sha256-based address, NOT keccak/EVM) ──────────────
//   priv      = 32B scalar (1..n-1 of secp256k1)
//   pub       = 33B compressed point (0x02|0x03 || X)
//   address   = "0x" + hex(sha256(pub_compressed))[48..64]      // last 20 bytes
//
// ── Event signing (authenticity) ──────────────────────────────────────────────────
//   canonicalMessage(e) = "whisperbox-sig-v1|" + type + "|" + wall + "|" + ctr + "|"
//                         + dev + "|" + id + "|" + cjson(payload)
//   (dev = hlc.dev || dev; binds envelope AND payload — one scheme for all types)
//   digest = sha256(utf8(canonicalMessage))
//   sig    = hex(compact ECDSA r||s, 64B), LOW-S (noble default)
//   Verifier: strict low-S first, then lenient retry with s' = n - s.
//
// ── Response sealing (ECIES to the creator; ONLY the creator can open) ────────────
// Ground truth (whisperbox.org src/lib/waku.ts): the ENTIRE response JSON — formId,
// respondent, submittedAt, answers, signature — is sealed to the creator's pubkey.
// Nothing about a response appears in plaintext on the topic: no identity leak, no
// content leak, no "who answered what" metadata. The sealed blob must therefore be
// self-contained (ephemeral pubkey embedded), exactly like Waku ECIES.
//   ephPriv = 32B CSPRNG            (or explicit via opts for deterministic tests)
//   ephPub  = secp256k1(ephPriv)
//   Sx      = X-coordinate of the ECDH shared point (32B)
//             sender:  ECDH(ephPriv, creatorPub);  creator: ECDH(creatorPriv, ephPub)
//   K       = HKDF-SHA256(ikm=Sx, salt="whisperbox-ecies-v1", info="", L=32)
//   nonce   = 12B CSPRNG            (or sha256("whisperbox-nonce-v1|"||ephPriv||creatorPub)[0..12]
//                                    when opts.deterministic — golden vectors)
//   aad     = creatorPub(33) || ephPub(33)
//   sealed  = 0x01 || ephPub(33) || nonce(12) || ChaCha20-Poly1305(K, nonce, pt, aad) || tag(16)

import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  hkdfSync, createHash, createCipheriv, createDecipheriv, randomBytes,
} from "node:crypto";

// secp256k1 group order (fixed curve constant; v2 of @noble/curves no longer
// exposes CURVE on the module).
export const SECP256K1_N = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);

const hexRe = /^[0-9a-fA-F]*$/;
export function toHex(b) {
  return Buffer.from(b).toString("hex");
}
export function fromHex(s) {
  if (!hexRe.test(s) || s.length % 2 !== 0) throw new Error("bad hex: " + String(s).slice(0, 24));
  return Buffer.from(s, "hex");
}
// bigint → 32-byte big-endian buffer (for ECDSA s-flip retry).
function be32(big) {
  let h = big.toString(16);
  if (h.length > 64) throw new Error("bigint overflow");
  return Buffer.from(h.padStart(64, "0"), "hex");
}

// ── Identity ───────────────────────────────────────────────────────────────────────
export function identityFromPriv(priv) {
  const priv32 = Buffer.isBuffer(priv) ? new Uint8Array(priv) : fromHex(priv);
  if (priv32.length !== 32) return null;
  let pub;
  try {
    pub = secp256k1.getPublicKey(priv32, true); // throws on invalid scalar
  } catch {
    return null;
  }
  const h = createHash("sha256").update(pub).digest();
  return {
    priv: Buffer.from(priv32),          // 32B
    pub: Buffer.from(pub),              // 33B compressed
    pubHex: toHex(pub),                 // 66 chars
    address: "0x" + toHex(h).slice(24), // last 20 bytes, qaku convention
  };
}

export function generateIdentity() {
  for (let i = 0; i < 8; i++) {
    const id = identityFromPriv(randomBytes(32));
    if (id) return id;
  }
  throw new Error("identity generation failed");
}

// ── Canonical JSON (sorted keys, compact) — must match C++ cjson() exactly ────────
export function cjson(v) {
  if (v === null || v === undefined) return "null";
  const t = typeof v;
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number") return JSON.stringify(v); // ints stay ints; payloads use ints
  if (t === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(cjson).join(",") + "]";
  if (t === "object") {
    const keys = Object.keys(v).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + cjson(v[k])).join(",") + "}";
  }
  throw new Error("cjson: unsupported type " + t);
}

// ── ECDSA (compact r||s 64B; noble signs low-S by default, verifies strict) ───────
// NOTE: v2 of @noble/curves defaults to prehash:true (it would hash our digest
// AGAIN). We sign/verify RAW 32-byte digests — pass prehash:false everywhere,
// matching C++ ECDSA_do_sign/do_verify over the digest.
export function signDigest(identity, digest32) {
  return Buffer.from(secp256k1.sign(new Uint8Array(digest32), identity.priv, { prehash: false }));
}

export function verifyDigest(pubHex, digest32, sig64Hex) {
  let pub, sig;
  try { pub = fromHex(pubHex); sig = fromHex(sig64Hex); } catch { return false; }
  if (pub.length !== 33 || sig.length !== 64) return false;
  const d = new Uint8Array(digest32);
  try {
    if (secp256k1.verify(new Uint8Array(sig), d, pub, { prehash: false })) return true; // strict low-S
  } catch { /* invalid point or malformed sig */ }
  // Lenient: accept a HIGH-S signature (other implementations) by retrying with
  // the low-S equivalent s' = n - s.
  const sBig = BigInt("0x" + toHex(sig.subarray(32)));
  if (sBig > SECP256K1_N / 2n) {
    const flipped = Buffer.from(sig);
    flipped.set(be32(SECP256K1_N - sBig), 32);
    try { return secp256k1.verify(new Uint8Array(flipped), d, pub, { prehash: false }); } catch { return false; }
  }
  return false;
}

// ── Event signing (canonical message binds envelope + full payload) ───────────────
export function canonicalMessage(e) {
  const dev = e.hlc?.dev || e.dev;
  return "whisperbox-sig-v1|" + e.type + "|" + e.hlc.wall + "|" + e.hlc.ctr + "|"
    + dev + "|" + e.id + "|" + cjson(e.payload);
}

export function signEvent(identity, event) {
  const digest = createHash("sha256").update(canonicalMessage(event)).digest();
  return { pub: identity.pubHex, sig: toHex(signDigest(identity, digest)) };
}

export function verifyEvent(event) {
  if (!event.pub || !event.sig) return false;
  if (!event.type || !event.id) return false;
  // Claimed identity: form.publish → payload.creator; other gated events →
  // payload.author. (dev/hlc.dev is HLC device metadata, NOT an identity claim.)
  const claimed = event.type === "form.publish" ? event.payload?.creator : event.payload?.author;
  if (!claimed) return false;
  let pub;
  try { pub = fromHex(event.pub); } catch { return false; }
  const h = createHash("sha256").update(pub).digest();
  if (("0x" + toHex(h).slice(24)) !== String(claimed).toLowerCase()) return false;
  const digest = createHash("sha256").update(canonicalMessage(event)).digest();
  return verifyDigest(event.pub, digest, event.sig);
}

// ── ECDH shared X-coordinate (32B) — matches C++ affine-X extraction ──────────────
export function ecdhX(priv32, pub33) {
  const priv = Buffer.isBuffer(priv32) ? new Uint8Array(priv32) : fromHex(priv32);
  const pub = Buffer.isBuffer(pub33) ? new Uint8Array(pub33) : fromHex(pub33);
  if (priv.length !== 32 || pub.length !== 33) throw new Error("bad ecdh inputs");
  const shared = secp256k1.getSharedSecret(priv, pub, false); // 65B uncompressed
  return Buffer.from(shared).subarray(1, 33); // X coordinate
}

// ── ECIES seal / open ──────────────────────────────────────────────────────────────
const hkdf = (ikm, salt, info, len) => Buffer.from(hkdfSync("sha256", ikm, salt, info, len));
const sha256b = (b) => createHash("sha256").update(b).digest();

/** Seal `plaintext` to a creator. opts: { ephPriv?, deterministic? } — both default
 *  to CSPRNG randomness; pass them for reproducible golden vectors. */
export function sealToCreator(respondentIdentity, creatorPubHexOrBuf, plaintext, opts = {}) {
  const pt = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, "utf8");
  const creatorPub = Buffer.isBuffer(creatorPubHexOrBuf) ? creatorPubHexOrBuf : fromHex(creatorPubHexOrBuf);
  if (creatorPub.length !== 33) throw new Error("creator pub must be 33 bytes");

  const ephPriv = opts.ephPriv
    ? Buffer.isBuffer(opts.ephPriv) ? opts.ephPriv : fromHex(opts.ephPriv)
    : randomBytes(32);
  if (ephPriv.length !== 32) throw new Error("ephPriv must be 32 bytes");
  let ephPub;
  try {
    ephPub = Buffer.from(secp256k1.getPublicKey(new Uint8Array(ephPriv), true));
  } catch {
    throw new Error("invalid ephemeral key");
  }

  const Sx = ecdhX(ephPriv, creatorPub);
  const K = hkdf(Sx, Buffer.from("whisperbox-ecies-v1"), Buffer.alloc(0), 32);
  const nonce = opts.deterministic
    ? sha256b(Buffer.concat([Buffer.from("whisperbox-nonce-v1|"), ephPriv, creatorPub])).subarray(0, 12)
    : randomBytes(12);
  const aad = Buffer.concat([creatorPub, ephPub]);

  const ch = createCipheriv("chacha20-poly1305", K, nonce, { authTagLength: 16 });
  ch.setAAD(aad);
  const ct = Buffer.concat([ch.update(pt), ch.final()]);
  return Buffer.concat([Buffer.from([0x01]), ephPub, nonce, ct, ch.getAuthTag()]);
}

/** Open a sealed response with the creator's private key. Returns plaintext Buffer;
 *  throws on bad tag (wrong creator / tampered blob). */
export function eciesOpen(creatorIdentity, sealed) {
  const blob = Buffer.isBuffer(sealed) ? sealed : fromHex(sealed);
  if (blob.length < 1 + 33 + 12 + 16) throw new Error("sealed too short");
  if (blob[0] !== 0x01) throw new Error("unknown seal version " + blob[0]);
  const ephPub = blob.subarray(1, 34);
  const nonce = blob.subarray(34, 46);
  const tag = blob.subarray(blob.length - 16);
  const ct = blob.subarray(46, blob.length - 16);

  const Sx = ecdhX(creatorIdentity.priv, ephPub); // symmetric — same shared point
  const K = hkdf(Sx, Buffer.from("whisperbox-ecies-v1"), Buffer.alloc(0), 32);
  const aad = Buffer.concat([creatorIdentity.pub, ephPub]);

  const dc = createDecipheriv("chacha20-poly1305", K, nonce, { authTagLength: 16 });
  dc.setAAD(aad);
  dc.setAuthTag(tag);
  let pt;
  try {
    pt = Buffer.concat([dc.update(ct), dc.final()]); // throws on bad tag
  } catch {
    throw new Error("aead tag verification failed");
  }
  return pt;
}
