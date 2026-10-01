// whisperbox contract — PORTABLE identity + signing + ECIES (pure @noble, no node:crypto).
// Same bytes as crypto.mjs (the Node reference) and whisperbox_core's C++; runs under Node,
// browsers and React Native/Hermes alike. The mobile app uses THIS file; parity with
// crypto.mjs and the golden fixtures is gated by test/crypto-portable.test.mjs.
//
// Scheme (see crypto.mjs for the full rationale):
//   address  = "0x" + hex(sha256(pub33))[24..64]
//   sign     = ECDSA low-S compact r||s over sha256(canonicalMessage(e)), raw digest
//   sealed   = 0x01 || ephPub(33) || nonce(12) || ChaCha20-Poly1305(K, nonce, pt, aad) || tag(16)
//              K = HKDF-SHA256(ecdhX, salt "whisperbox-ecies-v1", info "", 32),
//              aad = creatorPub || ephPub
// Randomness comes from @noble's randomBytes (globalThis.crypto.getRandomValues) — on
// Hermes the app must install a getRandomValues polyfill (expo-crypto) before use.
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { randomBytes, utf8ToBytes, bytesToHex, hexToBytes, concatBytes } from "@noble/hashes/utils.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";

export const SECP256K1_N = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const SALT = utf8ToBytes("whisperbox-ecies-v1");
const NONCE_PREFIX = utf8ToBytes("whisperbox-nonce-v1|");

export const toHex = (b) => bytesToHex(b);
export function fromHex(s) {
  if (typeof s !== "string" || !/^[0-9a-fA-F]*$/.test(s) || s.length % 2 !== 0) throw new Error("bad hex");
  return hexToBytes(s.toLowerCase());
}
const bytes = (x) => (typeof x === "string" ? fromHex(x) : new Uint8Array(x));
export const sha256Hex = (data) => bytesToHex(sha256(typeof data === "string" ? utf8ToBytes(data) : data));

// UTF-8 decode without TextDecoder (Hermes-safe).
export function utf8Decode(b) {
  let s = "", i = 0;
  while (i < b.length) {
    const c = b[i++];
    if (c < 0x80) s += String.fromCharCode(c);
    else if (c < 0xe0) s += String.fromCharCode(((c & 0x1f) << 6) | (b[i++] & 0x3f));
    else if (c < 0xf0) s += String.fromCharCode(((c & 0x0f) << 12) | ((b[i++] & 0x3f) << 6) | (b[i++] & 0x3f));
    else {
      const cp = (((c & 0x07) << 18) | ((b[i++] & 0x3f) << 12) | ((b[i++] & 0x3f) << 6) | (b[i++] & 0x3f)) - 0x10000;
      s += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
    }
  }
  return s;
}
export const utf8Encode = (s) => utf8ToBytes(s);

// ── Identity ──────────────────────────────────────────────────────────────────────
export function identityFromPriv(priv) {
  const p = bytes(priv);
  if (p.length !== 32) return null;
  let pub;
  try { pub = secp256k1.getPublicKey(p, true); } catch { return null; }
  return { priv: p, pub, pubHex: bytesToHex(pub), address: "0x" + bytesToHex(sha256(pub)).slice(24) };
}
export function generateIdentity() {
  for (let i = 0; i < 8; i++) { const id = identityFromPriv(randomBytes(32)); if (id) return id; }
  throw new Error("identity generation failed");
}
export const randomHex = (n) => bytesToHex(randomBytes(n));

// ── Per-form encryption keys ─────────────────────────────────────────────────────
// Every form gets its OWN sealing key (form.publish payload.publicKey), never the creator's
// identity key. A leaked form key opens one form's answers - not the identity (which signs)
// and not any other form - so one form's key can be handed to a validator hub.
//   soft (identity key on the device):
//     formPriv = first valid scalar of HKDF-SHA256(ikm=identityPriv, salt="whisperbox-formkey-v1",
//                info=utf8(formId) [|| "#" || i for retry i>=1], L=32)
//   keycard: exported from the EIP-1581 subtree, m/43'/60'/1581'/22338'/formKeyIndex(formId)'
//     formKeyIndex = u32be(sha256("whisperbox-formkey-v1|" || formId)[0..4]) & 0x7fffffff
// Respondents are unaffected: they always sealed to the form's publicKey. Legacy forms
// (publicKey == identity pub) keep opening with the identity key.
const FORMKEY_SALT = utf8ToBytes("whisperbox-formkey-v1");
export function deriveFormKey(identity, formId) {
  const fid = String(formId).toLowerCase();
  for (let i = 0; i < 8; i++) {
    const info = utf8ToBytes(i ? fid + "#" + i : fid);
    const id = identityFromPriv(hkdf(sha256, identity.priv, FORMKEY_SALT, info, 32));
    if (id) return id;
  }
  throw new Error("form key derivation failed");
}
export function formKeyIndex(formId) {
  const h = sha256(utf8ToBytes("whisperbox-formkey-v1|" + String(formId).toLowerCase()));
  return ((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) & 0x7fffffff;
}
export const FORMKEY_KEYCARD_PATH = (formId) => `m/43'/60'/1581'/22338'/${formKeyIndex(formId)}'`;

// ── Canonical JSON (sorted keys, compact) — matches crypto.mjs cjson and C++ ─────
export function cjson(v) {
  if (v === null || v === undefined) return "null";
  const t = typeof v;
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number" || t === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(cjson).join(",") + "]";
  if (t === "object") return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + cjson(v[k])).join(",") + "}";
  throw new Error("cjson: unsupported type " + t);
}

// ── ECDSA over raw 32-byte digests (prehash:false), low-S ─────────────────────────
export function signDigest(identity, digest32) {
  return secp256k1.sign(digest32, identity.priv, { prehash: false });
}
export function verifyDigest(pubHex, digest32, sig64Hex) {
  let pub, sig;
  try { pub = fromHex(pubHex); sig = fromHex(sig64Hex); } catch { return false; }
  if (pub.length !== 33 || sig.length !== 64) return false;
  try { if (secp256k1.verify(sig, digest32, pub, { prehash: false })) return true; } catch { /* malformed */ }
  // Lenient: accept a high-S signature by retrying with s' = n - s (as crypto.mjs/C++ do).
  const s = BigInt("0x" + bytesToHex(sig.subarray(32)));
  if (s > SECP256K1_N / 2n) {
    const flipped = new Uint8Array(sig);
    flipped.set(hexToBytes((SECP256K1_N - s).toString(16).padStart(64, "0")), 32);
    try { return secp256k1.verify(flipped, digest32, pub, { prehash: false }); } catch { return false; }
  }
  return false;
}

// ── Event signing: binds envelope + full payload ─────────────────────────────────
export function canonicalMessage(e) {
  const dev = (e.hlc && e.hlc.dev) || e.dev;
  return "whisperbox-sig-v1|" + e.type + "|" + e.hlc.wall + "|" + e.hlc.ctr + "|" + dev + "|" + e.id + "|" + cjson(e.payload);
}
export function signEvent(identity, event) {
  return { pub: identity.pubHex, sig: bytesToHex(signDigest(identity, sha256(utf8ToBytes(canonicalMessage(event))))) };
}
export function verifyEvent(event) {
  if (!event || !event.pub || !event.sig || !event.type || !event.id) return false;
  const claimed = event.type === "form.publish" ? event.payload?.creator : event.payload?.author;
  if (!claimed) return false;
  let pub;
  try { pub = fromHex(event.pub); } catch { return false; }
  if ("0x" + bytesToHex(sha256(pub)).slice(24) !== String(claimed).toLowerCase()) return false;
  return verifyDigest(event.pub, sha256(utf8ToBytes(canonicalMessage(event))), event.sig);
}

// ── Inner response signature (whitelisted forms): signed INSIDE the sealed blob ──
// "whisperbox-inner-v1|" + {"formId","respondent","submittedAt","answers"} in THIS key
// order, compact — exactly the C++ OrderedJson dump. Answers keep their own key order
// ({questionId, value}).
export function innerMessage(r) {
  return "whisperbox-inner-v1|" + JSON.stringify({
    formId: String(r.formId).toLowerCase(), respondent: String(r.respondent).toLowerCase(),
    submittedAt: r.submittedAt ?? 0, answers: r.answers ?? [],
  });
}
export function signInner(identity, r) {
  return bytesToHex(signDigest(identity, sha256(utf8ToBytes(innerMessage(r)))));
}
export function verifyInner(r) {
  if (!r || !r.pub || !r.signature) return false;
  if (!verifyDigest(r.pub, sha256(utf8ToBytes(innerMessage(r))), r.signature)) return false;
  return "0x" + bytesToHex(sha256(fromHex(r.pub))).slice(24) === String(r.respondent).toLowerCase();
}

// ── ECIES ─────────────────────────────────────────────────────────────────────────
export function ecdhX(priv32, pub33) {
  const priv = bytes(priv32), pub = bytes(pub33);
  if (priv.length !== 32 || pub.length !== 33) throw new Error("bad ecdh inputs");
  return secp256k1.getSharedSecret(priv, pub, false).slice(1, 33);
}
/** Seal `plaintext` (string or bytes) to a creator's 33-byte pubkey (hex or bytes).
 *  opts: { ephPriv?, deterministic? } for golden vectors only. */
export function sealToCreator(_respondent, creatorPub, plaintext, opts = {}) {
  const pt = typeof plaintext === "string" ? utf8ToBytes(plaintext) : new Uint8Array(plaintext);
  const cpub = bytes(creatorPub);
  if (cpub.length !== 33) throw new Error("creator pub must be 33 bytes");
  const ephPriv = opts.ephPriv ? bytes(opts.ephPriv) : secp256k1.utils.randomSecretKey();
  const ephPub = secp256k1.getPublicKey(ephPriv, true);
  const K = hkdf(sha256, ecdhX(ephPriv, cpub), SALT, new Uint8Array(0), 32);
  const nonce = opts.deterministic ? sha256(concatBytes(NONCE_PREFIX, ephPriv, cpub)).slice(0, 12) : randomBytes(12);
  const ct = chacha20poly1305(K, nonce, concatBytes(cpub, ephPub)).encrypt(pt);
  return concatBytes(Uint8Array.of(1), ephPub, nonce, ct);
}
/** Open with the creator's identity. Returns plaintext bytes; throws on any failure. */
export function eciesOpen(creatorIdentity, sealed) {
  const blob = bytes(sealed);
  if (blob.length < 1 + 33 + 12 + 16) throw new Error("sealed too short");
  if (blob[0] !== 0x01) throw new Error("unknown seal version " + blob[0]);
  const ephPub = blob.slice(1, 34), nonce = blob.slice(34, 46), ct = blob.slice(46);
  const K = hkdf(sha256, ecdhX(creatorIdentity.priv, ephPub), SALT, new Uint8Array(0), 32);
  try {
    return chacha20poly1305(K, nonce, concatBytes(creatorIdentity.pub, ephPub)).decrypt(ct);
  } catch {
    throw new Error("aead tag verification failed");
  }
}
