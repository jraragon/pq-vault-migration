// P15 -- architecture A1 in the browser (also runs on Node >= 20 for testing).
// Mirror of native/src/p15_a1.c and android/.../P15Core.java: same suites, byte
// formats, access package (version || suite id || KEM ct || AES-256-KW of the
// root key under HKDF-SHA256(ss, info = label || suite id || holder id)) and
// children wrapped with AES-256-KW.
// ML-KEM: @noble/post-quantum (pure JS). RSA-OAEP, HKDF and AES-KW: WebCrypto.
// SHA3-256 for the hybrid combiner: @noble/hashes (WebCrypto has no SHA3).
import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import * as KAT from './composite_kat.js';

const subtle = globalThis.crypto.subtle;
const rand = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
const enc = new TextEncoder();

export const SUITES = {
  rsa3072:   { id: 0x01, ml: null,       rsa: true  },
  mlkem768:  { id: 0x02, ml: ml_kem768,  rsa: false, mlCt: 1088 },
  mlkem1024: { id: 0x03, ml: ml_kem1024, rsa: false, mlCt: 1568 },
  hybrid:    { id: 0x04, ml: ml_kem1024, rsa: true,  mlCt: 1568 },
};
const OID_MLKEM768  = Uint8Array.from([0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x04,0x02]);
const OID_MLKEM1024 = Uint8Array.from([0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x04,0x03]);
const OID_HYBRID    = Uint8Array.from([0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x06,0x3e]);
// AlgorithmIdentifier content for rsaEncryption with NULL parameters
const ALG_RSA       = Uint8Array.from([0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00]);
const HYBRID_LABEL  = enc.encode('MLKEM1024-RSAOAEP3072');
const KDF_LABEL     = enc.encode('P15/A1/package/v1');
const RSA_ALG = { name: 'RSA-OAEP', hash: 'SHA-256' };

// ------------------------------------------------------------------ DER
export function cat(...parts) {
  const n = parts.reduce((a, p) => a + p.length, 0), out = new Uint8Array(n);
  let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
function derLen(n) {
  if (n < 0x80) return Uint8Array.of(n);
  if (n < 0x100) return Uint8Array.of(0x81, n);
  return Uint8Array.of(0x82, n >> 8, n & 0xff);
}
export const tlv = (tag, v) => cat(Uint8Array.of(tag), derLen(v.length), v);
export const pkcs8 = (algContent, priv) =>
  tlv(0x30, cat(Uint8Array.of(0x02, 0x01, 0x00), tlv(0x30, algContent), tlv(0x04, priv)));

// Minimal DER reader: returns {tag, start (of value), end}.
function readTLV(b, off) {
  const tag = b[off]; let len = b[off + 1], p = off + 2;
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = (len << 8) | b[p++]; }
  return { tag, start: p, end: p + len };
}
// PKCS#8 -> privateKey OCTET STRING content
function pkcs8PrivateKey(der) {
  const seq = readTLV(der, 0);
  const ver = readTLV(der, seq.start);
  const alg = readTLV(der, ver.end);
  const oct = readTLV(der, alg.end);
  if (oct.tag !== 0x04) throw new Error('bad PKCS#8');
  return der.subarray(oct.start, oct.end);
}
// SPKI of an RSA key -> RSAPublicKey DER
function spkiToRsaPublicKey(spki) {
  const seq = readTLV(spki, 0), alg = readTLV(spki, seq.start), bits = readTLV(spki, alg.end);
  return spki.slice(bits.start + 1, bits.end); // skip the unused-bits byte
}

// RFC 9935 PKCS#8 for a pure ML-KEM key: seed [0] IMPLICIT or expandedKey OCTET STRING.
export const mlkemCredential = (suiteName, fmt, bytes) =>
  pkcs8(suiteName === 'mlkem768' ? OID_MLKEM768 : OID_MLKEM1024, tlv(fmt === 'seed' ? 0x80 : 0x04, bytes));

// ------------------------------------------------------------------ credentials
export async function genCredential(suiteName, fmt) {
  const s = SUITES[suiteName];
  const pub = { ml: null, rsa: null, rsaPubDer: new Uint8Array(0) };
  let seed, expanded, rsaPkcs8;
  if (s.ml) {
    seed = rand(64);
    const kp = s.ml.keygen(seed);
    pub.ml = kp.publicKey; expanded = kp.secretKey;
  }
  if (s.rsa) {
    const kp = await subtle.generateKey({ ...RSA_ALG, modulusLength: 3072, publicExponent: Uint8Array.of(1, 0, 1) },
                                        true, ['encrypt', 'decrypt']);
    pub.rsa = kp.publicKey;
    pub.rsaPubDer = spkiToRsaPublicKey(new Uint8Array(await subtle.exportKey('spki', kp.publicKey)));
    rsaPkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey));
  }
  let cred;
  if (suiteName === 'rsa3072') cred = rsaPkcs8;
  else if (suiteName !== 'hybrid')
    cred = pkcs8(suiteName === 'mlkem768' ? OID_MLKEM768 : OID_MLKEM1024,
                 fmt === 'seed' ? tlv(0x80, seed) : tlv(0x04, expanded));
  else cred = pkcs8(OID_HYBRID, cat(fmt === 'seed' ? seed : expanded, pkcs8PrivateKey(rsaPkcs8)));
  return { cred, pub };
}

// Load a stored credential. noble has no PKCS#8 decoder, so the DER is parsed here;
// a seed is expanded with keygen (FIPS 203 ML-KEM.KeyGen_internal); RSA goes through
// WebCrypto's PKCS#8 import.
export async function loadCredential(suiteName, fmt, der) {
  const s = SUITES[suiteName], p = { ml: null, rsa: null };
  if (suiteName === 'rsa3072') {
    p.rsa = await subtle.importKey('pkcs8', der, RSA_ALG, false, ['decrypt']);
    return p;
  }
  const raw = pkcs8PrivateKey(der);
  if (suiteName !== 'hybrid') {
    const c = readTLV(raw, 0), v = raw.subarray(c.start, c.end);
    p.ml = c.tag === 0x80 ? s.ml.keygen(v).secretKey : v.slice();
    return p;
  }
  const mlLen = fmt === 'seed' ? 64 : 3168;
  const mlPart = raw.subarray(0, mlLen);
  p.ml = fmt === 'seed' ? s.ml.keygen(mlPart).secretKey : mlPart.slice();
  p.rsa = await subtle.importKey('pkcs8', pkcs8(ALG_RSA, raw.subarray(mlLen)), RSA_ALG, false, ['decrypt']);
  return p;
}

// ------------------------------------------------------------------ KEM
const combine = (ssMl, ssRsa, ctRsa, rsaPub) => sha3_256(cat(ssMl, ssRsa, ctRsa, rsaPub, HYBRID_LABEL));

export async function encap(suiteName, pub) {
  const s = SUITES[suiteName];
  let ctMl = new Uint8Array(0), ssMl = null;
  if (s.ml) {
    const r = s.ml.encapsulate(pub.ml);
    ctMl = r.cipherText; ssMl = r.sharedSecret;
    if (!s.rsa) return { ct: ctMl, ss: ssMl };
  }
  const ssRsa = rand(32);
  const ctRsa = new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, pub.rsa, ssRsa));
  if (!s.ml) return { ct: ctRsa, ss: ssRsa };
  return { ct: cat(ctMl, ctRsa), ss: combine(ssMl, ssRsa, ctRsa, pub.rsaPubDer) };
}

export async function decap(suiteName, priv, ct, rsaPubDer) {
  const s = SUITES[suiteName];
  let ssMl = null, mlCt = 0;
  if (s.ml) {
    mlCt = s.mlCt;
    ssMl = s.ml.decapsulate(ct.subarray(0, mlCt), priv.ml);
    if (!s.rsa) return ssMl;
  }
  const ctRsa = ct.subarray(mlCt);
  const ssRsa = new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, priv.rsa, ctRsa));
  if (!s.ml) return ssRsa;
  return combine(ssMl, ssRsa, ctRsa, rsaPubDer);
}

// ------------------------------------------------------------------ KDF, key wrap
async function kek(ss, suiteName, holder) {
  const info = cat(KDF_LABEL, Uint8Array.of(SUITES[suiteName].id, holder >>> 24, (holder >>> 16) & 0xff,
                                            (holder >>> 8) & 0xff, holder & 0xff));
  const base = await subtle.importKey('raw', ss, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info },
                          base, { name: 'AES-KW', length: 256 }, false, ['wrapKey', 'unwrapKey']);
}
const kwKey = (bytes, extractable = true) =>
  subtle.importKey('raw', bytes, 'AES-KW', extractable, ['wrapKey', 'unwrapKey']);
const wrap = async (wrappingKey, keyBytes) =>
  new Uint8Array(await subtle.wrapKey('raw', await kwKey(keyBytes), wrappingKey, 'AES-KW'));
const unwrap = (wrappingKey, wrapped) =>
  subtle.unwrapKey('raw', wrapped, wrappingKey, 'AES-KW', 'AES-KW', true, ['wrapKey', 'unwrapKey']);

// ------------------------------------------------------------------ account (A1)
export async function createAccount(suiteName, fmt, nf, holder) {
  const { cred, pub } = await genCredential(suiteName, fmt);
  const root = rand(32);
  const { ct, ss } = await encap(suiteName, pub);
  const pkg = cat(Uint8Array.of(0x01, SUITES[suiteName].id), ct, await wrap(await kek(ss, suiteName, holder), root));
  const rootKey = await kwKey(root);
  const children = [];
  for (let i = 0; i < nf; i++) children.push(await wrap(rootKey, rand(32)));
  return { suiteName, fmt, cred, pub, pkg, root, children };
}

// E2: open the account from cold stored credential bytes; returns the root key bytes.
export async function openAccount(a, holder) {
  const p = await loadCredential(a.suiteName, a.fmt, a.cred);
  if (a.pkg[0] !== 0x01 || a.pkg[1] !== SUITES[a.suiteName].id) throw new Error('bad header');
  const ctLen = a.pkg.length - 42;
  const ss = await decap(a.suiteName, p, a.pkg.subarray(2, 2 + ctLen), a.pub.rsaPubDer);
  const rootKey = await unwrap(await kek(ss, a.suiteName, holder), a.pkg.subarray(2 + ctLen));
  for (const c of a.children) await unwrap(rootKey, c);
  return rootKey;
}

// ------------------------------------------------------------------ selftest, sizes
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

export async function selftest(log) {
  let fails = 0;
  const check = (ok, msg) => { if (!ok) fails++; log(`  ${ok ? 'ok:  ' : 'FAIL:'} ${msg}`); };
  const seed = Uint8Array.from({ length: 64 }, (_, i) => i);
  const rfc = b64('MFQCAQAwCwYJYIZIAWUDBAQDBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=');
  check(eq(pkcs8(OID_MLKEM1024, tlv(0x80, seed)), rfc), 'seed-format PKCS#8 matches RFC 9935 C.1.3.1');
  const ex = (await loadCredential('mlkem1024', 'seed', rfc)).ml;
  check(ex.length === 3168 && eq(ex.subarray(0, 4), Uint8Array.of(0xf7, 0x7b, 0x7f, 0x6b)),
        'expanded key from the RFC seed matches C.1.3.2 prefix');
  // Known answers from the composite ML-KEM draft (tools/gen_composite_kat.py)
  try {
    const pm = await loadCredential('mlkem1024', 'seed', b64(KAT.ML_DK_PKCS8));
    check(eq(await decap('mlkem1024', pm, b64(KAT.ML_C)), b64(KAT.ML_K)), 'ML-KEM-1024 decapsulation matches composite-draft vector');
    const ph = await loadCredential('hybrid', 'seed', b64(KAT.HYB_DK_PKCS8));
    check(eq(await decap('hybrid', ph, b64(KAT.HYB_C), b64(KAT.HYB_RSA_PUB)), b64(KAT.HYB_K)),
          'hybrid decapsulation and combiner match id-MLKEM1024-RSA3072-SHA3-256 vector');
  } catch (e) { check(false, `composite-draft vectors: ${e}`); }
  for (const s of Object.keys(SUITES)) for (const f of ['seed', 'expanded']) {
    if (s === 'rsa3072' && f === 'expanded') continue;
    const tag = `${s.padEnd(9)} ${(s === 'rsa3072' ? 'na' : f).padEnd(8)}`;
    try {
      const a = await createAccount(s, f, 7, 1);
      const root = new Uint8Array(await subtle.exportKey('raw', await openAccount(a, 1)));
      check(eq(root, a.root), `${tag} open account round trip (package ${a.pkg.length} B, credential ${a.cred.length} B)`);
      let rejected = false; try { await openAccount(a, 2); } catch { rejected = true; }
      check(rejected, `${tag} wrong holder id is rejected`);
    } catch (e) { check(false, `${tag} ${e}`); }
  }
  log(fails ? `\nSELFTEST FAILED (${fails} failures)` : '\nSELFTEST PASSED (0 failures)');
  return fails;
}

export async function sizes() {
  const rows = ['suite,format,credential_pkcs8,public_raw,kem_ct,access_package'];
  for (const s of Object.keys(SUITES)) for (const f of ['seed', 'expanded']) {
    if (s === 'rsa3072' && f === 'expanded') continue;
    const a = await createAccount(s, f, 1, 1);
    const praw = (a.pub.ml ? a.pub.ml.length : 0) + a.pub.rsaPubDer.length;
    rows.push([s, s === 'rsa3072' ? 'na' : f, a.cred.length, praw, a.pkg.length - 42, a.pkg.length].join(','));
  }
  return rows.join('\n');
}

// ------------------------------------------------------------------ bench (one run)
// Returns nanoseconds per timed operation (performance.now(), resolution reported separately).
export async function bench(suiteName, fmt, op, iters, warmup, nf) {
  const lf = fmt === 'na' ? 'seed' : fmt;
  const a = await createAccount(suiteName, lf, nf, 1);
  const ns = new Float64Array(iters);
  const ctLen = a.pkg.length - 42, ct = a.pkg.subarray(2, 2 + ctLen);
  const oldRoot = await kwKey(a.root), newRoot = await kwKey(rand(32));
  for (let phase = 0; phase < 2; phase++) {
    const n = phase === 0 ? warmup : iters;
    for (let i = 0; i < n; i++) {
      let t0, t1;
      if (op === 'open') { t0 = performance.now(); await openAccount(a, 1); t1 = performance.now(); }
      else if (op === 'load') { t0 = performance.now(); await loadCredential(suiteName, lf, a.cred); t1 = performance.now(); }
      else if (op === 'encap') { t0 = performance.now(); await encap(suiteName, a.pub); t1 = performance.now(); }
      else if (op === 'decap') {
        const p = await loadCredential(suiteName, lf, a.cred);
        t0 = performance.now(); await decap(suiteName, p, ct, a.pub.rsaPubDer); t1 = performance.now();
      } else if (op === 'rewrap') {  // one migration step: unwrap under the old parent, wrap under the new one
        t0 = performance.now();
        await subtle.wrapKey('raw', await unwrap(oldRoot, a.children[0]), newRoot, 'AES-KW');
        t1 = performance.now();
      } else if (op === 'keygen') { t0 = performance.now(); await genCredential(suiteName, lf); t1 = performance.now(); }
      else throw new Error(`unknown op ${op}`);
      if (phase === 1) ns[i] = Math.round((t1 - t0) * 1e6);
    }
  }
  return ns;
}

// Smallest observable positive step of performance.now(), in microseconds.
export function timerResolutionUs() {
  let min = Infinity, last = performance.now();
  for (let i = 0; i < 200000; i++) {
    const t = performance.now();
    if (t > last) { min = Math.min(min, t - last); last = t; }
  }
  return min * 1000;
}
