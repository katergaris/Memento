'use strict';
// Cifratura dei dati della modalita' "Sul telefono": tutto passa da WebCrypto,
// che esiste sia nella WebView di Android sia in Node (per i test).
//
// Archivio e file di esportazione hanno la stessa busta:
//   { format, v: 1, kdf: { alg: 'PBKDF2-SHA256', iter, salt }, iv, ct }
// La chiave AES-GCM a 256 bit deriva dalla password con PBKDF2; il sale sta
// nella busta, quindi un file esportato si apre ovunque con la sola password.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(globalThis.crypto || require('crypto').webcrypto);
  else root.MementoCrypto = factory(root.crypto);
})(typeof self !== 'undefined' ? self : this, function (webcrypto) {
  const subtle = webcrypto.subtle;
  const ITERATIONS = 310000;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function toB64(bytes) {
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let s = '';
    for (let i = 0; i < arr.length; i += 0x8000) s += String.fromCharCode.apply(null, arr.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function fromB64(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  function randomBytes(n) {
    const b = new Uint8Array(n);
    webcrypto.getRandomValues(b);
    return b;
  }

  async function deriveKey(password, salt, iterations = ITERATIONS) {
    const base = await subtle.importKey('raw', enc.encode(String(password)), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      base,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptBytes(key, bytes) {
    const iv = randomBytes(12);
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
    return { iv: toB64(iv), ct: toB64(ct) };
  }
  async function decryptBytes(key, iv, ct) {
    const out = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(iv) }, key, fromB64(ct));
    return new Uint8Array(out);
  }

  // Busta completa con password: per il file esportato e la copia su Drive.
  async function sealWithPassword(format, password, value, iterations = ITERATIONS) {
    const salt = randomBytes(16);
    const key = await deriveKey(password, salt, iterations);
    const { iv, ct } = await encryptBytes(key, enc.encode(JSON.stringify(value)));
    return { format, v: 1, kdf: { alg: 'PBKDF2-SHA256', iter: iterations, salt: toB64(salt) }, iv, ct };
  }
  async function openWithPassword(envelope, password, expectedFormat) {
    if (!envelope || typeof envelope !== 'object' || !envelope.kdf || !envelope.iv || !envelope.ct) throw new Error('bad-file');
    if (expectedFormat && envelope.format !== expectedFormat) throw new Error('bad-file');
    const key = await deriveKey(password, fromB64(envelope.kdf.salt), envelope.kdf.iter);
    let bytes;
    try { bytes = await decryptBytes(key, envelope.iv, envelope.ct); } catch (_) { throw new Error('bad-password'); }
    return { value: JSON.parse(dec.decode(bytes)), key, salt: envelope.kdf.salt, iter: envelope.kdf.iter };
  }

  // Busta con una chiave gia' derivata (archivio locale: la password si
  // chiede una volta allo sblocco, poi si riusa la chiave in memoria).
  async function sealWithKey(format, key, salt, iter, value) {
    const { iv, ct } = await encryptBytes(key, enc.encode(JSON.stringify(value)));
    return { format, v: 1, kdf: { alg: 'PBKDF2-SHA256', iter, salt }, iv, ct };
  }
  async function exportKey(key) { return toB64(await subtle.exportKey('raw', key)); }
  async function importKey(b64) {
    return subtle.importKey('raw', fromB64(b64), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  }

  // ---------------- Condivisione: chiavi ECDH P-256 ----------------
  // Ogni telefono ha un'identita' (coppia di chiavi). Per condividere una
  // voce si cifra la sua chiave per la chiave pubblica di chi la riceve:
  // chiave effimera ECDH + AES-GCM (schema ECIES).
  async function generateIdentity() {
    const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
    return { publicJwk: await subtle.exportKey('jwk', pair.publicKey), privateJwk: await subtle.exportKey('jwk', pair.privateKey) };
  }
  const ecdhAes = (priv, pub) => subtle.deriveKey({ name: 'ECDH', public: pub }, priv, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  async function wrapFor(publicJwk, rawBytes) {
    const recipient = await subtle.importKey('jwk', publicJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
    const key = await ecdhAes(eph.privateKey, recipient);
    const { iv, ct } = await encryptBytes(key, rawBytes);
    return { epk: await subtle.exportKey('jwk', eph.publicKey), iv, ct };
  }
  async function unwrapWith(privateJwk, wrapped) {
    const priv = await subtle.importKey('jwk', privateJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
    const epk = await subtle.importKey('jwk', wrapped.epk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    return decryptBytes(await ecdhAes(priv, epk), wrapped.iv, wrapped.ct);
  }

  // Chiave pubblica compatta (65 byte, base64) per i QR.
  async function publicJwkToRaw(jwk) {
    const k = await subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    return toB64(await subtle.exportKey('raw', k));
  }
  async function rawToPublicJwk(b64) {
    const k = await subtle.importKey('raw', fromB64(b64), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    const jwk = await subtle.exportKey('jwk', k);
    return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  }

  async function sha256Hex(text) {
    const h = new Uint8Array(await subtle.digest('SHA-256', enc.encode(text)));
    return [...h].map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  return {
    ITERATIONS, toB64, fromB64, randomBytes, deriveKey, encryptBytes, decryptBytes,
    sealWithPassword, openWithPassword, sealWithKey, exportKey, importKey, sha256Hex,
    generateIdentity, wrapFor, unwrapWith, publicJwkToRaw, rawToPublicJwk,
  };
});
