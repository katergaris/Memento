'use strict';
// Codici TOTP (RFC 6238, SHA-1, 6 cifre, 30 secondi), come server/totp.js ma
// con WebCrypto, quindi asincroni.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(globalThis.crypto || require('crypto').webcrypto);
  else root.MementoTotp = factory(root.crypto);
})(typeof self !== 'undefined' ? self : this, function (webcrypto) {
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function base32Decode(input) {
    const clean = String(input).toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
    if (!clean || /[^A-Z2-7]/.test(clean)) throw new Error('Segreto TOTP non valido');
    let bits = 0, value = 0;
    const out = [];
    for (const ch of clean) {
      value = (value << 5) | ALPHABET.indexOf(ch);
      bits += 5;
      if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
    }
    return new Uint8Array(out);
  }

  async function codeForStep(secret, step) {
    const key = await webcrypto.subtle.importKey('raw', base32Decode(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const msg = new Uint8Array(8);
    let s = step;
    for (let i = 7; i >= 0; i--) { msg[i] = s & 0xff; s = Math.floor(s / 256); }
    const h = new Uint8Array(await webcrypto.subtle.sign('HMAC', key, msg));
    const off = h[h.length - 1] & 0x0f;
    const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
    return String(bin % 1000000).padStart(6, '0');
  }
  const currentStep = (now = Date.now()) => Math.floor(now / 1000 / 30);

  return { base32Decode, codeForStep, currentStep };
});
