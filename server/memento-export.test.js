const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Database in memoria e chiave di prova: i test non toccano i dati veri.
process.env.DB_PATH = ':memory:';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'test-encryption-key-not-for-production';
const db = require('./db');
const { encrypt } = require('./crypto');
const { buildPayload, seal } = require('./memento-export');

// Apre la busta come fa l'app (PBKDF2-SHA256 + AES-256-GCM, tag in coda).
function open(envelope, password) {
  const key = crypto.pbkdf2Sync(password, Buffer.from(envelope.kdf.salt, 'base64'), envelope.kdf.iter, 32, 'sha256');
  const data = Buffer.from(envelope.ct, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
  decipher.setAuthTag(data.subarray(data.length - 16));
  return JSON.parse(Buffer.concat([decipher.update(data.subarray(0, data.length - 16)), decipher.final()]).toString('utf8'));
}

test("esportazione per l'app: dati, segreti del vault in chiaro dentro il file cifrato, documenti", () => {
  db.prepare("INSERT INTO ideas (title, tags) VALUES ('Nota', '[\"casa\"]')").run();
  db.prepare("INSERT INTO vault_entries (site, password_encrypted, totp_secret_encrypted) VALUES ('Banca', ?, ?)").run(encrypt('pw'), encrypt('JBSWY3DPEHPK3PXP'));
  const uploads = fs.mkdtempSync(path.join(os.tmpdir(), 'memento-up-'));
  fs.writeFileSync(path.join(uploads, 'f.txt'), 'ciao');
  db.prepare("INSERT INTO documents (original_name, stored_name) VALUES ('f.txt', 'f.txt')").run();

  const envelope = seal('password-del-file', buildPayload(db, uploads), 1000);
  assert.equal(envelope.format, 'memento-export');
  assert.ok(!JSON.stringify(envelope).includes('JBSWY3DPEHPK3PXP'));
  assert.throws(() => open(envelope, 'sbagliata'));
  const payload = open(envelope, 'password-del-file');
  assert.deepEqual(payload.state.tables.ideas[0].tags, ['casa']);
  assert.equal(payload.state.tables.vault[0].password, 'pw');
  assert.equal(payload.state.tables.vault[0].totp_secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(payload.state.tables.vault[0].password_encrypted, undefined);
  assert.deepEqual(payload.state.tables.cards, []);
  assert.equal(Buffer.from(payload.files['f.txt'], 'base64').toString(), 'ciao');
});
