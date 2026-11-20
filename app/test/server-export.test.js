'use strict';
// Compatibilita' server -> telefono: il file .memento esportato dal server
// (server/memento-export.js) si importa nel motore del telefono con tutti i
// dati, segreti del vault compresi.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.DB_PATH = ':memory:';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'chiave-di-prova-per-il-test-di-esportazione-0123';
const db = require('../../server/db');
const { encrypt } = require('../../server/crypto');
const { buildPayload, seal } = require('../../server/memento-export');
const { LocalBackend, memoryStorage } = require('../src/local-backend');

test("il file esportato dal server si importa nell'app", async () => {
  db.prepare("INSERT INTO ideas (title, body, tags, checklist) VALUES ('Nota dal server', 'testo', '[\"casa\"]', '[{\"text\":\"a\",\"done\":false}]')").run();
  db.prepare("INSERT INTO vault_entries (site, username, password_encrypted, type, totp_secret_encrypted) VALUES ('Banca', 'io', ?, 'password', ?)")
    .run(encrypt('pw-del-server'), encrypt('JBSWY3DPEHPK3PXP'));
  db.prepare("INSERT INTO reminders (label, date) VALUES ('Bolletta', '2026-12-01')").run();
  const d = db.prepare("INSERT INTO dossiers (title) VALUES ('Casa')").run();
  db.prepare("INSERT INTO dossier_links (dossier_id, item_type, item_id) VALUES (?, 'idea', 1)").run(d.lastInsertRowid);
  db.prepare("INSERT INTO ideas (title, deleted_at) VALUES ('Nel cestino', datetime('now'))").run();

  const uploads = fs.mkdtempSync(path.join(os.tmpdir(), 'memento-up-'));
  fs.writeFileSync(path.join(uploads, 'abc123.txt'), 'documento del server');
  db.prepare("INSERT INTO documents (original_name, stored_name, mime, size) VALUES ('carta.txt', 'abc123.txt', 'text/plain', 20)").run();

  const envelope = seal('password-del-file', buildPayload(db, uploads), 1000);
  assert.ok(!JSON.stringify(envelope).includes('pw-del-server'));

  const phone = new LocalBackend(memoryStorage());
  await phone.request('/auth/setup', { method: 'POST', body: JSON.stringify({ username: 'io', password: 'password-telefono' }) });
  await assert.rejects(phone.importFile(envelope, 'sbagliata'), /errata/);
  const counts = await phone.importFile(envelope, 'password-del-file');
  assert.equal(counts.ideas, 1);
  assert.equal(counts.vault, 1);

  const get = async (p) => (await phone.request(p)).json();
  const [vault] = await get('/vault');
  assert.equal(vault.hasTotp, true);
  assert.equal((await get(`/vault/${vault.id}/reveal`)).password, 'pw-del-server');
  assert.match((await get(`/vault/${vault.id}/totp`)).code, /^\d{6}$/);
  const [idea] = await get('/ideas');
  assert.deepEqual(idea.tags, ['casa']);
  assert.equal(idea.checklist[0].text, 'a');
  assert.equal((await get('/dossiers'))[0].items[0].label, 'Nota dal server');
  assert.equal((await get('/trash')).length, 1);
  const [doc] = await get('/drive');
  assert.equal(await (await phone.fileBlob(doc.id)).blob.text(), 'documento del server');
});
