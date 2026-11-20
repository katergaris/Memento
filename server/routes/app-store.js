const express = require('express');
const crypto = require('crypto');
const db = require('../db');

// Copia dell'app Android ("Sul telefono") sul server di casa.
// - rotte del telefono (/files): chiave "Bearer" creata dalle Impostazioni
//   del server, niente sessione; i file arrivano gia' cifrati dal telefono.
// - rotte delle Impostazioni (/status, /keys): sessione normale.
const NAME_RE = /^[A-Za-z0-9._-]{1,200}$/;
const hash = (token) => crypto.createHash('sha256').update(token).digest('hex');

function requireKey(req, res, next) {
  const m = /^Bearer\s+(\S+)$/i.exec(req.get('authorization') || '');
  const row = m && db.prepare('SELECT id FROM app_store_keys WHERE token_hash = ?').get(hash(m[1]));
  if (!row) return res.status(401).json({ error: 'Chiave non valida' });
  db.prepare("UPDATE app_store_keys SET last_used_at = datetime('now') WHERE id = ?").run(row.id);
  next();
}

const phone = express.Router();
// Accesso solo con la chiave, mai con i cookie: qualunque origine va bene
// (l'app usa le richieste native, il browser serve per le prove).
phone.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.set('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});
// I file dei documenti possono essere grandi: limite proprio, prima del
// limite generale di 4 MB.
phone.use(express.json({ limit: '80mb' }));
phone.use(requireKey);
phone.get('/files', (req, res) => {
  res.json(db.prepare('SELECT name, size, updated_at FROM app_store_files ORDER BY name').all());
});
phone.get('/files/:name', (req, res) => {
  if (!NAME_RE.test(req.params.name)) return res.status(400).json({ error: 'Nome non valido' });
  const row = db.prepare('SELECT content FROM app_store_files WHERE name = ?').get(req.params.name);
  if (!row) return res.status(404).json({ error: 'File non trovato' });
  res.type('application/json').send(row.content);
});
phone.put('/files/:name', (req, res) => {
  if (!NAME_RE.test(req.params.name)) return res.status(400).json({ error: 'Nome non valido' });
  if (!req.body || typeof req.body !== 'object') return res.status(400).json({ error: 'Contenuto non valido' });
  const content = JSON.stringify(req.body);
  db.prepare(`INSERT INTO app_store_files (name, content, size, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(name) DO UPDATE SET content = excluded.content, size = excluded.size, updated_at = excluded.updated_at`).run(req.params.name, content, content.length);
  res.status(204).end();
});

const settings = express.Router();
settings.get('/status', (req, res) => {
  const files = db.prepare('SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS size, MAX(updated_at) AS last FROM app_store_files').get();
  const keys = db.prepare('SELECT COUNT(*) AS n FROM app_store_keys').get().n;
  res.json({ phones: keys, files: files.n, size: files.size, last: files.last });
});
// Collega un telefono: la chiave si vede una volta sola.
settings.post('/keys', (req, res) => {
  const token = crypto.randomBytes(24).toString('base64url');
  db.prepare('INSERT INTO app_store_keys (token_hash) VALUES (?)').run(hash(token));
  res.status(201).json({ token });
});
// Scollega tutti i telefoni (la copia resta).
settings.delete('/keys', (req, res) => {
  db.prepare('DELETE FROM app_store_keys').run();
  res.status(204).end();
});

module.exports = { phone, settings };
