const express = require('express');
const db = require('../db');
const { encrypt, decrypt } = require('../crypto');

// Carte fedelta' e carte regalo. Il numero non e' un segreto (lo legge la
// cassa): resta in chiaro e si cerca; il PIN delle carte regalo e' cifrato.
const router = express.Router();

const KINDS = ['fedelta', 'regalo'];
const FORMATS = ['QR', 'CODE128', 'EAN13', 'EAN8', 'UPC', 'CODE39', 'ITF', 'NONE'];

// Nell'elenco le foto non viaggiano (pesano): solo quante sono; la carta
// singola (GET /:id) le ha tutte.
function serialize(row, { photos = false } = {}) {
  const { pin_encrypted, photos: rawPhotos, ...card } = row;
  let list = [];
  try { list = JSON.parse(rawPhotos || '[]'); } catch (e) { list = []; }
  const out = { ...card, tags: JSON.parse(row.tags || '[]'), hasPin: !!pin_encrypted, photoCount: list.length };
  if (photos) out.photos = list;
  return out;
}
// Al massimo due immagini (fronte, retro), JPEG/PNG/WebP in data URL.
function cleanPhotos(raw) {
  if (!Array.isArray(raw)) return undefined;
  return raw.filter((p) => typeof p === 'string' && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(p) && p.length <= 900000).slice(0, 2);
}
function parseAmount(raw) {
  if (raw === undefined) return undefined;
  if (raw === null || raw === '') return null;
  const n = Number(String(raw).replace(',', '.'));
  return Number.isFinite(n) ? Math.round(n * 100) / 100 : null;
}
// Id di un logo di public/brands (minuscole, cifre, trattini).
function cleanBrand(raw) {
  return /^[a-z0-9-]{1,60}$/.test(String(raw || '')) ? raw : '';
}
function cleanColor(raw) {
  return /^#[0-9a-fA-F]{6}$/.test(String(raw || '')) ? raw : '';
}
const get = (id) => db.prepare('SELECT * FROM cards WHERE id = ?').get(id);

router.get('/', (req, res) => {
  const rows = db.prepare('SELECT * FROM cards WHERE deleted_at IS NULL ORDER BY updated_at DESC').all();
  res.json(rows.map(serialize));
});

router.get('/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM cards WHERE id = ? AND deleted_at IS NULL').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Carta non trovata' });
  res.json(serialize(row, { photos: true }));
});

router.post('/', (req, res) => {
  const { kind = 'fedelta', name, brand = '', number = '', format = 'CODE128', color = '', holder = '', pin = '', balance = null, currency = 'EUR', expiry_date = null, notes = '', tags = [] } = req.body;
  if (!name) return res.status(400).json({ error: 'Il nome e\' obbligatorio' });
  const info = db.prepare(
    'INSERT INTO cards (kind, name, brand, number, format, color, holder, pin_encrypted, balance, currency, expiry_date, notes, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(
    KINDS.includes(kind) ? kind : 'fedelta', name, cleanBrand(brand), String(number || '').trim(), FORMATS.includes(format) ? format : 'CODE128',
    cleanColor(color), holder, pin ? encrypt(String(pin)) : null, parseAmount(balance) ?? null, currency || 'EUR',
    expiry_date || null, notes, JSON.stringify(tags)
  );
  res.status(201).json(serialize(get(info.lastInsertRowid)));
});

router.put('/:id', (req, res) => {
  const existing = db.prepare('SELECT * FROM cards WHERE id = ? AND deleted_at IS NULL').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Carta non trovata' });
  const { kind, name, brand, number, format, color, holder, pin, balance, currency, expiry_date, notes, tags } = req.body;
  const photos = cleanPhotos(req.body.photos);
  if (photos !== undefined) db.prepare('UPDATE cards SET photos = ? WHERE id = ?').run(JSON.stringify(photos), req.params.id);
  const parsedBalance = parseAmount(balance);
  db.prepare(
    "UPDATE cards SET kind = ?, name = ?, brand = ?, number = ?, format = ?, color = ?, holder = ?, pin_encrypted = ?, balance = ?, currency = ?, expiry_date = ?, notes = ?, tags = ?, updated_at = datetime('now') WHERE id = ?"
  ).run(
    kind && KINDS.includes(kind) ? kind : existing.kind,
    name ?? existing.name,
    brand !== undefined ? cleanBrand(brand) : existing.brand,
    number !== undefined ? String(number || '').trim() : existing.number,
    format && FORMATS.includes(format) ? format : existing.format,
    color !== undefined ? cleanColor(color) : existing.color,
    holder ?? existing.holder,
    pin === '-' ? null : (pin ? encrypt(String(pin)) : existing.pin_encrypted),
    parsedBalance !== undefined ? parsedBalance : existing.balance,
    currency ?? existing.currency,
    expiry_date !== undefined ? (expiry_date || null) : existing.expiry_date,
    notes ?? existing.notes,
    JSON.stringify(tags ?? JSON.parse(existing.tags || '[]')),
    req.params.id
  );
  res.json(serialize(get(req.params.id)));
});

// Spesa con una carta regalo: scala il saldo (mai sotto zero).
router.post('/:id/spend', (req, res) => {
  const card = db.prepare('SELECT * FROM cards WHERE id = ? AND deleted_at IS NULL').get(req.params.id);
  if (!card) return res.status(404).json({ error: 'Carta non trovata' });
  const amount = parseAmount((req.body || {}).amount);
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Importo non valido' });
  const next = Math.max(0, Math.round(((card.balance || 0) - amount) * 100) / 100);
  db.prepare("UPDATE cards SET balance = ?, updated_at = datetime('now') WHERE id = ?").run(next, card.id);
  res.json(serialize(get(card.id)));
});

router.get('/:id/pin', (req, res) => {
  const card = db.prepare('SELECT pin_encrypted FROM cards WHERE id = ? AND deleted_at IS NULL').get(req.params.id);
  if (!card) return res.status(404).json({ error: 'Carta non trovata' });
  if (!card.pin_encrypted) return res.json({ pin: '' });
  try {
    res.json({ pin: decrypt(card.pin_encrypted) });
  } catch (e) {
    res.status(500).json({ error: 'Impossibile decifrare il PIN' });
  }
});

router.delete('/:id', (req, res) => {
  db.prepare("UPDATE cards SET deleted_at = datetime('now') WHERE id = ?").run(req.params.id);
  res.status(204).end();
});

router.post('/:id/restore', (req, res) => {
  db.prepare('UPDATE cards SET deleted_at = NULL WHERE id = ?').run(req.params.id);
  res.status(204).end();
});

module.exports = router;
module.exports.FORMATS = FORMATS;
