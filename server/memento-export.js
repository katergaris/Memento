'use strict';
// Esportazione per l'app Android (modalita' "Sul telefono"): tutti i dati del
// server in un file .memento, cifrato con una password scelta da chi esporta.
//
// Formato identico a quello dell'app (app/src/crypto.js e local-backend.js):
//   busta { format: 'memento-export', v: 1, kdf: { alg: 'PBKDF2-SHA256', iter, salt }, iv, ct }
//   chiave AES-256-GCM da PBKDF2-SHA256; ct = testo cifrato + tag di 16 byte
//   (come WebCrypto), tutto in base64.
// Il contenuto e' { app, exportedAt, state, files }: state ha le stesse tabelle
// del motore del telefono, con i segreti del vault in chiaro (sono protetti
// dalla cifratura del file), files i documenti del Drive in base64.
//
// Le tabelle assenti (es. cards su un server piu' vecchio) vengono saltate.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { decrypt } = require('./crypto');

const FORMAT = 'memento-export';
const ITERATIONS = 310000;

const JSON_FIELDS = ['tags', 'checklist', 'contacts', 'budget'];

function tableExists(db, name) {
  return !!db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?").get(name);
}
function rev(row) {
  const t = Date.parse(String(row.updated_at || row.created_at || '').replace(' ', 'T') + 'Z');
  return Number.isFinite(t) ? t : 0;
}
function parseJsonFields(row) {
  const out = { ...row };
  JSON_FIELDS.forEach((k) => {
    if (typeof out[k] === 'string') {
      try { out[k] = JSON.parse(out[k] || '[]'); } catch (_) { out[k] = []; }
    }
  });
  out._rev = rev(row);
  return out;
}
function tryDecrypt(value) {
  if (!value) return null;
  try { return decrypt(value); } catch (_) { return null; }
}

function buildState(db) {
  const all = (table) => (tableExists(db, table) ? db.prepare(`SELECT * FROM ${table}`).all() : []);
  const user = tableExists(db, 'users') ? db.prepare('SELECT username FROM users ORDER BY id LIMIT 1').get() : null;
  const vault = all('vault_entries').map((r) => {
    const { password_encrypted, totp_secret_encrypted, card_cvv_encrypted, ...rest } = parseJsonFields(r);
    return { ...rest, password: tryDecrypt(password_encrypted) || '', totp_secret: tryDecrypt(totp_secret_encrypted), card_cvv: tryDecrypt(card_cvv_encrypted) };
  });
  const cards = all('cards').map((r) => {
    const { pin_encrypted, ...rest } = parseJsonFields(r);
    return { ...rest, pin: tryDecrypt(pin_encrypted) };
  });
  const links = all('dossier_links').map((r) => ({ ...r, updated_at: r.created_at, deleted_at: null, _rev: rev(r) }));
  return {
    schema: 1,
    user: { username: user ? user.username : '' },
    tables: {
      ideas: all('ideas').map(parseJsonFields),
      projects: all('projects').map(parseJsonFields),
      reminders: all('reminders').map(parseJsonFields),
      accounts: all('accounts').map(parseJsonFields),
      vault,
      documents: all('documents').map(parseJsonFields),
      dossiers: all('dossiers').map(parseJsonFields),
      links,
      cards,
    },
    purged: [],
    settings: {},
  };
}

function buildPayload(db, uploadDir, { includeFiles = true } = {}) {
  const state = buildState(db);
  const files = {};
  if (includeFiles) {
    state.tables.documents.filter((d) => !d.deleted_at && d.stored_name).forEach((d) => {
      const file = path.join(uploadDir, path.basename(d.stored_name));
      if (fs.existsSync(file)) files[d.stored_name] = fs.readFileSync(file).toString('base64');
    });
  }
  return { app: 'memento', source: 'server', exportedAt: new Date().toISOString(), state, files };
}

function seal(password, value, iterations = ITERATIONS) {
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(String(password), salt, iterations, 32, 'sha256');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return { format: FORMAT, v: 1, kdf: { alg: 'PBKDF2-SHA256', iter: iterations, salt: salt.toString('base64') }, iv: iv.toString('base64'), ct: ct.toString('base64') };
}

module.exports = { buildState, buildPayload, seal, FORMAT };
