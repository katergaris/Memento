const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const { runMigrations } = require('./migrate');

const DATA_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// DB_PATH esiste solo per i test (es. ":memory:"), cosi' non toccano mai il
// database reale: in uso normale non va mai impostata.
// Rinomina Mindkeep -> Memento: le installazioni esistenti hanno ancora
// data/mindkeep.db (piu' i file -wal/-shm della modalita' WAL). Se il nuovo
// file non c'e' ancora, li si sposta prima di aprire il database, cosi'
// l'aggiornamento non riparte da un database vuoto.
const DB_FILE = path.join(DATA_DIR, 'memento.db');
const LEGACY_DB_FILE = path.join(DATA_DIR, 'mindkeep.db');
if (!process.env.DB_PATH && !fs.existsSync(DB_FILE) && fs.existsSync(LEGACY_DB_FILE)) {
  for (const suffix of ['', '-wal', '-shm']) {
    if (fs.existsSync(LEGACY_DB_FILE + suffix)) fs.renameSync(LEGACY_DB_FILE + suffix, DB_FILE + suffix);
  }
}

const db = new Database(process.env.DB_PATH || DB_FILE);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

runMigrations(db);

module.exports = db;
