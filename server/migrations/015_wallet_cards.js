module.exports = function up(db) {
  // Carte fedelta' e carte regalo (sezione Carte). Il codice si mostra come
  // codice a barre o QR nel formato indicato; il PIN delle carte regalo e'
  // cifrato come le password del vault. balance/currency/expiry_date servono
  // alle carte regalo (saldo e scadenza), sulle carte fedelta' restano vuoti.
  db.exec(`
    CREATE TABLE IF NOT EXISTS cards (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kind TEXT NOT NULL DEFAULT 'fedelta',
      name TEXT NOT NULL,
      number TEXT DEFAULT '',
      format TEXT NOT NULL DEFAULT 'CODE128',
      color TEXT DEFAULT '',
      holder TEXT DEFAULT '',
      pin_encrypted TEXT,
      balance REAL,
      currency TEXT DEFAULT 'EUR',
      expiry_date TEXT,
      notes TEXT DEFAULT '',
      tags TEXT DEFAULT '[]',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      deleted_at TEXT
    );
  `);
};
