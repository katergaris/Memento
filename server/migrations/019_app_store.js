module.exports = function up(db) {
  // Copia cifrata dell'app Android in modalita' "Sul telefono": il server
  // conserva file che non puo' leggere (cifrati sul telefono con la password
  // principale), cosi' finiscono anche nel backup del server.
  // app_store_keys: una chiave per telefono collegato (si salva solo l'hash).
  db.exec(`
    CREATE TABLE IF NOT EXISTS app_store_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_hash TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_used_at TEXT
    );
    CREATE TABLE IF NOT EXISTS app_store_files (
      name TEXT PRIMARY KEY,
      content TEXT NOT NULL,
      size INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
};
