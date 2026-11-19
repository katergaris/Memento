module.exports = function up(db) {
  // Marchio della carta (id del logo in public/brands/index.json): vuoto =
  // nessun logo, la tessera mostra l'iniziale colorata.
  db.exec(`ALTER TABLE cards ADD COLUMN brand TEXT DEFAULT ''`);
};
