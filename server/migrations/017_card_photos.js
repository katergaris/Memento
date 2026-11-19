module.exports = function up(db) {
  // Foto della tessera (fronte e retro) come immagini JPEG ridimensionate in
  // data URL: utili quando la cassa non legge lo schermo. Elenco JSON, max 2.
  db.exec(`ALTER TABLE cards ADD COLUMN photos TEXT DEFAULT '[]'`);
};
