module.exports = function up(db) {
  // Spese ricorrenti di tipo "finanziamento": numero totale di rate. Con la
  // data della prima rata (start_date), la cadenza e l'importo della rata si
  // calcolano rate pagate, rate mancanti, quota residua e ultima rata.
  db.exec('ALTER TABLE accounts ADD COLUMN installments INTEGER');
};
