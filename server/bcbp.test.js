const test = require('node:test');
const assert = require('node:assert');
const { parse, julianToDate, niceName } = require('../public/bcbp');

// Tratta nel formato IATA: PNR(7) da(3) a(3) compagnia(3) volo(5) giuliano(3)
// classe(1) posto(4) sequenza(5) stato(1) + lunghezza parte variabile (2 hex)
const leg = (pnr, from, to, carrier, flight, julian, seat, extra = '') =>
  pnr.padEnd(7) + from + to + carrier.padEnd(3) + flight.padStart(4, '0').padEnd(5) + String(julian).padStart(3, '0') +
  'Y' + seat.padStart(4, '0') + '0012 ' + '1' + extra.length.toString(16).toUpperCase().padStart(2, '0') + extra;
const pass = (name, legs) => `M${legs.length}${name.padEnd(20)}E${legs.join('')}`;

test('biglietto con una tratta', () => {
  const today = new Date(2026, 10, 21); // 21 novembre 2026
  const text = pass('UTENTE/A MR', [leg('ABC123', 'CTA', 'FCO', 'AZ', '1754', 330, '12C')]);
  const p = parse(text, today);
  assert.equal(p.passenger, 'A Utente');
  assert.equal(p.route, 'CTA → FCO');
  assert.equal(p.title, 'CTA → FCO · AZ 1754');
  assert.equal(p.legs[0].pnr, 'ABC123');
  assert.equal(p.legs[0].seat, '12C');
  assert.equal(p.legs[0].date, '2026-11-26'); // giorno 330 del 2026
  assert.equal(p.lastDate, '2026-11-26');
});

test('due tratte con parte variabile', () => {
  const today = new Date(2026, 10, 21);
  const text = pass('UTENTE/B', [
    leg('XYZ789', 'CTA', 'FCO', 'AZ', '1702', 340, '3A', '>5180'),
    leg('XYZ789', 'FCO', 'JFK', 'AZ', '608', 341, '22K'),
  ]);
  const p = parse(text, today);
  assert.equal(p.legs.length, 2);
  assert.equal(p.route, 'CTA → FCO → JFK');
  assert.equal(p.flights, 'AZ 1702, AZ 608');
  assert.equal(p.firstDate, '2026-12-06');
  assert.equal(p.lastDate, '2026-12-07');
});

test('il giorno giuliano sceglie l\'anno piu\' vicino', () => {
  assert.equal(julianToDate(2, new Date(2026, 11, 30)), '2027-01-02');
  assert.equal(julianToDate(364, new Date(2027, 0, 3)), '2026-12-30');
  assert.equal(julianToDate(0), null);
});

test('testi che non sono biglietti', () => {
  assert.equal(parse('8001234567897'), null);
  assert.equal(parse('https://example.com/qualcosa-di-molto-lungo-che-non-e-un-biglietto-aereo-valido'), null);
  assert.equal(parse(''), null);
});

test('nome del passeggero', () => {
  assert.equal(niceName('UTENTE/A MRS'), 'A Utente');
  assert.equal(niceName('DE LUCA/ANNA MARIA'), 'Anna Maria De Luca');
});
