const test = require('node:test');
const assert = require('node:assert');
const { airline, city, AIRLINES } = require('../public/airlines');

test('compagnia dal codice del volo', () => {
  assert.equal(airline('XZ').name, 'Aeroitalia');
  assert.equal(airline(' fr ').name, 'Ryanair');
  assert.equal(airline('QQ'), null);
  assert.equal(airline(''), null);
});

test('colori validi per tutte le compagnie', () => {
  for (const [code, [name, bg, fg]] of Object.entries(AIRLINES)) {
    assert.match(code, /^[A-Z0-9]{2}$/, code);
    assert.ok(name, code);
    assert.match(bg, /^#[0-9A-F]{6}$/i, code);
    assert.match(fg, /^#[0-9A-F]{6}$/i, code);
  }
});

test('citta dal codice dell aeroporto', () => {
  assert.equal(city('CTA'), 'Catania');
  assert.equal(city('bgy'), 'Bergamo');
  assert.equal(city('ZZZ'), '');
});

test('nome dell aeroporto', () => {
  const { airportName } = require('../public/airlines');
  assert.equal(airportName('CTA'), 'Fontanarossa');
  assert.equal(airportName('MAN'), '');
  assert.equal(airportName('ZZZ'), '');
});
