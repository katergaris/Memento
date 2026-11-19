const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');

// Database in memoria e chiave di prova: i test non toccano i dati veri.
process.env.DB_PATH = ':memory:';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'chiave-di-prova-per-i-test-delle-carte-0123456789';
const cardsRouter = require('./routes/cards');
const db = require('./db');

async function withServer(fn) {
  const app = express();
  app.use(express.json());
  app.use('/cards', cardsRouter);
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}/cards`;
  const call = (path, method = 'GET', body) => fetch(base + path, {
    method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined,
  }).then(async (r) => ({ status: r.status, data: r.status === 204 ? null : await r.json() }));
  try { await fn(call); } finally { await new Promise((resolve) => server.close(resolve)); }
}

test('carta fedelta\': crea, legge, aggiorna, elimina', async () => {
  await withServer(async (call) => {
    assert.equal((await call('', 'POST', { number: '123' })).status, 400);
    const c = (await call('', 'POST', { name: 'Supermercato', number: ' 8001234567890 ', format: 'EAN13', color: '#FF5500' })).data;
    assert.equal(c.kind, 'fedelta');
    assert.equal(c.number, '8001234567890');
    assert.equal(c.hasPin, false);
    const strano = (await call('', 'POST', { name: 'X', format: 'BOH', color: 'rosso' })).data;
    assert.equal(strano.format, 'CODE128');
    assert.equal(strano.color, '');
    const upd = (await call(`/${c.id}`, 'PUT', { notes: 'tessera famiglia' })).data;
    assert.equal(upd.name, 'Supermercato');
    assert.equal(upd.format, 'EAN13');
    await call(`/${c.id}`, 'DELETE');
    assert.equal((await call('')).data.length, 1);
  });
});

test('carta regalo: saldo, spesa, PIN cifrato', async () => {
  await withServer(async (call) => {
    const g = (await call('', 'POST', { kind: 'regalo', name: 'Libreria', balance: '25,50', pin: '4321', expiry_date: '2027-06-30' })).data;
    assert.equal(g.balance, 25.5);
    assert.equal(g.hasPin, true);
    assert.equal(g.pin, undefined);
    const raw = db.prepare('SELECT pin_encrypted FROM cards WHERE id = ?').get(g.id).pin_encrypted;
    assert.ok(raw && !raw.includes('4321'));
    assert.equal((await call(`/${g.id}/pin`)).data.pin, '4321');
    assert.equal((await call(`/${g.id}/spend`, 'POST', { amount: 10 })).data.balance, 15.5);
    assert.equal((await call(`/${g.id}/spend`, 'POST', { amount: 100 })).data.balance, 0);
    assert.equal((await call(`/${g.id}/spend`, 'POST', { amount: -3 })).status, 400);
    assert.equal((await call(`/${g.id}`, 'PUT', { pin: '-' })).data.hasPin, false);
  });
});
