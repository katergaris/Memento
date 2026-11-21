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
    assert.equal((await call(`/${c.id}`, 'PUT', { brand: 'esselunga' })).data.brand, 'esselunga');
    assert.equal((await call(`/${c.id}`, 'PUT', { brand: '../x' })).data.brand, '');
    const foto = 'data:image/jpeg;base64,' + Buffer.from('finta-immagine').toString('base64');
    const conFoto = (await call(`/${c.id}`, 'PUT', { photos: [foto, 'javascript:alert(1)', foto, foto] })).data;
    assert.equal(conFoto.photoCount, 2);
    assert.equal(conFoto.photos, undefined);
    assert.deepEqual((await call(`/${c.id}`)).data.photos, [foto, foto]);
    assert.equal((await call('')).data.find((x) => x.id === c.id).photos, undefined);
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

test('carta d\'imbarco: nel Cestino il giorno dopo il volo, cancellata dopo 30 giorni', async () => {
  await withServer(async (call) => {
    const iso = (days) => { const d = new Date(); d.setDate(d.getDate() + days); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
    const domani = (await call('', 'POST', { kind: 'volo', name: 'CTA → FCO · AZ 1754', number: 'M1UTENTE/A', format: 'AZTEC', expiry_date: iso(1), holder: 'A Utente' })).data;
    assert.equal(domani.kind, 'volo');
    assert.equal(domani.format, 'AZTEC');
    assert.equal(domani.holder, 'A Utente');
    const oggi = (await call('', 'POST', { kind: 'volo', name: 'FCO → CTA', format: 'PDF417', expiry_date: iso(0) })).data;
    const ieri = (await call('', 'POST', { kind: 'volo', name: 'CTA → MXP', format: 'QR', expiry_date: iso(-1) })).data;
    const ids = (await call('')).data.map((c) => c.id);
    assert.ok(ids.includes(domani.id) && ids.includes(oggi.id));
    assert.ok(!ids.includes(ieri.id));
    assert.ok(db.prepare('SELECT deleted_at FROM cards WHERE id = ?').get(ieri.id).deleted_at);
    // nel Cestino da 31 giorni: sparisce del tutto
    db.prepare("UPDATE cards SET deleted_at = datetime('now', '-31 days') WHERE id = ?").run(ieri.id);
    await call('');
    assert.equal(db.prepare('SELECT id FROM cards WHERE id = ?').get(ieri.id), undefined);
    // le carte regalo scadute non si toccano
    const regalo = (await call('', 'POST', { kind: 'regalo', name: 'Libreria', expiry_date: iso(-5) })).data;
    assert.ok((await call('')).data.some((c) => c.id === regalo.id));
  });
});
