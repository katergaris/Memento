const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');

process.env.DB_PATH = ':memory:';
const db = require('./db');
const { phone, settings } = require('./routes/app-store');

async function withServer(fn) {
  const app = express();
  app.use('/phone', phone);
  app.use(express.json());
  app.use('/settings', settings);
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  try { await fn(`http://127.0.0.1:${server.address().port}`); } finally { await new Promise((r) => server.close(r)); }
}

test('copia dell\'app: chiave obbligatoria, file salvati e riletti, scollegamento', async () => {
  await withServer(async (base) => {
    assert.equal((await fetch(`${base}/phone/files`)).status, 401);
    assert.equal((await fetch(`${base}/phone/files`, { headers: { Authorization: 'Bearer sbagliata' } })).status, 401);
    const { token } = await (await fetch(`${base}/settings/keys`, { method: 'POST' })).json();
    const auth = { Authorization: `Bearer ${token}` };
    const put = await fetch(`${base}/phone/files/memento-cloud.json`, { method: 'PUT', headers: { ...auth, 'Content-Type': 'application/json' }, body: JSON.stringify({ format: 'memento-cloud', ct: 'abc' }) });
    assert.equal(put.status, 204);
    assert.equal((await fetch(`${base}/phone/files/..%2Fsegreti`, { headers: auth })).status, 400);
    const list = await (await fetch(`${base}/phone/files`, { headers: auth })).json();
    assert.deepEqual(list.map((f) => f.name), ['memento-cloud.json']);
    const back = await (await fetch(`${base}/phone/files/memento-cloud.json`, { headers: auth })).json();
    assert.equal(back.ct, 'abc');
    const status = await (await fetch(`${base}/settings/status`)).json();
    assert.equal(status.phones, 1);
    assert.equal(status.files, 1);
    // Nel database c'e' solo l'hash della chiave.
    assert.ok(!db.prepare('SELECT token_hash FROM app_store_keys').all().some((r) => r.token_hash === token));
    await fetch(`${base}/settings/keys`, { method: 'DELETE' });
    assert.equal((await fetch(`${base}/phone/files`, { headers: auth })).status, 401);
  });
});
