const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');

process.env.DB_PATH = ':memory:';
const db = require('./db');
const accountsRouter = require('./routes/accounts');

// Riga minima per i test di collegamento: qui serve solo un id/site/username
// da referenziare, non serve passare dalle rotte Vault (niente cifratura da
// configurare).
function insertVaultEntry(site, username = '') {
  const info = db
    .prepare("INSERT INTO vault_entries (site, username, password_encrypted) VALUES (?, ?, 'x')")
    .run(site, username);
  return info.lastInsertRowid;
}

async function withServer(fn) {
  const app = express();
  app.use(express.json());
  app.use('/accounts', accountsRouter);
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}/accounts`;
  try {
    await fn(base);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('un abbonamento senza tipo dichiarato e\' digitale di default', async () => {
  await withServer(async (base) => {
    const created = await fetch(base, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service: 'Netflix', email: 'me@example.com' }),
    }).then((r) => r.json());
    assert.equal(created.type, 'digitale');
  });
});

test('un abbonamento cartaceo salva luogo e modalita\' di pagamento', async () => {
  await withServer(async (base) => {
    const created = await fetch(base, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service: 'Rivista mensile', type: 'cartaceo', location: 'Edicola di via Roma', payment_method: 'contanti' }),
    }).then((r) => r.json());
    assert.equal(created.type, 'cartaceo');
    assert.equal(created.location, 'Edicola di via Roma');
    assert.equal(created.payment_method, 'contanti');
  });
});

test('un tipo non valido viene ignorato e resta digitale', async () => {
  await withServer(async (base) => {
    const created = await fetch(base, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service: 'Qualcosa', type: 'non-esiste' }),
    }).then((r) => r.json());
    assert.equal(created.type, 'digitale');
  });
});

test('salva frequenza di addebito e importo, e li aggiorna in modifica', async () => {
  await withServer(async (base) => {
    const created = await fetch(base, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service: 'Netflix', billing_frequency: 'mensile', amount: '9.99' }),
    }).then((r) => r.json());
    assert.equal(created.billing_frequency, 'mensile');
    assert.equal(created.amount, 9.99);

    const updated = await fetch(`${base}/${created.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ billing_frequency: 'annuale', amount: '99' }),
    }).then((r) => r.json());
    assert.equal(updated.billing_frequency, 'annuale');
    assert.equal(updated.amount, 99);
  });
});

test('una frequenza di addebito non valida viene ignorata (non specificata)', async () => {
  await withServer(async (base) => {
    const created = await fetch(base, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service: 'Boh', billing_frequency: 'ogni-tanto' }),
    }).then((r) => r.json());
    assert.equal(created.billing_frequency, '');
  });
});

test('puo\' essere collegato a credenziali gia\' salvate nel Vault', async () => {
  await withServer(async (base) => {
    const vaultId = insertVaultEntry('Netflix', 'me@example.com');
    const created = await fetch(base, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service: 'Netflix', vault_entry_id: vaultId }),
    }).then((r) => r.json());
    assert.equal(created.vaultEntry.id, vaultId);
    assert.equal(created.vaultEntry.site, 'Netflix');
    assert.equal(created.vaultEntry.username, 'me@example.com');

    const unlinked = await fetch(`${base}/${created.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vault_entry_id: null }),
    }).then((r) => r.json());
    assert.equal(unlinked.vaultEntry, null);
  });
});

test('collegare una voce Vault inesistente viene rifiutato (404), non salvato silenziosamente', async () => {
  await withServer(async (base) => {
    const res = await fetch(base, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service: 'Netflix', vault_entry_id: 999999 }),
    });
    assert.equal(res.status, 404);
  });
});

test('finanziamento: numero di rate, giorno di addebito dalla prima rata, niente scadenze dopo l\'ultima', async () => {
  const { loanNextDate } = require('./routes/search');
  await withServer(async (base) => {
    const iso = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
    const start = new Date(); start.setHours(0, 0, 0, 0); start.setMonth(start.getMonth() - 3); start.setDate(10);
    const created = await fetch(base, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service: 'Auto', type: 'finanziamento', billing_frequency: 'mensile', amount: '200', start_date: iso(start), installments: '12' }),
    }).then((r) => r.json());
    assert.equal(created.type, 'finanziamento');
    assert.equal(created.installments, 12);
    assert.equal(created.renewal_day, 10);
    // Le rate non vengono salvate su una spesa che non e' un finanziamento.
    const updated = await fetch(`${base}/${created.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: 'digitale' }) }).then((r) => r.json());
    assert.equal(updated.installments, null);
  });
  const old = new Date(); old.setFullYear(old.getFullYear() - 2);
  const isoOld = `${old.getFullYear()}-${String(old.getMonth() + 1).padStart(2, '0')}-01`;
  assert.equal(loanNextDate(isoOld, 'mensile', 6), null);
  assert.match(loanNextDate(isoOld, 'mensile', 60), /^\d{4}-\d{2}-01$/);
});
