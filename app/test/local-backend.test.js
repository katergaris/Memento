'use strict';
// Motore della modalita' "Sul telefono": stesse risposte del server, archivio
// cifrato, esportazione, unione di due copie.
const test = require('node:test');
const assert = require('node:assert/strict');
const { LocalBackend, mergeStates, memoryStorage, parseCsv } = require('../src/local-backend');
const serverTotp = require('../../server/totp');
const appTotp = require('../src/totp');

async function call(be, path, method = 'GET', body) {
  const res = await be.request(path, { method, body: body === undefined ? undefined : (body instanceof FormData ? body : JSON.stringify(body)) });
  return { status: res.status, data: await res.json() };
}
async function fresh() {
  const storage = memoryStorage();
  const be = new LocalBackend(storage);
  await call(be, '/auth/setup', 'POST', { username: 'io', password: 'password-lunga' });
  return { be, storage };
}

test('primo avvio, blocco e sblocco con la password', async () => {
  const storage = memoryStorage();
  const be = new LocalBackend(storage);
  assert.deepEqual((await call(be, '/auth/status')).data, { setupNeeded: true, authenticated: false, local: true });
  assert.equal((await call(be, '/auth/setup', 'POST', { username: 'io', password: 'corta' })).status, 400);
  await call(be, '/auth/setup', 'POST', { username: 'io', password: 'password-lunga' });
  await call(be, '/ideas', 'POST', { title: 'Prima nota' });
  await call(be, '/auth/logout', 'POST');
  assert.equal((await call(be, '/ideas')).status, 401);

  const again = new LocalBackend(storage);
  assert.equal((await call(again, '/auth/login', 'POST', { password: 'sbagliata' })).status, 401);
  assert.equal((await call(again, '/auth/login', 'POST', { password: 'password-lunga' })).status, 200);
  assert.equal((await call(again, '/ideas')).data[0].title, 'Prima nota');
});

test("l'archivio su disco e' cifrato: niente testo in chiaro", async () => {
  const { be, storage } = await fresh();
  await call(be, '/vault', 'POST', { site: 'Banca', password: 'segretissima-123' });
  const raw = JSON.stringify(await storage.get('archive'));
  assert.ok(!raw.includes('segretissima-123'));
  assert.ok(!raw.includes('Banca'));
});

test('note, progetti e promemoria rispondono come il server', async () => {
  const { be } = await fresh();
  const idea = (await call(be, '/ideas', 'POST', { title: 'Idea', tags: ['casa'], checklist: [{ text: 'a', done: false }] }));
  assert.equal(idea.status, 201);
  assert.deepEqual(idea.data.tags, ['casa']);
  const upd = await call(be, `/ideas/${idea.data.id}`, 'PUT', { checklist: [{ text: 'a', done: true }] });
  assert.equal(upd.data.title, 'Idea');
  assert.equal(upd.data.checklist[0].done, true);

  const proj = await call(be, '/projects', 'POST', { title: 'Trasloco', status: 'strano', deadline: '2026-12-01' });
  assert.equal(proj.data.status, 'da_fare');
  assert.equal((await call(be, `/projects/${proj.data.id}`, 'PUT', { status: 'in_corso' })).data.deadline, '2026-12-01');

  assert.equal((await call(be, '/reminders', 'POST', { label: 'x' })).status, 400);
  const rem = await call(be, '/reminders', 'POST', { label: 'Bolletta', date: '2026-11-20', time: '' });
  assert.equal(rem.data.time, null);
  const moved = await call(be, `/reminders/${rem.data.id}`, 'PUT', { date: '2026-11-21' });
  assert.equal(moved.data.label, 'Bolletta');
  assert.equal(moved.data.date, '2026-11-21');
});

test('cestino: elimina, ripristina, svuota', async () => {
  const { be } = await fresh();
  const idea = (await call(be, '/ideas', 'POST', { title: 'Da buttare' })).data;
  assert.equal((await call(be, `/ideas/${idea.id}`, 'DELETE')).status, 204);
  assert.equal((await call(be, '/ideas')).data.length, 0);
  const trash = (await call(be, '/trash')).data;
  assert.equal(trash[0].type, 'idea');
  await call(be, `/trash/idea/${idea.id}/restore`, 'POST');
  assert.equal((await call(be, '/ideas')).data.length, 1);
  await call(be, `/ideas/${idea.id}`, 'DELETE');
  assert.equal((await call(be, `/trash/idea/${idea.id}`, 'DELETE')).status, 204);
  assert.equal((await call(be, '/trash')).data.length, 0);
  assert.equal(be.state.purged.length, 1);
});

test('cartelle: collegare e scollegare elementi', async () => {
  const { be } = await fresh();
  const d = (await call(be, '/dossiers', 'POST', { title: 'Casa' })).data;
  const idea = (await call(be, '/ideas', 'POST', { title: 'Caldaia' })).data;
  const linked = await call(be, `/dossiers/${d.id}/links`, 'POST', { item_type: 'idea', item_id: idea.id });
  assert.deepEqual(linked.data.items, [{ type: 'idea', id: idea.id, label: 'Caldaia' }]);
  await call(be, `/dossiers/${d.id}/links`, 'POST', { item_type: 'idea', item_id: idea.id });
  assert.equal((await call(be, `/dossiers/${d.id}`)).data.items.length, 1);
  await call(be, `/dossiers/${d.id}/links/idea/${idea.id}`, 'DELETE');
  assert.equal((await call(be, '/dossiers')).data[0].items.length, 0);
});

test('vault: la password si vede solo con reveal, il codice 2FA coincide con il server', async () => {
  const { be } = await fresh();
  const v = (await call(be, '/vault', 'POST', { site: 'Banca', username: 'io', password: 'pw', totp_secret: 'jbsw y3dp ehpk 3pxp' })).data;
  assert.equal(v.password, undefined);
  assert.equal(v.hasTotp, true);
  assert.equal((await call(be, `/vault/${v.id}/reveal`)).data.password, 'pw');
  const { data } = await call(be, `/vault/${v.id}/totp`);
  assert.equal(data.code, serverTotp.codeForStep('JBSWY3DPEHPK3PXP', serverTotp.currentStep()));
  for (const step of [0, 1, 59, 1234567]) {
    assert.equal(await appTotp.codeForStep('JBSWY3DPEHPK3PXP', step), serverTotp.codeForStep('JBSWY3DPEHPK3PXP', step));
  }
  assert.equal((await call(be, '/vault', 'POST', { site: 'x', password: 'y', totp_secret: '1111' })).status, 400);
});

test('vault: conferma con impronta richiesta dal telefono', async () => {
  const storage = memoryStorage();
  let allow = false;
  const be = new LocalBackend(storage, { confirmReveal: async () => allow });
  await call(be, '/auth/setup', 'POST', { username: 'io', password: 'password-lunga' });
  const v = (await call(be, '/vault', 'POST', { site: 'Banca', password: 'pw' })).data;
  assert.equal((await call(be, `/vault/${v.id}/reveal`)).status, 403);
  allow = true;
  assert.equal((await call(be, `/vault/${v.id}/reveal`)).data.password, 'pw');
});

test('import CSV del vault con virgolette', async () => {
  const rows = parseCsv('name,url,username,password\n"Banca, conto",https://b.it,io,"p""w"\nVuota,,,\n');
  assert.equal(rows[0].name, 'Banca, conto');
  assert.equal(rows[0].password, 'p"w');
  const { be } = await fresh();
  const fd = new FormData();
  fd.append('file', new File(['name,password\nA,1\nB,\n'], 'x.csv', { type: 'text/csv' }));
  const r = await call(be, '/vault/import', 'POST', fd);
  assert.deepEqual(r.data, { imported: 1, skipped: 1, total: 2 });
});

test('drive: i file sono cifrati e si riaprono', async () => {
  const { be, storage } = await fresh();
  const fd = new FormData();
  fd.append('file', new File(['contenuto riservato'], 'carta.txt', { type: 'text/plain' }));
  fd.append('display_name', 'Carta');
  const doc = (await call(be, '/drive', 'POST', fd)).data;
  assert.equal(doc.display_name, 'Carta');
  const stored = JSON.stringify(await storage.get('file:' + doc.stored_name));
  assert.ok(!stored.includes('riservato'));
  const { blob, name } = await be.fileBlob(doc.id);
  assert.equal(name, 'carta.txt');
  assert.equal(await blob.text(), 'contenuto riservato');
  await assert.rejects(be.fileBlob(doc.id, { preview: true }), /Anteprima/);
});

test('esportazione cifrata e importazione su un altro telefono', async () => {
  const { be } = await fresh();
  await call(be, '/ideas', 'POST', { title: 'Nota da portare' });
  const fd = new FormData();
  fd.append('file', new File(['pdf finto'], 'a.pdf', { type: 'application/pdf' }));
  await call(be, '/drive', 'POST', fd);
  const file = await be.exportFile('password-del-file');
  assert.equal(file.format, 'memento-export');
  assert.ok(!JSON.stringify(file).includes('Nota da portare'));

  const other = (await fresh()).be;
  await assert.rejects(other.importFile(file, 'sbagliata'), /errata/);
  const counts = await other.importFile(file, 'password-del-file');
  assert.equal(counts.ideas, 1);
  const docs = (await call(other, '/drive')).data;
  assert.equal(await (await other.fileBlob(docs[0].id)).blob.text(), 'pdf finto');
});

test('unione di due copie: vince la modifica piu\' recente, le lapidi restano', async () => {
  const base = { schema: 1, user: { username: 'io' }, purged: [], tables: { ideas: [{ id: 1, title: 'vecchio', _rev: 10 }, { id: 2, title: 'solo A', _rev: 5 }] } };
  const other = { schema: 1, user: { username: '' }, purged: [{ table: 'ideas', id: 2, at: 20 }], tables: { ideas: [{ id: 1, title: 'nuovo', _rev: 30 }, { id: 3, title: 'solo B', _rev: 7 }] } };
  const m = mergeStates(base, other);
  const titles = Object.fromEntries(m.tables.ideas.map((r) => [r.id, r.title]));
  assert.deepEqual(titles, { 1: 'nuovo', 3: 'solo B' });
  assert.equal(m.user.username, 'io');
});

test('cambio password: i dati e i file restano leggibili', async () => {
  const { be, storage } = await fresh();
  const fd = new FormData();
  fd.append('file', new File(['ciao'], 'a.txt', { type: 'text/plain' }));
  const doc = (await call(be, '/drive', 'POST', fd)).data;
  await assert.rejects(be.changePassword('sbagliata', 'nuova-password'), /errata/);
  await be.changePassword('password-lunga', 'nuova-password');
  const again = new LocalBackend(storage);
  assert.equal((await call(again, '/auth/login', 'POST', { password: 'password-lunga' })).status, 401);
  await call(again, '/auth/login', 'POST', { password: 'nuova-password' });
  assert.equal(await (await again.fileBlob(doc.id)).blob.text(), 'ciao');
});

test('sblocco con la chiave custodita dal telefono (impronta)', async () => {
  const { be, storage } = await fresh();
  await call(be, '/ideas', 'POST', { title: 'x' });
  const raw = await be.exportRawKey();
  const again = new LocalBackend(storage);
  await again.unlockWithKey(raw);
  assert.equal((await call(again, '/ideas')).data.length, 1);
});

test('carte fedelta\' e regalo: come sul server', async () => {
  const { be, storage } = await fresh();
  const g = (await call(be, '/cards', 'POST', { kind: 'regalo', name: 'Libreria', brand: 'feltrinelli', balance: '25,50', pin: '4321', format: 'QR', number: 'ABC' })).data;
  assert.equal(g.brand, 'feltrinelli');
  assert.equal(g.balance, 25.5);
  assert.equal(g.hasPin, true);
  assert.equal(g.pin, undefined);
  assert.equal((await call(be, `/cards/${g.id}/pin`)).data.pin, '4321');
  assert.equal((await call(be, `/cards/${g.id}/spend`, 'POST', { amount: 30 })).data.balance, 0);
  assert.ok(!JSON.stringify(await storage.get('archive')).includes('4321'));
  assert.equal((await call(be, '/search?q=libr')).data[0].type, 'card');
  await call(be, `/cards/${g.id}`, 'DELETE');
  assert.equal((await call(be, '/trash')).data[0].type, 'card');
});

test('vault: tipo Codici anche solo con il segreto 2FA', async () => {
  const { be } = await fresh();
  assert.equal((await call(be, '/vault', 'POST', { site: 'X', type: 'code' })).status, 400);
  const c = await call(be, '/vault', 'POST', { site: 'GitHub', type: 'code', totp_secret: 'JBSWY3DPEHPK3PXP' });
  assert.equal(c.status, 201);
  assert.equal(c.data.type, 'code');
  assert.equal(c.data.hasTotp, true);
});
