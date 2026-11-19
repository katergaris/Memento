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

test('verifica in due passaggi sul telefono: attivazione, sblocco, codici di recupero', async () => {
  const { be, storage } = await fresh();
  const setup = (await call(be, '/security/totp/setup', 'POST')).data;
  assert.match(setup.otpauth, /^otpauth:\/\/totp\//);
  const secret = setup.secret.replace(/\s/g, '');
  assert.equal((await call(be, '/security/totp/enable', 'POST', { code: '000000' })).status, 400);
  const code = await appTotp.codeForStep(secret, appTotp.currentStep());
  const enabled = (await call(be, '/security/totp/enable', 'POST', { code })).data;
  assert.equal(enabled.recoveryCodes.length, 10);
  assert.equal((await call(be, '/security')).data.recoveryCodesLeft, 10);

  const again = new LocalBackend(storage);
  const noCode = await call(again, '/auth/login', 'POST', { password: 'password-lunga' });
  assert.equal(noCode.status, 401);
  assert.equal(noCode.data.totpRequired, true);
  assert.equal((await call(again, '/ideas')).status, 401);
  // lo stesso codice gia' usato non vale una seconda volta
  assert.equal((await call(again, '/auth/login', 'POST', { password: 'password-lunga', code })).status, 401);
  assert.equal((await call(again, '/auth/login', 'POST', { password: 'password-lunga', code: enabled.recoveryCodes[0] })).status, 200);
  assert.equal((await call(again, '/security')).data.recoveryCodesLeft, 9);
  await call(again, '/auth/logout', 'POST');
  assert.equal((await call(again, '/auth/login', 'POST', { password: 'password-lunga', code: enabled.recoveryCodes[0] })).status, 401);
  await call(again, '/auth/login', 'POST', { password: 'password-lunga', code: enabled.recoveryCodes[1] });
  assert.equal((await call(again, '/security/totp/disable', 'POST', { password: 'sbagliata' })).status, 403);
  await call(again, '/security/totp/disable', 'POST', { password: 'password-lunga' });
  await call(again, '/auth/logout', 'POST');
  assert.equal((await call(again, '/auth/login', 'POST', { password: 'password-lunga' })).status, 200);
});

test('copia sul cloud: due telefoni con la stessa password principale', async () => {
  const a = (await fresh()).be;
  await call(a, '/ideas', 'POST', { title: 'Dal telefono A' });
  const fd = new FormData();
  fd.append('file', new File(['documento A'], 'a.txt', { type: 'text/plain' }));
  const doc = (await call(a, '/drive', 'POST', fd)).data;
  await assert.rejects(a.setupCloudKey('sbagliata'), /Password/);
  await a.setupCloudKey('password-lunga');
  const env = await a.cloudEnvelope();
  assert.ok(!JSON.stringify(env).includes('Dal telefono A'));
  assert.ok(!JSON.stringify(env).includes(a.state.settings.cloud.key));
  const encFile = await a.cloudFile(doc.stored_name);

  // telefono B: archivio con sale diverso, stessa password principale
  const b = (await fresh()).be;
  await call(b, '/ideas', 'POST', { title: 'Dal telefono B' });
  await assert.rejects(b.openCloudEnvelope(env), (e) => e.data && e.data.passwordRequired);
  const payload = await b.openCloudEnvelope(env, 'password-lunga');
  await b.mergeRemote(payload.state);
  await b.importCloudFile(doc.stored_name, encFile);
  const titles = (await call(b, '/ideas')).data.map((i) => i.title).sort();
  assert.deepEqual(titles, ['Dal telefono A', 'Dal telefono B']);
  assert.equal(await (await b.fileBlob(doc.id)).blob.text(), 'documento A');
  // B ricarica e A riapre senza chiedere la password (stessa chiave cloud)
  const env2 = await b.cloudEnvelope();
  const back = await a.openCloudEnvelope(env2);
  await a.mergeRemote(back.state);
  assert.equal((await call(a, '/ideas')).data.length, 2);
});

// Simula Google Drive: file per id, come li vede ciascuno.
async function syncShares(drive, be, email) {
  await be.ensureIdentity(email);
  drive.identities[email] = (await be.ensureIdentity(email)).publicJwk;
  for (const [who, jwk] of Object.entries(drive.identities)) if (who !== email) await be.learnContact(who, jwk);
  const ids = [];
  for (const [fid, f] of Object.entries(drive.files)) {
    if (!f.access.includes(email)) continue;
    ids.push(f.content.id);
    await be.applyShareFile(f.content, fid);
  }
  await be.dropMissingShares(ids);
  for (const o of await be.shareOutbox()) {
    const fid = o.fileId || 'f' + Object.keys(drive.files).length;
    const access = o.isOwner ? [o.owner, ...o.members.map((m) => m.email)] : drive.files[fid].access;
    drive.files[fid] = { content: o.file, access };
    await be.markShared(o.entryId, fid, o.pending);
  }
}

test('condivisione di una voce: invito, visualizzazione, modifica, revoca', async () => {
  const drive = { files: {}, identities: {} };
  const io = (await fresh()).be;
  const lei = (await fresh()).be;
  assert.equal((await call(io, '/vault', 'POST', { site: 'x', password: 'y' })).status, 201);
  const v = (await call(io, '/vault', 'POST', { site: 'Netflix', username: 'famiglia', password: 'segreta-1' })).data;
  assert.equal((await call(io, `/vault/${v.id}/share`, 'POST', { email: 'lei@example.com' })).status, 400); // Drive non collegato
  await syncShares(drive, io, 'io@example.com');
  assert.equal((await call(io, `/vault/${v.id}/share`, 'POST', { email: 'non-valida' })).status, 400);
  const shared = (await call(io, `/vault/${v.id}/share`, 'POST', { email: 'Lei@Example.com', role: 'reader' })).data;
  assert.deepEqual(shared.share.members, [{ email: 'lei@example.com', role: 'reader' }]);

  // primo giro: lei non ha ancora pubblicato la chiave -> in attesa
  await syncShares(drive, io, 'io@example.com');
  assert.ok(!JSON.stringify(drive.files).includes('segreta-1'));
  await syncShares(drive, lei, 'lei@example.com');
  assert.equal((await call(lei, '/vault')).data.length, 0);
  // io imparo la sua chiave e riscrivo il file, lei ora la vede
  await syncShares(drive, io, 'io@example.com');
  await syncShares(drive, lei, 'lei@example.com');
  const [got] = (await call(lei, '/vault')).data;
  assert.equal(got.site, 'Netflix');
  assert.equal(got.share.role, 'reader');
  assert.equal(got.share.owner, 'io@example.com');
  assert.equal((await call(lei, `/vault/${got.id}/reveal`)).data.password, 'segreta-1');
  assert.equal((await call(lei, `/vault/${got.id}`, 'PUT', { password: 'cambiata' })).status, 403);
  assert.equal((await call(lei, `/vault/${got.id}/share`, 'POST', { email: 'altro@example.com' })).status, 403);

  // permesso di modifica: lei cambia, io ricevo
  await call(io, `/vault/${v.id}/share`, 'POST', { email: 'lei@example.com', role: 'writer' });
  await syncShares(drive, io, 'io@example.com');
  await syncShares(drive, lei, 'lei@example.com');
  assert.equal((await call(lei, '/vault')).data[0].share.role, 'writer');
  await new Promise((r) => setTimeout(r, 5));
  assert.equal((await call(lei, `/vault/${got.id}`, 'PUT', { password: 'cambiata-da-lei' })).status, 200);
  await syncShares(drive, lei, 'lei@example.com');
  await syncShares(drive, io, 'io@example.com');
  assert.equal((await call(io, `/vault/${v.id}/reveal`)).data.password, 'cambiata-da-lei');

  // revoca: Drive le toglie il file, la voce sparisce dal suo vault
  await call(io, `/vault/${v.id}/share/lei@example.com`, 'DELETE');
  await syncShares(drive, io, 'io@example.com');
  assert.ok(!drive.files[Object.keys(drive.files)[0]].access.includes('lei@example.com'));
  await syncShares(drive, lei, 'lei@example.com');
  assert.equal((await call(lei, '/vault')).data.length, 0);
});
