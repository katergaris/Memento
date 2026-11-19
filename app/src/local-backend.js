'use strict';
// Modalita' "Sul telefono": risponde alle stesse richieste del server
// (/ideas, /vault, /drive, ...) con le stesse risposte, cosi' l'interfaccia
// non sa se dietro c'e' il server di casa o il telefono.
//
// I dati stanno in memoria mentre l'app e' sbloccata e su disco in un unico
// archivio cifrato (AES-GCM, chiave derivata dalla password principale). I
// file del Drive sono cifrati con la stessa chiave, uno per uno.
//
// Ogni record ha "_rev" (millisecondi dell'ultima modifica): serve a unire
// due copie (telefono e copia su Drive) voce per voce, vince la piu' recente.
// Anche eliminare e ripristinare sono modifiche; svuotare il cestino lascia
// una "lapide" in purged, cosi' la voce non ricompare dall'altra copia.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('./crypto'), require('./totp'));
  else root.MementoLocalBackend = factory(root.MementoCrypto, root.MementoTotp);
})(typeof self !== 'undefined' ? self : this, function (MC, TOTP) {
  const ARCHIVE_FORMAT = 'memento-archive';
  const EXPORT_FORMAT = 'memento-export';
  const TABLES = ['ideas', 'projects', 'reminders', 'accounts', 'vault', 'documents', 'dossiers', 'links', 'cards'];
  const TYPE_TABLE = { idea: 'ideas', project: 'projects', vault: 'vault', account: 'accounts', document: 'documents', reminder: 'reminders', dossier: 'dossiers', card: 'cards' };
  const LABEL = {
    idea: (r) => r.title, project: (r) => r.title, vault: (r) => r.site, account: (r) => r.service,
    document: (r) => r.display_name || r.original_name, dossier: (r) => r.title, reminder: (r) => r.label, card: (r) => r.name,
  };
  const PREVIEWABLE_MIME = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'application/pdf']);

  class HttpError extends Error {
    constructor(status, message, data) { super(message); this.status = status; this.data = data || {}; }
  }
  const fail = (status, message, data) => { throw new HttpError(status, message, data); };

  // "2026-11-19 08:30:00", come datetime('now') di SQLite.
  function sqlNow(d = new Date()) { return d.toISOString().slice(0, 19).replace('T', ' '); }
  function emptyState() {
    const tables = {};
    TABLES.forEach((t) => { tables[t] = []; });
    return { schema: 1, user: { username: '' }, tables, purged: [], settings: {} };
  }

  // CSV con virgolette (RFC 4180), sufficiente per gli export dei gestori di password.
  function parseCsv(text) {
    const rows = [];
    let row = [], field = '', quoted = false;
    const src = String(text).replace(/^﻿/, '');
    for (let i = 0; i < src.length; i++) {
      const c = src[i];
      if (quoted) {
        if (c === '"' && src[i + 1] === '"') { field += '"'; i++; }
        else if (c === '"') quoted = false;
        else field += c;
      } else if (c === '"') quoted = true;
      else if (c === ',') { row.push(field); field = ''; }
      else if (c === '\n' || c === '\r') {
        if (c === '\r' && src[i + 1] === '\n') i++;
        row.push(field); field = '';
        if (row.some((v) => v.trim() !== '')) rows.push(row);
        row = [];
      } else field += c;
    }
    row.push(field);
    if (row.some((v) => v.trim() !== '')) rows.push(row);
    if (!rows.length) return [];
    const headers = rows[0].map((h) => h.trim());
    return rows.slice(1).map((r) => Object.fromEntries(headers.map((h, i) => [h, (r[i] || '').trim()])));
  }

  // Prossima data di rinnovo (stessa logica di server/routes/search.js).
  const BILLING_STEP_MONTHS = { trimestrale: 3, semestrale: 6, annuale: 12 };
  function isoLocal(d) { return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; }
  function nextOccurrence(day, month, frequency) {
    const today = new Date(); today.setHours(0, 0, 0, 0);
    if (frequency === 'settimanale') {
      const todayIso = ((today.getDay() + 6) % 7) + 1;
      const c = new Date(today); c.setDate(c.getDate() + ((day - todayIso + 7) % 7));
      return isoLocal(c);
    }
    if (frequency === 'mensile') {
      let c = new Date(today.getFullYear(), today.getMonth(), day);
      if (c < today) c = new Date(today.getFullYear(), today.getMonth() + 1, day);
      return isoLocal(c);
    }
    const step = BILLING_STEP_MONTHS[frequency] || 12;
    const at = (off) => { const t = (today.getFullYear() - 1) * 12 + (month - 1) + off; return new Date(Math.floor(t / 12), ((t % 12) + 12) % 12, day); };
    let off = 0, c = at(0);
    while (c < today) { off += step; c = at(off); }
    return isoLocal(c);
  }

  // Unione di due copie: per ogni voce vince quella con _rev piu' alto; le
  // lapidi di "svuota cestino" cancellano la voce da entrambe.
  function mergeStates(a, b) {
    const out = emptyState();
    out.user = (a.user && a.user.username) ? a.user : (b.user || out.user);
    out.settings = { ...(b.settings || {}), ...(a.settings || {}) };
    const purgedKey = (p) => `${p.table}:${p.id}`;
    const purged = new Map();
    [...(a.purged || []), ...(b.purged || [])].forEach((p) => { if (!purged.has(purgedKey(p))) purged.set(purgedKey(p), p); });
    out.purged = [...purged.values()];
    TABLES.forEach((t) => {
      const byId = new Map();
      [...((a.tables || {})[t] || []), ...((b.tables || {})[t] || [])].forEach((rec) => {
        if (purged.has(`${t}:${rec.id}`)) return;
        const cur = byId.get(rec.id);
        if (!cur || (rec._rev || 0) > (cur._rev || 0)) byId.set(rec.id, rec);
      });
      out.tables[t] = [...byId.values()];
    });
    return out;
  }

  class LocalBackend {
    // storage: { get(key), put(key, value), del(key) } (valori JSON)
    // hooks:   { confirmReveal(): Promise<boolean>, version }
    constructor(storage, hooks = {}) {
      this.storage = storage;
      this.hooks = hooks;
      this.key = null;
      this.salt = null;
      this.iter = MC.ITERATIONS;
      this.state = null;
      this.lastId = 0;
      this.listeners = new Set();
    }

    get unlocked() { return !!this.key; }
    onChange(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }

    newId() {
      // Intero unico anche tra telefoni diversi (ms * 1000 + casuale), entro i
      // 2^53 che JSON e JavaScript gestiscono senza perdere cifre.
      let id = Date.now() * 1000 + Math.floor(Math.random() * 1000);
      if (id <= this.lastId) id = this.lastId + 1;
      this.lastId = id;
      return id;
    }
    rows(t) { return this.state.tables[t]; }
    find(t, id, { includeDeleted = false } = {}) {
      const r = this.rows(t).find((x) => String(x.id) === String(id));
      if (!r || (!includeDeleted && r.deleted_at)) return null;
      return r;
    }
    touch(rec, fields = {}) {
      Object.assign(rec, fields);
      rec.updated_at = sqlNow();
      rec._rev = Date.now();
      return rec;
    }
    insert(t, fields) {
      const now = sqlNow();
      const rec = { id: this.newId(), ...fields, created_at: now, updated_at: now, deleted_at: null, _rev: Date.now() };
      this.rows(t).push(rec);
      return rec;
    }

    // ---------------- Archivio cifrato ----------------
    async hasArchive() { return !!(await this.storage.get('archive')); }

    async setup(username, password) {
      if (await this.hasArchive()) fail(409, 'Account gia\' configurato');
      if (!password || String(password).length < 8) fail(400, 'La password deve avere almeno 8 caratteri');
      this.salt = MC.toB64(MC.randomBytes(16));
      this.key = await MC.deriveKey(password, MC.fromB64(this.salt), this.iter);
      this.state = emptyState();
      this.state.user.username = String(username || '').trim();
      await this.save();
    }

    async unlock(password) {
      const envelope = await this.storage.get('archive');
      if (!envelope) fail(400, 'Nessun archivio');
      try {
        const opened = await MC.openWithPassword(envelope, password, ARCHIVE_FORMAT);
        this.key = opened.key; this.salt = opened.salt; this.iter = opened.iter;
        this.state = mergeStates(emptyState(), opened.value);
      } catch (e) {
        if (e.message === 'bad-password') fail(401, 'Password errata');
        throw e;
      }
    }

    // Sblocco con la chiave gia' derivata (custodita dal portachiavi Android
    // dietro l'impronta): evita di riscrivere la password ogni volta.
    async unlockWithKey(rawKeyB64) {
      const envelope = await this.storage.get('archive');
      if (!envelope) fail(400, 'Nessun archivio');
      const key = await MC.importKey(rawKeyB64);
      let bytes;
      try { bytes = await MC.decryptBytes(key, envelope.iv, envelope.ct); } catch (_) { fail(401, 'Chiave non valida'); }
      this.key = key; this.salt = envelope.kdf.salt; this.iter = envelope.kdf.iter;
      this.state = mergeStates(emptyState(), JSON.parse(new TextDecoder().decode(bytes)));
    }
    async exportRawKey() { return MC.exportKey(this.key); }

    lock() { this.key = null; this.state = null; }

    async changePassword(current, next) {
      const envelope = await this.storage.get('archive');
      try { await MC.openWithPassword(envelope, current, ARCHIVE_FORMAT); } catch (_) { fail(401, 'Password attuale errata'); }
      if (!next || String(next).length < 8) fail(400, 'La password deve avere almeno 8 caratteri');
      const oldKey = this.key;
      this.salt = MC.toB64(MC.randomBytes(16));
      this.key = await MC.deriveKey(next, MC.fromB64(this.salt), this.iter);
      // I file del Drive sono cifrati con la vecchia chiave: si ricifrano.
      for (const d of this.rows('documents')) {
        const f = await this.storage.get('file:' + d.stored_name);
        if (!f) continue;
        const bytes = await MC.decryptBytes(oldKey, f.iv, f.ct);
        await this.storage.put('file:' + d.stored_name, await MC.encryptBytes(this.key, bytes));
      }
      await this.save();
    }

    async save() {
      if (!this.key) return;
      const envelope = await MC.sealWithKey(ARCHIVE_FORMAT, this.key, this.salt, this.iter, this.state);
      await this.storage.put('archive', envelope);
      this.listeners.forEach((fn) => { try { fn(); } catch (_) { /* un ascoltatore rotto non blocca il salvataggio */ } });
    }

    // ---------------- File cifrati del Drive ----------------
    async putFile(bytes) {
      const name = [...MC.randomBytes(16)].map((b) => b.toString(16).padStart(2, '0')).join('');
      await this.storage.put('file:' + name, await MC.encryptBytes(this.key, bytes));
      return name;
    }
    async fileBytes(id) {
      const doc = this.find('documents', id);
      if (!doc) fail(404, 'Documento non trovato');
      const f = await this.storage.get('file:' + doc.stored_name);
      if (!f) fail(404, 'File mancante');
      return { doc, bytes: await MC.decryptBytes(this.key, f.iv, f.ct) };
    }

    // ---------------- Esportazione / importazione ----------------
    // Il file contiene i dati e, se richiesto, i file del Drive (in base64).
    async exportFile(password, { includeFiles = true } = {}) {
      const payload = { app: 'memento', exportedAt: new Date().toISOString(), state: this.state, files: {} };
      if (includeFiles) {
        for (const d of this.rows('documents')) {
          if (d.deleted_at) continue;
          try { payload.files[d.stored_name] = MC.toB64((await this.fileBytes(d.id)).bytes); } catch (_) { /* file mancante: si esporta il resto */ }
        }
      }
      return MC.sealWithPassword(EXPORT_FORMAT, password, payload);
    }
    async readExport(envelope, password) {
      try {
        return (await MC.openWithPassword(envelope, password, EXPORT_FORMAT)).value;
      } catch (e) {
        if (e.message === 'bad-password') fail(401, 'Password del file errata');
        fail(400, 'File non riconosciuto');
      }
    }
    // mode: 'merge' unisce voce per voce, 'replace' sostituisce tutto.
    async importFile(envelope, password, mode = 'merge') {
      const payload = await this.readExport(envelope, password);
      const incoming = mergeStates(emptyState(), payload.state || {});
      for (const [name, b64] of Object.entries(payload.files || {})) {
        await this.storage.put('file:' + name, await MC.encryptBytes(this.key, MC.fromB64(b64)));
      }
      const username = this.state.user.username;
      this.state = mode === 'replace' ? incoming : mergeStates(this.state, incoming);
      if (username) this.state.user.username = username;
      await this.save();
      return this.counts();
    }
    counts() {
      const c = {};
      TABLES.filter((t) => t !== 'links').forEach((t) => { c[t] = this.rows(t).filter((r) => !r.deleted_at).length; });
      return c;
    }
    // Per la sincronizzazione: unisce una copia remota (gia' decifrata).
    async mergeRemote(remoteState) {
      const username = this.state.user.username;
      this.state = mergeStates(this.state, remoteState);
      if (username) this.state.user.username = username;
      await this.save();
    }

    // ---------------- Richieste come al server ----------------
    async request(path, opts = {}) {
      try {
        const data = await this.handle(path, opts);
        if (data === undefined) return { ok: true, status: 204, json: async () => null };
        const status = data && data.__status ? data.__status : 200;
        const body = data && data.__status ? data.body : data;
        return { ok: true, status, json: async () => body };
      } catch (e) {
        if (!(e instanceof HttpError)) {
          return { ok: false, status: 500, json: async () => ({ error: e.message || 'Errore interno' }) };
        }
        return { ok: false, status: e.status, json: async () => ({ error: e.message, ...e.data }) };
      }
    }

    async handle(fullPath, opts) {
      const method = (opts.method || 'GET').toUpperCase();
      const [pathname, query = ''] = String(fullPath).split('?');
      const params = new URLSearchParams(query);
      const parts = pathname.replace(/^\/+|\/+$/g, '').split('/').map(decodeURIComponent);
      let body = {};
      if (typeof opts.body === 'string' && opts.body) body = JSON.parse(opts.body);
      else if (opts.body && typeof opts.body === 'object') body = opts.body;
      const created = (x) => ({ __status: 201, body: x });
      const [res, id, sub, a3, a4] = parts;

      if (res === 'health') return { status: 'ok', version: this.hooks.version || 'app', build: 'telefono' };
      if (res === 'auth') {
        if (id === 'status') return { setupNeeded: !(await this.hasArchive()), authenticated: this.unlocked, local: true };
        if (id === 'setup' && method === 'POST') { await this.setup(body.username, body.password); return { ok: true }; }
        if (id === 'login' && method === 'POST') { await this.unlock(body.password); return { ok: true }; }
        if (id === 'logout' && method === 'POST') { this.lock(); return { ok: true }; }
        fail(404, 'Non trovato');
      }
      if (!this.unlocked) fail(401, 'Non autenticato');

      const mutate = async (fn) => { const out = await fn(); await this.save(); return out; };
      const softDelete = (t) => mutate(() => { const r = this.find(t, id, { includeDeleted: true }); if (r) this.touch(r, { deleted_at: sqlNow() }); });
      const restore = (t) => mutate(() => { const r = this.find(t, id, { includeDeleted: true }); if (r) this.touch(r, { deleted_at: null }); });

      switch (res) {
        case 'ideas': {
          const ser = (r) => ({ ...r });
          if (!id && method === 'GET') return this.sorted('ideas').map(ser);
          if (!id && method === 'POST') {
            if (!body.title) fail(400, 'Il titolo e\' obbligatorio');
            return mutate(() => created(ser(this.insert('ideas', { title: body.title, body: body.body || '', tags: body.tags || [], checklist: body.checklist || [] }))));
          }
          if (id && sub === 'restore') return restore('ideas');
          if (id && method === 'PUT') return mutate(() => {
            const r = this.find('ideas', id) || fail(404, 'Idea non trovata');
            const f = {};
            ['title', 'body', 'tags', 'checklist'].forEach((k) => { if (body[k] !== undefined && body[k] !== null) f[k] = body[k]; });
            return ser(this.touch(r, f));
          });
          if (id && method === 'DELETE') return softDelete('ideas');
          break;
        }
        case 'projects': {
          const VALID = ['da_fare', 'in_corso', 'fatto'];
          if (!id && method === 'GET') return this.sorted('projects');
          if (!id && method === 'POST') {
            if (!body.title) fail(400, 'Il titolo e\' obbligatorio');
            return mutate(() => created(this.insert('projects', {
              title: body.title, description: body.description || '', status: VALID.includes(body.status) ? body.status : 'da_fare',
              checklist: body.checklist || [], tags: body.tags || [], deadline: body.deadline || null, contacts: body.contacts || [], budget: body.budget || [],
            })));
          }
          if (id && sub === 'restore') return restore('projects');
          if (id && method === 'PUT') return mutate(() => {
            const r = this.find('projects', id) || fail(404, 'Progetto non trovato');
            const f = {};
            ['title', 'description', 'checklist', 'tags', 'contacts', 'budget'].forEach((k) => { if (body[k] !== undefined && body[k] !== null) f[k] = body[k]; });
            if (body.status && VALID.includes(body.status)) f.status = body.status;
            if (body.deadline !== undefined) f.deadline = body.deadline || null;
            return this.touch(r, f);
          });
          if (id && method === 'DELETE') return softDelete('projects');
          break;
        }
        case 'reminders': {
          if (!id && method === 'GET') return this.live('reminders').sort((x, y) => (x.created_at < y.created_at ? 1 : -1));
          if (!id && method === 'POST') {
            if (!body.label) fail(400, 'Il testo e\' obbligatorio');
            if (!body.date) fail(400, 'La data e\' obbligatoria');
            return mutate(() => created(this.insert('reminders', { label: body.label, date: body.date, time: body.time || null, notes: body.notes || '', notified_at: null })));
          }
          if (id && sub === 'restore') return restore('reminders');
          if (id && method === 'PUT') return mutate(() => {
            const r = this.find('reminders', id) || fail(404, 'Scadenza non trovata');
            const date = body.date ?? r.date;
            const time = body.time === undefined ? r.time : (body.time || null);
            const notified = date === r.date && time === r.time ? r.notified_at : null;
            return this.touch(r, { label: body.label ?? r.label, date, time, notes: body.notes ?? r.notes, notified_at: notified });
          });
          if (id && method === 'DELETE') return softDelete('reminders');
          break;
        }
        case 'cards': return this.cards(method, id, sub, body, { mutate, softDelete, restore, created });
        case 'accounts': return this.accounts(method, id, sub, body, { mutate, softDelete, restore, created });
        case 'vault': return this.vault(method, id, sub, body, { mutate, softDelete, restore, created });
        case 'drive': return this.drive(method, id, sub, body, { mutate, softDelete, restore, created });
        case 'dossiers': {
          if (!id && method === 'GET') return this.sorted('dossiers').map((d) => this.serDossier(d));
          if (!id && method === 'POST') {
            if (!body.title) fail(400, 'Il titolo e\' obbligatorio');
            return mutate(() => created(this.serDossier(this.insert('dossiers', { title: body.title, description: body.description || '' }))));
          }
          if (id && !sub && method === 'GET') return this.serDossier(this.find('dossiers', id) || fail(404, 'Fascicolo non trovato'));
          if (id && sub === 'restore') return restore('dossiers');
          if (id && sub === 'links' && method === 'POST') return mutate(() => {
            const d = this.find('dossiers', id) || fail(404, 'Fascicolo non trovato');
            const t = TYPE_TABLE[body.item_type];
            if (!t || body.item_type === 'dossier' || body.item_type === 'card') fail(400, 'Tipo di elemento non valido');
            if (!this.find(t, body.item_id)) fail(404, 'Elemento da collegare non trovato');
            const existing = this.rows('links').find((l) => String(l.dossier_id) === String(d.id) && l.item_type === body.item_type && String(l.item_id) === String(body.item_id));
            if (existing) { if (existing.deleted_at) this.touch(existing, { deleted_at: null }); }
            else this.insert('links', { dossier_id: d.id, item_type: body.item_type, item_id: Number(body.item_id) });
            return created(this.serDossier(d));
          });
          if (id && sub === 'links' && method === 'DELETE') return mutate(() => {
            this.rows('links').filter((l) => String(l.dossier_id) === String(id) && l.item_type === a3 && String(l.item_id) === String(a4) && !l.deleted_at)
              .forEach((l) => this.touch(l, { deleted_at: sqlNow() }));
          });
          if (id && method === 'PUT') return mutate(() => {
            const d = this.find('dossiers', id) || fail(404, 'Fascicolo non trovato');
            return this.serDossier(this.touch(d, { title: body.title ?? d.title, description: body.description ?? d.description }));
          });
          if (id && method === 'DELETE') return softDelete('dossiers');
          break;
        }
        case 'trash': {
          if (!id && method === 'GET') {
            const items = [];
            Object.entries(TYPE_TABLE).forEach(([type, t]) => {
              this.rows(t).filter((r) => r.deleted_at).forEach((r) => items.push({ type, id: r.id, label: LABEL[type](r), deleted_at: r.deleted_at }));
            });
            return items.sort((x, y) => (x.deleted_at < y.deleted_at ? 1 : -1));
          }
          const t = TYPE_TABLE[id];
          if (!t) fail(400, 'Tipo non valido');
          if (a3 === 'restore' || (sub && method === 'POST')) {
            return mutate(() => { const r = this.find(t, sub, { includeDeleted: true }); if (r) this.touch(r, { deleted_at: null }); });
          }
          if (method === 'DELETE') return mutate(async () => {
            const r = this.rows(t).find((x) => String(x.id) === String(sub) && x.deleted_at);
            if (!r) fail(404, 'Elemento non trovato nel cestino');
            this.state.tables[t] = this.rows(t).filter((x) => x !== r);
            this.state.purged.push({ table: t, id: r.id, at: Date.now() });
            if (id !== 'dossier') {
              this.rows('links').filter((l) => l.item_type === id && String(l.item_id) === String(r.id)).forEach((l) => {
                this.state.tables.links = this.rows('links').filter((x) => x !== l);
                this.state.purged.push({ table: 'links', id: l.id, at: Date.now() });
              });
            }
            if (id === 'vault') this.rows('accounts').filter((x) => String(x.vault_entry_id) === String(r.id)).forEach((x) => this.touch(x, { vault_entry_id: null }));
            if (id === 'document' && r.stored_name) await this.storage.del('file:' + r.stored_name);
          });
          break;
        }
        case 'search': {
          if (id === 'reminders' && sub === 'upcoming') return this.upcoming(Number(params.get('days')) || 30);
          const q = String(params.get('q') || '').trim().toLowerCase();
          if (!q) return [];
          const has = (...vals) => vals.some((v) => (Array.isArray(v) ? v.join(' ') : String(v || '')).toLowerCase().includes(q));
          const out = [];
          this.live('ideas').filter((r) => has(r.title, r.body, r.tags)).forEach((r) => out.push({ type: 'idea', id: r.id, label: r.title }));
          this.live('projects').filter((r) => has(r.title, r.description, r.tags)).forEach((r) => out.push({ type: 'project', id: r.id, label: r.title }));
          this.live('vault').filter((r) => has(r.site, r.username, r.notes, r.tags)).forEach((r) => out.push({ type: 'vault', id: r.id, label: r.site }));
          this.live('accounts').filter((r) => has(r.service, r.email, r.notes, r.tags)).forEach((r) => out.push({ type: 'account', id: r.id, label: r.service }));
          this.live('documents').filter((r) => has(r.original_name, r.display_name, r.folder, r.tags)).forEach((r) => out.push({ type: 'document', id: r.id, label: r.display_name || r.original_name }));
          this.live('dossiers').filter((r) => has(r.title, r.description)).forEach((r) => out.push({ type: 'dossier', id: r.id, label: r.title }));
          this.live('cards').filter((r) => has(r.name, r.number, r.notes, r.tags)).forEach((r) => out.push({ type: 'card', id: r.id, label: r.name }));
          this.live('reminders').filter((r) => has(r.label, r.notes)).forEach((r) => out.push({ type: 'reminder', id: r.id, label: r.label }));
          return out;
        }
        case 'security':
          if (!id && method === 'GET') return { username: this.state.user.username, totpEnabled: false, local: true, webauthn: [] };
          fail(404, 'Non disponibile sul telefono');
          break;
        case 'push':
          fail(404, 'Non disponibile sul telefono');
          break;
        default:
          break;
      }
      fail(404, 'Endpoint non trovato');
    }

    live(t) { return this.rows(t).filter((r) => !r.deleted_at); }
    sorted(t) { return this.live(t).sort((x, y) => ((x._rev || 0) < (y._rev || 0) ? 1 : -1)); }

    serDossier(d) {
      const items = this.rows('links')
        .filter((l) => String(l.dossier_id) === String(d.id) && !l.deleted_at)
        .map((l) => {
          const t = TYPE_TABLE[l.item_type];
          const item = t && this.find(t, l.item_id);
          return item ? { type: l.item_type, id: item.id, label: LABEL[l.item_type](item) } : null;
        })
        .filter(Boolean);
      return { ...d, items };
    }

    accounts(method, id, sub, body, h) {
      const VALID_TYPES = ['digitale', 'cartaceo'];
      const VALID_BILLING = ['settimanale', 'mensile', 'trimestrale', 'semestrale', 'annuale', 'una_tantum'];
      const amountOf = (raw) => (raw === undefined ? undefined : raw === null || raw === '' ? null : (Number.isFinite(Number(raw)) ? Number(raw) : null));
      const dm = (raw, max) => { if (raw === undefined) return undefined; if (raw === null || raw === '') return null; const n = parseInt(raw, 10); return Number.isInteger(n) && n >= 1 && n <= max ? n : null; };
      const vid = (raw) => { if (raw === undefined) return undefined; if (raw === null || raw === '') return null; const n = Number(raw); return Number.isFinite(n) ? n : null; };
      const ser = (r) => {
        const v = r.vault_entry_id != null ? this.find('vault', r.vault_entry_id) : null;
        return { ...r, vaultEntry: v ? { id: v.id, site: v.site, username: v.username, type: v.type } : null };
      };
      if (!id && method === 'GET') return this.sorted('accounts').map(ser);
      if (!id && method === 'POST') {
        if (!body.service) fail(400, 'Il servizio e\' obbligatorio');
        const billing = VALID_BILLING.includes(body.billing_frequency) ? body.billing_frequency : '';
        const v = vid(body.vault_entry_id);
        if (v != null && !this.find('vault', v)) fail(404, 'Voce Vault da collegare non trovata');
        return h.mutate(() => h.created(ser(this.insert('accounts', {
          service: body.service, type: VALID_TYPES.includes(body.type) ? body.type : 'digitale', email: body.email || '', plan: body.plan || '',
          location: body.location || '', payment_method: body.payment_method || '', start_date: body.start_date || null,
          renewal_date: null, renewal_day: dm(body.renewal_day, billing === 'settimanale' ? 7 : 31) ?? null, renewal_month: dm(body.renewal_month, 12) ?? null,
          notes: body.notes || '', tags: body.tags || [], billing_frequency: billing, amount: amountOf(body.amount) ?? null, vault_entry_id: v ?? null,
        }))));
      }
      if (id && sub === 'restore') return h.restore('accounts');
      if (id && method === 'PUT') return h.mutate(() => {
        const r = this.find('accounts', id) || fail(404, 'Account non trovato');
        const billing = body.billing_frequency !== undefined ? (VALID_BILLING.includes(body.billing_frequency) ? body.billing_frequency : '') : r.billing_frequency;
        const f = { billing_frequency: billing };
        ['service', 'email', 'plan', 'location', 'payment_method', 'notes', 'tags'].forEach((k) => { if (body[k] !== undefined && body[k] !== null) f[k] = body[k]; });
        if (body.type && VALID_TYPES.includes(body.type)) f.type = body.type;
        if (body.start_date !== undefined) f.start_date = body.start_date || null;
        const am = amountOf(body.amount); if (am !== undefined) f.amount = am;
        const d = dm(body.renewal_day, billing === 'settimanale' ? 7 : 31); if (body.renewal_day !== undefined) f.renewal_day = d;
        const m = dm(body.renewal_month, 12); if (body.renewal_month !== undefined) f.renewal_month = m;
        const v = vid(body.vault_entry_id);
        if (v !== undefined) { if (v != null && !this.find('vault', v)) fail(404, 'Voce Vault da collegare non trovata'); f.vault_entry_id = v; }
        return ser(this.touch(r, f));
      });
      if (id && method === 'DELETE') return h.softDelete('accounts');
      fail(404, 'Endpoint non trovato');
    }

    cards(method, id, sub, body, h) {
      const KINDS = ['fedelta', 'regalo'];
      const FORMATS = ['QR', 'CODE128', 'EAN13', 'EAN8', 'UPC', 'CODE39', 'ITF', 'NONE'];
      const amount = (raw) => { if (raw === undefined) return undefined; if (raw === null || raw === '') return null; const n = Number(String(raw).replace(',', '.')); return Number.isFinite(n) ? Math.round(n * 100) / 100 : null; };
      const color = (raw) => (/^#[0-9a-fA-F]{6}$/.test(String(raw || '')) ? raw : '');
      const ser = (r) => { const { pin, ...rest } = r; return { ...rest, hasPin: !!pin }; };
      if (!id && method === 'GET') return this.sorted('cards').map(ser);
      if (!id && method === 'POST') {
        if (!body.name) fail(400, 'Il nome e\' obbligatorio');
        return h.mutate(() => h.created(ser(this.insert('cards', {
          kind: KINDS.includes(body.kind) ? body.kind : 'fedelta', name: body.name, number: String(body.number || '').trim(),
          format: FORMATS.includes(body.format) ? body.format : 'CODE128', color: color(body.color), holder: body.holder || '',
          pin: body.pin ? String(body.pin) : null, balance: amount(body.balance) ?? null, currency: body.currency || 'EUR',
          expiry_date: body.expiry_date || null, notes: body.notes || '', tags: body.tags || [],
        }))));
      }
      if (id && sub === 'restore') return h.restore('cards');
      if (id && sub === 'pin') { const r = this.find('cards', id) || fail(404, 'Carta non trovata'); return { pin: r.pin || '' }; }
      if (id && sub === 'spend') return h.mutate(() => {
        const r = this.find('cards', id) || fail(404, 'Carta non trovata');
        const a = amount(body.amount);
        if (!a || a <= 0) fail(400, 'Importo non valido');
        return ser(this.touch(r, { balance: Math.max(0, Math.round(((r.balance || 0) - a) * 100) / 100) }));
      });
      if (id && method === 'PUT') return h.mutate(() => {
        const r = this.find('cards', id) || fail(404, 'Carta non trovata');
        const f = {};
        ['name', 'holder', 'currency', 'notes', 'tags'].forEach((k) => { if (body[k] !== undefined && body[k] !== null) f[k] = body[k]; });
        if (body.kind && KINDS.includes(body.kind)) f.kind = body.kind;
        if (body.format && FORMATS.includes(body.format)) f.format = body.format;
        if (body.number !== undefined) f.number = String(body.number || '').trim();
        if (body.color !== undefined) f.color = color(body.color);
        if (body.pin === '-') f.pin = null; else if (body.pin) f.pin = String(body.pin);
        const b = amount(body.balance); if (b !== undefined) f.balance = b;
        if (body.expiry_date !== undefined) f.expiry_date = body.expiry_date || null;
        return ser(this.touch(r, f));
      });
      if (id && method === 'DELETE') return h.softDelete('cards');
      fail(404, 'Endpoint non trovato');
    }

    async vault(method, id, sub, body, h) {
      const VALID = ['password', 'note', 'card', 'code'];
      const ser = (r, reveal = false) => {
        const { password, totp_secret, card_cvv, ...rest } = r;
        const out = { ...rest, hasTotp: !!totp_secret };
        if (reveal) { out.password = password; if (card_cvv) out.cvv = card_cvv; }
        return out;
      };
      const cleanTotp = (raw) => { const c = String(raw).replace(/\s/g, ''); try { TOTP.base32Decode(c); } catch (_) { fail(400, 'Segreto TOTP non valido'); } return c.toUpperCase(); };
      if (!id && method === 'GET') return this.sorted('vault').map((r) => ser(r));
      if (id === 'import' && method === 'POST') {
        const file = body instanceof Object && typeof body.get === 'function' ? body.get('file') : null;
        if (!file) fail(400, 'Nessun file caricato');
        const records = parseCsv(await file.text());
        if (!records.length) fail(400, 'Il file CSV e\' vuoto');
        const headers = Object.keys(records[0]);
        const pick = (aliases) => headers.find((x) => aliases.includes(x.trim().toLowerCase()));
        const map = { site: pick(['site', 'name', 'title']), username: pick(['username', 'login', 'email', 'user']), password: pick(['password', 'pass']), url: pick(['url', 'link', 'website']), notes: pick(['notes', 'note', 'comment']) };
        if (!map.site || !map.password) fail(400, 'Non trovo colonne riconoscibili per sito e password. Intestazioni attese: site/name/title, password.');
        let imported = 0, skipped = 0;
        records.forEach((row) => {
          if (!row[map.site] || !row[map.password]) { skipped += 1; return; }
          this.insert('vault', { site: row[map.site], username: map.username ? row[map.username] || '' : '', password: row[map.password], url: map.url ? row[map.url] || '' : '', notes: map.notes ? row[map.notes] || '' : '', tags: ['importato-csv'], type: 'password', totp_secret: null, card_cvv: null, card_expiry: null });
          imported += 1;
        });
        await this.save();
        return { imported, skipped, total: records.length };
      }
      if (id && sub === 'reveal') {
        const r = this.find('vault', id) || fail(404, 'Voce non trovata');
        if (this.hooks.confirmReveal && !(await this.hooks.confirmReveal(r))) fail(403, 'Conferma con impronta non riuscita');
        return ser(r, true);
      }
      if (id && sub === 'totp') {
        const r = this.find('vault', id) || fail(404, 'Voce non trovata');
        if (!r.totp_secret) fail(404, 'Nessun codice configurato per questa voce');
        return { code: await TOTP.codeForStep(r.totp_secret, TOTP.currentStep()), secondsRemaining: 30 - (Math.floor(Date.now() / 1000) % 30) };
      }
      if (!id && method === 'POST') {
        const codeOnly = body.type === 'code' && body.totp_secret;
        if (!body.site || (!body.password && !codeOnly)) fail(400, 'Titolo e contenuto sono obbligatori');
        const totp = body.totp_secret ? cleanTotp(body.totp_secret) : null;
        return h.mutate(() => h.created(ser(this.insert('vault', {
          site: body.site, username: body.username || '', password: body.password || '', url: body.url || '', notes: body.notes || '', tags: body.tags || [],
          type: VALID.includes(body.type) ? body.type : 'password', totp_secret: totp, card_cvv: body.card_cvv || null, card_expiry: body.card_expiry || null,
        }))));
      }
      if (id && sub === 'restore') return h.restore('vault');
      if (id && method === 'PUT') return h.mutate(() => {
        const r = this.find('vault', id) || fail(404, 'Voce non trovata');
        const f = {};
        ['site', 'username', 'url', 'notes', 'tags'].forEach((k) => { if (body[k] !== undefined && body[k] !== null) f[k] = body[k]; });
        if (body.type && VALID.includes(body.type)) f.type = body.type;
        if (body.password) f.password = body.password;
        if (body.totp_secret === '-') f.totp_secret = null;
        else if (body.totp_secret) f.totp_secret = cleanTotp(body.totp_secret);
        if (body.card_cvv) f.card_cvv = body.card_cvv;
        if (body.card_expiry !== undefined) f.card_expiry = body.card_expiry || null;
        return ser(this.touch(r, f));
      });
      if (id && method === 'DELETE') return h.softDelete('vault');
      fail(404, 'Endpoint non trovato');
    }

    async drive(method, id, sub, body, h) {
      if (!id && method === 'GET') return this.live('documents').sort((x, y) => (x.created_at < y.created_at ? 1 : -1));
      if (!id && method === 'POST') {
        const file = body && typeof body.get === 'function' ? body.get('file') : null;
        if (!file) fail(400, 'Nessun file caricato');
        let tags = [];
        try { tags = JSON.parse(body.get('tags') || '[]'); } catch (_) { tags = []; }
        const stored = await this.putFile(new Uint8Array(await file.arrayBuffer()));
        const display = String(body.get('display_name') || '').trim();
        return h.mutate(() => h.created(this.insert('documents', {
          original_name: file.name || 'file', stored_name: stored, folder: body.get('folder') || '', mime: file.type || '', size: file.size || 0,
          expiry_date: body.get('expiry_date') || null, tags, display_name: display || null,
        })));
      }
      if (id && sub === 'restore') return h.restore('documents');
      if (id && method === 'PUT') return h.mutate(() => {
        const r = this.find('documents', id) || fail(404, 'Documento non trovato');
        const f = {};
        if (body.folder !== undefined && body.folder !== null) f.folder = body.folder;
        if (body.tags !== undefined && body.tags !== null) f.tags = body.tags;
        if (body.expiry_date !== undefined) f.expiry_date = body.expiry_date;
        if (body.display_name !== undefined) f.display_name = String(body.display_name || '').trim() || null;
        return this.touch(r, f);
      });
      if (id && method === 'DELETE') return h.softDelete('documents');
      fail(404, 'Endpoint non trovato');
    }

    // Blob del documento per anteprima e scaricamento (l'interfaccia lo apre
    // con un indirizzo blob: invece di /api/drive/:id/view).
    async fileBlob(id, { preview = false } = {}) {
      const { doc, bytes } = await this.fileBytes(id);
      if (preview && !PREVIEWABLE_MIME.has(doc.mime)) fail(415, 'Anteprima non disponibile per questo tipo di file');
      return { blob: new Blob([bytes], { type: doc.mime || 'application/octet-stream' }), name: doc.original_name };
    }

    upcoming(days) {
      const end = new Date(); end.setHours(0, 0, 0, 0); end.setDate(end.getDate() + Math.min(Math.max(days, 0), 3650));
      const endStr = isoLocal(end);
      const out = [];
      this.live('accounts').filter((r) => r.renewal_day != null).forEach((r) => {
        const date = nextOccurrence(r.renewal_day, r.renewal_month, r.billing_frequency);
        if (date <= endStr) out.push({ id: r.id, label: r.service, date, type: 'account' });
      });
      this.live('documents').filter((r) => r.expiry_date && r.expiry_date.slice(0, 10) <= endStr).forEach((r) => out.push({ id: r.id, label: r.display_name || r.original_name, date: r.expiry_date, type: 'document' }));
      this.live('reminders').filter((r) => r.date.slice(0, 10) <= endStr).forEach((r) => out.push({ id: r.id, label: r.label, date: r.date, type: 'reminder' }));
      this.live('projects').filter((r) => r.deadline && r.deadline.slice(0, 10) <= endStr).forEach((r) => out.push({ id: r.id, label: r.title, date: r.deadline, type: 'project' }));
      return out.sort((x, y) => (x.date > y.date ? 1 : -1));
    }
  }

  // Archivio di prova in memoria (test e anteprima nel browser).
  function memoryStorage() {
    const m = new Map();
    return {
      async get(k) { return m.has(k) ? JSON.parse(m.get(k)) : null; },
      async put(k, v) { m.set(k, JSON.stringify(v)); },
      async del(k) { m.delete(k); },
      async keys() { return [...m.keys()]; },
    };
  }

  return { LocalBackend, mergeStates, emptyState, parseCsv, memoryStorage, ARCHIVE_FORMAT, EXPORT_FORMAT, HttpError };
});
