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
  const CLOUD_FORMAT = 'memento-cloud';
  const EXPORT_FORMAT = 'memento-export';
  const TABLES = ['ideas', 'projects', 'reminders', 'accounts', 'vault', 'documents', 'dossiers', 'links', 'cards'];
  const TYPE_TABLE = { idea: 'ideas', project: 'projects', vault: 'vault', account: 'accounts', document: 'documents', reminder: 'reminders', dossier: 'dossiers', card: 'cards' };
  const LABEL = {
    idea: (r) => r.title, project: (r) => r.title, vault: (r) => r.site, account: (r) => r.service,
    document: (r) => r.display_name || r.original_name, dossier: (r) => r.title, reminder: (r) => r.label, card: (r) => r.name,
  };
  const PREVIEWABLE_MIME = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'application/pdf']);

  // Campi che passano da un telefono all'altro (niente id, date interne,
  // condivisioni, collegamenti al Vault o nomi dei file cifrati).
  const TRANSFER_FIELDS = {
    ideas: ['title', 'body', 'tags', 'checklist'],
    projects: ['title', 'description', 'status', 'checklist', 'tags', 'deadline', 'contacts', 'budget'],
    reminders: ['label', 'date', 'time', 'notes'],
    accounts: ['service', 'type', 'email', 'plan', 'location', 'payment_method', 'start_date', 'renewal_day', 'renewal_month', 'installments', 'notes', 'tags', 'billing_frequency', 'amount'],
    vault: ['site', 'username', 'password', 'url', 'notes', 'tags', 'type', 'totp_secret', 'card_cvv', 'card_expiry'],
    cards: ['kind', 'name', 'brand', 'number', 'format', 'color', 'holder', 'pin', 'balance', 'currency', 'expiry_date', 'notes', 'tags', 'photos'],
    documents: ['original_name', 'folder', 'mime', 'expiry_date', 'tags', 'display_name'],
    dossiers: ['title', 'description'],
  };
  const TRANSFER_DEFAULTS = {
    ideas: { title: 'Nota ricevuta', body: '', tags: [], checklist: [] },
    projects: { title: 'Progetto ricevuto', description: '', status: 'da_fare', checklist: [], tags: [], deadline: null, contacts: [], budget: [] },
    reminders: { label: 'Scadenza ricevuta', date: null, time: null, notes: '', notified_at: null },
    accounts: { service: 'Abbonamento ricevuto', type: 'digitale', email: '', plan: '', location: '', payment_method: '', start_date: null, renewal_date: null, renewal_day: null, renewal_month: null, installments: null, notes: '', tags: [], billing_frequency: '', amount: null, vault_entry_id: null },
    vault: { site: 'Voce ricevuta', username: '', password: '', url: '', notes: '', tags: [], type: 'password', totp_secret: null, card_cvv: null, card_expiry: null },
    cards: { kind: 'fedelta', name: 'Carta ricevuta', brand: '', number: '', format: 'CODE128', color: '', holder: '', pin: null, balance: null, currency: 'EUR', expiry_date: null, notes: '', tags: [], photos: [] },
    documents: { original_name: 'file', folder: '', mime: '', size: 0, expiry_date: null, tags: [], display_name: null },
    dossiers: { title: 'Cartella ricevuta', description: '' },
  };
  const TRANSFER_ENUMS = {
    'projects.status': ['da_fare', 'in_corso', 'fatto'],
    'accounts.type': ['digitale', 'cartaceo', 'finanziamento'],
    'vault.type': ['password', 'note', 'card', 'code'],
    'cards.kind': ['fedelta', 'regalo'],
    'cards.format': ['QR', 'CODE128', 'EAN13', 'EAN8', 'UPC', 'CODE39', 'ITF', 'NONE'],
  };
  function pickFields(rec, fields) {
    const out = {};
    fields.forEach((k) => { if (rec[k] !== undefined && rec[k] !== null && rec[k] !== '') out[k] = rec[k]; });
    return out;
  }
  // Solo i campi previsti, con il tipo giusto: il resto prende il valore vuoto.
  function cleanTransferData(t, data) {
    const out = JSON.parse(JSON.stringify(TRANSFER_DEFAULTS[t]));
    TRANSFER_FIELDS[t].forEach((k) => {
      const v = data[k];
      if (v === undefined || v === null) return;
      const def = TRANSFER_DEFAULTS[t][k];
      if (Array.isArray(def)) { if (Array.isArray(v)) out[k] = v; return; }
      const allowed = TRANSFER_ENUMS[`${t}.${k}`];
      if (allowed) { if (allowed.includes(v)) out[k] = v; return; }
      if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') out[k] = v;
    });
    if (t === 'cards') out.photos = out.photos.filter((p) => typeof p === 'string' && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(p)).slice(0, 2);
    if (t === 'reminders' && !out.date) out.date = new Date().toISOString().slice(0, 10);
    return out;
  }
  // Compressione (deflate) dove il motore la offre; altrimenti null.
  async function streamBytes(bytes, Stream) {
    const s = new Blob([bytes]).stream().pipeThrough(new Stream('deflate-raw'));
    return new Uint8Array(await new Response(s).arrayBuffer());
  }
  async function deflate(bytes) {
    if (typeof CompressionStream === 'undefined') return null;
    try { return await streamBytes(bytes, CompressionStream); } catch (_) { return null; }
  }
  async function inflate(bytes) { return streamBytes(bytes, DecompressionStream); }

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
  // Finanziamento: prossima rata (oggi compreso) o null se le rate sono finite;
  // stessa logica di loanNextDate in server/routes/search.js.
  function loanNextDate(startDate, frequency, installments) {
    const start = new Date(`${String(startDate).slice(0, 10)}T00:00:00`);
    if (Number.isNaN(start.getTime()) || !installments) return undefined;
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const stepMonths = { mensile: 1, trimestrale: 3, semestrale: 6, annuale: 12 }[frequency] || 1;
    for (let i = 0; i < installments; i++) {
      let d;
      if (frequency === 'settimanale') { d = new Date(start); d.setDate(d.getDate() + 7 * i); }
      else {
        const total = start.getFullYear() * 12 + start.getMonth() + stepMonths * i;
        const y = Math.floor(total / 12), m = total % 12;
        d = new Date(y, m, Math.min(start.getDate(), new Date(y, m + 1, 0).getDate()));
      }
      if (d >= today) return isoLocal(d);
    }
    return null;
  }
  // Finanziamento senza giorno di addebito: quello della prima rata.
  function renewalFromStart(type, startDate, frequency, day, month) {
    if (type !== 'finanziamento' || day != null || !startDate) return [day, month];
    const d = new Date(`${String(startDate).slice(0, 10)}T00:00:00`);
    if (Number.isNaN(d.getTime())) return [day, month];
    if (frequency === 'settimanale') return [((d.getDay() + 6) % 7) + 1, null];
    if (frequency === 'mensile' || !frequency) return [d.getDate(), null];
    return [d.getDate(), d.getMonth() + 1];
  }
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
    out.settings.contacts = { ...((b.settings || {}).contacts || {}), ...((a.settings || {}).contacts || {}) };
    out.settings.leftShares = [...new Set([...((b.settings || {}).leftShares || []), ...((a.settings || {}).leftShares || [])])];
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

    async unlock(password, code) {
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
      // Verifica in due passaggi: il segreto sta dentro l'archivio cifrato,
      // quindi si controlla dopo la password; senza codice valido si richiude.
      const t = this.state.settings.totp;
      if (t && t.enabled) {
        if (!code) { this.lock(); fail(401, 'Serve il codice di verifica', { totpRequired: true }); }
        if (!(await this.checkSecondFactor(code))) { this.lock(); fail(401, 'Codice non valido', { totpRequired: true }); }
        await this.save();
      }
    }

    // ---------------- Verifica in due passaggi ----------------
    async checkSecondFactor(code) {
      const t = this.state.settings.totp;
      const clean = String(code || '').trim().toLowerCase().replace(/\s/g, '');
      if (/^\d{6}$/.test(clean)) {
        const now = TOTP.currentStep();
        for (const step of [now - 1, now, now + 1]) {
          if (step <= (t.lastStep || 0)) continue;
          if ((await TOTP.codeForStep(t.secret, step)) === clean) { t.lastStep = step; return true; }
        }
        return false;
      }
      const hash = await MC.sha256Hex(clean.replace(/-/g, ''));
      const rc = (t.recovery || []).find((r) => !r.used && r.hash === hash);
      if (rc) { rc.used = true; return true; }
      return false;
    }
    async verifyPassword(password) {
      try { await MC.openWithPassword(await this.storage.get('archive'), password, ARCHIVE_FORMAT); return true; } catch (_) { return false; }
    }
    async newRecoveryCodes() {
      const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
      const codes = [];
      const recovery = [];
      for (let i = 0; i < 10; i++) {
        const bytes = MC.randomBytes(8);
        const raw = [...bytes].map((b) => alphabet[b % alphabet.length]).join('');
        codes.push(raw.slice(0, 4) + '-' + raw.slice(4));
        recovery.push({ hash: await MC.sha256Hex(raw), used: false });
      }
      this.state.settings.totp.recovery = recovery;
      return codes;
    }
    async security(method, id, sub, body) {
      const t = this.state.settings.totp || null;
      if (!id && method === 'GET') {
        return { username: this.state.user.username, totpEnabled: !!(t && t.enabled), recoveryCodesLeft: t && t.enabled ? (t.recovery || []).filter((r) => !r.used).length : 0, local: true };
      }
      if (id === 'totp' && sub === 'setup' && method === 'POST') {
        if (t && t.enabled) fail(400, 'La verifica in due passaggi e\' gia\' attiva');
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        const secret = [...MC.randomBytes(20)].map((b) => alphabet[b % 32]).join('');
        this.state.settings.totp = { secret, enabled: false, lastStep: 0, recovery: [] };
        await this.save();
        const account = encodeURIComponent(this.state.user.username || 'telefono');
        return { qr: '', secret: secret.replace(/(.{4})/g, '$1 ').trim(), otpauth: `otpauth://totp/Memento:${account}?secret=${secret}&issuer=Memento` };
      }
      if (id === 'totp' && sub === 'enable' && method === 'POST') {
        if (!t || !t.secret) fail(400, 'Genera prima il QR da inquadrare');
        if (t.enabled) fail(400, 'La verifica in due passaggi e\' gia\' attiva');
        if (!/^\d{6}$/.test(String(body.code || '').trim()) || !(await this.checkSecondFactor(body.code))) {
          fail(400, 'Codice non valido. Controlla che l\'ora del telefono sia corretta e riprova.');
        }
        t.enabled = true;
        const codes = await this.newRecoveryCodes();
        await this.save();
        return { ok: true, recoveryCodes: codes };
      }
      if (id === 'totp' && sub === 'recovery-codes' && method === 'POST') {
        if (!t || !t.enabled) fail(400, 'La verifica in due passaggi non e\' attiva');
        if (!(await this.verifyPassword(body.password))) fail(403, 'Password non corretta');
        const codes = await this.newRecoveryCodes();
        await this.save();
        return { ok: true, recoveryCodes: codes };
      }
      if (id === 'totp' && sub === 'disable' && method === 'POST') {
        if (!(await this.verifyPassword(body.password))) fail(403, 'Password non corretta');
        delete this.state.settings.totp;
        await this.save();
        return { ok: true };
      }
      fail(404, 'Non disponibile sul telefono');
    }

    // ---------------- Copia sul cloud (Google Drive) ----------------
    // La copia e' cifrata con una chiave ricavata dalla password principale e
    // da un sale che viaggia con la copia: un altro telefono con la stessa
    // password la apre anche se il suo archivio usa un sale diverso. La
    // chiave resta solo dentro l'archivio cifrato di ogni telefono.
    get cloudReady() { return !!(this.state && this.state.settings.cloud && this.state.settings.cloud.key); }
    async setupCloudKey(password, remoteKdf) {
      if (!(await this.verifyPassword(password))) fail(403, 'Password non corretta');
      const salt = remoteKdf ? remoteKdf.salt : MC.toB64(MC.randomBytes(16));
      const iter = remoteKdf ? remoteKdf.iter : MC.ITERATIONS;
      const key = await MC.deriveKey(password, MC.fromB64(salt), iter);
      this.state.settings.cloud = { salt, iter, key: await MC.exportKey(key) };
      await this.save();
    }
    async cloudKey() {
      if (!this.cloudReady) fail(400, 'Copia sul cloud non configurata');
      return MC.importKey(this.state.settings.cloud.key);
    }
    // Stato da caricare: senza la chiave cloud e con l'elenco dei file.
    async cloudEnvelope() {
      const key = await this.cloudKey();
      const { cloud, ...settings } = this.state.settings;
      const state = { ...this.state, settings };
      const files = this.rows('documents').filter((d) => !d.deleted_at && d.stored_name).map((d) => d.stored_name);
      return MC.sealWithKey(CLOUD_FORMAT, key, cloud.salt, cloud.iter, { app: 'memento', savedAt: new Date().toISOString(), state, files });
    }
    // Apre una copia del cloud: con la chiave di questo telefono se il sale
    // coincide, altrimenti serve la password principale (stessa su tutti).
    async openCloudEnvelope(envelope, password) {
      if (!envelope || envelope.format !== CLOUD_FORMAT) fail(400, 'Copia sul cloud non riconosciuta');
      const c = this.state.settings.cloud;
      if (!c || c.salt !== envelope.kdf.salt || c.iter !== envelope.kdf.iter) {
        if (!password) fail(401, 'Serve la password principale', { passwordRequired: true });
        await this.setupCloudKey(password, envelope.kdf);
      }
      try {
        const bytes = await MC.decryptBytes(await this.cloudKey(), envelope.iv, envelope.ct);
        return JSON.parse(new TextDecoder().decode(bytes));
      } catch (_) {
        fail(401, 'La copia sul cloud usa un\'altra password principale', { passwordRequired: true });
      }
    }
    async cloudFile(storedName) {
      const f = await this.storage.get('file:' + storedName);
      if (!f) return null;
      const bytes = await MC.decryptBytes(this.key, f.iv, f.ct);
      return MC.encryptBytes(await this.cloudKey(), bytes);
    }
    async hasFile(storedName) { return !!(await this.storage.get('file:' + storedName)); }
    async importCloudFile(storedName, enc) {
      const bytes = await MC.decryptBytes(await this.cloudKey(), enc.iv, enc.ct);
      await this.storage.put('file:' + storedName, await MC.encryptBytes(this.key, bytes));
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
      // La copia sul cloud segue la nuova password (nuovo sale): gli altri
      // telefoni la chiederanno alla prossima sincronizzazione.
      if (this.state.settings.cloud) {
        const salt = MC.toB64(MC.randomBytes(16));
        const ck = await MC.deriveKey(next, MC.fromB64(salt), MC.ITERATIONS);
        this.state.settings.cloud = { salt, iter: MC.ITERATIONS, key: await MC.exportKey(ck) };
      }
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

      if (res === 'health') return { status: 'ok', version: this.hooks.version || 'app', build: this.hooks.build || '' };
      if (res === 'auth') {
        if (id === 'status') return { setupNeeded: !(await this.hasArchive()), authenticated: this.unlocked, local: true };
        if (id === 'setup' && method === 'POST') { await this.setup(body.username, body.password); return { ok: true }; }
        if (id === 'login' && method === 'POST') { await this.unlock(body.password, body.code); return { ok: true }; }
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
        case 'vault': return this.vault(method, id, sub, body, { mutate, softDelete, restore, created, a3 });
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
          return this.security(method, id, sub, body);
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
      const VALID_TYPES = ['digitale', 'cartaceo', 'finanziamento'];
      const inst = (raw) => { if (raw === undefined) return undefined; if (raw === null || raw === '') return null; const n = parseInt(raw, 10); return Number.isInteger(n) && n >= 1 && n <= 1200 ? n : null; };
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
        const type = VALID_TYPES.includes(body.type) ? body.type : 'digitale';
        const [rd, rm] = renewalFromStart(type, body.start_date, billing, dm(body.renewal_day, billing === 'settimanale' ? 7 : 31) ?? null, dm(body.renewal_month, 12) ?? null);
        return h.mutate(() => h.created(ser(this.insert('accounts', {
          service: body.service, type, email: body.email || '', plan: body.plan || '',
          location: body.location || '', payment_method: body.payment_method || '', start_date: body.start_date || null,
          renewal_date: null, renewal_day: rd, renewal_month: rm, installments: type === 'finanziamento' ? (inst(body.installments) ?? null) : null,
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
        const type = f.type || r.type;
        const n = inst(body.installments);
        f.installments = type !== 'finanziamento' ? null : (n !== undefined ? n : (r.installments ?? null));
        const start = f.start_date !== undefined ? f.start_date : r.start_date;
        const [rd, rm] = renewalFromStart(type, start, billing, f.renewal_day !== undefined ? f.renewal_day : r.renewal_day, f.renewal_month !== undefined ? f.renewal_month : r.renewal_month);
        f.renewal_day = rd; f.renewal_month = rm;
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
      const brand = (raw) => (/^[a-z0-9-]{1,60}$/.test(String(raw || '')) ? raw : '');
      const ser = (r, withPhotos = false) => {
        const { pin, photos, ...rest } = r;
        const out = { ...rest, hasPin: !!pin, photoCount: (photos || []).length };
        if (withPhotos) out.photos = (photos || []).slice();
        return out;
      };
      const cleanPhotos = (raw) => (Array.isArray(raw) ? raw.filter((p) => typeof p === 'string' && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(p) && p.length <= 900000).slice(0, 2) : undefined);
      if (!id && method === 'GET') return this.sorted('cards').map((r) => ser(r));
      if (id && !sub && method === 'GET') return ser(this.find('cards', id) || fail(404, 'Carta non trovata'), true);
      if (!id && method === 'POST') {
        if (!body.name) fail(400, 'Il nome e\' obbligatorio');
        return h.mutate(() => h.created(ser(this.insert('cards', {
          kind: KINDS.includes(body.kind) ? body.kind : 'fedelta', name: body.name, brand: brand(body.brand), number: String(body.number || '').trim(),
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
        if (body.brand !== undefined) f.brand = brand(body.brand);
        const ph = cleanPhotos(body.photos); if (ph !== undefined) f.photos = ph;
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
        const { password, totp_secret, card_cvv, share, ...rest } = r;
        const out = { ...rest, hasTotp: !!totp_secret };
        if (share) {
          out.share = { owner: share.owner, role: share.role, members: share.members.map(({ email, role }) => ({ email, role })), pending: (share.pending || []).slice() };
        }
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
      if (id && sub === 'share') return this.vaultShare(method, id, h.a3, body, ser);
      if (id && sub === 'restore') return h.restore('vault');
      if (id && method === 'PUT') return h.mutate(() => {
        const r = this.find('vault', id) || fail(404, 'Voce non trovata');
        if (r.share && r.share.role === 'reader') fail(403, 'Voce condivisa in sola visualizzazione');
        if (r.share) r.share.dirty = true;
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
      if (id && method === 'DELETE') {
        const r = this.find('vault', id);
        // Voce ricevuta: si toglie solo dal proprio vault e non torna piu'.
        if (r && r.share && r.share.owner !== this.myEmail()) {
          this.state.settings.leftShares = [...(this.state.settings.leftShares || []), r.share.id];
          this.state.tables.vault = this.rows('vault').filter((x) => x !== r);
          await this.save();
          return undefined;
        }
        if (r && r.share) r.share.dirty = true;
        return h.softDelete('vault');
      }
      fail(404, 'Endpoint non trovato');
    }

    // ---------------- Condivisione di voci del vault ----------------
    // La voce condivisa e' un file cifrato con una chiave sua (share.key),
    // a sua volta cifrata per la chiave pubblica di ogni persona (owner
    // compreso, per i suoi altri telefoni). Il trasporto (Google Drive) sta in
    // native.js: qui solo dati e cifratura, cosi' si prova tutto nei test.
    myEmail() { return ((this.state.settings.identity || {}).email || '').toLowerCase(); }
    async ensureIdentity(email) {
      let ident = this.state.settings.identity;
      const clean = String(email || '').trim().toLowerCase();
      if (!ident) {
        ident = { email: clean, ...(await MC.generateIdentity()) };
        this.state.settings.identity = ident;
        await this.save();
      } else if (clean && ident.email !== clean) {
        ident.email = clean;
        await this.save();
      }
      return { email: ident.email, publicJwk: ident.publicJwk };
    }
    async learnContact(email, publicJwk) {
      const clean = String(email || '').trim().toLowerCase();
      if (!clean || !publicJwk) return;
      const contacts = this.state.settings.contacts || {};
      if (JSON.stringify(contacts[clean]) === JSON.stringify(publicJwk)) return;
      contacts[clean] = publicJwk;
      this.state.settings.contacts = contacts;
      // Le voci in attesa di questa persona vanno riscritte con la sua chiave.
      this.rows('vault').forEach((r) => { if (r.share && (r.share.pending || []).includes(clean)) r.share.dirty = true; });
      await this.save();
    }
    async vaultShare(method, id, email, body, ser) {
      const r = this.find('vault', id) || fail(404, 'Voce non trovata');
      const me = this.myEmail();
      if (!me) fail(400, 'Collega Google Drive nelle Impostazioni per condividere');
      if (r.share && r.share.role !== 'owner') fail(403, 'Solo chi ha creato la voce puo\' condividerla');
      if (method === 'POST') {
        const who = String(body.email || '').trim().toLowerCase();
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(who)) fail(400, 'Indirizzo email non valido');
        if (who === me) fail(400, 'E\' il tuo indirizzo');
        const role = body.role === 'writer' ? 'writer' : 'reader';
        if (!r.share) r.share = { id: [...MC.randomBytes(16)].map((b) => b.toString(16).padStart(2, '0')).join(''), owner: me, role: 'owner', members: [], key: MC.toB64(MC.randomBytes(32)), fileId: null, removed: [], pending: [] };
        const existing = r.share.members.find((m) => m.email === who);
        if (existing) existing.role = role; else r.share.members.push({ email: who, role });
        r.share.removed = (r.share.removed || []).filter((x) => x !== who);
        r.share.dirty = true;
        this.touch(r);
        await this.save();
        return ser(r);
      }
      if (method === 'DELETE') {
        const who = String(email || '').toLowerCase();
        if (!r.share) fail(404, 'Voce non condivisa');
        r.share.members = r.share.members.filter((m) => m.email !== who);
        r.share.removed = [...new Set([...(r.share.removed || []), who])];
        // Chiave nuova: chi e' stato tolto non legge le versioni successive.
        r.share.key = MC.toB64(MC.randomBytes(32));
        r.share.dirty = true;
        this.touch(r);
        await this.save();
        return ser(r);
      }
      fail(404, 'Endpoint non trovato');
    }
    // File da scrivere su Drive: voci condivise modificate (o in attesa).
    async shareOutbox() {
      const me = this.myEmail();
      const ident = this.state.settings.identity;
      const contacts = this.state.settings.contacts || {};
      const out = [];
      for (const r of this.rows('vault')) {
        const sh = r.share;
        if (!sh || !sh.dirty || sh.role === 'reader') continue;
        const key = await MC.importKey(sh.key);
        const fields = {};
        ['site', 'username', 'password', 'url', 'notes', 'tags', 'type', 'totp_secret', 'card_cvv', 'card_expiry', 'deleted_at'].forEach((k) => { fields[k] = r[k] === undefined ? null : r[k]; });
        const { iv, ct } = await MC.encryptBytes(key, new TextEncoder().encode(JSON.stringify(fields)));
        let members = [];
        const pending = [];
        if (sh.owner !== me) {
          // Chi modifica senza esserne il proprietario non ha le chiavi
          // pubbliche degli altri: riusa quelle gia' cifrate nel file.
          members = sh.wraps || [];
        } else for (const m of [{ email: sh.owner, role: 'owner' }, ...sh.members]) {
          const pub = m.email === me ? ident.publicJwk : contacts[m.email];
          if (!pub) pending.push(m.email);
          members.push({ email: m.email, role: m.role, wrapped: pub ? await MC.wrapFor(pub, MC.fromB64(sh.key)) : null });
        }
        out.push({
          entryId: r.id, fileId: sh.fileId || null, owner: sh.owner, isOwner: sh.owner === me,
          members: sh.members.slice(), removed: (sh.removed || []).slice(), pending,
          file: { format: 'memento-share', v: 1, id: sh.id, owner: sh.owner, rev: r._rev || Date.now(), members, iv, ct },
        });
      }
      return out;
    }
    async markShared(entryId, fileId, pending) {
      const r = this.rows('vault').find((x) => String(x.id) === String(entryId));
      if (!r || !r.share) return;
      r.share.fileId = fileId;
      r.share.removed = [];
      r.share.pending = pending || [];
      r.share.dirty = (pending || []).length > 0;
      await this.save();
    }
    // File letto da Drive: crea o aggiorna la voce. 'pending' = la nostra
    // chiave pubblica non e' ancora arrivata a chi condivide.
    async applyShareFile(file, fileId) {
      const me = this.myEmail();
      if (!me) return { status: 'no-identity' };
      if (!file || file.format !== 'memento-share') return { status: 'invalid' };
      if ((this.state.settings.leftShares || []).includes(file.id)) return { status: 'left' };
      const mine = (file.members || []).find((m) => m.email === me);
      if (!mine) return { status: 'not-member' };
      if (!mine.wrapped) return { status: 'pending', owner: file.owner };
      const raw = await MC.unwrapWith(this.state.settings.identity.privateJwk, mine.wrapped);
      const key = await MC.importKey(MC.toB64(raw));
      const fields = JSON.parse(new TextDecoder().decode(await MC.decryptBytes(key, file.iv, file.ct)));
      let rec = this.rows('vault').find((x) => x.share && x.share.id === file.id);
      const shareMeta = (old) => ({
        id: file.id, owner: file.owner, role: mine.role, key: MC.toB64(raw), fileId,
        members: file.members.filter((m) => m.email !== file.owner).map(({ email, role }) => ({ email, role })),
        removed: [], dirty: old ? old.dirty : false,
        pending: file.members.filter((m) => !m.wrapped).map((m) => m.email),
        wraps: file.members,
      });
      if (rec && (rec._rev || 0) >= file.rev) {
        // Il proprietario tiene la sua condivisione (puo' aver appena cambiato
        // persone o chiave); agli altri si aggiornano persone e permessi.
        if (mine.role === 'owner' && rec.share) rec.share.fileId = rec.share.fileId || fileId;
        else rec.share = { ...shareMeta(rec.share), dirty: rec.share ? rec.share.dirty : false };
        await this.save();
        return { status: 'current' };
      }
      if (rec && mine.role === 'owner' && rec.share && rec.share.dirty) {
        // Versione del file piu' recente ma modifiche locali non ancora
        // caricate: si prende il contenuto, la condivisione resta quella locale.
        Object.assign(rec, fields);
        rec._rev = file.rev;
        await this.save();
        return { status: 'ok' };
      }
      if (!rec) {
        rec = this.insert('vault', { ...fields });
      } else {
        Object.assign(rec, fields);
      }
      rec._rev = file.rev;
      rec.updated_at = sqlNow();
      rec.share = shareMeta(null);
      await this.save();
      return { status: 'ok' };
    }
    // ---------------- Passaggio diretto tra telefoni ----------------
    // Chi riceve mostra il suo QR (nome, chiave pubblica e, se c'e', l'indirizzo
    // PeerJS su cui aspetta). Chi passa cifra l'elemento per quella chiave e lo
    // manda direttamente (WebRTC), oppure con un secondo QR o un file .memento.
    // Il contenuto e' leggibile solo dal telefono di chi riceve.
    // Nome con cui il telefono si presenta a chi riceve o passa un elemento.
    identityName() { return (this.state.settings.identity && this.state.settings.identity.name) || ''; }
    async setIdentityName(name) {
      if (!this.state.settings.identity) await this.ensureIdentity('');
      this.state.settings.identity.name = String(name || '').trim().slice(0, 60);
      await this.save();
    }
    identityLabel() {
      const ident = this.state.settings.identity;
      return (ident && (ident.name || ident.email)) || 'Memento';
    }
    async identityQr(peerId) {
      if (!this.state.settings.identity) await this.ensureIdentity('');
      const raw = await MC.publicJwkToRaw(this.state.settings.identity.publicJwk);
      const label = encodeURIComponent(this.identityLabel());
      return peerId ? `MEMENTO-ID2:${raw}:${label}:${peerId}` : `MEMENTO-ID1:${raw}:${label}`;
    }
    async readIdentityQr(text) {
      const m = String(text || '').match(/^MEMENTO-ID[12]:([A-Za-z0-9+/=]+):([^:]*)(?::([A-Za-z0-9_-]{8,64}))?$/);
      if (!m) fail(400, 'Non e\' il codice di un telefono Memento');
      const label = decodeURIComponent(m[2]) || 'Memento';
      const publicJwk = await MC.rawToPublicJwk(m[1]);
      // Chiave scambiata di persona: vale anche come contatto verificato.
      if (/^[^@\s]+@[^@\s]+$/.test(label)) await this.learnContact(label, publicJwk);
      return { label, publicJwk, peer: m[3] || null };
    }
    // Pacchetto in chiaro: l'elemento e, per una cartella, cio' che contiene.
    async transferPackage(type, id) {
      const t = TYPE_TABLE[type];
      if (!t) fail(400, 'Tipo non valido');
      const rec = this.find(t, id) || fail(404, 'Elemento non trovato');
      const items = [];
      const add = async (itemType, r) => {
        const entry = { type: itemType, data: pickFields(r, TRANSFER_FIELDS[TYPE_TABLE[itemType]]) };
        if (itemType === 'document') entry.file = MC.toB64((await this.fileBytes(r.id)).bytes);
        items.push(entry);
      };
      await add(type, rec);
      if (type === 'dossier') {
        for (const l of this.rows('links')) {
          if (l.deleted_at || String(l.dossier_id) !== String(rec.id) || l.item_type === 'dossier') continue;
          const item = TYPE_TABLE[l.item_type] && this.find(TYPE_TABLE[l.item_type], l.item_id);
          if (item) { try { await add(l.item_type, item); } catch (_) { /* file mancante: si passa il resto */ } }
        }
      }
      return { v: 2, items };
    }
    // Busta cifrata per chi riceve (stringhe base64, va bene per QR, file e WebRTC).
    async sealTransfer(type, id, recipient) {
      const pkg = await this.transferPackage(type, id);
      const plain = new TextEncoder().encode(JSON.stringify(pkg));
      const packed = await deflate(plain);
      const key = MC.randomBytes(32);
      const { iv, ct } = await MC.encryptBytes(await MC.importKey(MC.toB64(key)), packed || plain);
      const w = await MC.wrapFor(recipient.publicJwk, key);
      return { format: 'memento-transfer', v: 2, from: this.identityLabel(), epk: await MC.publicJwkToRaw(w.epk), wiv: w.iv, wct: w.ct, iv, ct, z: packed ? 1 : 0, items: pkg.items.length };
    }
    // Testo del QR, o null se l'elemento e' troppo grande per un QR.
    transferQrText(sealed) {
      const text = `MEMENTO-V2:${[encodeURIComponent(sealed.from), sealed.epk, sealed.wiv, sealed.wct, sealed.iv, sealed.ct, sealed.z].join('|')}`;
      return text.length > 2600 ? null : text;
    }
    // Compatibilita': QR di una voce del Vault (come nelle versioni precedenti).
    async transferQr(entryId, recipient) {
      const text = this.transferQrText(await this.sealTransfer('vault', entryId, recipient));
      if (!text) fail(413, 'Voce troppo lunga per un QR: usa l\'esportazione');
      return text;
    }
    // Accetta il testo di un QR (V1 o V2), il contenuto di un file .memento o
    // la busta arrivata via WebRTC. Crea gli elementi e dice cosa e' arrivato.
    async receiveTransfer(input) {
      let env = input;
      if (typeof input === 'string') {
        const s = input.trim();
        if (s.startsWith('MEMENTO-V1:')) return this.receiveTransferV1(s);
        const m = s.match(/^MEMENTO-V2:(.*)$/);
        if (m) {
          const [from, epk, wiv, wct, iv, ct, z] = m[1].split('|');
          env = { from: decodeURIComponent(from || ''), epk, wiv, wct, iv, ct, z: Number(z) || 0 };
        } else {
          try { env = JSON.parse(s); } catch (_) { fail(400, 'Non e\' il codice di un elemento Memento'); }
        }
      }
      if (!env || typeof env !== 'object' || !env.epk || !env.ct) fail(400, 'Non e\' il codice di un elemento Memento');
      if (!this.state.settings.identity) fail(400, 'Mostra prima il tuo codice a chi ti passa l\'elemento');
      let pkg;
      try {
        const key = await MC.unwrapWith(this.state.settings.identity.privateJwk, { epk: await MC.rawToPublicJwk(env.epk), iv: env.wiv, ct: env.wct });
        let bytes = await MC.decryptBytes(await MC.importKey(MC.toB64(key)), env.iv, env.ct);
        if (env.z) bytes = await inflate(bytes);
        pkg = JSON.parse(new TextDecoder().decode(bytes));
      } catch (_) {
        fail(400, 'Questo codice e\' stato preparato per un altro telefono');
      }
      return this.importTransfer(pkg, String(env.from || 'Memento').slice(0, 60));
    }
    async importTransfer(pkg, from) {
      const items = pkg && Array.isArray(pkg.items) ? pkg.items : [];
      const made = [];
      let dossier = null;
      for (let i = 0; i < items.length; i++) {
        const it = items[i] || {};
        const t = TYPE_TABLE[it.type];
        if (!t || (it.type === 'dossier' && i > 0)) continue;
        const data = cleanTransferData(t, it.data || {});
        if (it.type === 'document') {
          if (typeof it.file !== 'string') continue;
          const bytes = MC.fromB64(it.file);
          data.stored_name = await this.putFile(bytes);
          data.size = bytes.length;
        }
        const rec = this.insert(t, data);
        if (i === 0 && it.type === 'dossier') dossier = rec;
        else if (dossier) this.insert('links', { dossier_id: dossier.id, item_type: it.type, item_id: rec.id });
        made.push({ type: it.type, id: rec.id, label: LABEL[it.type](rec) });
      }
      if (!made.length) fail(400, 'Il codice non contiene elementi');
      await this.save();
      return { ...made[0], site: made[0].label, from, count: made.length };
    }
    async receiveTransferV1(text) {
      const [from, epk, wiv, wct, iv, ct] = text.slice('MEMENTO-V1:'.length).split('|').map(decodeURIComponent);
      if (!this.state.settings.identity) fail(400, 'Mostra prima il tuo codice a chi ti passa la voce');
      let fields;
      try {
        const key = await MC.unwrapWith(this.state.settings.identity.privateJwk, { epk: await MC.rawToPublicJwk(epk), iv: wiv, ct: wct });
        fields = JSON.parse(new TextDecoder().decode(await MC.decryptBytes(await MC.importKey(MC.toB64(key)), iv, ct)));
      } catch (_) {
        fail(400, 'Questo codice e\' stato preparato per un altro telefono');
      }
      return this.importTransfer({ items: [{ type: 'vault', data: fields }] }, from);
    }
    // Vecchio nome, usato dall'interfaccia delle versioni precedenti.
    receiveTransferQr(text) { return this.receiveTransfer(text); }

    // Voci ricevute che non sono piu' accessibili (condivisione tolta).
    async dropMissingShares(accessibleIds) {
      const me = this.myEmail();
      const keep = new Set(accessibleIds);
      const before = this.rows('vault').length;
      this.state.tables.vault = this.rows('vault').filter((r) => !(r.share && r.share.owner !== me && !keep.has(r.share.id)));
      if (this.rows('vault').length !== before) await this.save();
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
      this.live('accounts').forEach((r) => {
        const loan = r.type === 'finanziamento' && r.installments && r.start_date ? loanNextDate(r.start_date, r.billing_frequency, r.installments) : undefined;
        const date = loan !== undefined ? loan : (r.renewal_day != null ? nextOccurrence(r.renewal_day, r.renewal_month, r.billing_frequency) : null);
        if (date && date <= endStr) out.push({ id: r.id, label: r.service, date, type: 'account' });
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

  return { LocalBackend, mergeStates, emptyState, parseCsv, memoryStorage, ARCHIVE_FORMAT, EXPORT_FORMAT, CLOUD_FORMAT, HttpError };
});
