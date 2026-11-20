'use strict';
// Funzioni del telefono per l'app Android: notifiche delle scadenze,
// impronta (sblocco e conferma del vault), sincronizzazione con Google
// Drive. Ognuna degrada senza errori se il plugin non c'e' (browser, test).
(function () {
  const Cap = window.Capacitor;
  const plugin = (name) => (Cap && Cap.Plugins && Cap.Plugins[name]) || null;
  const tr = (k, p) => window.MementoI18n.t(k, p);
  const pref = (key, def) => { try { return { ...def, ...JSON.parse(localStorage.getItem(key) || '{}') }; } catch (_) { return { ...def }; } };
  const setPref = (key, value) => localStorage.setItem(key, JSON.stringify(value));
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const json = async (be, path) => { const r = await be.request(path, {}); if (!r.ok) throw new Error('richiesta non riuscita'); return r.json(); };

  // ==================================================================
  // NOTIFICHE DELLE SCADENZE (notifiche locali, funzionano senza rete)
  // ==================================================================
  const NOTIFY_KEY = 'memento-notify';
  const Notify = {
    available: () => !!plugin('LocalNotifications'),
    settings: () => pref(NOTIFY_KEY, { on: false, hour: 9 }),
    async enable(on) {
      const LN = plugin('LocalNotifications');
      if (on && LN) {
        const perm = await LN.requestPermissions();
        if (perm.display !== 'granted') throw new Error(tr('notify_denied'));
      }
      setPref(NOTIFY_KEY, { ...Notify.settings(), on });
      if (!on && LN) await Notify.clear();
    },
    setHour(hour) { setPref(NOTIFY_KEY, { ...Notify.settings(), hour }); },
    async clear() {
      const LN = plugin('LocalNotifications');
      if (!LN) return;
      const pending = await LN.getPending();
      if (pending.notifications.length) await LN.cancel({ notifications: pending.notifications.map((n) => ({ id: n.id })) });
    },
    // Riprogramma tutto: le scadenze dei prossimi 60 giorni (promemoria con
    // la loro ora, il resto all'ora scelta), una notifica per voce.
    async reschedule(be) {
      const LN = plugin('LocalNotifications');
      const s = Notify.settings();
      if (!LN || !s.on) return;
      let upcoming, reminders;
      try {
        [upcoming, reminders] = await Promise.all([json(be, '/search/reminders/upcoming?days=60'), json(be, '/reminders')]);
      } catch (_) { return; } // bloccata o senza rete: si riprova alla prossima modifica
      const times = new Map(reminders.map((r) => [String(r.id), r.time]));
      const typeLabel = { reminder: tr('type_reminder'), account: tr('type_account'), document: tr('type_document'), project: tr('type_project') };
      const now = Date.now();
      const notifications = [];
      let hidden = [];
      try { hidden = JSON.parse(localStorage.getItem('memento-hidden-sections') || '[]'); } catch (_) { hidden = []; }
      const viewOf = { project: 'projects', account: 'accounts', document: 'drive' };
      upcoming.filter((x) => !hidden.includes(viewOf[x.type])).forEach((x) => {
        const time = x.type === 'reminder' && times.get(String(x.id)) ? times.get(String(x.id)).slice(0, 5) : `${String(s.hour).padStart(2, '0')}:00`;
        const at = new Date(`${String(x.date).slice(0, 10)}T${time}:00`);
        if (isNaN(at) || at.getTime() <= now) return;
        let h = 0;
        for (const ch of `${x.type}:${x.id}:${x.date}`) h = (h * 31 + ch.charCodeAt(0)) | 0;
        const title = x.type === 'account' ? tr('today_renewal_of', { name: x.label }) : x.label;
        notifications.push({ id: Math.abs(h) % 2147483000 + 1, title, body: typeLabel[x.type] || '', schedule: { at, allowWhileIdle: true }, extra: { type: x.type, id: x.id } });
      });
      notifications.sort((a, b) => a.schedule.at - b.schedule.at);
      await Notify.clear();
      if (notifications.length) await LN.schedule({ notifications: notifications.slice(0, 60) });
    },
  };

  // ==================================================================
  // IMPRONTA
  // ==================================================================
  const BIO_KEY = 'memento-bio';
  const BIO_SERVER = 'io.github.katergaris.memento';
  const Bio = {
    settings: () => pref(BIO_KEY, { unlock: false, vault: false }),
    async available() {
      const NB = plugin('NativeBiometric');
      if (!NB) return false;
      try { return !!(await NB.isAvailable()).isAvailable; } catch (_) { return false; }
    },
    async verify(reason) {
      const NB = plugin('NativeBiometric');
      if (!NB) return true;
      try {
        await NB.verifyIdentity({ title: 'Memento', reason, subtitle: reason, negativeButtonText: tr('btn_cancel') });
        return true;
      } catch (_) { return false; }
    },
    // Sblocco: la chiave dell'archivio sta nel portachiavi di Android.
    async enableUnlock(engine) {
      if (!(await Bio.verify(tr('bio_enable_reason')))) throw new Error(tr('bio_failed'));
      await plugin('NativeBiometric').setCredentials({ username: 'memento', password: await engine.exportRawKey(), server: BIO_SERVER });
      setPref(BIO_KEY, { ...Bio.settings(), unlock: true });
    },
    async disableUnlock() {
      try { await plugin('NativeBiometric').deleteCredentials({ server: BIO_SERVER }); } catch (_) { /* gia' assente */ }
      setPref(BIO_KEY, { ...Bio.settings(), unlock: false });
    },
    async refreshKey(engine) {
      if (!Bio.settings().unlock || !plugin('NativeBiometric')) return;
      await plugin('NativeBiometric').setCredentials({ username: 'memento', password: await engine.exportRawKey(), server: BIO_SERVER });
    },
    async unlock(engine) {
      if (!(await Bio.verify(tr('bio_unlock_reason')))) return false;
      const cred = await plugin('NativeBiometric').getCredentials({ server: BIO_SERVER });
      await engine.unlockWithKey(cred.password);
      return true;
    },
    setVault(on) { setPref(BIO_KEY, { ...Bio.settings(), vault: on }); },
    async confirmVault() { return !Bio.settings().vault || Bio.verify(tr('bio_vault_reason')); },
  };

  // ==================================================================
  // SINCRONIZZAZIONE CON GOOGLE DRIVE (cartella privata dell'app)
  // ==================================================================
  const SYNC_KEY = 'memento-sync';
  const DRIVE = 'https://www.googleapis.com/drive/v3';
  const UPLOAD = 'https://www.googleapis.com/upload/drive/v3';
  const MAIN_FILE = 'memento-cloud.json';
  let token = null, tokenUntil = 0, initialized = false, running = null;

  const Sync = {
    clientId: () => (window.MEMENTO_CONFIG && window.MEMENTO_CONFIG.googleWebClientId) || '',
    configured: () => !!(Sync.clientId() && plugin('SocialLogin')),
    settings: () => pref(SYNC_KEY, { on: false, last: null, error: '' }),
    async token(interactive = true) {
      if (token && Date.now() < tokenUntil) return token;
      if (!interactive) return null;
      const SL = plugin('SocialLogin');
      if (!initialized) { await SL.initialize({ google: { webClientId: Sync.clientId() } }); initialized = true; }
      // drive.appdata: copia privata; drive: voci condivise con altre persone.
      const res = await SL.login({ provider: 'google', options: { scopes: ['https://www.googleapis.com/auth/drive.appdata', 'https://www.googleapis.com/auth/drive'] } });
      const t = res && res.result && res.result.accessToken && res.result.accessToken.token;
      if (!t) throw new Error(tr('sync_no_token'));
      const email = res.result.profile && res.result.profile.email;
      if (email) setPref(SYNC_KEY, { ...Sync.settings(), email: email.toLowerCase() });
      token = t; tokenUntil = Date.now() + 50 * 60 * 1000;
      return token;
    },
    async api(method, url, { body, type } = {}) {
      const t = await Sync.token();
      const res = await fetch(url, { method, headers: { Authorization: `Bearer ${t}`, ...(type ? { 'Content-Type': type } : {}) }, body });
      if (res.status === 401) { token = null; throw new Error(tr('sync_auth_expired')); }
      if (!res.ok) throw new Error(`Google Drive: ${res.status}`);
      return res;
    },
    async find(name) {
      const q = encodeURIComponent(`name = '${name}'`);
      const res = await Sync.api('GET', `${DRIVE}/files?spaces=appDataFolder&q=${q}&fields=files(id,name)`);
      const files = (await res.json()).files || [];
      return files[0] || null;
    },
    async listFiles() {
      const out = new Map();
      let page = '';
      do {
        const res = await Sync.api('GET', `${DRIVE}/files?spaces=appDataFolder&pageSize=1000&fields=nextPageToken,files(id,name)${page ? `&pageToken=${page}` : ''}`);
        const data = await res.json();
        (data.files || []).forEach((f) => out.set(f.name, f.id));
        page = data.nextPageToken || '';
      } while (page);
      return out;
    },
    async download(id) { return (await Sync.api('GET', `${DRIVE}/files/${id}?alt=media`)).json(); },
    async query(q, fields = 'files(id,name)') {
      const out = [];
      let page = '';
      do {
        const res = await Sync.api('GET', `${DRIVE}/files?q=${encodeURIComponent(q)}&pageSize=1000&fields=nextPageToken,${encodeURIComponent(fields)}${page ? `&pageToken=${page}` : ''}`);
        const data = await res.json();
        out.push(...(data.files || []));
        page = data.nextPageToken || '';
      } while (page);
      return out;
    },
    // inAppData=false: file nel Drive normale (servono per condividere).
    async upload(name, value, id, inAppData = true) {
      const content = JSON.stringify(value);
      if (id) { await Sync.api('PATCH', `${UPLOAD}/files/${id}?uploadType=media`, { body: content, type: 'application/json' }); return id; }
      const boundary = 'memento' + Math.random().toString(36).slice(2);
      const meta = inAppData ? { name, parents: ['appDataFolder'] } : { name, mimeType: 'application/json' };
      const body = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(meta)}\r\n--${boundary}\r\nContent-Type: application/json\r\n\r\n${content}\r\n--${boundary}--`;
      const res = await Sync.api('POST', `${UPLOAD}/files?uploadType=multipart&fields=id`, { body, type: `multipart/related; boundary=${boundary}` });
      return (await res.json()).id;
    },
    // Scarica la copia, la unisce voce per voce, ricarica la versione unita.
    // password serve solo la prima volta su un telefono (o dopo un cambio).
    async run(engine, password) {
      if (running) return running;
      running = (async () => {
        const files = await Sync.listFiles();
        const mainId = files.get(MAIN_FILE) || null;
        let remoteFiles = [];
        if (mainId) {
          const payload = await engine.openCloudEnvelope(await Sync.download(mainId), password);
          await engine.mergeRemote(payload.state);
          remoteFiles = payload.files || [];
          for (const name of remoteFiles) {
            if (await engine.hasFile(name)) continue;
            const fid = files.get(`file-${name}.json`);
            if (fid) await engine.importCloudFile(name, await Sync.download(fid));
          }
        } else if (!engine.cloudReady) {
          if (!password) { const e = new Error(tr('sync_need_password')); e.passwordRequired = true; throw e; }
          await engine.setupCloudKey(password);
        }
        const envelope = await engine.cloudEnvelope();
        for (const d of engine.rows('documents')) {
          if (d.deleted_at || !d.stored_name || files.has(`file-${d.stored_name}.json`)) continue;
          const enc = await engine.cloudFile(d.stored_name);
          if (enc) await Sync.upload(`file-${d.stored_name}.json`, enc);
        }
        await Sync.upload(MAIN_FILE, envelope, mainId);
        await Sync.runShares(engine);
        setPref(SYNC_KEY, { ...Sync.settings(), on: true, last: new Date().toISOString(), error: '' });
      })();
      try { return await running; } catch (e) {
        if (!e.passwordRequired && !(e.data && e.data.passwordRequired)) setPref(SYNC_KEY, { ...Sync.settings(), error: e.message });
        throw e;
      } finally { running = null; }
    },
    // Voci del vault condivise: chiave pubblica di ciascuno in un file
    // memento-identity.json, ogni voce in un file memento-share-<id>.json
    // condiviso su Drive con le persone (lettura o modifica).
    async grant(fileId, email, role, notify) {
      const perms = (await (await Sync.api('GET', `${DRIVE}/files/${fileId}/permissions?fields=permissions(id,emailAddress,role)`)).json()).permissions || [];
      const has = perms.find((p) => (p.emailAddress || '').toLowerCase() === email);
      if (has) {
        if (has.role !== role && has.role !== 'owner') await Sync.api('PATCH', `${DRIVE}/files/${fileId}/permissions/${has.id}`, { body: JSON.stringify({ role }), type: 'application/json' });
        return;
      }
      const qs = notify ? `sendNotificationEmail=true&emailMessage=${encodeURIComponent(tr('share_email_message'))}` : 'sendNotificationEmail=false';
      await Sync.api('POST', `${DRIVE}/files/${fileId}/permissions?${qs}`, { body: JSON.stringify({ type: 'user', role, emailAddress: email }), type: 'application/json' });
    },
    async revoke(fileId, email) {
      const perms = (await (await Sync.api('GET', `${DRIVE}/files/${fileId}/permissions?fields=permissions(id,emailAddress,role)`)).json()).permissions || [];
      const has = perms.find((p) => (p.emailAddress || '').toLowerCase() === email && p.role !== 'owner');
      if (has) await Sync.api('DELETE', `${DRIVE}/files/${fileId}/permissions/${has.id}`);
    },
    async runShares(engine) {
      const email = Sync.settings().email;
      if (!email) return;
      const ident = await engine.ensureIdentity(email);
      const mine = await Sync.query("name = 'memento-identity.json' and 'me' in owners and trashed = false");
      const identityId = await Sync.upload('memento-identity.json', { email, publicJwk: ident.publicJwk }, mine[0] && mine[0].id, false);
      for (const f of await Sync.query("name = 'memento-identity.json' and not 'me' in owners and trashed = false", 'files(id,owners(emailAddress))')) {
        const owner = ((f.owners || [])[0] || {}).emailAddress;
        const c = await Sync.download(f.id);
        if (owner && c && String(c.email).toLowerCase() === owner.toLowerCase()) await engine.learnContact(owner, c.publicJwk);
      }
      const ids = [];
      for (const f of await Sync.query("name contains 'memento-share-' and trashed = false")) {
        const c = await Sync.download(f.id);
        if (!c || !c.id) continue;
        ids.push(c.id);
        const res = await engine.applyShareFile(c, f.id);
        // In attesa della nostra chiave: la si rende leggibile a chi condivide.
        if (res.status === 'pending' && res.owner) await Sync.grant(identityId, res.owner.toLowerCase(), 'reader', false);
      }
      await engine.dropMissingShares(ids);
      for (const o of await engine.shareOutbox()) {
        const fileId = await Sync.upload(`memento-share-${o.file.id}.json`, o.file, o.fileId, false);
        if (o.isOwner) {
          for (const m of o.members) await Sync.grant(fileId, m.email, m.role === 'writer' ? 'writer' : 'reader', true);
          for (const gone of o.removed) await Sync.revoke(fileId, gone);
        }
        await engine.markShared(o.entryId, fileId, o.pending);
      }
    },

    // Sincronizzazione automatica: solo se gia' collegata e con un accesso
    // Google ancora valido (niente finestre inattese mentre si lavora).
    async auto(engine) {
      if (!Sync.settings().on || !engine.cloudReady || !(await Sync.token(false))) return;
      try { await Sync.run(engine); } catch (_) { /* resta l'errore nello stato */ }
    },
    disconnect() {
      token = null; tokenUntil = 0;
      setPref(SYNC_KEY, { on: false, last: null, error: '' });
      try { plugin('SocialLogin').logout({ provider: 'google' }); } catch (_) { /* gia' scollegato */ }
    },
    renderPanel(block, ui, engine) {
      const state = block.querySelector('[data-sync-state]');
      const actions = block.querySelector('[data-sync-actions]');
      const paint = () => {
        const s = Sync.settings();
        actions.innerHTML = '';
        if (!Sync.configured()) { state.textContent = tr('sync_not_configured'); return; }
        if (!s.on) {
          state.textContent = tr('sync_off');
          const b = ui.el(`<button type="button" class="btn btn-primary">${esc(tr('sync_connect'))}</button>`);
          b.addEventListener('click', () => go());
          actions.appendChild(b);
          return;
        }
        state.textContent = s.error ? tr('sync_error', { msg: s.error }) : (s.last ? tr('sync_last', { when: new Date(s.last).toLocaleString() }) : tr('sync_on'));
        const now = ui.el(`<button type="button" class="btn btn-primary">${esc(tr('sync_now'))}</button>`);
        const off = ui.el(`<button type="button" class="btn btn-ghost">${esc(tr('sync_disconnect'))}</button>`);
        now.addEventListener('click', () => go());
        off.addEventListener('click', () => { Sync.disconnect(); paint(); });
        actions.append(now, off);
      };
      const askPassword = () => new Promise((resolve) => {
        const form = ui.el(`<form class="modal-body" style="padding:0"><p class="card-sub">${esc(tr('sync_password_why'))}</p>
          <div class="form-row"><label>${esc(tr('local_password_current'))}</label><input type="password" name="p" required autocomplete="current-password" /></div>
          <div class="form-actions"><button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button><button type="submit" class="btn btn-primary">${esc(tr('btn_confirm'))}</button></div></form>`);
        form.addEventListener('submit', (e) => { e.preventDefault(); ui.closeModal(); resolve(form.p.value); });
        form.querySelector('[data-cancel]').addEventListener('click', () => { ui.closeModal(); resolve(null); });
        ui.openModal(tr('sync_title_password'), form);
      });
      const go = async (password) => {
        state.textContent = tr('sync_running');
        try {
          await Sync.run(engine, password);
          ui.toast(tr('sync_done'));
        } catch (e) {
          if (e.passwordRequired || (e.data && e.data.passwordRequired)) {
            const p = await askPassword();
            if (p) return go(p);
          } else ui.toast(e.message);
        }
        paint();
      };
      paint();
    },
  };

  // ==================================================================
  // AGGIORNAMENTI: all'apertura confronta la versione installata con le
  // release "app-v*" di GitHub; se c'e' di meglio propone di installarla.
  // ==================================================================
  const UPDATE_KEY = 'memento-update';
  const RELEASES = 'https://api.github.com/repos/katergaris/Memento/releases?per_page=20';
  const cmpVer = (a, b) => {
    const pa = String(a).split(/[.-]/).map((x) => parseInt(x, 10) || 0);
    const pb = String(b).split(/[.-]/).map((x) => parseInt(x, 10) || 0);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
    }
    return 0;
  };
  const Update = {
    available: () => !!plugin('ApkUpdater'),
    async current() {
      const App = plugin('App');
      try { return (await App.getInfo()).version; } catch (_) { return null; }
    },
    // Ultima release con un APK allegato: { version, url, notes }.
    async latest() {
      const r = await fetch(RELEASES, { headers: { Accept: 'application/vnd.github+json' } });
      if (!r.ok) throw new Error(tr('update_check_failed'));
      const list = await r.json();
      let best = null;
      for (const rel of list) {
        const m = /^app-v(\d+\.\d+\.\d+)$/.exec(rel.tag_name || '');
        const apk = (rel.assets || []).find((a) => /\.apk$/i.test(a.name));
        if (!m || rel.draft || !apk) continue;
        if (!best || cmpVer(m[1], best.version) > 0) best = { version: m[1], url: apk.browser_download_url, size: apk.size };
      }
      return best;
    },
    // Nuova versione rispetto a quella installata, oppure null.
    async check() {
      const [cur, last] = await Promise.all([Update.current(), Update.latest()]);
      return cur && last && cmpVer(last.version, cur) > 0 ? last : null;
    },
    async install(rel, onProgress) {
      const U = plugin('ApkUpdater');
      if (!(await U.canInstall()).value) {
        await U.openInstallSettings();
        throw Object.assign(new Error(tr('update_allow_install')), { needPermission: true });
      }
      const h = await U.addListener('progress', (e) => onProgress && onProgress(e.percent));
      try { await U.downloadAndInstall({ url: rel.url }); } finally { h.remove(); }
    },
    // Riquadro con versione, avanzamento e tasti.
    offer(ui, rel) {
      const mb = rel.size ? ` · ${(rel.size / 1048576).toFixed(1)} MB` : '';
      const body = ui.el(`<div class="modal-body" style="padding:0">
        <p class="update-version">${esc(tr('update_version', { v: rel.version }))}${esc(mb)}</p>
        <div class="update-bar hidden"><span></span></div>
        <div class="form-actions"><button type="button" class="btn btn-ghost" data-later>${esc(tr('update_later'))}</button>
        <button type="button" class="btn btn-primary" data-go>${esc(tr('update_install'))}</button></div></div>`);
      const bar = body.querySelector('.update-bar');
      const go = body.querySelector('[data-go]');
      body.querySelector('[data-later]').addEventListener('click', () => {
        setPref(UPDATE_KEY, { later: rel.version, at: Date.now() });
        ui.closeModal();
      });
      go.addEventListener('click', async () => {
        go.disabled = true;
        bar.classList.remove('hidden');
        try {
          await Update.install(rel, (p) => { bar.firstElementChild.style.width = `${p}%`; go.textContent = `${p}%`; });
          ui.closeModal();
        } catch (e) {
          ui.toast(e.message);
          go.disabled = false;
          go.textContent = e.needPermission ? tr('update_retry') : tr('update_install');
          bar.classList.add('hidden');
        }
      });
      ui.openModal(tr('update_title'), body);
    },
    // All'apertura: una volta, dopo lo sblocco. "Piu' tardi" vale un giorno.
    async onStart() {
      if (!Update.available()) return;
      let rel;
      try { rel = await Update.check(); } catch (_) { return; }
      if (!rel) return;
      const p = pref(UPDATE_KEY, {});
      if (p.later === rel.version && Date.now() - (p.at || 0) < 24 * 3600 * 1000) return;
      const show = () => {
        const ui = window.MementoUI;
        if (!ui || !ui.isReady() || document.querySelector('.modal-backdrop')) { setTimeout(show, 800); return; }
        Update.offer(ui, rel);
      };
      show();
    },
    // Blocco in Sicurezza: versione installata e controllo a mano.
    block(ui) {
      const b = ui.el(`<div class="section-block"><h3>${esc(tr('update_section'))}</h3><p class="card-sub" data-ver></p>
        <div class="card-actions" style="padding-top:10px"><button type="button" class="btn" data-check>${esc(tr('update_check'))}</button></div></div>`);
      Update.current().then((v) => { b.querySelector('[data-ver]').textContent = tr('update_installed', { v: v || '?' }); });
      const btn = b.querySelector('[data-check]');
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        try {
          const rel = await Update.check();
          if (rel) Update.offer(ui, rel); else ui.toast(tr('update_none'));
        } catch (e) { ui.toast(e.message); }
        btn.disabled = false;
      });
      return b;
    },
  };

  window.MementoNative = { Notify, Bio, Sync, Update };
})();
