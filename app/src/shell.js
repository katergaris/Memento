'use strict';
// Guscio dell'app Android: sceglie la modalita' e prepara window.MementoBackend
// prima di caricare app.js (la stessa interfaccia del server).
//
// - "Collegata": le richieste vanno al server Memento di casa. Con
//   CapacitorHttp attivo, fetch passa dal telefono (niente CORS, cookie di
//   sessione salvati dal sistema).
// - "Sul telefono": risponde MementoLocalBackend, dati cifrati in IndexedDB.
(function () {
  const MODE_KEY = 'memento-app-mode';
  const URL_KEY = 'memento-server-url';
  const tr = (k, p) => window.MementoI18n.t(k, p);
  const Cap = window.Capacitor;
  const plugin = (name) => (Cap && Cap.Plugins && Cap.Plugins[name]) || null;
  const isNative = !!(Cap && Cap.isNativePlatform && Cap.isNativePlatform());

  function h(html) { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; }
  function esc(s) { return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

  // ---------------- Archivio IndexedDB ----------------
  function idbStorage(dbName = 'memento-local') {
    let dbp = null;
    const open = () => (dbp = dbp || new Promise((resolve, reject) => {
      const req = indexedDB.open(dbName, 1);
      req.onupgradeneeded = () => req.result.createObjectStore('kv');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    }));
    const tx = async (mode, fn) => {
      const db = await open();
      return new Promise((resolve, reject) => {
        const t = db.transaction('kv', mode);
        const out = fn(t.objectStore('kv'));
        t.oncomplete = () => resolve(out && 'result' in out ? out.result : undefined);
        t.onerror = () => reject(t.error);
      });
    };
    return {
      get: (k) => tx('readonly', (s) => s.get(k)).then((v) => (v === undefined ? null : v)),
      put: (k, v) => tx('readwrite', (s) => s.put(v, k)),
      del: (k) => tx('readwrite', (s) => s.delete(k)),
      clear: () => tx('readwrite', (s) => s.clear()),
    };
  }

  // ---------------- Salvare e condividere un file ----------------
  async function blobToBase64(blob) {
    const buf = new Uint8Array(await blob.arrayBuffer());
    return window.MementoCrypto.toB64(buf);
  }
  async function saveFile(blob, name) {
    const Filesystem = plugin('Filesystem');
    const Share = plugin('Share');
    if (isNative && Filesystem) {
      const written = await Filesystem.writeFile({ path: name, data: await blobToBase64(blob), directory: 'CACHE' });
      if (Share) { await Share.share({ title: name, url: written.uri }); return; }
    }
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  function pickFile(accept) {
    return new Promise((resolve) => {
      const input = h(`<input type="file" accept="${esc(accept)}" class="hidden" />`);
      input.addEventListener('change', () => { resolve(input.files[0] || null); input.remove(); });
      document.body.appendChild(input);
      input.click();
    });
  }

  // Dopo ogni modifica (e allo sblocco) si riprogrammano le notifiche e, nella
  // modalita' telefono, si sincronizza con Drive se collegato. A raffica:
  // una sola volta dopo qualche secondo di calma.
  function afterChanges(be, engine) {
    const N = window.MementoNative;
    if (!N) return;
    clearTimeout(afterChanges.t1); clearTimeout(afterChanges.t2);
    afterChanges.t1 = setTimeout(() => N.Notify.reschedule(be).catch(() => {}), 3000);
    if (engine) afterChanges.t2 = setTimeout(() => N.Sync.auto(engine), 30000);
  }
  function watch(be, engine) {
    const inner = be.request;
    be.request = async (path, opts = {}) => {
      const method = (opts.method || 'GET').toUpperCase();
      // Impronta prima di mostrare una password del vault (preferenza).
      if (/^\/vault\/[^/]+\/reveal$/.test(path) && method === 'GET' && window.MementoNative && engine === null) {
        if (!(await window.MementoNative.Bio.confirmVault())) {
          return { ok: false, status: 403, json: async () => ({ error: tr('bio_failed') }) };
        }
      }
      const res = await inner(path, opts);
      const authOk = res.ok && (path === '/auth/login' || path === '/auth/setup');
      if (res.ok && (method !== 'GET' || authOk)) afterChanges(be, engine);
      if (res.ok && path === '/auth/status') {
        // La risposta si legge una volta sola: la si rilegge da qui.
        const data = await res.json();
        if (data.authenticated) afterChanges(be, engine);
        return { ok: true, status: res.status, json: async () => data, headers: res.headers };
      }
      return res;
    };
    return be;
  }

  // ---------------- Modalita' collegata ----------------
  function serverBackend(base) {
    const root = base.replace(/\/+$/, '');
    const req = (path, opts = {}) => fetch(root + '/api' + path, {
      credentials: 'include',
      headers: opts.body instanceof FormData ? {} : { 'Content-Type': 'application/json' },
      ...opts,
    });
    return {
      mode: 'server',
      request: req,
      async fileUrl(url) {
        const res = await fetch(root + url, { credentials: 'include' });
        if (!res.ok) throw new Error(tr('err_unexpected'));
        return URL.createObjectURL(await res.blob());
      },
      async download(url) {
        const res = await fetch(root + url, { credentials: 'include' });
        if (!res.ok) throw new Error(tr('err_unexpected'));
        const cd = res.headers.get('Content-Disposition') || '';
        const m = cd.match(/filename\*?=(?:UTF-8'')?"?([^";]+)"?/i);
        await saveFile(await res.blob(), m ? decodeURIComponent(m[1]) : 'memento-file');
      },
      async extendSettings(root2, ui) {
        root2.appendChild(notifyBlock(ui, this));
        root2.appendChild(await bioBlock(ui, null));
        root2.appendChild(appBlock(ui, tr('app_mode_server_on', { url: root })));
      },
    };
  }

  // ---------------- Modalita' sul telefono ----------------
  function localBackend() {
    const storage = idbStorage();
    const be = new window.MementoLocalBackend.LocalBackend(storage, {
      version: 'app',
      confirmReveal: () => (window.MementoNative ? window.MementoNative.Bio.confirmVault() : true),
    });
    const today = () => new Date().toISOString().slice(0, 10);
    return {
      mode: 'local',
      engine: be,
      request: (path, opts) => be.request(path, opts),
      // Condivisione di voci del vault (passa da Google Drive).
      canShare: true,
      syncNow() {
        const N = window.MementoNative;
        if (!N || !N.Sync.settings().on) { window.MementoUI.toast(tr('share_need_drive')); return; }
        N.Sync.run(be).catch((e) => window.MementoUI.toast(e.message));
      },
      // Schermata di sblocco: tasto impronta (e primo tentativo automatico).
      async offerBiometric(onUnlocked) {
        const N = window.MementoNative;
        if (!N || !N.Bio.settings().unlock || !(await N.Bio.available())) return;
        const form = document.getElementById('auth-form');
        if (form.querySelector('[data-bio-unlock]')) return;
        const btn = document.createElement('button');
        btn.type = 'button'; btn.className = 'btn btn-block'; btn.dataset.bioUnlock = '1';
        btn.textContent = tr('bio_unlock_btn');
        const tryUnlock = async () => {
          try { if (await N.Bio.unlock(be)) { btn.remove(); afterChanges(this, be); onUnlocked(); } } catch (_) { /* resta la password */ }
        };
        btn.addEventListener('click', tryUnlock);
        form.appendChild(btn);
        tryUnlock();
      },
      async fileUrl(url) {
        const m = url.match(/\/api\/drive\/([^/]+)\/(view|download)/);
        if (!m) throw new Error(tr('err_unexpected'));
        const { blob } = await be.fileBlob(m[1], { preview: m[2] === 'view' });
        return URL.createObjectURL(blob);
      },
      async download(url) {
        const m = url.match(/\/api\/drive\/([^/]+)\/download/);
        if (m) { const { blob, name } = await be.fileBlob(m[1]); await saveFile(blob, name); return; }
        if (url.startsWith('/api/backup')) { await exportFlow(); return; }
        throw new Error(tr('err_unexpected'));
      },
      // Sezione Sicurezza sul telefono: dati, password, modalita'.
      async renderSettings(root, ui) {
        root.innerHTML = '';
        root.appendChild(ui.el(`<div class="view-header"><h2>${esc(tr('nav_security_title'))}</h2></div>`));
        const counts = be.counts();
        const data = ui.el(`<div class="section-block"><h3>${esc(tr('local_data_title'))}</h3>
          <p class="card-sub">${esc(tr('local_data_counts', { notes: counts.ideas, vault: counts.vault, docs: counts.documents }))}</p>
          <div class="card-actions" style="padding-top:10px">
            <button type="button" class="btn btn-primary" data-export>${esc(tr('local_export'))}</button>
            <button type="button" class="btn" data-import>${esc(tr('local_import'))}</button>
          </div></div>`);
        data.querySelector('[data-export]').addEventListener('click', () => exportFlow().catch((e) => ui.toast(e.message)));
        data.querySelector('[data-import]').addEventListener('click', () => importFlow(ui).catch((e) => ui.toast(e.message)));
        root.appendChild(data);

        const sync = ui.el(`<div class="section-block"><h3>${esc(tr('local_sync_title'))}</h3>
          <p class="card-sub" data-sync-state></p>
          <div class="card-actions" style="padding-top:10px" data-sync-actions></div></div>`);
        root.appendChild(sync);
        if (window.MementoNative) window.MementoNative.Sync.renderPanel(sync, ui, be);
        else sync.querySelector('[data-sync-state]').textContent = tr('sync_not_configured');

        const info = await (await be.request('/security')).json();
        root.appendChild(ui.totpBlock(info));
        root.appendChild(await bioBlock(ui, be));
        root.appendChild(notifyBlock(ui, this));

        const pw = ui.el(`<div class="section-block"><h3>${esc(tr('local_password_title'))}</h3>
          <div class="card-actions" style="padding-top:4px"><button type="button" class="btn" data-change>${esc(tr('local_change_password'))}</button>
          <button type="button" class="btn" data-lock>${esc(tr('local_lock_now'))}</button></div></div>`);
        pw.querySelector('[data-change]').addEventListener('click', () => changePasswordFlow(ui));
        pw.querySelector('[data-lock]').addEventListener('click', () => { be.lock(); location.reload(); });
        root.appendChild(pw);

        root.appendChild(ui.themeBlock());
        root.appendChild(ui.sectionsBlock());
        root.appendChild(appBlock(ui, tr('app_mode_local_on')));
        return true;
      },
    };

    async function askTwice(ui, title, { confirm = true } = {}) {
      return new Promise((resolve) => {
        const form = ui.el(`<form class="modal-body" style="padding:0">
          <div class="form-row"><label>${esc(tr('auth_password'))}</label><input type="password" name="p1" required minlength="8" autocomplete="new-password" /></div>
          ${confirm ? `<div class="form-row"><label>${esc(tr('local_password_repeat'))}</label><input type="password" name="p2" required minlength="8" autocomplete="new-password" /></div>` : ''}
          <div class="form-actions"><button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button><button type="submit" class="btn btn-primary">${esc(tr('btn_confirm'))}</button></div></form>`);
        form.addEventListener('submit', (e) => {
          e.preventDefault();
          if (confirm && form.p1.value !== form.p2.value) { ui.toast(tr('local_password_mismatch')); return; }
          ui.closeModal(); resolve(form.p1.value);
        });
        form.querySelector('[data-cancel]').addEventListener('click', () => { ui.closeModal(); resolve(null); });
        ui.openModal(title, form);
      });
    }
    async function exportFlow() {
      const ui = window.MementoUI;
      const password = await askTwice(ui, tr('local_export_password'));
      if (!password) return;
      ui.toast(tr('local_exporting'));
      const envelope = await be.exportFile(password);
      await saveFile(new Blob([JSON.stringify(envelope)], { type: 'application/json' }), `memento-${today()}.memento`);
    }
    async function importFlow(ui) {
      const file = await pickFile('.memento,application/json');
      if (!file) return;
      let envelope;
      try { envelope = JSON.parse(await file.text()); } catch (_) { ui.toast(tr('local_file_unknown')); return; }
      const password = await askTwice(ui, tr('local_import_password'), { confirm: false });
      if (!password) return;
      const counts = await be.importFile(envelope, password, 'merge');
      ui.toast(tr('local_import_done', { notes: counts.ideas, vault: counts.vault }));
      ui.render('security', { fromHash: true });
    }
    async function changePasswordFlow(ui) {
      const form = ui.el(`<form class="modal-body" style="padding:0">
        <div class="form-row"><label>${esc(tr('local_password_current'))}</label><input type="password" name="cur" required autocomplete="current-password" /></div>
        <div class="form-row"><label>${esc(tr('local_password_new'))}</label><input type="password" name="p1" required minlength="8" autocomplete="new-password" /></div>
        <div class="form-row"><label>${esc(tr('local_password_repeat'))}</label><input type="password" name="p2" required minlength="8" autocomplete="new-password" /></div>
        <div class="form-actions"><button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button><button type="submit" class="btn btn-primary">${esc(tr('btn_save'))}</button></div></form>`);
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (form.p1.value !== form.p2.value) { ui.toast(tr('local_password_mismatch')); return; }
        try { await be.changePassword(form.cur.value, form.p1.value); } catch (err) { ui.toast(err.message); return; }
        if (window.MementoNative) window.MementoNative.Bio.refreshKey(be).catch(() => {});
        ui.closeModal(); ui.toast(tr('local_password_changed'));
      });
      form.querySelector('[data-cancel]').addEventListener('click', ui.closeModal);
      ui.openModal(tr('local_change_password'), form);
    }
  }

  // Interruttore come quelli di "Sezioni visibili".
  function toggleRow(ui, label, checked, onChange) {
    const row = ui.el(`<label class="toggle-row"><span></span><input type="checkbox" role="switch" /></label>`);
    row.querySelector('span').textContent = label;
    const input = row.querySelector('input');
    input.checked = checked;
    input.addEventListener('change', async () => {
      try { await onChange(input.checked); } catch (e) { input.checked = !input.checked; ui.toast(e.message); }
    });
    return row;
  }
  function notifyBlock(ui, be) {
    const N = window.MementoNative;
    const block = ui.el(`<div class="section-block"><h3>${esc(tr('notify_title'))}</h3><div class="toggle-list"></div></div>`);
    const list = block.querySelector('.toggle-list');
    if (!N || !N.Notify.available()) { list.appendChild(ui.el(`<p class="card-sub">${esc(tr('notify_unavailable'))}</p>`)); return block; }
    const s = N.Notify.settings();
    const hourRow = ui.el(`<label class="toggle-row"><span>${esc(tr('notify_hour'))}</span><select>${Array.from({ length: 24 }, (_, h) => `<option value="${h}">${String(h).padStart(2, '0')}:00</option>`).join('')}</select></label>`);
    hourRow.querySelector('select').value = String(s.hour);
    hourRow.querySelector('select').addEventListener('change', (e) => { N.Notify.setHour(Number(e.target.value)); N.Notify.reschedule(be).catch(() => {}); });
    hourRow.classList.toggle('hidden', !s.on);
    list.appendChild(toggleRow(ui, tr('notify_on'), s.on, async (on) => {
      await N.Notify.enable(on);
      hourRow.classList.toggle('hidden', !on);
      if (on) { await N.Notify.reschedule(be); ui.toast(tr('notify_enabled')); }
    }));
    list.appendChild(hourRow);
    return block;
  }
  async function bioBlock(ui, engine) {
    const N = window.MementoNative;
    const block = ui.el(`<div class="section-block"><h3>${esc(tr('bio_title'))}</h3><div class="toggle-list"></div></div>`);
    const list = block.querySelector('.toggle-list');
    if (!N || !(await N.Bio.available())) { list.appendChild(ui.el(`<p class="card-sub">${esc(tr('bio_unavailable'))}</p>`)); return block; }
    const s = N.Bio.settings();
    if (engine) {
      list.appendChild(toggleRow(ui, tr('bio_unlock'), s.unlock, async (on) => {
        if (on) await N.Bio.enableUnlock(engine); else await N.Bio.disableUnlock();
      }));
    }
    list.appendChild(toggleRow(ui, tr('bio_vault'), s.vault, async (on) => {
      if (on && !(await N.Bio.verify(tr('bio_enable_reason')))) throw new Error(tr('bio_failed'));
      N.Bio.setVault(on);
    }));
    return block;
  }

  // Blocco comune: modalita' attuale e cambio modalita'.
  function appBlock(ui, label) {
    const b = ui.el(`<div class="section-block"><h3>${esc(tr('app_mode_title'))}</h3><p class="card-sub"></p>
      <div class="card-actions" style="padding-top:10px"><button type="button" class="btn" data-switch>${esc(tr('app_mode_switch'))}</button></div></div>`);
    b.querySelector('.card-sub').textContent = label;
    b.querySelector('[data-switch]').addEventListener('click', async () => {
      if (!(await ui.askConfirm(tr('app_mode_switch_confirm'), { confirmLabel: tr('app_mode_switch'), danger: false }))) return;
      localStorage.removeItem(MODE_KEY);
      location.hash = '';
      location.reload();
    });
    return b;
  }

  // ---------------- Scelta della modalita' al primo avvio ----------------
  function chooseMode() {
    return new Promise((resolve) => {
      const screen = h(`
        <div class="auth-screen mode-screen">
          <div class="mode-card">
            <img src="/icon-192.png" width="64" height="64" alt="" class="mode-logo" />
            <h1>Memento</h1>
            <button type="button" class="mode-tile mode-tile-local" data-mode="local">
              <b>${esc(tr('app_mode_local'))}</b>
              <span>${esc(tr('app_mode_local_sub'))}</span>
            </button>
            <button type="button" class="mode-tile" data-mode="server">
              <b>${esc(tr('app_mode_server'))}</b>
              <span>${esc(tr('app_mode_server_sub'))}</span>
            </button>
            <form class="mode-server hidden">
              <input type="url" name="url" required placeholder="https://memento.casa.example" autocomplete="url" inputmode="url" />
              <p class="form-error hidden"></p>
              <button type="submit" class="btn btn-primary btn-block">${esc(tr('app_mode_connect'))}</button>
            </form>
          </div>
        </div>`);
      document.body.appendChild(screen);
      const form = screen.querySelector('.mode-server');
      const err = form.querySelector('.form-error');
      form.url.value = localStorage.getItem(URL_KEY) || '';
      screen.querySelector('[data-mode="local"]').addEventListener('click', () => {
        localStorage.setItem(MODE_KEY, 'local');
        screen.remove();
        resolve('local');
      });
      screen.querySelector('[data-mode="server"]').addEventListener('click', () => {
        form.classList.remove('hidden');
        form.url.focus();
      });
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        let url = form.url.value.trim().replace(/\/+$/, '');
        if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
        err.classList.add('hidden');
        try {
          const res = await fetch(url + '/api/health');
          const data = await res.json();
          if (data.status !== 'ok') throw new Error();
        } catch (_) {
          err.textContent = tr('app_mode_unreachable');
          err.classList.remove('hidden');
          return;
        }
        localStorage.setItem(URL_KEY, url);
        localStorage.setItem(MODE_KEY, 'server');
        screen.remove();
        resolve('server');
      });
    });
  }

  // ---------------- Tasto indietro di Android ----------------
  function wireBackButton() {
    const App = plugin('App');
    if (!App || !App.addListener) return;
    App.addListener('backButton', () => {
      const close = document.querySelector('.modal-backdrop .modal-close, .preview-backdrop .preview-close');
      if (close) { close.click(); return; }
      const sheet = document.querySelector('#sections-sheet:not(.hidden)');
      if (sheet) { sheet.classList.add('hidden'); return; }
      const qc = document.querySelector('#quick-capture:not(.hidden)');
      if (qc) { document.body.click(); return; }
      if (location.hash && !/^#\/?(today)?$/.test(location.hash)) { history.back(); return; }
      App.exitApp();
    });
    // Tornando all'app dopo un po', la modalita' locale si blocca da sola.
    let hiddenAt = 0;
    App.addListener('appStateChange', ({ isActive }) => {
      const be = window.MementoBackend;
      if (!be || be.mode !== 'local') return;
      if (!isActive) { hiddenAt = Date.now(); return; }
      if (window.MementoNative && be.engine.unlocked) window.MementoNative.Sync.auto(be.engine);
      if (hiddenAt && Date.now() - hiddenAt > 5 * 60 * 1000 && be.engine.unlocked) { be.engine.lock(); location.reload(); }
    });
  }

  function loadApp() {
    const s = document.createElement('script');
    s.src = '/app.js';
    document.body.appendChild(s);
  }

  async function boot() {
    let mode = localStorage.getItem(MODE_KEY);
    if (mode !== 'local' && mode !== 'server') mode = await chooseMode();
    const backend = mode === 'local' ? localBackend() : serverBackend(localStorage.getItem(URL_KEY) || '');
    window.MementoBackend = watch(backend, mode === 'local' ? backend.engine : null);
    document.documentElement.dataset.appMode = mode;
    wireBackButton();
    loadApp();
  }

  // La scelta della lingua viene prima di tutto (stessa schermata del server).
  window.MementoShell = { boot, idbStorage, saveFile };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
