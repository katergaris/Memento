(() => {
  'use strict';

  // ---------------- Lingua ----------------
  const I18N = window.MementoI18n;
  const tr = I18N.t;

  // ---------------- PWA: cache del guscio per installabilita' e avvio offline ----------------
  // Se la registrazione fallisce (es. accesso in http semplice, senza
  // certificato: i service worker richiedono https) l'app funziona comunque,
  // solo senza installabilita' ne' cache offline.
  // Dentro l'app Android (window.MementoBackend) i file sono gia' nel telefono.
  if ('serviceWorker' in navigator && !window.MementoBackend) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/sw.js').catch(() => {});
    });
  }

  // ---------------- Notifiche push (scadenze) ----------------
  // La chiave pubblica VAPID arriva codificata base64url (compatta, sicura
  // negli URL): PushManager.subscribe vuole invece un Uint8Array grezzo.
  function urlBase64ToUint8Array(base64) {
    const padding = '='.repeat((4 - (base64.length % 4)) % 4);
    const raw = atob((base64 + padding).replace(/-/g, '+').replace(/_/g, '/'));
    return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
  }

  async function getPushSubscription() {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) return null;
    const reg = await navigator.serviceWorker.ready;
    return reg.pushManager.getSubscription();
  }

  async function enablePushNotifications() {
    const permission = await Notification.requestPermission();
    if (permission !== 'granted') throw new Error(tr('err_notification_permission_denied'));
    const { publicKey } = await api('/push/vapid-public-key');
    if (!publicKey) throw new Error(tr('err_server_key_unavailable'));
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(publicKey),
    });
    await api('/push/subscribe', { method: 'POST', body: JSON.stringify(sub.toJSON()) });
  }

  async function disablePushNotifications() {
    const sub = await getPushSubscription();
    if (!sub) return;
    await api('/push/unsubscribe', { method: 'POST', body: JSON.stringify({ endpoint: sub.endpoint }) });
    await sub.unsubscribe();
  }

  // ---------------- Impronta digitale / Face ID (WebAuthn) ----------------
  function b64urlToBuffer(b64url) {
    const padding = '='.repeat((4 - (b64url.length % 4)) % 4);
    const base64 = (b64url + padding).replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(base64);
    const arr = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i += 1) arr[i] = raw.charCodeAt(i);
    return arr.buffer;
  }

  function bufferToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let str = '';
    for (let i = 0; i < bytes.length; i += 1) str += String.fromCharCode(bytes[i]);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function webauthnSupported() {
    return !!(window.PublicKeyCredential && navigator.credentials);
  }

  function guessDeviceName() {
    const ua = navigator.userAgent;
    if (/ipad/i.test(ua)) return 'iPad';
    if (/iphone/i.test(ua)) return 'iPhone';
    if (/android/i.test(ua)) return 'Android';
    if (/macintosh/i.test(ua)) return 'Mac';
    if (/windows/i.test(ua)) return 'Windows';
    return 'Dispositivo';
  }

  async function enrollFingerprint() {
    const options = await api('/security/webauthn/register/options', { method: 'POST' });
    const publicKey = {
      ...options,
      challenge: b64urlToBuffer(options.challenge),
      user: { ...options.user, id: b64urlToBuffer(options.user.id) },
      excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: b64urlToBuffer(c.id) })),
    };
    let cred;
    try {
      cred = await navigator.credentials.create({ publicKey });
    } catch (e) {
      throw new Error(tr('err_webauthn_cancelled'));
    }
    const credentialJSON = {
      id: cred.id,
      rawId: bufferToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
        attestationObject: bufferToB64url(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : undefined,
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    };
    await api('/security/webauthn/register/verify', {
      method: 'POST',
      body: JSON.stringify({ credential: credentialJSON, deviceName: guessDeviceName() }),
    });
  }

  async function revealWithFingerprint(vaultId) {
    const options = await api(`/vault/${vaultId}/reveal/options`);
    const publicKey = {
      ...options,
      challenge: b64urlToBuffer(options.challenge),
      allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: b64urlToBuffer(c.id) })),
    };
    let assertion;
    try {
      assertion = await navigator.credentials.get({ publicKey });
    } catch (e) {
      throw new Error(tr('err_webauthn_cancelled'));
    }
    const credentialJSON = {
      id: assertion.id,
      rawId: bufferToB64url(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON: bufferToB64url(assertion.response.clientDataJSON),
        authenticatorData: bufferToB64url(assertion.response.authenticatorData),
        signature: bufferToB64url(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufferToB64url(assertion.response.userHandle) : undefined,
      },
      clientExtensionResults: assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {},
    };
    return api(`/vault/${vaultId}/reveal`, { method: 'POST', body: JSON.stringify({ credential: credentialJSON }) });
  }

  // ---------------- API helper ----------------
  async function api(path, opts = {}) {
    let res;
    try {
      // App Android: risponde il motore scelto (server di casa o telefono).
      res = window.MementoBackend
        ? await window.MementoBackend.request(path, opts)
        : await fetch('/api' + path, {
          credentials: 'same-origin',
          headers: opts.body instanceof FormData ? {} : { 'Content-Type': 'application/json' },
          ...opts,
        });
    } catch (e) {
      // fetch() lancia (invece di rispondere con un errore HTTP) quando non
      // c'e' proprio connessione: senza questo l'utente vedeva "Failed to
      // fetch" invece di un messaggio comprensibile.
      throw new Error(tr('err_offline'));
    }
    // Un 401 sulle rotte di accesso e' una credenziale sbagliata, non una
    // sessione scaduta: va lasciato passare alla schermata di login, che sa
    // spiegare cosa manca (password errata, codice a due fattori, ...).
    if (res.status === 401 && !path.startsWith('/auth/')) {
      showAuthScreen();
      throw new Error(tr('err_session_expired'));
    }
    if (res.status === 204) return null;
    let data = null;
    try { data = await res.json(); } catch (e) { /* corpo vuoto */ }
    if (!res.ok) {
      const err = new Error((data && data.error) || tr('err_unexpected'));
      err.status = res.status;
      err.data = data || {};
      throw err;
    }
    return data;
  }

  // Avviso in basso; con action mostra un tasto (es. "Annulla").
  function toast(msg, { action, onAction, duration } = {}) {
    document.querySelectorAll('.toast').forEach((t) => t.remove());
    const box = document.createElement('div');
    box.className = 'toast';
    const text = document.createElement('span');
    text.textContent = msg;
    box.appendChild(text);
    if (action && onAction) {
      const b = document.createElement('button');
      b.type = 'button'; b.className = 'toast-action'; b.textContent = action;
      b.addEventListener('click', () => { box.remove(); onAction(); });
      box.appendChild(b);
    }
    document.body.appendChild(box);
    setTimeout(() => box.remove(), duration || (action ? 5500 : 3200));
  }
  // Annullabile: l'azione e' gia' fatta, "Annulla" la disfa.
  const undoToast = (msg, undo) => toast(msg, { action: tr('btn_undo'), onAction: async () => { await undo(); haptic('light'); } });

  // Vibrazione leggera dove c'e' (app Android).
  function haptic(kind = 'light') {
    const H = window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.Haptics;
    if (!H) return;
    try {
      if (kind === 'success') H.notification({ type: 'SUCCESS' });
      else H.impact({ style: kind === 'medium' ? 'MEDIUM' : 'LIGHT' });
    } catch (_) { /* senza vibrazione */ }
  }

  // Conferma con un foglio dell'app al posto di confirm() del browser.
  function askConfirm(message, { confirmLabel, danger = true } = {}) {
    return new Promise((resolve) => {
      const wrap = el(`<div class="ask"><p class="ask-text"></p><div class="form-actions"><button type="button" class="btn btn-ghost" data-no></button><button type="button" class="btn ${danger ? 'btn-danger-solid' : 'btn-primary'}" data-yes></button></div></div>`);
      wrap.querySelector('.ask-text').textContent = message;
      wrap.querySelector('[data-no]').textContent = tr('btn_cancel');
      wrap.querySelector('[data-yes]').textContent = confirmLabel || (danger ? tr('btn_delete') : tr('btn_confirm'));
      let done = false;
      const finish = (v) => { if (done) return; done = true; closeModal(); resolve(v); };
      wrap.querySelector('[data-no]').addEventListener('click', () => finish(false));
      wrap.querySelector('[data-yes]').addEventListener('click', () => finish(true));
      openModal('', wrap, { onClose: () => { if (!done) { done = true; resolve(false); } } });
    });
  }
  // Richiesta di un valore (es. importo) al posto di prompt().
  function askValue(title, { label = '', inputmode = 'text', placeholder = '' } = {}) {
    return new Promise((resolve) => {
      const form = el(`<form class="modal-body" style="padding:0"><div class="form-row"><label></label><input type="text" name="v" required /></div>
        <div class="form-actions"><button type="button" class="btn btn-ghost" data-no>${esc(tr('btn_cancel'))}</button><button type="submit" class="btn btn-primary">${esc(tr('btn_confirm'))}</button></div></form>`);
      form.querySelector('label').textContent = label;
      form.v.setAttribute('inputmode', inputmode); form.v.placeholder = placeholder;
      let done = false;
      form.addEventListener('submit', (e) => { e.preventDefault(); done = true; closeModal(); resolve(form.v.value); });
      form.querySelector('[data-no]').addEventListener('click', () => { done = true; closeModal(); resolve(null); });
      openModal(title, form, { onClose: () => { if (!done) { done = true; resolve(null); } } });
      setTimeout(() => form.v.focus(), 250);
    });
  }

  function esc(str) {
    return String(str ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  // Il testo va accorciato PRIMA di essere convertito in HTML: tagliando dopo
  // l'escape si poteva spezzare un'entita' (&amp; -> &am) e sporcare la pagina.
  function escTrim(str, max) {
    const s = String(str ?? '');
    return esc(s.length > max ? s.slice(0, max) + '…' : s);
  }

  function fmtDate(d) {
    if (!d) return '—';
    try { return new Date(d).toLocaleDateString('it-IT'); } catch (e) { return d; }
  }

  // Tempo concreto invece della sola data (countdown, non solo calendario):
  // riusato da Scadenze e dalla scadenza dei Progetti in Bacheca.
  function daysUntil(dateStr) {
    return Math.round((new Date(dateStr) - new Date()) / 86400000);
  }

  // Etichetta "Scade tra N giorni"/"Scaduto da N giorni", riusata da
  // Progetti/Scadenze/Abbonamenti ovunque serva mostrare una scadenza.
  function dueLabel(days) {
    if (days === 0) return tr('due_today');
    const unit = tr(Math.abs(days) === 1 ? 'day_one' : 'day_other');
    return days > 0 ? tr('due_in', { n: days, unit }) : tr('overdue_by', { n: -days, unit });
  }

  function parseTags(form) {
    return form.tags.value.split(',').map((t) => t.trim()).filter(Boolean);
  }

  function checklistProgress(list) {
    const total = (list || []).length;
    const done = (list || []).filter((c) => c.done).length;
    return { done, total };
  }

  // Formato di input rapido per il budget: una riga per voce, "etichetta, importo".
  function parseBudgetLines(text) {
    return text.split('\n').map((l) => l.trim()).filter(Boolean).map((line) => {
      const idx = line.indexOf(',');
      if (idx === -1) return { label: line, amount: 0 };
      const label = line.slice(0, idx).trim();
      const amount = parseFloat(line.slice(idx + 1).replace(',', '.').trim()) || 0;
      return { label, amount };
    });
  }

  function budgetTotal(list) {
    return (list || []).reduce((sum, b) => sum + (Number(b.amount) || 0), 0);
  }

  function fmtMoney(n) {
    return new Intl.NumberFormat('it-IT', { style: 'currency', currency: 'EUR' }).format(n || 0);
  }

  // Riusata sia dalla vista Progetti sia dalla Vista Bacheca del Flusso.
  function collectChecklist(form, previous) {
    const lines = form.checklist.value.split('\n').map((l) => l.trim()).filter(Boolean);
    const prevMap = new Map((previous || []).map((c) => [c.text, c.done]));
    return lines.map((text) => ({ text, done: prevMap.get(text) || false }));
  }

  function fmtSize(bytes) {
    if (!bytes) return '0 B';
    // Sotto il KB mostriamo i byte: prima qualsiasi file piccolo risultava "0 KB".
    if (bytes < 1024) return `${bytes} B`;
    const kb = bytes / 1024;
    if (kb < 1024) return `${kb.toFixed(0)} KB`;
    return `${(kb / 1024).toFixed(1)} MB`;
  }

  // ---------------- Modal ----------------
  const modalTpl = document.getElementById('tpl-modal');
  let activeModal = null;

  function openModal(title, bodyNode, { onClose } = {}) {
    closeModal();
    const frag = modalTpl.content.cloneNode(true);
    const backdrop = frag.querySelector('.modal-backdrop');
    I18N.applyStaticTranslations(backdrop);
    frag.querySelector('.modal-title').textContent = title;
    frag.querySelector('.modal-body').appendChild(bodyNode);
    frag.querySelector('.modal-close').addEventListener('click', closeModal);
    backdrop.addEventListener('click', (e) => { if (e.target === backdrop) closeModal(); });
    // Con una connessione lenta, piu' click sul pulsante "Salva" prima che la
    // prima richiesta finisca creavano piu' voci identiche. Il bottone si
    // riabilita da solo dopo un po' nel caso la richiesta fallisca e la
    // finestra resti aperta (altrimenti non si potrebbe piu' riprovare).
    const form = bodyNode.tagName === 'FORM' ? bodyNode : bodyNode.querySelector('form');
    const submitBtn = form && form.querySelector('button[type="submit"]');
    if (form && submitBtn) {
      form.addEventListener('submit', () => {
        submitBtn.disabled = true;
        setTimeout(() => { submitBtn.disabled = false; }, 8000);
      });
    }
    if (!title) frag.querySelector('.modal-title').classList.add('hidden');
    document.body.appendChild(frag);
    activeModal = document.body.lastElementChild;
    activeModal._onClose = onClose;
    attachSheetDrag(activeModal);
  }

  function closeModal() {
    if (!activeModal) return false;
    const m = activeModal;
    activeModal = null;
    if (m._onClose) { try { m._onClose(); } catch (_) { /* nessuno */ } }
    // Uscita con movimento (foglio che scende / riquadro che svanisce).
    m.classList.add('closing');
    setTimeout(() => m.remove(), 180);
    return true;
  }

  // Telefono: il foglio si chiude anche trascinandolo verso il basso.
  function attachSheetDrag(backdrop) {
    const sheet = backdrop.querySelector('.modal');
    const handle = backdrop.querySelector('.modal-header');
    if (!sheet || !handle || !window.matchMedia('(max-width: 760px)').matches) return;
    let startY = null, dy = 0;
    handle.addEventListener('pointerdown', (e) => {
      // La X e gli altri tasti dell'intestazione devono ricevere il tocco.
      if (e.target.closest('button, a, input, select')) return;
      startY = e.clientY; dy = 0; sheet.style.transition = 'none'; handle.setPointerCapture(e.pointerId); });
    handle.addEventListener('pointermove', (e) => {
      if (startY === null) return;
      dy = Math.max(0, e.clientY - startY);
      sheet.style.transform = `translateY(${dy}px)`;
    });
    const end = () => {
      if (startY === null) return;
      startY = null;
      sheet.style.transition = '';
      if (dy > 110) closeModal(); else sheet.style.transform = '';
    };
    handle.addEventListener('pointerup', end);
    handle.addEventListener('pointercancel', end);
  }

  // ---------------- Anteprima documento a schermo intero ----------------
  const PREVIEWABLE_MIME = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'application/pdf']);

  // Simbolo per categoria di file in Drive, cosi' si riconosce a colpo
  // d'occhio se e' un'immagine/audio/video senza dover leggere l'estensione.
  function fileCategoryIcon(mime) {
    const m = mime || '';
    if (m.startsWith('image/')) return 'immagine';
    if (m.startsWith('audio/')) return 'musica';
    if (m.startsWith('video/')) return 'video';
    return 'documento';
  }
  let activePreview = null;

  function closePreview() {
    if (!activePreview) return false;
    activePreview.remove(); activePreview = null;
    return true;
  }

  function openDocumentPreview(doc) {
    if (!PREVIEWABLE_MIME.has(doc.mime)) return;
    closePreview();
    const label = doc.display_name || doc.original_name;
    const url = `/api/drive/${doc.id}/view`;
    const backdrop = el('<div class="preview-backdrop"></div>');
    const box = el(`
      <div class="preview-box">
        <div class="preview-head">
          <span class="preview-title"></span>
          <div style="display:flex;gap:8px;align-items:center">
            <a class="btn btn-sm" href="/api/drive/${doc.id}/download">${esc(tr('btn_download'))}</a>
            <button type="button" class="preview-close" aria-label="${esc(tr('btn_close'))}">${phIcon('x', 18)}</button>
          </div>
        </div>
      </div>
    `);
    box.querySelector('.preview-title').textContent = label;
    box.querySelector('.preview-close').addEventListener('click', closePreview);
    const media = doc.mime.startsWith('image/')
      ? el(`<img class="preview-media" alt="${esc(label)}" />`)
      : el(`<iframe class="preview-media preview-frame" title="${esc(label)}"></iframe>`);
    box.appendChild(media);
    if (window.MementoBackend && window.MementoBackend.fileUrl) {
      window.MementoBackend.fileUrl(url).then((u) => { media.src = u; }).catch((err) => toast(err.message));
    } else {
      media.src = url;
    }
    backdrop.appendChild(box);
    backdrop.addEventListener('click', (e) => { if (e.target === backdrop) closePreview(); });
    document.body.appendChild(backdrop);
    activePreview = backdrop;
  }

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    // Chiude tutti i livelli "locali" gia' aperti (come prima), e se non
    // ce n'era nessuno chiude come ultima risorsa la finestra a fuoco
    // (stesso effetto della sua ×) - cosi' Escape su una finestra senza
    // nient'altro sopra non resta senza alcun effetto.
    let closedSomething = false;
    if (closePreview()) closedSomething = true;
    if (closeModal()) closedSomething = true;
    if (typeof closeQuickCapture === 'function' && closeQuickCapture()) closedSomething = true;
    if (!closedSomething && typeof closeSectionsSheet === 'function') closeSectionsSheet();
  });

  function el(html) {
    const div = document.createElement('div');
    div.innerHTML = html.trim();
    // Con piu' elementi al primo livello restituiamo un frammento: prima ne
    // usciva solo il primo e il resto spariva senza avvisare (era il caso dei
    // testi di aiuto di Vault e Fascicoli).
    if (div.children.length > 1) {
      const frag = document.createDocumentFragment();
      while (div.firstChild) frag.appendChild(div.firstChild);
      return frag;
    }
    return div.firstElementChild;
  }

  // Rende un <div>/<span> cliccabile raggiungibile e attivabile da tastiera
  // (Tab per il focus, Invio/Spazio per attivare) senza cambiare il click
  // esistente. Serve per elementi che semanticamente sono voci di menu/opzioni
  // ma non possono essere <button> per via dello stile (bordo/hover custom).
  function makeActivatable(elm, role, onActivate) {
    elm.setAttribute('tabindex', '0');
    elm.setAttribute('role', role);
    elm.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      e.preventDefault();
      onActivate(e);
    });
  }

  // ---------------- Effetto "decodifica" per il nome (una tantum) ----------------
  // Ogni carattere scorre tra simboli casuali prima di fermarsi su quello vero,
  // con un piccolo ritardo crescente da sinistra a destra. Gioca una sola volta
  // (non e' un loop): sul nome dell'app, ripeterlo ad ogni click sarebbe fastidioso.
  function decodeReveal(el, text) {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      el.textContent = text;
      return;
    }
    const CHARS = '!<>-_/[]{}=+*^?#$%&';
    const randChar = () => CHARS[(Math.random() * CHARS.length) | 0];
    el.textContent = '';
    el.classList.add('decode-name');
    const chars = text.split('');
    const spans = chars.map(() => el.appendChild(document.createElement('span')));
    const caret = el.appendChild(document.createElement('span'));
    caret.className = 'decode-caret';

    const churnStart = chars.map((_, i) => i * 28 + Math.random() * 35);
    const lockTime = churnStart.map((t) => t + 150 + Math.random() * 160);
    const locked = chars.map(() => false);
    const start = performance.now();
    const timer = setInterval(() => {
      const elapsed = performance.now() - start;
      let allLocked = true;
      chars.forEach((ch, i) => {
        if (locked[i]) return;
        if (elapsed >= lockTime[i]) {
          spans[i].textContent = ch;
          spans[i].className = 'decode-cell--locked';
          locked[i] = true;
        } else {
          allLocked = false;
          if (elapsed >= churnStart[i]) {
            spans[i].textContent = ch === ' ' ? ' ' : randChar();
            spans[i].className = 'decode-cell--churn';
          }
        }
      });
      if (allLocked) { clearInterval(timer); caret.remove(); }
    }, 45);
  }

  // ---------------- Auth ----------------
  const authScreen = document.getElementById('auth-screen');
  const appRoot = document.getElementById('app');
  const authForm = document.getElementById('auth-form');
  const authSub = document.getElementById('auth-sub');
  const authError = document.getElementById('auth-error');
  const authSubmit = document.getElementById('auth-submit');
  const authTitle = document.getElementById('auth-title');
  let setupMode = false;
  let authTitleDecoded = false;

  function showAuthScreen() {
    appRoot.classList.add('hidden');
    authScreen.classList.remove('hidden');
    if (!authTitleDecoded) { authTitleDecoded = true; decodeReveal(authTitle, 'Memento'); }
  }

  async function checkAuth() {
    const status = await api('/auth/status');
    if (status.authenticated) {
      startApp();
      return;
    }
    setupMode = status.setupNeeded;
    authSub.textContent = setupMode ? tr('auth_sub_setup') : tr('auth_sub_login');
    authSubmit.textContent = setupMode ? tr('auth_submit_setup') : tr('auth_submit_login');
    // Sul telefono c'e' una sola persona: basta la password principale.
    if (status.local) {
      const userRow = document.getElementById('auth-username').closest('label');
      userRow.classList.add('hidden');
      document.getElementById('auth-username').value = 'io';
      authSub.textContent = setupMode ? tr('local_auth_setup') : tr('local_auth_unlock');
      authSubmit.textContent = setupMode ? tr('local_auth_create') : tr('local_auth_unlock_btn');
      document.getElementById('auth-password').setAttribute('autocomplete', setupMode ? 'new-password' : 'current-password');
    }
    showAuthScreen();
    if (status.local && !setupMode && window.MementoBackend.offerBiometric) window.MementoBackend.offerBiometric(startApp);
  }

  const authCodeRow = document.getElementById('auth-code-row');
  const authCodeInput = document.getElementById('auth-code');

  authForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    authError.classList.add('hidden');
    const username = document.getElementById('auth-username').value.trim();
    const password = document.getElementById('auth-password').value;
    const code = authCodeInput.value.trim();
    try {
      if (setupMode) {
        await api('/auth/setup', { method: 'POST', body: JSON.stringify({ username, password }) });
      } else {
        await api('/auth/login', {
          method: 'POST',
          body: JSON.stringify(code ? { username, password, code } : { username, password }),
        });
      }
      startApp();
    } catch (err) {
      // La password e' giusta ma manca il secondo fattore: mostriamo il campo
      // del codice invece di far ricominciare da capo.
      if (err.data && err.data.totpRequired) {
        authCodeRow.classList.remove('hidden');
        authCodeInput.value = '';
        authCodeInput.focus();
        authSubmit.textContent = tr('auth_submit_verify');
      }
      authError.textContent = err.message;
      authError.classList.remove('hidden');
    }
  });

  // Dichiarazione (non costante) perche' viene usata anche dal foglio del
  // telefono, costruito prima di questo punto del file.
  async function logout() {
    try {
      await api('/auth/logout', { method: 'POST' });
    } catch (err) {
      // Anche se la chiamata fallisce ricarichiamo: la sessione va comunque chiusa lato client.
    }
    location.reload();
  }

  function startApp() {
    authScreen.classList.add('hidden');
    appRoot.classList.remove('hidden');
    buildNavigation();
    updateHeaderDate();
    const { view, opts } = routeFromHash();
    render(view, { ...opts, replace: true });
  }

  // ---------------- Navigation ----------------
  // Ogni sezione ha un colore pieno e un glifo bianco: le stesse tessere
  // compaiono nella barra laterale, nel foglio "Sezioni" del telefono e nelle
  // griglie di Progetti/Cartelle, cosi' una sezione si riconosce dal colore
  // prima ancora di leggerne il nome (icone piene e colorate, mai grigio minimal).
  // Icone delle sezioni: serie Phosphor (MIT, licenza in public/vendor/LICENZE.txt).
  // Nel menu e nel foglio "Altro" quadratino con sfumatura e simbolo pieno
  // bianco; nella barra in basso e nei pulsanti la versione a tratto.
  const PH = {"today":{"fill":"<path d=\"M120,40V16a8,8,0,0,1,16,0V40a8,8,0,0,1-16,0Zm8,24a64,64,0,1,0,64,64A64.07,64.07,0,0,0,128,64ZM58.34,69.66A8,8,0,0,0,69.66,58.34l-16-16A8,8,0,0,0,42.34,53.66Zm0,116.68-16,16a8,8,0,0,0,11.32,11.32l16-16a8,8,0,0,0-11.32-11.32ZM192,72a8,8,0,0,0,5.66-2.34l16-16a8,8,0,0,0-11.32-11.32l-16,16A8,8,0,0,0,192,72Zm5.66,114.34a8,8,0,0,0-11.32,11.32l16,16a8,8,0,0,0,11.32-11.32ZM48,128a8,8,0,0,0-8-8H16a8,8,0,0,0,0,16H40A8,8,0,0,0,48,128Zm80,80a8,8,0,0,0-8,8v24a8,8,0,0,0,16,0V216A8,8,0,0,0,128,208Zm112-88H216a8,8,0,0,0,0,16h24a8,8,0,0,0,0-16Z\"/>","line":"<path d=\"M120,40V16a8,8,0,0,1,16,0V40a8,8,0,0,1-16,0Zm72,88a64,64,0,1,1-64-64A64.07,64.07,0,0,1,192,128Zm-16,0a48,48,0,1,0-48,48A48.05,48.05,0,0,0,176,128ZM58.34,69.66A8,8,0,0,0,69.66,58.34l-16-16A8,8,0,0,0,42.34,53.66Zm0,116.68-16,16a8,8,0,0,0,11.32,11.32l16-16a8,8,0,0,0-11.32-11.32ZM192,72a8,8,0,0,0,5.66-2.34l16-16a8,8,0,0,0-11.32-11.32l-16,16A8,8,0,0,0,192,72Zm5.66,114.34a8,8,0,0,0-11.32,11.32l16,16a8,8,0,0,0,11.32-11.32ZM48,128a8,8,0,0,0-8-8H16a8,8,0,0,0,0,16H40A8,8,0,0,0,48,128Zm80,80a8,8,0,0,0-8,8v24a8,8,0,0,0,16,0V216A8,8,0,0,0,128,208Zm112-88H216a8,8,0,0,0,0,16h24a8,8,0,0,0,0-16Z\"/>","grad":["#FF8A65","#FF5A3C"]},"projects":{"fill":"<path d=\"M160,56v96a8,8,0,0,1-8,8H112a8,8,0,0,1-8-8V56a8,8,0,0,1,8-8h40A8,8,0,0,1,160,56Zm64-8H184a8,8,0,0,0-8,8v52a4,4,0,0,0,4,4h48a4,4,0,0,0,4-4V56A8,8,0,0,0,224,48Zm4,80H180a4,4,0,0,0-4,4v44a16,16,0,0,0,16,16h24a16,16,0,0,0,16-16V132A4,4,0,0,0,228,128ZM80,48H40a8,8,0,0,0-8,8v52a4,4,0,0,0,4,4H84a4,4,0,0,0,4-4V56A8,8,0,0,0,80,48Zm4,80H36a4,4,0,0,0-4,4v76a16,16,0,0,0,16,16H72a16,16,0,0,0,16-16V132A4,4,0,0,0,84,128Z\"/>","line":"<path d=\"M216,48H40a8,8,0,0,0-8,8V208a16,16,0,0,0,16,16H88a16,16,0,0,0,16-16V160h48v16a16,16,0,0,0,16,16h40a16,16,0,0,0,16-16V56A8,8,0,0,0,216,48ZM88,208H48V128H88Zm0-96H48V64H88Zm64,32H104V64h48Zm56,32H168V128h40Zm0-64H168V64h40Z\"/>","grad":["#8B7CFF","#5B47E0"]},"ideas":{"fill":"<path d=\"M224,128v80a16,16,0,0,1-16,16H48a16,16,0,0,1-16-16V48A16,16,0,0,1,48,32h80a8,8,0,0,1,0,16H48V208H208V128a8,8,0,0,1,16,0Zm5.66-58.34-96,96A8,8,0,0,1,128,168H96a8,8,0,0,1-8-8V128a8,8,0,0,1,2.34-5.66l96-96a8,8,0,0,1,11.32,0l32,32A8,8,0,0,1,229.66,69.66Zm-17-5.66L192,43.31,179.31,56,200,76.69Z\"/>","line":"<path d=\"M229.66,58.34l-32-32a8,8,0,0,0-11.32,0l-96,96A8,8,0,0,0,88,128v32a8,8,0,0,0,8,8h32a8,8,0,0,0,5.66-2.34l96-96A8,8,0,0,0,229.66,58.34ZM124.69,152H104V131.31l64-64L188.69,88ZM200,76.69,179.31,56,192,43.31,212.69,64ZM224,128v80a16,16,0,0,1-16,16H48a16,16,0,0,1-16-16V48A16,16,0,0,1,48,32h80a8,8,0,0,1,0,16H48V208H208V128a8,8,0,0,1,16,0Z\"/>","grad":["#FFC260","#F59E0B"]},"vault":{"fill":"<path d=\"M208,80H176V56a48,48,0,0,0-96,0V80H48A16,16,0,0,0,32,96V208a16,16,0,0,0,16,16H208a16,16,0,0,0,16-16V96A16,16,0,0,0,208,80Zm-72,78.63V184a8,8,0,0,1-16,0V158.63a24,24,0,1,1,16,0ZM160,80H96V56a32,32,0,0,1,64,0Z\"/>","line":"<path d=\"M128,112a28,28,0,0,0-8,54.83V184a8,8,0,0,0,16,0V166.83A28,28,0,0,0,128,112Zm0,40a12,12,0,1,1,12-12A12,12,0,0,1,128,152Zm80-72H176V56a48,48,0,0,0-96,0V80H48A16,16,0,0,0,32,96V208a16,16,0,0,0,16,16H208a16,16,0,0,0,16-16V96A16,16,0,0,0,208,80ZM96,56a32,32,0,0,1,64,0V80H96ZM208,208H48V96H208V208Z\"/>","grad":["#3B4A7A","#141B33"]},"cards":{"fill":"<path d=\"M200,88V200a16,16,0,0,1-16,16H40a16,16,0,0,1-16-16V88A16,16,0,0,1,40,72H184A16,16,0,0,1,200,88Zm16-48H64a8,8,0,0,0,0,16H216V176a8,8,0,0,0,16,0V56A16,16,0,0,0,216,40Z\"/>","line":"<path d=\"M184,72H40A16,16,0,0,0,24,88V200a16,16,0,0,0,16,16H184a16,16,0,0,0,16-16V88A16,16,0,0,0,184,72Zm0,128H40V88H184V200ZM232,56V176a8,8,0,0,1-16,0V56H64a8,8,0,0,1,0-16H216A16,16,0,0,1,232,56Z\"/>","grad":["#FF7AA2","#E5487A"]},"accounts":{"fill":"<path d=\"M224,48V96a8,8,0,0,1-8,8H168a8,8,0,0,1-5.66-13.66L180.65,72a79.48,79.48,0,0,0-54.72-22.09h-.45A79.52,79.52,0,0,0,69.59,72.71,8,8,0,0,1,58.41,61.27,96,96,0,0,1,192,60.7l18.36-18.36A8,8,0,0,1,224,48ZM186.41,183.29A80,80,0,0,1,75.35,184l18.31-18.31A8,8,0,0,0,88,152H40a8,8,0,0,0-8,8v48a8,8,0,0,0,13.66,5.66L64,195.3a95.42,95.42,0,0,0,66,26.76h.53a95.36,95.36,0,0,0,67.07-27.33,8,8,0,0,0-11.18-11.44Z\"/>","line":"<path d=\"M224,48V96a8,8,0,0,1-8,8H168a8,8,0,0,1,0-16h28.69L182.06,73.37a79.56,79.56,0,0,0-56.13-23.43h-.45A79.52,79.52,0,0,0,69.59,72.71,8,8,0,0,1,58.41,61.27a96,96,0,0,1,135,.79L208,76.69V48a8,8,0,0,1,16,0ZM186.41,183.29a80,80,0,0,1-112.47-.66L59.31,168H88a8,8,0,0,0,0-16H40a8,8,0,0,0-8,8v48a8,8,0,0,0,16,0V179.31l14.63,14.63A95.43,95.43,0,0,0,130,222.06h.53a95.36,95.36,0,0,0,67.07-27.33,8,8,0,0,0-11.18-11.44Z\"/>","grad":["#C77DFF","#9B4DE0"]},"drive":{"fill":"<path d=\"M247.93,124.52C246.11,77.54,207.07,40,160.06,40A88.1,88.1,0,0,0,81.29,88.67h0A87.48,87.48,0,0,0,72,127.73,8.18,8.18,0,0,1,64.57,136,8,8,0,0,1,56,128a103.66,103.66,0,0,1,5.34-32.92,4,4,0,0,0-4.75-5.18A64.09,64.09,0,0,0,8,152c0,35.19,29.75,64,65,64H160A88.09,88.09,0,0,0,247.93,124.52Zm-50.27,9.14a8,8,0,0,1-11.32,0L168,115.31V176a8,8,0,0,1-16,0V115.31l-18.34,18.35a8,8,0,0,1-11.32-11.32l32-32a8,8,0,0,1,11.32,0l32,32A8,8,0,0,1,197.66,133.66Z\"/>","line":"<path d=\"M178.34,165.66,160,147.31V208a8,8,0,0,1-16,0V147.31l-18.34,18.35a8,8,0,0,1-11.32-11.32l32-32a8,8,0,0,1,11.32,0l32,32a8,8,0,0,1-11.32,11.32ZM160,40A88.08,88.08,0,0,0,81.29,88.68,64,64,0,1,0,72,216h40a8,8,0,0,0,0-16H72a48,48,0,0,1,0-96c1.1,0,2.2,0,3.29.12A88,88,0,0,0,72,128a8,8,0,0,0,16,0,72,72,0,1,1,100.8,66,8,8,0,0,0,3.2,15.34,7.9,7.9,0,0,0,3.2-.68A88,88,0,0,0,160,40Z\"/>","grad":["#5FA8FF","#2F6BFF"]},"dossiers":{"fill":"<path d=\"M232,88V200.89A15.13,15.13,0,0,1,216.89,216H40a16,16,0,0,1-16-16V64A16,16,0,0,1,40,48H93.33a16.12,16.12,0,0,1,9.6,3.2L130.67,72H216A16,16,0,0,1,232,88Z\"/>","line":"<path d=\"M216,72H130.67L102.93,51.2a16.12,16.12,0,0,0-9.6-3.2H40A16,16,0,0,0,24,64V200a16,16,0,0,0,16,16H216.89A15.13,15.13,0,0,0,232,200.89V88A16,16,0,0,0,216,72Zm0,128H40V64H93.33L123.2,86.4A8,8,0,0,0,128,88h88Z\"/>","grad":["#4ED39A","#1F9E63"]},"reminders":{"fill":"<path d=\"M61.66,37.66l-32,32A8,8,0,0,1,18.34,58.34l32-32A8,8,0,0,1,61.66,37.66Zm176,20.68-32-32a8,8,0,0,0-11.32,11.32l32,32a8,8,0,0,0,11.32-11.32ZM224,136a96,96,0,1,1-96-96A96.11,96.11,0,0,1,224,136Zm-32,0a8,8,0,0,0-8-8H136V80a8,8,0,0,0-16,0v56a8,8,0,0,0,8,8h56A8,8,0,0,0,192,136Z\"/>","line":"<path d=\"M128,40a96,96,0,1,0,96,96A96.11,96.11,0,0,0,128,40Zm0,176a80,80,0,1,1,80-80A80.09,80.09,0,0,1,128,216ZM61.66,37.66l-32,32A8,8,0,0,1,18.34,58.34l32-32A8,8,0,0,1,61.66,37.66Zm176,32a8,8,0,0,1-11.32,0l-32-32a8,8,0,0,1,11.32-11.32l32,32A8,8,0,0,1,237.66,69.66ZM184,128a8,8,0,0,1,0,16H128a8,8,0,0,1-8-8V80a8,8,0,0,1,16,0v48Z\"/>","grad":["#FF6B6B","#E5484D"]},"calendar":{"fill":"<path d=\"M208,32H184V24a8,8,0,0,0-16,0v8H88V24a8,8,0,0,0-16,0v8H48A16,16,0,0,0,32,48V208a16,16,0,0,0,16,16H208a16,16,0,0,0,16-16V48A16,16,0,0,0,208,32ZM84,184a12,12,0,1,1,12-12A12,12,0,0,1,84,184Zm44,0a12,12,0,1,1,12-12A12,12,0,0,1,128,184Zm0-40a12,12,0,1,1,12-12A12,12,0,0,1,128,144Zm44,40a12,12,0,1,1,12-12A12,12,0,0,1,172,184Zm0-40a12,12,0,1,1,12-12A12,12,0,0,1,172,144Zm36-64H48V48H72v8a8,8,0,0,0,16,0V48h80v8a8,8,0,0,0,16,0V48h24Z\"/>","line":"<path d=\"M208,32H184V24a8,8,0,0,0-16,0v8H88V24a8,8,0,0,0-16,0v8H48A16,16,0,0,0,32,48V208a16,16,0,0,0,16,16H208a16,16,0,0,0,16-16V48A16,16,0,0,0,208,32ZM72,48v8a8,8,0,0,0,16,0V48h80v8a8,8,0,0,0,16,0V48h24V80H48V48ZM208,208H48V96H208V208Zm-68-76a12,12,0,1,1-12-12A12,12,0,0,1,140,132Zm44,0a12,12,0,1,1-12-12A12,12,0,0,1,184,132ZM96,172a12,12,0,1,1-12-12A12,12,0,0,1,96,172Zm44,0a12,12,0,1,1-12-12A12,12,0,0,1,140,172Zm44,0a12,12,0,1,1-12-12A12,12,0,0,1,184,172Z\"/>","grad":["#5FA8FF","#2F6BFF"]},"trash":{"fill":"<path d=\"M216,48H176V40a24,24,0,0,0-24-24H104A24,24,0,0,0,80,40v8H40a8,8,0,0,0,0,16h8V208a16,16,0,0,0,16,16H192a16,16,0,0,0,16-16V64h8a8,8,0,0,0,0-16ZM112,168a8,8,0,0,1-16,0V104a8,8,0,0,1,16,0Zm48,0a8,8,0,0,1-16,0V104a8,8,0,0,1,16,0Zm0-120H96V40a8,8,0,0,1,8-8h48a8,8,0,0,1,8,8Z\"/>","line":"<path d=\"M216,48H176V40a24,24,0,0,0-24-24H104A24,24,0,0,0,80,40v8H40a8,8,0,0,0,0,16h8V208a16,16,0,0,0,16,16H192a16,16,0,0,0,16-16V64h8a8,8,0,0,0,0-16ZM96,40a8,8,0,0,1,8-8h48a8,8,0,0,1,8,8v8H96Zm96,168H64V64H192ZM112,104v64a8,8,0,0,1-16,0V104a8,8,0,0,1,16,0Zm48,0v64a8,8,0,0,1-16,0V104a8,8,0,0,1,16,0Z\"/>","grad":["#A1A7B3","#6B7280"]},"security":{"fill":"<path d=\"M237.94,107.21a8,8,0,0,0-3.89-5.4l-29.83-17-.12-33.62a8,8,0,0,0-2.83-6.08,111.91,111.91,0,0,0-36.72-20.67,8,8,0,0,0-6.46.59L128,41.85,97.88,25a8,8,0,0,0-6.47-.6A111.92,111.92,0,0,0,54.73,45.15a8,8,0,0,0-2.83,6.07l-.15,33.65-29.83,17a8,8,0,0,0-3.89,5.4,106.47,106.47,0,0,0,0,41.56,8,8,0,0,0,3.89,5.4l29.83,17,.12,33.63a8,8,0,0,0,2.83,6.08,111.91,111.91,0,0,0,36.72,20.67,8,8,0,0,0,6.46-.59L128,214.15,158.12,231a7.91,7.91,0,0,0,3.9,1,8.09,8.09,0,0,0,2.57-.42,112.1,112.1,0,0,0,36.68-20.73,8,8,0,0,0,2.83-6.07l.15-33.65,29.83-17a8,8,0,0,0,3.89-5.4A106.47,106.47,0,0,0,237.94,107.21ZM128,168a40,40,0,1,1,40-40A40,40,0,0,1,128,168Z\"/>","line":"<path d=\"M128,80a48,48,0,1,0,48,48A48.05,48.05,0,0,0,128,80Zm0,80a32,32,0,1,1,32-32A32,32,0,0,1,128,160Zm109.94-52.79a8,8,0,0,0-3.89-5.4l-29.83-17-.12-33.62a8,8,0,0,0-2.83-6.08,111.91,111.91,0,0,0-36.72-20.67,8,8,0,0,0-6.46.59L128,41.85,97.88,25a8,8,0,0,0-6.47-.6A112.1,112.1,0,0,0,54.73,45.15a8,8,0,0,0-2.83,6.07l-.15,33.65-29.83,17a8,8,0,0,0-3.89,5.4,106.47,106.47,0,0,0,0,41.56,8,8,0,0,0,3.89,5.4l29.83,17,.12,33.62a8,8,0,0,0,2.83,6.08,111.91,111.91,0,0,0,36.72,20.67,8,8,0,0,0,6.46-.59L128,214.15,158.12,231a7.91,7.91,0,0,0,3.9,1,8.09,8.09,0,0,0,2.57-.42,112.1,112.1,0,0,0,36.68-20.73,8,8,0,0,0,2.83-6.07l.15-33.65,29.83-17a8,8,0,0,0,3.89-5.4A106.47,106.47,0,0,0,237.94,107.21Zm-15,34.91-28.57,16.25a8,8,0,0,0-3,3c-.58,1-1.19,2.06-1.81,3.06a7.94,7.94,0,0,0-1.22,4.21l-.15,32.25a95.89,95.89,0,0,1-25.37,14.3L134,199.13a8,8,0,0,0-3.91-1h-.19c-1.21,0-2.43,0-3.64,0a8.08,8.08,0,0,0-4.1,1l-28.84,16.1A96,96,0,0,1,67.88,201l-.11-32.2a8,8,0,0,0-1.22-4.22c-.62-1-1.23-2-1.8-3.06a8.09,8.09,0,0,0-3-3.06l-28.6-16.29a90.49,90.49,0,0,1,0-28.26L61.67,97.63a8,8,0,0,0,3-3c.58-1,1.19-2.06,1.81-3.06a7.94,7.94,0,0,0,1.22-4.21l.15-32.25a95.89,95.89,0,0,1,25.37-14.3L122,56.87a8,8,0,0,0,4.1,1c1.21,0,2.43,0,3.64,0a8.08,8.08,0,0,0,4.1-1l28.84-16.1A96,96,0,0,1,188.12,55l.11,32.2a8,8,0,0,0,1.22,4.22c.62,1,1.23,2,1.8,3.06a8.09,8.09,0,0,0,3,3.06l28.6,16.29A90.49,90.49,0,0,1,222.9,142.12Z\"/>","grad":["#A1A7B3","#6B7280"]},"esci":{"fill":"<path d=\"M120,216a8,8,0,0,1-8,8H48a8,8,0,0,1-8-8V40a8,8,0,0,1,8-8h64a8,8,0,0,1,0,16H56V208h56A8,8,0,0,1,120,216Zm109.66-93.66-40-40A8,8,0,0,0,176,88v32H112a8,8,0,0,0,0,16h64v32a8,8,0,0,0,13.66,5.66l40-40A8,8,0,0,0,229.66,122.34Z\"/>","line":"<path d=\"M120,216a8,8,0,0,1-8,8H48a8,8,0,0,1-8-8V40a8,8,0,0,1,8-8h64a8,8,0,0,1,0,16H56V208h56A8,8,0,0,1,120,216Zm109.66-93.66-40-40a8,8,0,0,0-11.32,11.32L204.69,120H112a8,8,0,0,0,0,16h92.69l-26.35,26.34a8,8,0,0,0,11.32,11.32l40-40A8,8,0,0,0,229.66,122.34Z\"/>","grad":["#A1A7B3","#6B7280"]},"more":{"fill":"<path d=\"M156,128a28,28,0,1,1-28-28A28,28,0,0,1,156,128ZM48,100a28,28,0,1,0,28,28A28,28,0,0,0,48,100Zm160,0a28,28,0,1,0,28,28A28,28,0,0,0,208,100Z\"/>","line":"<path d=\"M128,96a32,32,0,1,0,32,32A32,32,0,0,0,128,96Zm0,48a16,16,0,1,1,16-16A16,16,0,0,1,128,144ZM48,96a32,32,0,1,0,32,32A32,32,0,0,0,48,96Zm0,48a16,16,0,1,1,16-16A16,16,0,0,1,48,144ZM208,96a32,32,0,1,0,32,32A32,32,0,0,0,208,96Zm0,48a16,16,0,1,1,16-16A16,16,0,0,1,208,144Z\"/>"},"search":{"fill":"<path d=\"M168,112a56,56,0,1,1-56-56A56,56,0,0,1,168,112Zm61.66,117.66a8,8,0,0,1-11.32,0l-50.06-50.07a88,88,0,1,1,11.32-11.31l50.06,50.06A8,8,0,0,1,229.66,229.66ZM112,184a72,72,0,1,0-72-72A72.08,72.08,0,0,0,112,184Z\"/>","line":"<path d=\"M229.66,218.34l-50.07-50.06a88.11,88.11,0,1,0-11.31,11.31l50.06,50.07a8,8,0,0,0,11.32-11.32ZM40,112a72,72,0,1,1,72,72A72.08,72.08,0,0,1,40,112Z\"/>"}};
  const APP_TILES = Object.fromEntries(Object.entries(PH).filter(([, v]) => v.grad).map(([k, v]) => [k, { color: v.grad[1], grad: v.grad, fill: v.fill, line: v.line }]));

  let appIconSeq = 0;
  function appIcon(nome, size = 18) {
    const t = APP_TILES[nome];
    if (!t) return '';
    // id unico: un gradiente definito dentro un elemento nascosto (es. la
    // barra laterale sul telefono) non viene disegnato altrove.
    const id = `ph-g-${nome}-${++appIconSeq}`;
    return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" aria-hidden="true" class="app-tile"><defs><linearGradient id="${id}" x1="0" y1="0" x2="0.35" y2="1"><stop offset="0" stop-color="${t.grad[0]}"/><stop offset="1" stop-color="${t.grad[1]}"/></linearGradient></defs><rect width="24" height="24" rx="7" fill="url(#${id})"/><svg x="5.5" y="5.5" width="13" height="13" viewBox="0 0 256 256" fill="#fff">${t.fill}</svg></svg>`;
  }
  // Simbolo a tratto (Phosphor regular) che prende il colore del testo.
  function lineIcon(nome, size = 24) {
    const t = PH[nome];
    return t ? `<svg width="${size}" height="${size}" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true">${t.line}</svg>` : '';
  }

  // Simboli d'interfaccia: stessa famiglia della barra in basso (Phosphor).
  // Peso "bold" per i tasti piccoli (fino a 20px), "regular" per i grandi,
  // cosi' il tratto resta simile a ogni dimensione.
  const PI = {"magnifying-glass":["<path d=\"M229.66,218.34l-50.07-50.06a88.11,88.11,0,1,0-11.31,11.31l50.06,50.07a8,8,0,0,0,11.32-11.32ZM40,112a72,72,0,1,1,72,72A72.08,72.08,0,0,1,40,112Z\"/>","<path d=\"M232.49,215.51,185,168a92.12,92.12,0,1,0-17,17l47.53,47.54a12,12,0,0,0,17-17ZM44,112a68,68,0,1,1,68,68A68.07,68.07,0,0,1,44,112Z\"/>"],"x":["<path d=\"M205.66,194.34a8,8,0,0,1-11.32,11.32L128,139.31,61.66,205.66a8,8,0,0,1-11.32-11.32L116.69,128,50.34,61.66A8,8,0,0,1,61.66,50.34L128,116.69l66.34-66.35a8,8,0,0,1,11.32,11.32L139.31,128Z\"/>","<path d=\"M208.49,191.51a12,12,0,0,1-17,17L128,145,64.49,208.49a12,12,0,0,1-17-17L111,128,47.51,64.49a12,12,0,0,1,17-17L128,111l63.51-63.52a12,12,0,0,1,17,17L145,128Z\"/>"],"eye":["<path d=\"M247.31,124.76c-.35-.79-8.82-19.58-27.65-38.41C194.57,61.26,162.88,48,128,48S61.43,61.26,36.34,86.35C17.51,105.18,9,124,8.69,124.76a8,8,0,0,0,0,6.5c.35.79,8.82,19.57,27.65,38.4C61.43,194.74,93.12,208,128,208s66.57-13.26,91.66-38.34c18.83-18.83,27.3-37.61,27.65-38.4A8,8,0,0,0,247.31,124.76ZM128,192c-30.78,0-57.67-11.19-79.93-33.25A133.47,133.47,0,0,1,25,128,133.33,133.33,0,0,1,48.07,97.25C70.33,75.19,97.22,64,128,64s57.67,11.19,79.93,33.25A133.46,133.46,0,0,1,231.05,128C223.84,141.46,192.43,192,128,192Zm0-112a48,48,0,1,0,48,48A48.05,48.05,0,0,0,128,80Zm0,80a32,32,0,1,1,32-32A32,32,0,0,1,128,160Z\"/>","<path d=\"M251,123.13c-.37-.81-9.13-20.26-28.48-39.61C196.63,57.67,164,44,128,44S59.37,57.67,33.51,83.52C14.16,102.87,5.4,122.32,5,123.13a12.08,12.08,0,0,0,0,9.75c.37.82,9.13,20.26,28.49,39.61C59.37,198.34,92,212,128,212s68.63-13.66,94.48-39.51c19.36-19.35,28.12-38.79,28.49-39.61A12.08,12.08,0,0,0,251,123.13Zm-46.06,33C183.47,177.27,157.59,188,128,188s-55.47-10.73-76.91-31.88A130.36,130.36,0,0,1,29.52,128,130.45,130.45,0,0,1,51.09,99.89C72.54,78.73,98.41,68,128,68s55.46,10.73,76.91,31.89A130.36,130.36,0,0,1,226.48,128,130.45,130.45,0,0,1,204.91,156.12ZM128,84a44,44,0,1,0,44,44A44.05,44.05,0,0,0,128,84Zm0,64a20,20,0,1,1,20-20A20,20,0,0,1,128,148Z\"/>"],"eye-slash":["<path d=\"M53.92,34.62A8,8,0,1,0,42.08,45.38L61.32,66.55C25,88.84,9.38,123.2,8.69,124.76a8,8,0,0,0,0,6.5c.35.79,8.82,19.57,27.65,38.4C61.43,194.74,93.12,208,128,208a127.11,127.11,0,0,0,52.07-10.83l22,24.21a8,8,0,1,0,11.84-10.76Zm47.33,75.84,41.67,45.85a32,32,0,0,1-41.67-45.85ZM128,192c-30.78,0-57.67-11.19-79.93-33.25A133.16,133.16,0,0,1,25,128c4.69-8.79,19.66-33.39,47.35-49.38l18,19.75a48,48,0,0,0,63.66,70l14.73,16.2A112,112,0,0,1,128,192Zm6-95.43a8,8,0,0,1,3-15.72,48.16,48.16,0,0,1,38.77,42.64,8,8,0,0,1-7.22,8.71,6.39,6.39,0,0,1-.75,0,8,8,0,0,1-8-7.26A32.09,32.09,0,0,0,134,96.57Zm113.28,34.69c-.42.94-10.55,23.37-33.36,43.8a8,8,0,1,1-10.67-11.92A132.77,132.77,0,0,0,231.05,128a133.15,133.15,0,0,0-23.12-30.77C185.67,75.19,158.78,64,128,64a118.37,118.37,0,0,0-19.36,1.57A8,8,0,1,1,106,49.79,134,134,0,0,1,128,48c34.88,0,66.57,13.26,91.66,38.35,18.83,18.83,27.3,37.62,27.65,38.41A8,8,0,0,1,247.31,131.26Z\"/>","<path d=\"M56.88,31.93A12,12,0,1,0,39.12,48.07l16,17.65C20.67,88.66,5.72,121.58,5,123.13a12.08,12.08,0,0,0,0,9.75c.37.82,9.13,20.26,28.49,39.61C59.37,198.34,92,212,128,212a131.34,131.34,0,0,0,51-10l20.09,22.1a12,12,0,0,0,17.76-16.14ZM128,188c-29.59,0-55.47-10.73-76.91-31.88A130.69,130.69,0,0,1,29.52,128c5.27-9.31,18.79-29.9,42-44.29l90.09,99.11A109.33,109.33,0,0,1,128,188Zm123-55.12c-.36.81-9,20-28,39.16a12,12,0,1,1-17-16.9A130.48,130.48,0,0,0,226.48,128a130.36,130.36,0,0,0-21.57-28.12C183.46,78.73,157.59,68,128,68c-3.35,0-6.7.14-10,.42a12,12,0,1,1-2-23.91c3.93-.34,8-.51,12-.51,36,0,68.63,13.67,94.49,39.52,19.35,19.35,28.11,38.8,28.48,39.61A12.08,12.08,0,0,1,251,132.88Z\"/>"],"pencil-simple":["<path d=\"M227.31,73.37,182.63,28.68a16,16,0,0,0-22.63,0L36.69,152A15.86,15.86,0,0,0,32,163.31V208a16,16,0,0,0,16,16H92.69A15.86,15.86,0,0,0,104,219.31L227.31,96a16,16,0,0,0,0-22.63ZM92.69,208H48V163.31l88-88L180.69,120ZM192,108.68,147.31,64l24-24L216,84.68Z\"/>","<path d=\"M230.14,70.54,185.46,25.85a20,20,0,0,0-28.29,0L33.86,149.17A19.85,19.85,0,0,0,28,163.31V208a20,20,0,0,0,20,20H92.69a19.86,19.86,0,0,0,14.14-5.86L230.14,98.82a20,20,0,0,0,0-28.28ZM91,204H52V165l84-84,39,39ZM192,103,153,64l18.34-18.34,39,39Z\"/>"],"folder":["<path d=\"M216,72H131.31L104,44.69A15.86,15.86,0,0,0,92.69,40H40A16,16,0,0,0,24,56V200.62A15.4,15.4,0,0,0,39.38,216H216.89A15.13,15.13,0,0,0,232,200.89V88A16,16,0,0,0,216,72ZM40,56H92.69l16,16H40ZM216,200H40V88H216Z\"/>","<path d=\"M216,68H133.39l-26-29.29a20,20,0,0,0-15-6.71H40A20,20,0,0,0,20,52V200.62A19.41,19.41,0,0,0,39.38,220H216.89A19.13,19.13,0,0,0,236,200.89V88A20,20,0,0,0,216,68ZM44,56H90.61l10.67,12H44ZM212,196H44V92H212Z\"/>"],"trash":["<path d=\"M216,48H176V40a24,24,0,0,0-24-24H104A24,24,0,0,0,80,40v8H40a8,8,0,0,0,0,16h8V208a16,16,0,0,0,16,16H192a16,16,0,0,0,16-16V64h8a8,8,0,0,0,0-16ZM96,40a8,8,0,0,1,8-8h48a8,8,0,0,1,8,8v8H96Zm96,168H64V64H192ZM112,104v64a8,8,0,0,1-16,0V104a8,8,0,0,1,16,0Zm48,0v64a8,8,0,0,1-16,0V104a8,8,0,0,1,16,0Z\"/>","<path d=\"M216,48H180V36A28,28,0,0,0,152,8H104A28,28,0,0,0,76,36V48H40a12,12,0,0,0,0,24h4V208a20,20,0,0,0,20,20H192a20,20,0,0,0,20-20V72h4a12,12,0,0,0,0-24ZM100,36a4,4,0,0,1,4-4h48a4,4,0,0,1,4,4V48H100Zm88,168H68V72H188ZM116,104v64a12,12,0,0,1-24,0V104a12,12,0,0,1,24,0Zm48,0v64a12,12,0,0,1-24,0V104a12,12,0,0,1,24,0Z\"/>"],"image":["<path d=\"M216,40H40A16,16,0,0,0,24,56V200a16,16,0,0,0,16,16H216a16,16,0,0,0,16-16V56A16,16,0,0,0,216,40Zm0,16V158.75l-26.07-26.06a16,16,0,0,0-22.63,0l-20,20-44-44a16,16,0,0,0-22.62,0L40,149.37V56ZM40,172l52-52,80,80H40Zm176,28H194.63l-36-36,20-20L216,181.38V200ZM144,100a12,12,0,1,1,12,12A12,12,0,0,1,144,100Z\"/>","<path d=\"M144,96a16,16,0,1,1,16,16A16,16,0,0,1,144,96Zm92-40V200a20,20,0,0,1-20,20H40a20,20,0,0,1-20-20V56A20,20,0,0,1,40,36H216A20,20,0,0,1,236,56ZM44,60v79.72l33.86-33.86a20,20,0,0,1,28.28,0L147.31,147l17.18-17.17a20,20,0,0,1,28.28,0L212,149.09V60Zm0,136H162.34L92,125.66l-48,48Zm168,0V183l-33.37-33.37L164.28,164l32,32Z\"/>"],"music-note":["<path d=\"M210.3,56.34l-80-24A8,8,0,0,0,120,40V148.26A48,48,0,1,0,136,184V98.75l69.7,20.91A8,8,0,0,0,216,112V64A8,8,0,0,0,210.3,56.34ZM88,216a32,32,0,1,1,32-32A32,32,0,0,1,88,216ZM200,101.25l-64-19.2V50.75L200,70Z\"/>","<path d=\"M211.45,52.51l-80-24A12,12,0,0,0,116,40V140.22A52,52,0,1,0,140,184V104.13l64.55,19.36A12,12,0,0,0,220,112V64A12,12,0,0,0,211.45,52.51ZM88,212a28,28,0,1,1,28-28A28,28,0,0,1,88,212ZM196,95.87l-56-16.8V56.13l56,16.8Z\"/>"],"video":["<path d=\"M164.44,105.34l-48-32A8,8,0,0,0,104,80v64a8,8,0,0,0,12.44,6.66l48-32a8,8,0,0,0,0-13.32ZM120,129.05V95l25.58,17ZM216,40H40A16,16,0,0,0,24,56V168a16,16,0,0,0,16,16H216a16,16,0,0,0,16-16V56A16,16,0,0,0,216,40Zm0,128H40V56H216V168Zm16,40a8,8,0,0,1-8,8H32a8,8,0,0,1,0-16H224A8,8,0,0,1,232,208Z\"/>","<path d=\"M216,36H40A20,20,0,0,0,20,56V160a20,20,0,0,0,20,20H216a20,20,0,0,0,20-20V56A20,20,0,0,0,216,36Zm-4,120H44V60H212Zm24,52a12,12,0,0,1-12,12H32a12,12,0,0,1,0-24H224A12,12,0,0,1,236,208ZM104,128V88a12,12,0,0,1,18.36-10.18l32,20a12,12,0,0,1,0,20.36l-32,20A12,12,0,0,1,104,128Z\"/>"],"file-text":["<path d=\"M213.66,82.34l-56-56A8,8,0,0,0,152,24H56A16,16,0,0,0,40,40V216a16,16,0,0,0,16,16H200a16,16,0,0,0,16-16V88A8,8,0,0,0,213.66,82.34ZM160,51.31,188.69,80H160ZM200,216H56V40h88V88a8,8,0,0,0,8,8h48V216Zm-32-80a8,8,0,0,1-8,8H96a8,8,0,0,1,0-16h64A8,8,0,0,1,168,136Zm0,32a8,8,0,0,1-8,8H96a8,8,0,0,1,0-16h64A8,8,0,0,1,168,168Z\"/>","<path d=\"M216.49,79.52l-56-56A12,12,0,0,0,152,20H56A20,20,0,0,0,36,40V216a20,20,0,0,0,20,20H200a20,20,0,0,0,20-20V88A12,12,0,0,0,216.49,79.52ZM160,57l23,23H160ZM60,212V44h76V92a12,12,0,0,0,12,12h48V212Zm112-80a12,12,0,0,1-12,12H96a12,12,0,0,1,0-24h64A12,12,0,0,1,172,132Zm0,40a12,12,0,0,1-12,12H96a12,12,0,0,1,0-24h64A12,12,0,0,1,172,172Z\"/>"],"plus":["<path d=\"M224,128a8,8,0,0,1-8,8H136v80a8,8,0,0,1-16,0V136H40a8,8,0,0,1,0-16h80V40a8,8,0,0,1,16,0v80h80A8,8,0,0,1,224,128Z\"/>","<path d=\"M228,128a12,12,0,0,1-12,12H140v76a12,12,0,0,1-24,0V140H40a12,12,0,0,1,0-24h76V40a12,12,0,0,1,24,0v76h76A12,12,0,0,1,228,128Z\"/>"],"check":["<path d=\"M229.66,77.66l-128,128a8,8,0,0,1-11.32,0l-56-56a8,8,0,0,1,11.32-11.32L96,188.69,218.34,66.34a8,8,0,0,1,11.32,11.32Z\"/>","<path d=\"M232.49,80.49l-128,128a12,12,0,0,1-17,0l-56-56a12,12,0,1,1,17-17L96,183,215.51,63.51a12,12,0,0,1,17,17Z\"/>"],"clock-clockwise":["<path d=\"M136,80v43.47l36.12,21.67a8,8,0,0,1-8.24,13.72l-40-24A8,8,0,0,1,120,128V80a8,8,0,0,1,16,0Zm88-24a8,8,0,0,0-8,8V82c-6.35-7.36-12.83-14.45-20.12-21.83a96,96,0,1,0-2,137.7,8,8,0,0,0-11-11.64A80,80,0,1,1,184.54,71.4C192.68,79.64,199.81,87.58,207,96H184a8,8,0,0,0,0,16h40a8,8,0,0,0,8-8V64A8,8,0,0,0,224,56Z\"/>","<path d=\"M140,80v41.21l34.17,20.5a12,12,0,1,1-12.34,20.58l-40-24A12,12,0,0,1,116,128V80a12,12,0,0,1,24,0Zm84-28a12,12,0,0,0-12,12v7.37c-4.21-4.67-8.58-9.31-13.29-14.08a100,100,0,1,0-2.07,143.44,12,12,0,0,0-16.48-17.46,76,76,0,1,1,1.53-109.06C187.61,80.2,193,86,198.23,92H184a12,12,0,0,0,0,24h40a12,12,0,0,0,12-12V64A12,12,0,0,0,224,52Z\"/>"],"copy":["<path d=\"M216,32H88a8,8,0,0,0-8,8V80H40a8,8,0,0,0-8,8V216a8,8,0,0,0,8,8H168a8,8,0,0,0,8-8V176h40a8,8,0,0,0,8-8V40A8,8,0,0,0,216,32ZM160,208H48V96H160Zm48-48H176V88a8,8,0,0,0-8-8H96V48H208Z\"/>","<path d=\"M216,28H88A12,12,0,0,0,76,40V76H40A12,12,0,0,0,28,88V216a12,12,0,0,0,12,12H168a12,12,0,0,0,12-12V180h36a12,12,0,0,0,12-12V40A12,12,0,0,0,216,28ZM156,204H52V100H156Zm48-48H180V88a12,12,0,0,0-12-12H100V52H204Z\"/>"],"caret-right":["<path d=\"M181.66,133.66l-80,80a8,8,0,0,1-11.32-11.32L164.69,128,90.34,53.66a8,8,0,0,1,11.32-11.32l80,80A8,8,0,0,1,181.66,133.66Z\"/>","<path d=\"M184.49,136.49l-80,80a12,12,0,0,1-17-17L159,128,87.51,56.49a12,12,0,1,1,17-17l80,80A12,12,0,0,1,184.49,136.49Z\"/>"],"note":["<path d=\"M88,96a8,8,0,0,1,8-8h64a8,8,0,0,1,0,16H96A8,8,0,0,1,88,96Zm8,40h64a8,8,0,0,0,0-16H96a8,8,0,0,0,0,16Zm32,16H96a8,8,0,0,0,0,16h32a8,8,0,0,0,0-16ZM224,48V156.69A15.86,15.86,0,0,1,219.31,168L168,219.31A15.86,15.86,0,0,1,156.69,224H48a16,16,0,0,1-16-16V48A16,16,0,0,1,48,32H208A16,16,0,0,1,224,48ZM48,208H152V160a8,8,0,0,1,8-8h48V48H48Zm120-40v28.7L196.69,168Z\"/>","<path d=\"M84,108A12,12,0,0,1,96,96h64a12,12,0,0,1,0,24H96A12,12,0,0,1,84,108Zm32,28H96a12,12,0,0,0,0,24h20a12,12,0,0,0,0-24ZM228,48V156.69a19.86,19.86,0,0,1-5.86,14.14l-51.31,51.31A19.86,19.86,0,0,1,156.69,228H48a20,20,0,0,1-20-20V48A20,20,0,0,1,48,28H208A20,20,0,0,1,228,48ZM52,204h92V156a12,12,0,0,1,12-12h48V52H52Zm139-36H168v23Z\"/>"],"camera":["<path d=\"M208,56H180.28L166.65,35.56A8,8,0,0,0,160,32H96a8,8,0,0,0-6.65,3.56L75.71,56H48A24,24,0,0,0,24,80V192a24,24,0,0,0,24,24H208a24,24,0,0,0,24-24V80A24,24,0,0,0,208,56Zm8,136a8,8,0,0,1-8,8H48a8,8,0,0,1-8-8V80a8,8,0,0,1,8-8H80a8,8,0,0,0,6.66-3.56L100.28,48h55.43l13.63,20.44A8,8,0,0,0,176,72h32a8,8,0,0,1,8,8ZM128,88a44,44,0,1,0,44,44A44.05,44.05,0,0,0,128,88Zm0,72a28,28,0,1,1,28-28A28,28,0,0,1,128,160Z\"/>","<path d=\"M208,52H182.42L170,33.34A12,12,0,0,0,160,28H96a12,12,0,0,0-10,5.34L73.57,52H48A28,28,0,0,0,20,80V192a28,28,0,0,0,28,28H208a28,28,0,0,0,28-28V80A28,28,0,0,0,208,52Zm4,140a4,4,0,0,1-4,4H48a4,4,0,0,1-4-4V80a4,4,0,0,1,4-4H80a12,12,0,0,0,10-5.34L102.42,52h51.15L166,70.66A12,12,0,0,0,176,76h32a4,4,0,0,1,4,4ZM128,84a48,48,0,1,0,48,48A48.05,48.05,0,0,0,128,84Zm0,72a24,24,0,1,1,24-24A24,24,0,0,1,128,156Z\"/>"],"share-network":["<path d=\"M176,160a39.89,39.89,0,0,0-28.62,12.09l-46.1-29.63a39.8,39.8,0,0,0,0-28.92l46.1-29.63a40,40,0,1,0-8.66-13.45l-46.1,29.63a40,40,0,1,0,0,55.82l46.1,29.63A40,40,0,1,0,176,160Zm0-128a24,24,0,1,1-24,24A24,24,0,0,1,176,32ZM64,152a24,24,0,1,1,24-24A24,24,0,0,1,64,152Zm112,72a24,24,0,1,1,24-24A24,24,0,0,1,176,224Z\"/>","<path d=\"M176,156a43.78,43.78,0,0,0-29.09,11L106.1,140.8a44.07,44.07,0,0,0,0-25.6L146.91,89a43.83,43.83,0,1,0-13-20.17L93.09,95a44,44,0,1,0,0,65.94L133.9,187.2A44,44,0,1,0,176,156Zm0-120a20,20,0,1,1-20,20A20,20,0,0,1,176,36ZM64,148a20,20,0,1,1,20-20A20,20,0,0,1,64,148Zm112,72a20,20,0,1,1,20-20A20,20,0,0,1,176,220Z\"/>"],"user":["<path d=\"M230.92,212c-15.23-26.33-38.7-45.21-66.09-54.16a72,72,0,1,0-73.66,0C63.78,166.78,40.31,185.66,25.08,212a8,8,0,1,0,13.85,8c18.84-32.56,52.14-52,89.07-52s70.23,19.44,89.07,52a8,8,0,1,0,13.85-8ZM72,96a56,56,0,1,1,56,56A56.06,56.06,0,0,1,72,96Z\"/>","<path d=\"M234.38,210a123.36,123.36,0,0,0-60.78-53.23,76,76,0,1,0-91.2,0A123.36,123.36,0,0,0,21.62,210a12,12,0,1,0,20.77,12c18.12-31.32,50.12-50,85.61-50s67.49,18.69,85.61,50a12,12,0,0,0,20.77-12ZM76,96a52,52,0,1,1,52,52A52.06,52.06,0,0,1,76,96Z\"/>"],"password":["<path d=\"M48,56V200a8,8,0,0,1-16,0V56a8,8,0,0,1,16,0Zm92,54.5L120,117V96a8,8,0,0,0-16,0v21L84,110.5a8,8,0,0,0-5,15.22l20,6.49-12.34,17a8,8,0,1,0,12.94,9.4l12.34-17,12.34,17a8,8,0,1,0,12.94-9.4l-12.34-17,20-6.49A8,8,0,0,0,140,110.5ZM246,115.64A8,8,0,0,0,236,110.5L216,117V96a8,8,0,0,0-16,0v21l-20-6.49a8,8,0,0,0-4.95,15.22l20,6.49-12.34,17a8,8,0,1,0,12.94,9.4l12.34-17,12.34,17a8,8,0,1,0,12.94-9.4l-12.34-17,20-6.49A8,8,0,0,0,246,115.64Z\"/>","<path d=\"M48,56V200a12,12,0,0,1-24,0V56a12,12,0,0,1,24,0Zm86.73,50.7L120,111.48V96a12,12,0,0,0-24,0v15.48L81.27,106.7a12,12,0,1,0-7.41,22.82l14.72,4.79-9.1,12.52A12,12,0,1,0,98.9,160.94l9.1-12.52,9.1,12.52a12,12,0,1,0,19.42-14.11l-9.1-12.52,14.72-4.79a12,12,0,1,0-7.41-22.82Zm115.12,7.7a12,12,0,0,0-15.12-7.7L220,111.48V96a12,12,0,0,0-24,0v15.48l-14.73-4.78a12,12,0,1,0-7.41,22.82l14.72,4.79-9.1,12.52a12,12,0,1,0,19.42,14.11l9.1-12.52,9.1,12.52a12,12,0,1,0,19.42-14.11l-9.1-12.52,14.72-4.79A12,12,0,0,0,249.85,114.4Z\"/>"],"credit-card":["<path d=\"M224,48H32A16,16,0,0,0,16,64V192a16,16,0,0,0,16,16H224a16,16,0,0,0,16-16V64A16,16,0,0,0,224,48Zm0,16V88H32V64Zm0,128H32V104H224v88Zm-16-24a8,8,0,0,1-8,8H168a8,8,0,0,1,0-16h32A8,8,0,0,1,208,168Zm-64,0a8,8,0,0,1-8,8H120a8,8,0,0,1,0-16h16A8,8,0,0,1,144,168Z\"/>","<path d=\"M224,44H32A20,20,0,0,0,12,64V192a20,20,0,0,0,20,20H224a20,20,0,0,0,20-20V64A20,20,0,0,0,224,44Zm-4,24V88H36V68ZM36,188V112H220v76Zm172-24a12,12,0,0,1-12,12H164a12,12,0,0,1,0-24h32A12,12,0,0,1,208,164Zm-68,0a12,12,0,0,1-12,12H116a12,12,0,0,1,0-24h12A12,12,0,0,1,140,164Z\"/>"],"arrow-left":["<path d=\"M224,128a8,8,0,0,1-8,8H59.31l58.35,58.34a8,8,0,0,1-11.32,11.32l-72-72a8,8,0,0,1,0-11.32l72-72a8,8,0,0,1,11.32,11.32L59.31,120H216A8,8,0,0,1,224,128Z\"/>","<path d=\"M228,128a12,12,0,0,1-12,12H69l51.52,51.51a12,12,0,0,1-17,17l-72-72a12,12,0,0,1,0-17l72-72a12,12,0,0,1,17,17L69,116H216A12,12,0,0,1,228,128Z\"/>"],"arrow-right":["<path d=\"M221.66,133.66l-72,72a8,8,0,0,1-11.32-11.32L196.69,136H40a8,8,0,0,1,0-16H196.69L138.34,61.66a8,8,0,0,1,11.32-11.32l72,72A8,8,0,0,1,221.66,133.66Z\"/>","<path d=\"M224.49,136.49l-72,72a12,12,0,0,1-17-17L187,140H40a12,12,0,0,1,0-24H187L135.51,64.48a12,12,0,0,1,17-17l72,72A12,12,0,0,1,224.49,136.49Z\"/>"],"dots-six":["<path d=\"M72,92A12,12,0,1,1,60,80,12,12,0,0,1,72,92Zm56-12a12,12,0,1,0,12,12A12,12,0,0,0,128,80Zm68,24a12,12,0,1,0-12-12A12,12,0,0,0,196,104ZM60,152a12,12,0,1,0,12,12A12,12,0,0,0,60,152Zm68,0a12,12,0,1,0,12,12A12,12,0,0,0,128,152Zm68,0a12,12,0,1,0,12,12A12,12,0,0,0,196,152Z\"/>","<path d=\"M76,92A16,16,0,1,1,60,76,16,16,0,0,1,76,92Zm52-16a16,16,0,1,0,16,16A16,16,0,0,0,128,76Zm68,32a16,16,0,1,0-16-16A16,16,0,0,0,196,108ZM60,148a16,16,0,1,0,16,16A16,16,0,0,0,60,148Zm68,0a16,16,0,1,0,16,16A16,16,0,0,0,128,148Zm68,0a16,16,0,1,0,16,16A16,16,0,0,0,196,148Z\"/>"],"notepad":["<path d=\"M168,128a8,8,0,0,1-8,8H96a8,8,0,0,1,0-16h64A8,8,0,0,1,168,128Zm-8,24H96a8,8,0,0,0,0,16h64a8,8,0,0,0,0-16ZM216,40V200a32,32,0,0,1-32,32H72a32,32,0,0,1-32-32V40a8,8,0,0,1,8-8H72V24a8,8,0,0,1,16,0v8h32V24a8,8,0,0,1,16,0v8h32V24a8,8,0,0,1,16,0v8h24A8,8,0,0,1,216,40Zm-16,8H184v8a8,8,0,0,1-16,0V48H136v8a8,8,0,0,1-16,0V48H88v8a8,8,0,0,1-16,0V48H56V200a16,16,0,0,0,16,16H184a16,16,0,0,0,16-16Z\"/>","<path d=\"M172,124a12,12,0,0,1-12,12H96a12,12,0,0,1,0-24h64A12,12,0,0,1,172,124Zm-12,28H96a12,12,0,0,0,0,24h64a12,12,0,0,0,0-24ZM220,40V200a36,36,0,0,1-36,36H72a36,36,0,0,1-36-36V40A12,12,0,0,1,48,28H72V24a12,12,0,0,1,24,0v4h20V24a12,12,0,0,1,24,0v4h20V24a12,12,0,0,1,24,0v4h24A12,12,0,0,1,220,40ZM196,52H184v4a12,12,0,0,1-24,0V52H140v4a12,12,0,0,1-24,0V52H96v4a12,12,0,0,1-24,0V52H60V200a12,12,0,0,0,12,12H184a12,12,0,0,0,12-12Z\"/>"],"code":["<path d=\"M69.12,94.15,28.5,128l40.62,33.85a8,8,0,1,1-10.24,12.29l-48-40a8,8,0,0,1,0-12.29l48-40a8,8,0,0,1,10.24,12.3Zm176,27.7-48-40a8,8,0,1,0-10.24,12.3L227.5,128l-40.62,33.85a8,8,0,1,0,10.24,12.29l48-40a8,8,0,0,0,0-12.29ZM162.73,32.48a8,8,0,0,0-10.25,4.79l-64,176a8,8,0,0,0,4.79,10.26A8.14,8.14,0,0,0,96,224a8,8,0,0,0,7.52-5.27l64-176A8,8,0,0,0,162.73,32.48Z\"/>","<path d=\"M71.68,97.22,34.74,128l36.94,30.78a12,12,0,1,1-15.36,18.44l-48-40a12,12,0,0,1,0-18.44l48-40A12,12,0,0,1,71.68,97.22Zm176,21.56-48-40a12,12,0,1,0-15.36,18.44L221.26,128l-36.94,30.78a12,12,0,1,0,15.36,18.44l48-40a12,12,0,0,0,0-18.44ZM164.1,28.72a12,12,0,0,0-15.38,7.18l-64,176a12,12,0,0,0,7.18,15.37A11.79,11.79,0,0,0,96,228a12,12,0,0,0,11.28-7.9l64-176A12,12,0,0,0,164.1,28.72Z\"/>"],"push-pin":["<path d=\"M235.32,81.37,174.63,20.69a16,16,0,0,0-22.63,0L98.37,74.49c-10.66-3.34-35-7.37-60.4,13.14a16,16,0,0,0-1.29,23.78L85,159.71,42.34,202.34a8,8,0,0,0,11.32,11.32L96.29,171l48.29,48.29A16,16,0,0,0,155.9,224c.38,0,.75,0,1.13,0a15.93,15.93,0,0,0,11.64-6.33c19.64-26.1,17.75-47.32,13.19-60L235.33,104A16,16,0,0,0,235.32,81.37ZM224,92.69h0l-57.27,57.46a8,8,0,0,0-1.49,9.22c9.46,18.93-1.8,38.59-9.34,48.62L48,100.08c12.08-9.74,23.64-12.31,32.48-12.31A40.13,40.13,0,0,1,96.81,91a8,8,0,0,0,9.25-1.51L163.32,32,224,92.68Z\"/>","<path d=\"M238.15,78.54,177.46,17.86a20,20,0,0,0-28.3,0L97.2,70c-12.43-3.33-36.68-5.72-61.74,14.5a20,20,0,0,0-1.6,29.73l45.46,45.47-39.8,39.8a12,12,0,0,0,17,17l39.8-39.81,45.47,45.46A20,20,0,0,0,155.91,228c.46,0,.93,0,1.4-.05A20,20,0,0,0,171.87,220c4.69-6.23,11-16.13,14.44-28s3.45-22.88.16-33.4l51.7-51.87A20,20,0,0,0,238.15,78.54Zm-74.26,68.79a12,12,0,0,0-2.23,13.84c3.43,6.86,6.9,21-6.28,40.65L54.08,100.53c21.09-14.59,39.53-6.64,41-6a11.67,11.67,0,0,0,13.81-2.29l54.43-54.61,55,55Z\"/>"],"push-pin-fill":["<path d=\"M235.33,104l-53.47,53.65c4.56,12.67,6.45,33.89-13.19,60A15.93,15.93,0,0,1,157,224c-.38,0-.75,0-1.13,0a16,16,0,0,1-11.32-4.69L96.29,171,53.66,213.66a8,8,0,0,1-11.32-11.32L85,159.71l-48.3-48.3A16,16,0,0,1,38,87.63c25.42-20.51,49.75-16.48,60.4-13.14L152,20.7a16,16,0,0,1,22.63,0l60.69,60.68A16,16,0,0,1,235.33,104Z\"/>","<path d=\"M235.33,104l-53.47,53.65c4.56,12.67,6.45,33.89-13.19,60A15.93,15.93,0,0,1,157,224c-.38,0-.75,0-1.13,0a16,16,0,0,1-11.32-4.69L96.29,171,53.66,213.66a8,8,0,0,1-11.32-11.32L85,159.71l-48.3-48.3A16,16,0,0,1,38,87.63c25.42-20.51,49.75-16.48,60.4-13.14L152,20.7a16,16,0,0,1,22.63,0l60.69,60.68A16,16,0,0,1,235.33,104Z\"/>"],"squares-four":["<path d=\"M104,40H56A16,16,0,0,0,40,56v48a16,16,0,0,0,16,16h48a16,16,0,0,0,16-16V56A16,16,0,0,0,104,40Zm0,64H56V56h48v48Zm96-64H152a16,16,0,0,0-16,16v48a16,16,0,0,0,16,16h48a16,16,0,0,0,16-16V56A16,16,0,0,0,200,40Zm0,64H152V56h48v48Zm-96,32H56a16,16,0,0,0-16,16v48a16,16,0,0,0,16,16h48a16,16,0,0,0,16-16V152A16,16,0,0,0,104,136Zm0,64H56V152h48v48Zm96-64H152a16,16,0,0,0-16,16v48a16,16,0,0,0,16,16h48a16,16,0,0,0,16-16V152A16,16,0,0,0,200,136Zm0,64H152V152h48v48Z\"/>","<path d=\"M100,36H56A20,20,0,0,0,36,56v44a20,20,0,0,0,20,20h44a20,20,0,0,0,20-20V56A20,20,0,0,0,100,36ZM96,96H60V60H96ZM200,36H156a20,20,0,0,0-20,20v44a20,20,0,0,0,20,20h44a20,20,0,0,0,20-20V56A20,20,0,0,0,200,36Zm-4,60H160V60h36Zm-96,40H56a20,20,0,0,0-20,20v44a20,20,0,0,0,20,20h44a20,20,0,0,0,20-20V156A20,20,0,0,0,100,136Zm-4,60H60V160H96Zm104-60H156a20,20,0,0,0-20,20v44a20,20,0,0,0,20,20h44a20,20,0,0,0,20-20V156A20,20,0,0,0,200,136Zm-4,60H160V160h36Z\"/>"],"file-csv":["<path d=\"M48,180c0,11,7.18,20,16,20a14.24,14.24,0,0,0,10.22-4.66A8,8,0,0,1,85.78,206.4,30.06,30.06,0,0,1,64,216c-17.65,0-32-16.15-32-36s14.35-36,32-36a30.06,30.06,0,0,1,21.78,9.6,8,8,0,0,1-11.56,11.06A14.24,14.24,0,0,0,64,160C55.18,160,48,169,48,180Zm79.6-8.69c-4-1.16-8.14-2.35-10.45-3.84-1.25-.81-1.23-1-1.12-1.9a4.57,4.57,0,0,1,2-3.67c4.6-3.12,15.34-1.73,19.82-.56A8,8,0,0,0,142,145.86c-2.12-.55-21-5.22-32.84,2.76a20.58,20.58,0,0,0-9,14.95c-2,15.88,13.65,20.41,23,23.11,12.06,3.49,13.12,4.92,12.78,7.59-.31,2.41-1.26,3.34-2.14,3.93-4.6,3.06-15.17,1.56-19.55.36A8,8,0,0,0,109.94,214a61.34,61.34,0,0,0,15.19,2c5.82,0,12.3-1,17.49-4.46a20.82,20.82,0,0,0,9.19-15.23C154,179,137.49,174.17,127.6,171.31Zm83.09-26.84a8,8,0,0,0-10.23,4.84L188,184.21l-12.47-34.9a8,8,0,0,0-15.07,5.38l20,56a8,8,0,0,0,15.07,0l20-56A8,8,0,0,0,210.69,144.47ZM216,88v24a8,8,0,0,1-16,0V96H152a8,8,0,0,1-8-8V40H56v72a8,8,0,0,1-16,0V40A16,16,0,0,1,56,24h96a8,8,0,0,1,5.66,2.34l56,56A8,8,0,0,1,216,88Zm-27.31-8L160,51.31V80Z\"/>","<path d=\"M48,180c0,8.67,5.49,16,12,16a10.27,10.27,0,0,0,7.33-3.43,12,12,0,1,1,17.34,16.6A34,34,0,0,1,60,220C40.15,220,24,202,24,180s16.15-40,36-40a34,34,0,0,1,24.67,10.83,12,12,0,1,1-17.34,16.6A10.27,10.27,0,0,0,60,164C53.49,164,48,171.31,48,180Zm97.51-5.71c-5.13-3.45-11.33-5.24-16.8-6.82a79.5,79.5,0,0,1-7.91-2.59c2.45-1.18,9.71-1.3,16.07.33A12,12,0,0,0,143,142a69.24,69.24,0,0,0-12-1.86c-9.93-.66-18,1.08-24.1,5.17a24.45,24.45,0,0,0-10.69,17.76c-1.1,8.74,2.48,16.27,10.11,21.19,4.78,3.09,10.36,4.7,15.75,6.26,3,.89,7.94,2.3,9.88,3.53a2,2,0,0,1-.22.71c-1.36,1.55-9.57,1.79-16.39-.06a12,12,0,0,0-6.45,23.11A63.73,63.73,0,0,0,125.09,220c6.47,0,13.74-1.17,19.74-5.15a24.73,24.73,0,0,0,10.95-18C157,187.53,153.32,179.53,145.51,174.27ZM216,140.68A12,12,0,0,0,200.7,148L192,172.3,183.3,148A12,12,0,1,0,160.7,156l20,56a12,12,0,0,0,22.6,0l20-56A12,12,0,0,0,216,140.68ZM36,108V40A20,20,0,0,1,56,20h96a12,12,0,0,1,8.49,3.51l56,56A12,12,0,0,1,220,88v20a12,12,0,1,1-24,0v-4H148a12,12,0,0,1-12-12V44H60v64a12,12,0,1,1-24,0ZM160,80h23L160,57Z\"/>"],"qr-code":["<path d=\"M104,40H56A16,16,0,0,0,40,56v48a16,16,0,0,0,16,16h48a16,16,0,0,0,16-16V56A16,16,0,0,0,104,40Zm0,64H56V56h48v48Zm0,32H56a16,16,0,0,0-16,16v48a16,16,0,0,0,16,16h48a16,16,0,0,0,16-16V152A16,16,0,0,0,104,136Zm0,64H56V152h48v48ZM200,40H152a16,16,0,0,0-16,16v48a16,16,0,0,0,16,16h48a16,16,0,0,0,16-16V56A16,16,0,0,0,200,40Zm0,64H152V56h48v48Zm-64,72V144a8,8,0,0,1,16,0v32a8,8,0,0,1-16,0Zm80-16a8,8,0,0,1-8,8H184v40a8,8,0,0,1-8,8H144a8,8,0,0,1,0-16h24V144a8,8,0,0,1,16,0v8h24A8,8,0,0,1,216,160Zm0,32v16a8,8,0,0,1-16,0V192a8,8,0,0,1,16,0Z\"/>","<path d=\"M100,36H56A20,20,0,0,0,36,56v44a20,20,0,0,0,20,20h44a20,20,0,0,0,20-20V56A20,20,0,0,0,100,36ZM96,96H60V60H96Zm4,40H56a20,20,0,0,0-20,20v44a20,20,0,0,0,20,20h44a20,20,0,0,0,20-20V156A20,20,0,0,0,100,136Zm-4,60H60V160H96ZM200,36H156a20,20,0,0,0-20,20v44a20,20,0,0,0,20,20h44a20,20,0,0,0,20-20V56A20,20,0,0,0,200,36Zm-4,60H160V60h36Zm-60,76V148a12,12,0,0,1,24,0v24a12,12,0,0,1-24,0Zm84-8a12,12,0,0,1-12,12H196v32a12,12,0,0,1-12,12H148a12,12,0,0,1,0-24h24V148a12,12,0,0,1,24,0v4h12A12,12,0,0,1,220,164Z\"/>"],"caret-left":["<path d=\"M165.66,202.34a8,8,0,0,1-11.32,11.32l-80-80a8,8,0,0,1,0-11.32l80-80a8,8,0,0,1,11.32,11.32L91.31,128Z\"/>","<path d=\"M168.49,199.51a12,12,0,0,1-17,17l-80-80a12,12,0,0,1,0-17l80-80a12,12,0,0,1,17,17L97,128Z\"/>"]};
  function phIcon(nome, size = 18, cls = '') {
    const t = PI[nome];
    if (!t) return '';
    const dim = size ? ` width="${size}" height="${size}"` : '';
    return `<svg class="ph${cls ? ' ' + cls : ''}"${dim} viewBox="0 0 256 256" fill="currentColor" aria-hidden="true">${t[size && size > 20 ? 0 : 1]}</svg>`;
  }
  // Nomi storici usati nel codice -> simbolo Phosphor.
  const ICONA_PH = {
    cerca: 'magnifying-glass', chiudi: 'x', occhio: 'eye', 'occhio-off': 'eye-slash', matita: 'pencil-simple',
    cartellaLinea: 'folder', cestino: 'trash', codice: 'code', immagine: 'image', musica: 'music-note',
    video: 'video', documento: 'file-text',
  };
  // Dimensione dal CSS (.icon); "grande" usa il peso regular.
  function iconaLinea(nome, grande = false) {
    const t = PI[ICONA_PH[nome]];
    return t ? `<svg class="icon ph" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true">${t[grande ? 0 : 1]}</svg>` : '';
  }

  // Elenco unico delle app: alimenta il menu Avvio (computer e telefono).
  const SECTIONS = [
    { view: 'today', label: tr('nav_today') },
    { view: 'projects', label: tr('nav_projects') },
    { view: 'ideas', label: tr('nav_ideas') },
    { view: 'vault', label: tr('nav_vault') },
    { view: 'cards', label: tr('nav_cards') },
    { view: 'accounts', label: tr('nav_accounts') },
    { view: 'drive', label: tr('nav_drive') },
    { view: 'dossiers', label: tr('nav_dossiers') },
    { view: 'reminders', label: tr('nav_reminders') },
    { view: 'calendar', label: tr('nav_calendar') },
    { view: 'trash', label: tr('nav_trash') },
    { view: 'security', label: tr('nav_security') },
  ];
  // Sezioni che si possono spegnere (Sicurezza -> Sezioni visibili): spariscono
  // da menu, Oggi e ricerca, i dati restano. Preferenza del dispositivo.
  const HIDEABLE_VIEWS = ['projects', 'cards', 'accounts', 'drive', 'dossiers'];
  // Il Calendario si apre dalle schede di Scadenze, non dal menu.
  const NAV_SKIP = new Set(['calendar']);
  const HIDDEN_KEY = 'memento-hidden-sections';
  function hiddenViews() {
    try { return new Set(JSON.parse(localStorage.getItem(HIDDEN_KEY) || '[]')); } catch (_) { return new Set(); }
  }
  function isHidden(view) { return hiddenViews().has(view); }
  function visibleSections() { const h = hiddenViews(); return SECTIONS.filter((s) => !h.has(s.view)); }
  // Barra in basso del telefono: tre posti scelti dall'utente (oltre a + e
  // Altro). Una sezione spenta lascia il posto alla prima libera.
  const TAB_FAVS_KEY = 'memento-tab-favs';
  const TAB_FAVS_DEFAULT = ['today', 'ideas', 'vault'];
  const favCandidates = () => visibleSections().filter((s) => !NAV_SKIP.has(s.view)).map((s) => s.view);
  function tabFavs() {
    let saved;
    try { saved = JSON.parse(localStorage.getItem(TAB_FAVS_KEY) || 'null'); } catch (_) { saved = null; }
    if (!Array.isArray(saved) || saved.length !== 3) saved = TAB_FAVS_DEFAULT;
    const ok = favCandidates();
    const out = [];
    saved.forEach((v) => { out.push(ok.includes(v) && !out.includes(v) ? v : null); });
    const spare = [...TAB_FAVS_DEFAULT, ...ok].filter((v) => ok.includes(v) && !saved.includes(v));
    return out.map((v) => v || spare.shift() || null);
  }
  function setTabFav(slot, view) {
    const favs = tabFavs();
    const other = favs.indexOf(view);
    if (other >= 0) favs[other] = favs[slot]; // gia' in barra: si scambiano di posto
    favs[slot] = view;
    localStorage.setItem(TAB_FAVS_KEY, JSON.stringify(favs));
    buildNavigation();
    markActiveNav(currentView);
  }
  // Griglia delle sezioni per scegliere cosa mettere in un posto.
  function pickTabFav(slot, onDone) {
    const favs = tabFavs();
    const grid = el('<div class="fav-grid"></div>');
    favCandidates().forEach((view) => {
      const b = el(`<button type="button" class="fav-pick${favs[slot] === view ? ' active' : ''}">${lineIcon(view, 30)}<span></span></button>`);
      b.querySelector('span').textContent = VIEW_LABELS[view];
      b.addEventListener('click', () => { setTabFav(slot, view); closeModal(); haptic(); if (onDone) onDone(); });
      grid.appendChild(b);
    });
    openModal(tr('tabbar_pick_title', { n: slot + 1 }), grid);
  }
  // Etichette lunghe (es. "Abbonamenti") nella barra: carattere ridotto
  // quanto basta perche' entrino, mai sotto gli 8px.
  function fitLabels(root, sel) {
    requestAnimationFrame(() => root.querySelectorAll(sel).forEach((sp) => {
      sp.style.fontSize = '';
      const avail = sp.parentElement.clientWidth - 2;
      if (sp.scrollWidth > avail && avail > 0) {
        const fs = parseFloat(getComputedStyle(sp).fontSize);
        sp.style.fontSize = `${Math.max(8, Math.floor(fs * avail / sp.scrollWidth * 10) / 10)}px`;
      }
    }));
  }
  function tabbarBlock() {
    const block = el(`<div class="section-block tabbar-block"><h3>${esc(tr('section_tabbar'))}</h3><div class="tabbar-preview"></div></div>`);
    const prev = block.querySelector('.tabbar-preview');
    const paint = () => {
      prev.innerHTML = '';
      const favs = tabFavs();
      const slot = (i) => {
        const b = el(`<button type="button" class="tabbar-slot">${favs[i] ? lineIcon(favs[i]) : ''}<span></span></button>`);
        b.querySelector('span').textContent = favs[i] ? VIEW_LABELS[favs[i]] : '—';
        b.addEventListener('click', () => pickTabFav(i, paint));
        return b;
      };
      prev.append(slot(0), slot(1), el(`<span class="tabbar-slot-plus">${phIcon('plus', 24)}</span>`), slot(2));
      const more = el(`<span class="tabbar-slot tabbar-slot-fixed">${lineIcon('more')}<span></span></span>`);
      more.querySelector('span').textContent = tr('tab_sections');
      prev.appendChild(more);
      fitLabels(prev, '.tabbar-slot > span');
    };
    paint();
    return block;
  }

  function sectionsBlock() {
    const frag = document.createDocumentFragment();
    const block = el(`<div class="section-block"><h3>${esc(tr('section_visible_sections'))}</h3><div class="toggle-list"></div></div>`);
    const list = block.querySelector('.toggle-list');
    HIDEABLE_VIEWS.forEach((view) => {
      const row = el(`<label class="toggle-row">${appIcon(view, 30)}<span></span><input type="checkbox" role="switch" /></label>`);
      row.querySelector('span').textContent = VIEW_LABELS[view];
      const input = row.querySelector('input');
      input.checked = !isHidden(view);
      input.addEventListener('change', () => {
        const h = hiddenViews();
        if (input.checked) h.delete(view); else h.add(view);
        localStorage.setItem(HIDDEN_KEY, JSON.stringify([...h]));
        if (window.MementoNative && window.MementoBackend) window.MementoNative.Notify.reschedule(window.MementoBackend).catch(() => {});
        buildNavigation();
        markActiveNav(currentView);
        const tb = block.parentNode && block.parentNode.querySelector('.tabbar-block');
        if (tb) tb.replaceWith(tabbarBlock());
      });
      list.appendChild(row);
    });
    frag.append(block, tabbarBlock());
    return frag;
  }

  // Tema: automatico (come il telefono), chiaro o scuro. Il primo calcolo e'
  // in index.html, prima del disegno; qui la scelta e il cambio al volo.
  const THEME_KEY = 'memento-theme';
  function applyTheme() {
    const pref = localStorage.getItem(THEME_KEY) || 'auto';
    const dark = pref === 'dark' || (pref === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', dark ? '#0F1013' : '#F2F3EE');
    const SB = window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.StatusBar;
    if (SB) { try { SB.setStyle({ style: dark ? 'DARK' : 'LIGHT' }); SB.setBackgroundColor({ color: dark ? '#0F1013' : '#F2F3EE' }); } catch (_) { /* barra di sistema non disponibile */ } }
  }
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyTheme);
  applyTheme();
  function themeBlock() {
    const block = el(`<div class="section-block"><h3>${esc(tr('section_theme'))}</h3><div class="seg seg-form theme-seg"></div></div>`);
    const seg = block.querySelector('.theme-seg');
    const paint = () => {
      const cur = localStorage.getItem(THEME_KEY) || 'auto';
      seg.innerHTML = '';
      [['auto', tr('theme_auto')], ['light', tr('theme_light')], ['dark', tr('theme_dark')]].forEach(([v, label]) => {
        const b = el(`<button type="button" class="${v === cur ? 'on' : ''}"></button>`);
        b.textContent = label;
        b.addEventListener('click', () => { localStorage.setItem(THEME_KEY, v); applyTheme(); paint(); haptic(); });
        seg.appendChild(b);
      });
    };
    paint();
    return block;
  }

  // Voci di configurazione separate da quelle d'uso quotidiano con un
  // divisore nel menu Avvio, per ridurre le scelte a parita' di sguardo.
  const SETTINGS_VIEWS = new Set(['trash', 'security']);

  // Sezione in cui vive ciascun tipo di elemento collegato a una cartella o
  // trovato dalla ricerca globale: usata per aprire l'elemento cliccandolo.
  const TYPE_TO_VIEW = { document: 'drive', idea: 'ideas', project: 'projects', account: 'accounts', vault: 'vault', reminder: 'reminders', dossier: 'dossiers', card: 'cards' };

  const VIEW_LABELS = Object.fromEntries(SECTIONS.map((s) => [s.view, s.label]));

  // Aprire un elemento da dentro una cartella mostra solo quell'elemento
  // (non l'intero elenco) e aggiunge un modo per tornare alla cartella —
  // stesso meccanismo in ogni vista che puo' essere raggiunta da li'.
  function onlyFilter(opts) {
    return (item) => !opts.only || String(item.id) === String(opts.only);
  }
  function backToDossierButtonHtml(opts) {
    return opts.fromDossier ? `<button type="button" class="btn btn-sm" data-back-to-dossier>${esc(tr('btn_back_to_folder'))}</button>` : '';
  }
  function wireBackToDossier(root, opts) {
    if (!opts.fromDossier) return;
    const btn = root.querySelector('[data-back-to-dossier]');
    if (btn) btn.addEventListener('click', () => render('dossiers', { highlight: opts.fromDossier }));
  }

  // ---------------- Barra laterale, barra del telefono, indirizzi ----------------
  // Una sezione alla volta nell'area centrale. Ogni sezione ha il suo
  // indirizzo (#/vault, #/projects...): il tasto "indietro" del telefono e
  // del browser torna alla sezione precedente invece di uscire dall'app.
  const sidebarNav = document.getElementById('sidebar-nav');
  const sidebarSecondary = document.getElementById('sidebar-secondary');
  const tabbar = document.getElementById('tabbar');
  const sectionsSheet = document.getElementById('sections-sheet');
  const viewHost = document.getElementById('view-host');
  const viewTitle = document.getElementById('view-title');
  const headerDate = document.getElementById('header-date');
  let currentView = null;

  function navLink(s, extraClass) {
    const a = el(`<a class="nav-link ${extraClass}" href="#/${s.view}" data-view="${s.view}">${appIcon(s.view, 30)}<span class="nav-label"></span></a>`);
    a.querySelector('.nav-label').textContent = s.label;
    return a;
  }

  // Il + del telefono, fuori da Oggi, crea una voce della sezione aperta
  // (in Carte una carta, in Vault una voce...). Oggi, Cestino e
  // Impostazioni tengono la cattura veloce.
  const NEW_BUTTON = { cards: 'new-card', vault: 'new-vault', ideas: 'new-idea', projects: 'new-project', accounts: 'new-account', drive: 'new-doc', dossiers: 'new-dossier', reminders: 'new-reminder', calendar: 'new-reminder-cal' };
  function newInCurrentView() {
    const id = NEW_BUTTON[currentView];
    if (!id) return false;
    // Dentro una cartella: aggiungi a quella cartella.
    const addHere = viewHost.querySelector('[data-add]');
    if (currentView === 'dossiers' && addHere) { addHere.click(); return true; }
    const btn = document.getElementById(id);
    if (btn && !btn.classList.contains('hidden')) { btn.click(); return true; }
    // Pagina di dettaglio (una carta, un progetto): elenco e poi "nuovo".
    render(currentView).then(() => { const b = document.getElementById(id); if (b) b.click(); });
    return true;
  }

  function buildNavigation() {
    sidebarNav.innerHTML = '';
    sidebarSecondary.innerHTML = '';
    visibleSections().filter((s) => !NAV_SKIP.has(s.view)).forEach((s) => {
      const quiet = SETTINGS_VIEWS.has(s.view);
      (quiet ? sidebarSecondary : sidebarNav).appendChild(navLink(s, quiet ? 'nav-link-quiet' : ''));
    });
    const esci = el(`<button type="button" class="nav-link nav-link-quiet">${appIcon('esci', 30)}<span class="nav-label"></span></button>`);
    esci.querySelector('.nav-label').textContent = tr('btn_logout');
    esci.addEventListener('click', logout);
    sidebarSecondary.appendChild(esci);

    // Telefono: tre preferiti (Oggi, Note, Vault se non scelti), + (cattura),
    // Altro (tutto il resto).
    // La ricerca sta nell'intestazione (lente), non occupa un posto qui.
    tabbar.innerHTML = '';
    const tab = (view, label) => {
      const a = el(`<a class="tab" href="#/${view}" data-view="${view}">${lineIcon(view)}<span></span></a>`);
      a.querySelector('span').textContent = label;
      return a;
    };
    const button = (cls, label, icon, onClick) => {
      const b = el(`<button type="button" class="${cls}">${icon}${label ? '<span></span>' : ''}</button>`);
      if (label) b.querySelector('span').textContent = label;
      b.addEventListener('click', onClick);
      return b;
    };
    const favs = tabFavs();
    // Fuori da Oggi il primo tasto e' sempre Oggi (se non e' gia' tra i
    // preferiti): i preferiti scorrono di un posto, il terzo va in Altro.
    const shown = favs.map((view, slot) => ({ view, slot }));
    if (currentView && currentView !== 'today' && !favs.includes('today') && !isHidden('today')) {
      shown.splice(0, 0, { view: 'today', slot: null });
      shown.length = 3;
    }
    const shownViews = shown.map((x) => x.view);
    // Pressione lunga su un posto: scegli cosa metterci.
    const favTab = (k) => {
      const { view, slot: i } = shown[k];
      const a = view ? tab(view, VIEW_LABELS[view]) : el('<span class="tab"></span>');
      if (i === null) return a;
      let timer = null;
      let fired = false;
      const cancel = () => { clearTimeout(timer); timer = null; };
      a.addEventListener('pointerdown', () => { fired = false; timer = setTimeout(() => { fired = true; haptic(); pickTabFav(i); }, 550); });
      ['pointerup', 'pointerleave', 'pointercancel'].forEach((ev) => a.addEventListener(ev, cancel));
      a.addEventListener('click', (e) => { if (fired) { e.preventDefault(); fired = false; } });
      a.addEventListener('contextmenu', (e) => e.preventDefault());
      return a;
    };
    tabbar.appendChild(favTab(0));
    tabbar.appendChild(favTab(1));
    const capture = button('tab-capture', '', phIcon('plus', 18), () => {
      closeSectionsSheet();
      if (!quickCaptureEl.classList.contains('hidden')) { closeQuickCapture(); return; }
      if (!newInCurrentView()) openQuickCapture();
    });
    capture.setAttribute('aria-label', tr('title_quick_capture'));
    tabbar.appendChild(capture);
    tabbar.appendChild(favTab(2));
    const more = button('tab', tr('tab_sections'), lineIcon('more'), () => {
      if (sectionsSheet.classList.contains('hidden') || sectionsSheet.classList.contains('closing')) openSectionsSheet(); else closeSectionsSheet();
    });
    more.setAttribute('aria-haspopup', 'dialog');
    tabbar.appendChild(more);
    fitLabels(tabbar, '.tab > span');

    // Foglio "Sezioni" del telefono: tutte le sezioni come tessere grandi.
    sectionsSheet.innerHTML = '';
    const grid = el('<div class="sheet-grid"></div>');
    // Solo cio' che non e' gia' nella barra.
    visibleSections().filter((s) => !NAV_SKIP.has(s.view) && !shownViews.includes(s.view)).forEach((s) => {
      const a = el(`<a class="sheet-tile" href="#/${s.view}" data-view="${s.view}">${lineIcon(s.view, 30)}<span></span></a>`);
      a.querySelector('span').textContent = s.label;
      grid.appendChild(a);
    });
    const esciTile = el(`<button type="button" class="sheet-tile">${lineIcon('esci', 30)}<span></span></button>`);
    esciTile.querySelector('span').textContent = tr('btn_logout');
    esciTile.addEventListener('click', logout);
    grid.appendChild(esciTile);
    sectionsSheet.appendChild(grid);
  }

  // Apertura e chiusura con movimento (il pannello sale dalla barra).
  let sheetTimer = null;
  function openSectionsSheet() {
    clearTimeout(sheetTimer);
    sectionsSheet.classList.remove('hidden', 'closing');
  }
  function closeSectionsSheet() {
    const wasOpen = !sectionsSheet.classList.contains('hidden') && !sectionsSheet.classList.contains('closing');
    if (!wasOpen) return false;
    sectionsSheet.classList.add('closing');
    sheetTimer = setTimeout(() => sectionsSheet.classList.add('hidden'), 170);
    return true;
  }
  sectionsSheet.addEventListener('click', (e) => { if (e.target === sectionsSheet) closeSectionsSheet(); });

  function markActiveNav(view) {
    document.querySelectorAll('.nav-link[data-view], .tab[data-view], .sheet-tile[data-view]').forEach((n) => {
      const on = n.dataset.view === view;
      n.classList.toggle('active', on);
      if (on) n.setAttribute('aria-current', 'page'); else n.removeAttribute('aria-current');
    });
    // Una sezione che non ha un posto nella barra in basso accende "Altro".
    const more = tabbar.querySelector('button.tab');
    if (more) more.classList.toggle('active', !tabbar.querySelector(`.tab[data-view="${view}"]`));
  }

  function updateHeaderDate() {
    const label = new Date().toLocaleDateString(I18N.getLang() === 'en' ? 'en-GB' : 'it-IT', { weekday: 'long', day: 'numeric', month: 'long' });
    headerDate.textContent = label.charAt(0).toUpperCase() + label.slice(1);
  }

  // #/vault, #/dossiers/12 -> { view, opts }. Sezione sconosciuta: Oggi.
  function routeFromHash() {
    const [view, id] = location.hash.replace(/^#\/?/, '').split('/');
    if (!view || !visibleSections().some((s) => s.view === view)) return { view: 'today', opts: {} };
    return { view, opts: id ? { highlight: id } : {} };
  }
  window.addEventListener('hashchange', () => {
    if (appRoot.classList.contains('hidden')) return;
    const { view, opts } = routeFromHash();
    render(view, { ...opts, fromHash: true });
  });

  // ---------------- Cattura veloce ("Nuovo" in barra) ----------------
  // Prende il posto del vecchio composer di Flusso: sempre a un tocco,
  // qualunque finestra sia aperta. Stessa logica /comandi e @cartella,
  // in un riquadro invece che in una pagina intera.
  const quickCaptureEl = document.getElementById('quick-capture');
  const btnNuovo = document.getElementById('btn-nuovo');
  let qcMenuEl = null, qcMenuItems = [], qcMenuActive = 0, qcMenuTrigger = null, qcSelectedDossier = null;

  const QC_COMMANDS = [
    { token: '/nota', desc: tr('qc_desc_note') },
    { token: '/doc', desc: tr('qc_desc_doc') },
    { token: '/scadenza', desc: tr('qc_desc_reminder') },
    { token: '/progetto', desc: tr('qc_desc_project') },
  ];

  // Aperta "sul posto" (es. dal campo "Annota al volo" di Oggi): il riquadro
  // prende il posto del campo toccato invece di galleggiare in basso, e alla
  // chiusura torna nel suo contenitore di sempre.
  let qcAnchor = null;

  function closeQuickCapture() {
    const wasOpen = !quickCaptureEl.classList.contains('hidden');
    quickCaptureEl.classList.add('hidden');
    quickCaptureEl.innerHTML = '';
    if (qcAnchor) {
      qcAnchor.classList.remove('hidden');
      qcAnchor = null;
      quickCaptureEl.classList.remove('qc-inline');
      appRoot.appendChild(quickCaptureEl);
    }
    // Riportata alla posizione di default (in alto al centro): uno
    // spostamento manuale non e' pensato per restare tra un'apertura e
    // l'altra, solo per togliersi di mezzo da quello che stai facendo ora.
    quickCaptureEl.style.left = '';
    quickCaptureEl.style.top = '';
    quickCaptureEl.style.transform = '';
    btnNuovo.classList.remove('pressed');
    qcMenuEl = null; qcMenuItems = []; qcMenuTrigger = null; qcSelectedDossier = null;
    return wasOpen;
  }

  // Trascinamento libero del riquadro tramite la barretta in cima — stessa
  // tecnica pointer-capture del vecchio gestore finestre, ma indipendente: la
  // cattura veloce non e' una finestra vera (niente focus/z-index/taskbar).
  function attachQcDrag(handle) {
    handle.addEventListener('pointerdown', (e) => {
      handle.setPointerCapture(e.pointerId);
      const rect = quickCaptureEl.getBoundingClientRect();
      quickCaptureEl.style.left = rect.left + 'px';
      quickCaptureEl.style.top = rect.top + 'px';
      quickCaptureEl.style.transform = 'none';
      const startX = e.clientX, startY = e.clientY;
      const startLeft = rect.left, startTop = rect.top;
      const onMove = (e2) => {
        const left = Math.max(4, Math.min(window.innerWidth - 60, startLeft + (e2.clientX - startX)));
        const top = Math.max(4, Math.min(window.innerHeight - 60, startTop + (e2.clientY - startY)));
        quickCaptureEl.style.left = left + 'px';
        quickCaptureEl.style.top = top + 'px';
      };
      const onUp = () => {
        handle.removeEventListener('pointermove', onMove);
        handle.removeEventListener('pointerup', onUp);
        handle.removeEventListener('pointercancel', onUp);
      };
      handle.addEventListener('pointermove', onMove);
      handle.addEventListener('pointerup', onUp);
      handle.addEventListener('pointercancel', onUp);
    });
  }

  async function openQuickCapture(presetDossier, anchor) {
    closeSectionsSheet();
    if (qcAnchor) closeQuickCapture();
    quickCaptureEl.innerHTML = '';
    if (anchor && anchor.parentNode) {
      qcAnchor = anchor;
      anchor.parentNode.insertBefore(quickCaptureEl, anchor);
      anchor.classList.add('hidden');
      quickCaptureEl.classList.add('qc-inline');
    }
    const dossiers = await api('/dossiers').catch(() => []);
    const dragHandle = el(`<div class="qc-drag-handle" title="${esc(tr('qc_drag_title'))}">${phIcon('dots-six', 18)}</div>`);
    const composer = el(`
      <div class="composer">
        <textarea id="qc-text" placeholder="${esc(tr('qc_placeholder'))}" rows="2"></textarea>
        <div id="qc-link-badge"></div>
        <div class="composer-row">
          <div class="qc-types" role="group">
            <button type="button" class="qc-type on" data-token="/nota">${lineIcon('ideas')}<span>${esc(tr('type_idea'))}</span></button>
            <button type="button" class="qc-type" data-token="/scadenza">${lineIcon('reminders')}<span>${esc(tr('type_reminder'))}</span></button>
            ${isHidden('projects') ? '' : `<button type="button" class="qc-type" data-token="/progetto">${lineIcon('projects')}<span>${esc(tr('type_project'))}</span></button>`}
            ${isHidden('drive') ? '' : `<button type="button" class="qc-type" data-token="/doc">${lineIcon('drive')}<span>${esc(tr('type_document'))}</span></button>`}
          </div>
          <button type="button" class="btn btn-primary" id="qc-save">${esc(tr('btn_save'))}</button>
        </div>
      </div>
    `);
    if (!qcAnchor) quickCaptureEl.appendChild(dragHandle);
    quickCaptureEl.appendChild(composer);
    quickCaptureEl.classList.remove('hidden');
    btnNuovo.classList.add('pressed');
    if (!qcAnchor) attachQcDrag(dragHandle);

    const textarea = composer.querySelector('#qc-text');
    const linkBadgeWrap = composer.querySelector('#qc-link-badge');
    const ideasForTags = await api('/ideas').catch(() => []);
    const knownTags = [...new Set(ideasForTags.flatMap((x) => x.tags || []))].sort();

    function renderLinkBadge() {
      linkBadgeWrap.innerHTML = '';
      if (!qcSelectedDossier) return;
      const badge = el(`<span class="composer-link-badge">${phIcon('arrow-right', 14)} ${esc(qcSelectedDossier.title)} <button type="button" title="${esc(tr('title_remove'))}">${phIcon('x', 12)}</button></span>`);
      badge.querySelector('button').addEventListener('click', () => { qcSelectedDossier = null; renderLinkBadge(); });
      linkBadgeWrap.appendChild(badge);
    }

    function closeQcMenu() {
      if (qcMenuEl) { qcMenuEl.remove(); qcMenuEl = null; }
      qcMenuItems = []; qcMenuTrigger = null;
    }
    function highlightQcMenu() {
      if (!qcMenuEl) return;
      qcMenuEl.querySelectorAll('.composer-menu-item').forEach((n, i) => {
        const isActive = i === qcMenuActive;
        n.classList.toggle('active', isActive);
        n.setAttribute('aria-selected', String(isActive));
      });
    }
    function openQcMenu(items) {
      if (qcMenuEl) { qcMenuEl.remove(); qcMenuEl = null; }
      if (!items.length) { qcMenuItems = []; return; }
      qcMenuItems = items; qcMenuActive = 0;
      qcMenuEl = el('<div class="composer-menu" role="listbox"></div>');
      items.forEach((it, i) => {
        const row = el(`<div class="composer-menu-item ${i === 0 ? 'active' : ''}" role="option" aria-selected="${i === 0}"><span class="cmi-token">${esc(it.token)}</span><span class="cmi-desc">${esc(it.desc)}</span></div>`);
        // mousedown (non click) apposta: previene il blur della textarea, che
        // deve restare a fuoco per le frecce/Invio (vedi keydown piu' sotto) -
        // questo e' un combobox pilotato da tastiera sulla textarea, non una
        // lista di voci tabbabili singolarmente.
        row.addEventListener('mousedown', (e) => { e.preventDefault(); selectQcMenuItem(i); });
        qcMenuEl.appendChild(row);
      });
      composer.appendChild(qcMenuEl);
    }
    function qcCurrentTrigger() {
      const pos = textarea.selectionStart;
      const upToCaret = textarea.value.slice(0, pos);
      const match = upToCaret.match(/(^|\s)([/@#][^\s]*)$/);
      if (!match) return null;
      const tokenStart = pos - match[2].length;
      return { type: match[2][0], query: match[2].slice(1).toLowerCase(), start: tokenStart, end: pos };
    }
    function updateQcMenu() {
      const trigger = qcCurrentTrigger();
      qcMenuTrigger = trigger;
      if (!trigger) { closeQcMenu(); return; }
      if (trigger.type === '/') {
        const off = { '/progetto': 'projects', '/doc': 'drive' };
        openQcMenu(QC_COMMANDS.filter((c) => c.token.slice(1).startsWith(trigger.query) && !(off[c.token] && isHidden(off[c.token]))));
      } else if (trigger.type === '@') {
        openQcMenu(dossiers.filter((d) => d.title.toLowerCase().includes(trigger.query)).map((d) => ({ token: '@' + d.title, desc: tr('qc_desc_folder'), dossier: d })));
      } else {
        openQcMenu(knownTags.filter((t) => t.toLowerCase().startsWith(trigger.query)).map((t) => ({ token: '#' + t, desc: tr('qc_desc_tag') })));
      }
    }
    // Cambiare tipo (da /comando digitato o dal tasto "…") non scrive mai
    // dentro la cattura veloce: /nota resta li' (e' gia' il default), gli
    // altri chiudono il riquadro e aprono la finestra di inserimento completa
    // di quel tipo sopra la pagina attuale, senza cambiare pagina.
    function applyTypeCommand(token) {
      if (token === '/nota') return;
      if ((token === '/progetto' && isHidden('projects')) || (token === '/doc' && isHidden('drive'))) return;
      if (token === '/scadenza') {
        const form = reminderModal();
        form.addEventListener('submit', async (e) => {
          e.preventDefault();
          await api('/reminders', { method: 'POST', body: JSON.stringify({ label: form.label.value, date: form.date.value, time: form.time.value, notes: form.notes.value }) });
          closeModal(); toast(tr('toast_reminder_saved')); closeQuickCapture();
          if (['reminders', 'today', 'calendar'].includes(currentView)) render(currentView);
        });
        form.querySelector('[data-cancel]').addEventListener('click', closeModal);
        openModal(tr('modal_new_reminder'), form);
        return;
      }
      if (token === '/doc') {
        closeQuickCapture();
        api('/dossiers').then((ds) => openUploadDocument(ds, () => { if (currentView === 'drive' || currentView === 'today') render(currentView); })).catch((e) => toast(e.message));
        return;
      }
      if (token === '/progetto') {
        closeQuickCapture();
        openNewProject(() => { if (currentView === 'projects' || currentView === 'today') render(currentView); });
      }
    }

    async function selectQcMenuItem(i) {
      const item = qcMenuItems[i];
      const trigger = qcMenuTrigger;
      closeQcMenu();
      if (!item || !trigger) return;
      if (trigger.type === 'button') { applyTypeCommand(item.token); return; }
      if (trigger.type === '#') {
        const before = textarea.value.slice(0, trigger.start);
        const after = textarea.value.slice(trigger.end);
        const needsSpace = !/^\s/.test(after);
        textarea.value = before + item.token + (needsSpace ? ' ' : '') + after;
        const caret = before.length + item.token.length + (needsSpace ? 1 : 0);
        textarea.focus(); textarea.setSelectionRange(caret, caret);
        return;
      }
      const before = textarea.value.slice(0, trigger.start);
      const after = textarea.value.slice(trigger.end);
      textarea.value = before + after;
      const caret = before.length;
      textarea.focus(); textarea.setSelectionRange(caret, caret);
      if (trigger.type === '@') { qcSelectedDossier = item.dossier; renderLinkBadge(); return; }
      applyTypeCommand(item.token);
    }

    // Tipi come pulsanti con simbolo: Nota resta qui, gli altri aprono il
    // modulo completo del loro tipo (scadenza, progetto, documento).
    composer.querySelectorAll('.qc-type').forEach((b) => b.addEventListener('click', () => {
      if (b.dataset.token === '/nota') { textarea.focus(); return; }
      applyTypeCommand(b.dataset.token);
    }));

    textarea.addEventListener('input', updateQcMenu);
    textarea.addEventListener('click', updateQcMenu);
    textarea.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); saveQc(); return; }
      if (!qcMenuEl) return;
      if (e.key === 'ArrowDown') { e.preventDefault(); qcMenuActive = (qcMenuActive + 1) % qcMenuItems.length; highlightQcMenu(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); qcMenuActive = (qcMenuActive - 1 + qcMenuItems.length) % qcMenuItems.length; highlightQcMenu(); }
      else if (e.key === 'Enter' || e.key === 'Tab') { e.preventDefault(); selectQcMenuItem(qcMenuActive); }
      else if (e.key === 'Escape') { closeQcMenu(); }
    });

    let qcSaving = false;
    async function saveQc() {
      const text = textarea.value.trim();
      if (!text || qcSaving) return;
      qcSaving = true;
      composer.querySelector('#qc-save').disabled = true;
      try {
        const title = text.length > 80 ? text.slice(0, 80) + '…' : text;
        const tags = [...new Set((text.match(/#([a-zA-Z0-9_-]+)/g) || []).map((t) => t.slice(1)))];
        const idea = await api('/ideas', { method: 'POST', body: JSON.stringify({ title, body: text, tags }) });
        if (qcSelectedDossier) {
          await api(`/dossiers/${qcSelectedDossier.id}/links`, { method: 'POST', body: JSON.stringify({ item_type: 'idea', item_id: idea.id }) });
          if (currentView === 'dossiers') render('dossiers', { highlight: qcSelectedDossier.id, fromHash: true });
        }
        toast(tr('toast_idea_saved'));
        closeQuickCapture();
        if (currentView === 'today' || currentView === 'ideas') render(currentView, { fromHash: true });
      } finally {
        qcSaving = false;
      }
    }
    composer.querySelector('#qc-save').addEventListener('click', saveQc);
    if (presetDossier) { qcSelectedDossier = presetDossier; renderLinkBadge(); }
    textarea.focus();
  }

  // Come il + del telefono: fuori da Oggi crea una voce della sezione aperta.
  btnNuovo.addEventListener('click', () => {
    if (!quickCaptureEl.classList.contains('hidden')) { closeQuickCapture(); return; }
    if (!newInCurrentView()) openQuickCapture();
  });
  const NEW_LABEL = { cards: 'btn_new_card', vault: 'btn_new_vault_entry', ideas: 'btn_new_idea', projects: 'btn_new_project', accounts: 'btn_new_account', drive: 'btn_upload_document', dossiers: 'btn_new_dossier', reminders: 'btn_new_reminder', calendar: 'btn_new_reminder' };
  function paintNewButton(view) {
    const label = btnNuovo.querySelector('span');
    if (label) label.textContent = tr(NEW_LABEL[view] || 'btn_capture');
  }
  document.addEventListener('click', (e) => {
    if (quickCaptureEl.classList.contains('hidden')) return;
    // Anche il "+" della barra in basso apre la cattura: con il motore del
    // telefono la finestra compare prima che questo stesso tocco arrivi qui,
    // e senza questa eccezione si richiudeva subito.
    if (quickCaptureEl.contains(e.target) || btnNuovo.contains(e.target) || e.target.closest('.tab-capture')) return;
    closeQuickCapture();
  });

  const views = {}; // popolate piu' sotto

  async function render(view, opts = {}) {
    if (!views[view] || isHidden(view)) view = 'today';
    if (window.__restoreBrightness) { window.__restoreBrightness(); window.__restoreBrightness = null; }
    // Indirizzo della sezione: un passo nuovo nella cronologia, tranne quando
    // ci si arriva proprio dalla cronologia (indietro/avanti) o all'avvio.
    // Una cartella aperta ha il suo indirizzo (#/dossiers/12): "indietro"
    // riporta all'elenco delle cartelle.
    const hash = (view === 'dossiers' || view === 'cards') && opts.highlight ? `#/${view}/${opts.highlight}` : `#/${view}`;
    if (!opts.fromHash && location.hash !== hash) {
      if (opts.replace) history.replaceState(null, '', hash); else history.pushState(null, '', hash);
    }
    const wasToday = !currentView || currentView === 'today';
    currentView = view;
    closeSectionsSheet();
    if (wasToday !== (view === 'today')) buildNavigation();
    paintNewButton(view);
    // Una finestra rimasta aperta apparterrebbe alla sezione di prima
    // (succedeva con "indietro" o toccando la barra in basso).
    closeModal();
    // Il riquadro aperto sul posto vive dentro la vista: va rimesso al suo
    // posto prima di svuotarla.
    if (qcAnchor) closeQuickCapture();
    markActiveNav(view);
    viewTitle.textContent = VIEW_LABELS[view] || view;
    document.title = view === 'today' ? 'Memento' : `${VIEW_LABELS[view] || view} — Memento`;
    const contentEl = el(`<div class="view view-${view}"></div>`);
    viewHost.innerHTML = '';
    viewHost.appendChild(contentEl);
    viewHost.scrollTop = 0;
    contentEl.appendChild(el('<div class="skeleton" aria-hidden="true"><i></i><i></i><i></i></div>'));
    try {
      await views[view](contentEl, opts);
    } catch (err) {
      contentEl.innerHTML = '';
      contentEl.appendChild(el(`<div class="empty-state">${esc(tr('err_view_prefix'))}: ${esc(err.message)}</div>`));
    }
  }

  // Tirare giu' in cima alla sezione la ridisegna (e sincronizza, se c'e').
  (function pullToRefresh() {
    let y0 = null, pulled = 0;
    const tip = el('<div class="pull-tip" aria-hidden="true"></div>');
    viewHost.parentNode.insertBefore(tip, viewHost);
    viewHost.addEventListener('touchstart', (e) => { y0 = viewHost.scrollTop <= 0 ? e.touches[0].clientY : null; pulled = 0; }, { passive: true });
    viewHost.addEventListener('touchmove', (e) => {
      if (y0 === null) return;
      pulled = Math.max(0, Math.min(110, e.touches[0].clientY - y0));
      tip.style.height = `${pulled * 0.6}px`;
      tip.classList.toggle('ready', pulled > 80);
    }, { passive: true });
    viewHost.addEventListener('touchend', () => {
      if (y0 === null) return;
      y0 = null;
      tip.style.height = '';
      tip.classList.remove('ready');
      if (pulled > 80 && currentView) {
        haptic();
        if (window.MementoBackend && window.MementoBackend.syncNow && window.MementoNative && window.MementoNative.Sync.settings().on) window.MementoBackend.syncNow();
        render(currentView, { fromHash: true });
      }
    });
  })();

  // ---------------- Collegamento a fascicolo (riutilizzabile) ----------------
  async function openLinkToDossierModal(itemType, itemId, itemLabel) {
    const dossiers = await api('/dossiers');
    const wrap = el('<div></div>');
    if (!dossiers.length) {
      wrap.appendChild(el(`<p class="card-sub">${esc(tr('dossiers_none_yet'))}</p>`));
    } else {
      dossiers.forEach((d) => {
        const row = el(`
          <div class="trash-row row-card">
            <span>${esc(d.title)}</span>
            <button class="btn btn-sm btn-primary">${esc(tr('btn_link'))}</button>
          </div>
        `);
        row.querySelector('button').addEventListener('click', async () => {
          await api(`/dossiers/${d.id}/links`, {
            method: 'POST',
            body: JSON.stringify({ item_type: itemType, item_id: itemId }),
          });
          toast(tr('toast_linked_to_dossier', { item: itemLabel, dossier: d.title }));
          closeModal();
        });
        wrap.appendChild(row);
      });
    }
    openModal(tr('modal_link_to_dossier'), wrap);
  }

  // ==================================================================
  // SCADENZE (promemoria — elenco minimo; il calendario vero e' lavoro futuro)
  // ==================================================================
  function reminderModal(existing) {
    const form = el(`
      <form class="modal-body" style="padding:0">
        <div class="form-row"><label>${esc(tr('field_what'))}</label><input type="text" name="label" required /></div>
        <div style="display:flex;gap:10px">
          <div class="form-row" style="flex:1"><label>${esc(tr('field_when'))}</label><input type="date" name="date" required /></div>
          <div class="form-row" style="flex:1"><label>${esc(tr('field_time_optional'))}</label><input type="time" name="time" /></div>
        </div>
        <div class="form-row"><label>${esc(tr('field_notes'))}</label><textarea name="notes" rows="3"></textarea></div>
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button>
          <button type="submit" class="btn btn-primary">${esc(tr('btn_save'))}</button>
        </div>
      </form>
    `);
    if (existing) {
      form.label.value = existing.label;
      form.date.value = existing.date ? existing.date.slice(0, 10) : '';
      form.time.value = existing.time || '';
      form.notes.value = existing.notes;
    }
    return form;
  }

  // ---------------- Oggi ----------------
  // La schermata d'ingresso: tutto quello che conta adesso, senza aprire
  // nessuna sezione. Le scadenze arrivano da quattro fonti diverse
  // (promemoria, progetti, rinnovi degli abbonamenti, documenti in scadenza)
  // ma per chi le guarda sono la stessa cosa: "cosa devo fare e quando".
  const TODAY_WINDOW_DAYS = 30;
  const TODAY_MAX_DEADLINES = 8;

  // Giorni di calendario tra oggi e la data (negativo = gia' passata).
  // "2026-10-07" va letta come data locale, non come mezzanotte UTC.
  function calendarDaysFromToday(value) {
    const d = value instanceof Date ? new Date(value) : new Date(String(value).slice(0, 10) + 'T00:00:00');
    if (isNaN(d)) return null;
    d.setHours(0, 0, 0, 0);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    return Math.round((d - today) / 86400000);
  }

  // Tempo concreto e mai punitivo: una scadenza passata e' "3 giorni fa",
  // non "SCADUTO", e ha accanto il modo di rimediare (Sposta / Fatto).
  function relativeDayLabel(days) {
    if (days === 0) return tr('rel_today');
    if (days === 1) return tr('rel_tomorrow');
    if (days === -1) return tr('rel_yesterday');
    if (days < 0) return tr('rel_days_ago', { n: -days });
    return tr('rel_in_days', { n: days });
  }
  function urgencyClass(days) {
    if (days < 0) return 'due-past';
    if (days <= 3) return 'due-soon';
    if (days <= 14) return 'due-near';
    return 'due-far';
  }

  // Mese abbreviato per la colonna data dell'elenco ("28 / nov").
  function shortMonth(value) {
    const d = new Date(String(value).slice(0, 10) + 'T00:00:00');
    return d.toLocaleDateString(I18N.getLang() === 'en' ? 'en-GB' : 'it-IT', { month: 'short' }).replace('.', '');
  }
  const ICON_CHECK = phIcon('check');
  const ICON_SNOOZE = phIcon('clock-clockwise');
  const ICON_COPY = phIcon('copy');
  const ICON_ARROW = phIcon('caret-right');

  // Gesto: scorrere una riga verso destra (Fatto) o sinistra (Domani).
  function attachSwipe(row, { right, left }) {
    let x0 = null, y0 = 0, dx = 0, swiping = false;
    row.classList.add('swipeable');
    row.addEventListener('pointerdown', (e) => { if (e.pointerType === 'mouse') return; x0 = e.clientX; y0 = e.clientY; dx = 0; swiping = false; });
    row.addEventListener('pointermove', (e) => {
      if (x0 === null) return;
      const mx = e.clientX - x0, my = e.clientY - y0;
      if (!swiping && Math.abs(mx) > 12 && Math.abs(mx) > Math.abs(my) * 1.5) { swiping = true; row.setPointerCapture(e.pointerId); }
      if (!swiping) return;
      dx = (mx > 0 && !right) || (mx < 0 && !left) ? 0 : mx;
      row.style.transform = `translateX(${dx}px)`;
      row.dataset.swipe = dx > 60 ? 'right' : dx < -60 ? 'left' : '';
    });
    const end = () => {
      if (x0 === null) return;
      x0 = null;
      row.style.transition = 'transform .18s ease';
      row.style.transform = '';
      setTimeout(() => { row.style.transition = ''; }, 200);
      const dir = row.dataset.swipe; row.dataset.swipe = '';
      if (swiping) { row.addEventListener('click', (ev) => ev.stopPropagation(), { capture: true, once: true }); }
      if (dir === 'right' && right) { haptic('medium'); right(); }
      if (dir === 'left' && left) { haptic('medium'); left(); }
    };
    row.addEventListener('pointerup', end);
    row.addEventListener('pointercancel', end);
  }

  // Bacheca a blocchi: in cima quello che va fatto oggi e domani (blocco
  // scuro, con il numero in grande), poi i prossimi 30 giorni, i progetti col
  // prossimo passo da spuntare, le note e le cartelle. Ogni promemoria ha le
  // stesse due azioni (Sposta a domani, Fatto), sempre nello stesso posto.
  views.today = async (root) => {
    const [reminders, projects, accounts, docs, ideas, dossiers, cards] = await Promise.all([
      api('/reminders'), api('/projects'), api('/accounts'), api('/drive'), api('/ideas'), api('/dossiers'), api('/cards').catch(() => []),
    ]);
    root.innerHTML = '';
    const refresh = () => render('today', { fromHash: true });

    const deadlines = [];
    reminders.forEach((r) => {
      const days = calendarDaysFromToday(r.date);
      if (days !== null) deadlines.push({ kind: 'reminder', item: r, days, date: r.date, title: r.label, sub: r.time ? r.time.slice(0, 5) : '' });
    });
    if (!isHidden('projects')) projects.filter((p) => p.deadline && p.status !== 'fatto').forEach((p) => {
      const days = calendarDaysFromToday(p.deadline);
      if (days !== null) deadlines.push({ kind: 'project', item: p, days, date: p.deadline, title: p.title, sub: tr('type_project') });
    });
    if (!isHidden('accounts')) accounts.forEach((a) => {
      const next = nextChargeDate(a) || (!loanInfo(a) && a.renewal_date ? a.renewal_date : null);
      if (!next) return;
      const days = calendarDaysFromToday(next);
      if (days === null) return;
      const amount = a.amount ? ` · ${fmtMoney(a.amount)}` : '';
      const iso = next instanceof Date ? `${next.getFullYear()}-${String(next.getMonth() + 1).padStart(2, '0')}-${String(next.getDate()).padStart(2, '0')}` : String(next);
      deadlines.push({ kind: 'account', item: a, days, date: iso, title: tr(loanInfo(a) ? 'loan_installment_of' : 'today_renewal_of', { name: a.service }), sub: tr(loanInfo(a) ? 'account_type_loan' : 'type_account') + amount });
    });
    if (!isHidden('drive')) docs.filter((d) => d.expiry_date).forEach((d) => {
      const days = calendarDaysFromToday(d.expiry_date);
      if (days !== null) deadlines.push({ kind: 'document', item: d, days, date: d.expiry_date, title: d.display_name || d.original_name, sub: tr('type_document') });
    });
    if (!isHidden('cards')) cards.filter((c) => c.kind === 'regalo' && c.expiry_date && (c.balance == null || c.balance > 0)).forEach((c) => {
      const days = calendarDaysFromToday(c.expiry_date);
      const bal = c.balance != null ? ` · ${fmtMoney(c.balance)}` : '';
      if (days !== null) deadlines.push({ kind: 'card', item: c, days, date: c.expiry_date, title: c.name, sub: tr('card_kind_gift') + bal });
    });
    const relevant = deadlines
      .filter((x) => x.days <= TODAY_WINDOW_DAYS && (x.days >= 0 || x.kind === 'reminder' || x.kind === 'project'))
      .sort((a, b) => a.days - b.days || String(a.sub).localeCompare(String(b.sub)));
    const focus = relevant.filter((x) => x.days <= 1);
    const later = relevant.filter((x) => x.days > 1);
    const KIND_VIEW = { reminder: 'reminders', project: 'projects', account: 'accounts', document: 'drive', card: 'cards' };
    const open = (x) => render(KIND_VIEW[x.kind], { highlight: x.item.id });

    async function snooze(r) {
      const t = new Date(); t.setDate(t.getDate() + 1);
      const date = `${t.getFullYear()}-${String(t.getMonth() + 1).padStart(2, '0')}-${String(t.getDate()).padStart(2, '0')}`;
      await api(`/reminders/${r.id}`, { method: 'PUT', body: JSON.stringify({ label: r.label, date, time: r.time || '', notes: r.notes || '' }) });
      toast(tr('toast_snoozed'));
      refresh();
    }
    async function done(r) {
      await api(`/reminders/${r.id}`, { method: 'DELETE' });
      haptic('success');
      undoToast(tr('toast_done_nice'), async () => { await api(`/reminders/${r.id}/restore`, { method: 'POST' }); refresh(); });
      refresh();
    }
    // Azioni a destra della riga: promemoria = Sposta a domani + Fatto,
    // il resto (rinnovi, progetti, documenti) si apre e basta.
    function rowActions(x) {
      const wrap = el('<span class="row-acts"></span>');
      if (x.kind === 'reminder') {
        const s = el(`<button type="button" class="sq-btn sq-snooze" title="${esc(tr('btn_snooze_tomorrow'))}" aria-label="${esc(tr('btn_snooze_tomorrow'))}">${ICON_SNOOZE}</button>`);
        const d = el(`<button type="button" class="sq-btn sq-done" title="${esc(tr('btn_done'))}" aria-label="${esc(tr('btn_done'))}">${ICON_CHECK}</button>`);
        s.addEventListener('click', (e) => { e.stopPropagation(); s.disabled = true; snooze(x.item); });
        d.addEventListener('click', (e) => { e.stopPropagation(); d.disabled = true; done(x.item); });
        if (x.days < 1) wrap.appendChild(s);
        wrap.appendChild(d);
      } else {
        wrap.appendChild(el(`<span class="sq-btn sq-open" aria-hidden="true">${ICON_ARROW}</span>`));
      }
      return wrap;
    }

    const board = el('<div class="board"></div>');
    root.appendChild(board);

    // --- Blocco scuro: oggi e domani ---
    const focusTile = el(`
      <section class="tile tile-focus">
        <div class="focus-head"><span class="focus-num"></span><span class="focus-label"></span></div>
        <ul class="focus-list"></ul>
      </section>
    `);
    focusTile.querySelector('.focus-num').textContent = String(focus.length);
    focusTile.querySelector('.focus-label').textContent = tr('today_focus_label');
    const focusList = focusTile.querySelector('.focus-list');
    if (!focus.length) focusList.appendChild(el(`<li class="focus-empty">${esc(tr('today_focus_empty'))}</li>`));
    focus.forEach((x) => {
      const li = el(`<li class="focus-row" tabindex="0" role="button"><span class="focus-text"><b></b><small></small><em class="pill"></em></span></li>`);
      li.querySelector('b').textContent = x.title;
      li.querySelector('small').textContent = x.sub;
      const pill = li.querySelector('.pill');
      pill.textContent = x.days === 0 && x.sub && /^\d\d:\d\d$/.test(x.sub) ? x.sub : relativeDayLabel(x.days);
      pill.classList.add(x.days < 0 ? 'pill-late' : 'pill-today');
      if (pill.textContent === x.sub) li.querySelector('small').textContent = '';
      li.appendChild(rowActions(x));
      if (x.kind === 'reminder') attachSwipe(li, { right: () => done(x.item), left: x.days < 1 ? () => snooze(x.item) : null });
      li.addEventListener('click', () => open(x));
      li.addEventListener('keydown', (e) => { if (e.key === 'Enter') open(x); });
      focusList.appendChild(li);
    });
    board.appendChild(focusTile);

    // --- Prossimi 30 giorni ---
    const upTile = el(`<section class="tile tile-list"><div class="tile-head"><h2></h2><a href="#/calendar"></a></div><div class="date-list"></div></section>`);
    upTile.querySelector('h2').textContent = tr('today_upcoming_title');
    upTile.querySelector('.tile-head a').textContent = tr('nav_calendar');
    const dateList = upTile.querySelector('.date-list');
    if (!later.length) dateList.appendChild(el(`<p class="panel-empty">${esc(tr('today_due_empty'))}</p>`));
    later.slice(0, TODAY_MAX_DEADLINES).forEach((x) => {
      const row = el(`<div class="date-row" tabindex="0" role="button"><span class="date-cell"><b></b><small></small></span><span class="date-text"><b></b><small></small></span></div>`);
      const day = String(x.date).slice(8, 10);
      row.querySelector('.date-cell b').textContent = day;
      row.querySelector('.date-cell small').textContent = shortMonth(x.date);
      row.querySelector('.date-text b').textContent = x.title;
      row.querySelector('.date-text small').textContent = [x.sub, relativeDayLabel(x.days)].filter(Boolean).join(' · ');
      if (x.days <= 3) row.classList.add('date-soon');
      row.appendChild(rowActions(x));
      if (x.kind === 'reminder') attachSwipe(row, { right: () => done(x.item), left: null });
      row.addEventListener('click', () => open(x));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter') open(x); });
      dateList.appendChild(row);
    });
    if (later.length > TODAY_MAX_DEADLINES) {
      dateList.appendChild(el(`<a class="panel-more" href="#/calendar">${esc(tr('today_more', { n: later.length - TODAY_MAX_DEADLINES }))}</a>`));
    }
    board.appendChild(upTile);

    // --- Progetti: avanzamento a tacche e prossimo passo spuntabile ---
    const active = isHidden('projects') ? [] : projects.filter((p) => p.status === 'in_corso')
      .sort((a, b) => (a.deadline || '9999').localeCompare(b.deadline || '9999'));
    active.slice(0, 4).forEach((p) => {
      const card = el(`
        <section class="tile tile-project">
          <button type="button" class="tile-kicker"></button>
          <button type="button" class="tile-title"></button>
          <div class="ticks"></div>
          <small class="tile-sub"></small>
          <div class="next-step"></div>
        </section>
      `);
      card.querySelector('.tile-kicker').textContent = tr('type_project');
      card.querySelector('.tile-title').textContent = p.title;
      card.querySelectorAll('.tile-kicker, .tile-title').forEach((b) => b.addEventListener('click', () => render('projects', { highlight: p.id })));
      const paint = (proj) => {
        const { done: nDone, total } = checklistProgress(proj.checklist);
        const ticks = card.querySelector('.ticks');
        ticks.innerHTML = '';
        if (total && total <= 12) {
          for (let i = 0; i < total; i++) ticks.appendChild(el(`<i class="${i < nDone ? 'on' : ''}"></i>`));
        } else {
          const bar = el('<span class="ticks-bar"><span></span></span>');
          bar.firstChild.style.width = total ? `${Math.round((nDone / total) * 100)}%` : '0%';
          ticks.appendChild(bar);
        }
        const bits = [];
        if (total) bits.push(tr('label_completed_count', { done: nDone, total }));
        if (proj.deadline) bits.push(relativeDayLabel(calendarDaysFromToday(proj.deadline)));
        card.querySelector('.tile-sub').textContent = bits.join(' · ') || tr('today_no_checklist');
        const nextWrap = card.querySelector('.next-step');
        nextWrap.innerHTML = '';
        const idx = (proj.checklist || []).findIndex((c) => !c.done);
        if (idx < 0) return;
        const label = el('<label class="check-row"><input type="checkbox" /><span></span></label>');
        label.querySelector('span').textContent = proj.checklist[idx].text;
        label.querySelector('input').addEventListener('change', async (e) => {
          e.target.disabled = true;
          const checklist = proj.checklist.map((item, j) => (j === idx ? { ...item, done: true } : item));
          const updated = await api(`/projects/${proj.id}`, { method: 'PUT', body: JSON.stringify({ checklist }) });
          toast(tr('toast_done_nice'));
          paint(updated);
        });
        nextWrap.appendChild(label);
      };
      paint(p);
      board.appendChild(card);
    });

    // --- Note come foglietti ---
    const NOTE_TINTS = ['note-yellow', 'note-lilac', 'note-pink', 'note-sky'];
    ideas.slice(0, 4).forEach((idea, i) => {
      const n = el(`<button type="button" class="tile tile-note ${NOTE_TINTS[i % NOTE_TINTS.length]}"><span class="tile-kicker"></span><span class="note-text"></span><span class="note-tags"></span></button>`);
      n.querySelector('.tile-kicker').textContent = tr('type_idea');
      const text = idea.title || idea.body || '';
      n.querySelector('.note-text').textContent = text.length > 90 ? text.slice(0, 90) + '…' : text;
      n.querySelector('.note-tags').textContent = (idea.tags || []).map((t) => '#' + t).join(' ');
      n.addEventListener('click', () => render('ideas', { highlight: idea.id }));
      board.appendChild(n);
    });

    // --- Cartelle ---
    if (dossiers.length && !isHidden('dossiers')) {
      const dt = el(`<section class="tile tile-list tile-wide"><div class="tile-head"><h2></h2><a href="#/dossiers"></a></div><div class="chip-row"></div></section>`);
      dt.querySelector('h2').textContent = tr('nav_dossiers');
      dt.querySelector('.tile-head a').textContent = tr('today_all_n', { n: dossiers.length });
      const chips = dt.querySelector('.chip-row');
      dossiers.slice(0, 10).forEach((d) => {
        const c = el(`<a class="chip" href="#/dossiers/${d.id}"><span></span><span class="chip-count"></span></a>`);
        c.querySelector('span').textContent = d.title;
        c.querySelector('.chip-count').textContent = String((d.items || []).length);
        chips.appendChild(c);
      });
      board.appendChild(dt);
    }
  };

  // Schede in cima a Scadenze e Calendario: sono la stessa cosa vista in due modi.
  function remindersSwitch(active) {
    const seg = el(`<div class="seg seg-switch"><button type="button" data-v="reminders">${esc(tr('reminders_list'))}</button><button type="button" data-v="calendar">${esc(tr('nav_calendar'))}</button></div>`);
    seg.querySelectorAll('button').forEach((b) => {
      b.classList.toggle('on', b.dataset.v === active);
      b.addEventListener('click', () => { if (b.dataset.v !== active) render(b.dataset.v); });
    });
    return seg;
  }

  views.reminders = async (root, opts = {}) => {
    const highlightId = opts.highlight ? String(opts.highlight) : null;
    const reminders = (await api('/reminders')).filter(onlyFilter(opts));
    root.innerHTML = '';
    root.appendChild(el(`
      <div class="view-header">
        <h2>${esc(tr('nav_reminders_title'))}</h2>
        <div class="view-header-actions">${backToDossierButtonHtml(opts)}<button class="btn btn-primary" id="new-reminder">${phIcon('plus', 16)}${esc(tr('btn_new_reminder'))}</button></div>
      </div>
    `));
    wireBackToDossier(root, opts);
    if (!opts.fromDossier && !isHidden('calendar')) root.appendChild(remindersSwitch('reminders'));

    const saveForm = (form, existing) => async (e) => {
      e.preventDefault();
      const body = JSON.stringify({ label: form.label.value, date: form.date.value, time: form.time.value, notes: form.notes.value });
      if (existing) await api(`/reminders/${existing.id}`, { method: 'PUT', body });
      else await api('/reminders', { method: 'POST', body });
      closeModal(); toast(existing ? tr('toast_reminder_updated') : tr('toast_reminder_saved')); render('reminders', { fromHash: true });
    };
    root.querySelector('#new-reminder').addEventListener('click', () => {
      const form = reminderModal();
      form.addEventListener('submit', saveForm(form, null));
      form.querySelector('[data-cancel]').addEventListener('click', closeModal);
      openModal(tr('modal_new_reminder'), form);
    });
    const edit = (r) => {
      const form = reminderModal(r);
      form.addEventListener('submit', saveForm(form, r));
      form.querySelector('[data-cancel]').addEventListener('click', closeModal);
      const side = el(`<span class="form-actions-side"><button type="button" class="btn btn-ghost" data-link>${esc(tr('btn_link_folder'))}</button><button type="button" class="btn btn-ghost btn-danger" data-del>${esc(tr('btn_delete'))}</button></span>`);
      side.querySelector('[data-link]').addEventListener('click', () => { closeModal(); openLinkToDossierModal('reminder', r.id, r.label); });
      const passR = passButton('reminder', r.id, r.label);
      if (passR) side.insertBefore(passR, side.querySelector('[data-del]'));
      side.querySelector('[data-del]').addEventListener('click', async () => { closeModal(); await done(r, tr('toast_moved_trash')); });
      form.querySelector('.form-actions').prepend(side);
      openModal(tr('modal_edit_reminder'), form);
    };
    // Fatto / eliminata: va nel cestino, si annulla dall'avviso.
    const done = async (r, msg) => {
      await api(`/reminders/${r.id}`, { method: 'DELETE' });
      haptic('success');
      undoToast(msg || tr('toast_done_nice'), async () => { await api(`/reminders/${r.id}/restore`, { method: 'POST' }); render('reminders', { fromHash: true }); });
      render('reminders', { fromHash: true });
    };
    const tomorrow = async (r) => {
      const t = new Date(); t.setDate(t.getDate() + 1);
      const date = `${t.getFullYear()}-${String(t.getMonth() + 1).padStart(2, '0')}-${String(t.getDate()).padStart(2, '0')}`;
      await api(`/reminders/${r.id}`, { method: 'PUT', body: JSON.stringify({ label: r.label, date, time: r.time || '', notes: r.notes || '' }) });
      toast(tr('toast_snoozed')); render('reminders', { fromHash: true });
    };

    if (!reminders.length) {
      root.appendChild(el(`<div class="empty-state">${esc(tr('empty_reminders'))}</div>`));
      return;
    }
    const sorted = reminders.slice().sort((a, b) => `${a.date}T${a.time || '00:00'}`.localeCompare(`${b.date}T${b.time || '00:00'}`));
    const groups = [
      [tr('group_late'), (d) => d < 0], [tr('group_today_tomorrow'), (d) => d >= 0 && d <= 1],
      [tr('group_week'), (d) => d > 1 && d <= 7], [tr('group_later'), (d) => d > 7],
    ];
    groups.forEach(([title, test]) => {
      const list = sorted.filter((r) => test(calendarDaysFromToday(r.date)));
      if (!list.length) return;
      const tile = el(`<section class="tile tile-list rem-group"><div class="tile-head"><h2></h2><small class="rem-count"></small></div><div class="date-list"></div></section>`);
      tile.querySelector('h2').textContent = title;
      tile.querySelector('.rem-count').textContent = String(list.length);
      const box = tile.querySelector('.date-list');
      list.forEach((r) => {
        const days = calendarDaysFromToday(r.date);
        const row = el(`<div class="date-row" tabindex="0" role="button"><span class="date-cell"><b></b><small></small></span><span class="date-text"><b></b><small></small></span></div>`);
        row.querySelector('.date-cell b').textContent = String(r.date).slice(8, 10);
        row.querySelector('.date-cell small').textContent = shortMonth(r.date);
        row.querySelector('.date-text b').textContent = r.label;
        row.querySelector('.date-text small').textContent = [r.time ? r.time.slice(0, 5) : '', relativeDayLabel(days), r.notes ? r.notes.slice(0, 60) : ''].filter(Boolean).join(' · ');
        if (days < 0) row.classList.add('date-late'); else if (days <= 1) row.classList.add('date-soon');
        const ok = el(`<button type="button" class="sq-btn sq-done" aria-label="${esc(tr('btn_done'))}">${ICON_CHECK}</button>`);
        ok.addEventListener('click', (e) => { e.stopPropagation(); ok.disabled = true; done(r); });
        row.appendChild(ok);
        attachSwipe(row, { right: () => done(r), left: () => tomorrow(r) });
        row.addEventListener('click', () => edit(r));
        row.addEventListener('keydown', (e) => { if (e.key === 'Enter') edit(r); });
        if (highlightId && String(r.id) === highlightId) row.classList.add('card-highlight');
        box.appendChild(row);
      });
      root.appendChild(tile);
    });
    if (highlightId) { const t = root.querySelector('.card-highlight'); if (t) t.scrollIntoView({ block: 'center' }); }
  };

  // Calendario: griglia mensile, riusa l'API e il modulo delle Scadenze —
  // stessi dati, vista diversa. Click su un giorno vuoto = nuova scadenza con
  // quella data precompilata; click su una voce = modifica.
  const MONTH_LABELS = ['month_0', 'month_1', 'month_2', 'month_3', 'month_4', 'month_5', 'month_6', 'month_7', 'month_8', 'month_9', 'month_10', 'month_11'].map(tr);
  const WEEKDAY_LABELS = ['weekday_short_1', 'weekday_short_2', 'weekday_short_3', 'weekday_short_4', 'weekday_short_5', 'weekday_short_6', 'weekday_short_7'].map(tr);
  const WEEKDAY_LABELS_FULL = ['weekday_1', 'weekday_2', 'weekday_3', 'weekday_4', 'weekday_5', 'weekday_6', 'weekday_7'].map(tr);

  views.calendar = async (root, opts = {}) => {
    const switchBar = remindersSwitch('calendar');
    const reminders = await api('/reminders');
    root.innerHTML = '';
    root.appendChild(el(`
      <div class="view-header">
        <h2>${esc(tr('nav_calendar_title'))}</h2>
        <div class="view-header-actions"><button class="btn btn-primary" id="new-reminder-cal">${phIcon('plus', 16)}${esc(tr('btn_new_reminder'))}</button></div>
      </div>
    `));
    root.appendChild(switchBar);
    viewTitle.textContent = VIEW_LABELS.reminders;

    function saveNew(dateStr) {
      const form = reminderModal();
      if (dateStr) form.date.value = dateStr;
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        await api('/reminders', { method: 'POST', body: JSON.stringify({ label: form.label.value, date: form.date.value, time: form.time.value, notes: form.notes.value }) });
        closeModal(); toast(tr('toast_reminder_saved')); render('calendar', { month: monthKey(cursor) });
      });
      form.querySelector('[data-cancel]').addEventListener('click', closeModal);
      openModal(tr('modal_new_reminder'), form);
    }

    function saveEdit(r) {
      const form = reminderModal(r);
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        await api(`/reminders/${r.id}`, { method: 'PUT', body: JSON.stringify({ label: form.label.value, date: form.date.value, time: form.time.value, notes: form.notes.value }) });
        closeModal(); toast(tr('toast_reminder_updated')); render('calendar', { month: monthKey(cursor) });
      });
      form.querySelector('[data-cancel]').addEventListener('click', closeModal);
      openModal(tr('modal_edit_reminder'), form);
    }

    root.querySelector('#new-reminder-cal').addEventListener('click', () => saveNew());

    function monthKey(d) { return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`; }
    const cursor = opts.month ? new Date(`${opts.month}-01T00:00:00`) : new Date();
    cursor.setDate(1);

    const toolbar = el(`
      <div class="calendar-toolbar">
        <button type="button" class="btn" id="cal-prev" aria-label="${esc(tr('cal_prev'))}">${phIcon('caret-left', 18)}</button>
        <span class="calendar-label" id="cal-label"></span>
        <button type="button" class="btn" id="cal-next" aria-label="${esc(tr('cal_next'))}">${phIcon('caret-right', 18)}</button>
        <button type="button" class="btn" id="cal-today">${esc(tr('btn_today'))}</button>
      </div>
    `);
    const gridWrap = el('<div class="calendar-grid"></div>');
    root.appendChild(toolbar);
    root.appendChild(gridWrap);

    function remindersOn(dateStr) {
      return reminders
        .filter((r) => (r.date || '').slice(0, 10) === dateStr)
        .sort((a, b) => (a.time || '').localeCompare(b.time || ''));
    }

    function renderMonth() {
      toolbar.querySelector('#cal-label').textContent = `${MONTH_LABELS[cursor.getMonth()]} ${cursor.getFullYear()}`;
      gridWrap.innerHTML = '';
      WEEKDAY_LABELS.forEach((w) => gridWrap.appendChild(el(`<div class="calendar-weekday">${w}</div>`)));

      const firstOfMonth = new Date(cursor.getFullYear(), cursor.getMonth(), 1);
      const firstWeekday = (firstOfMonth.getDay() + 6) % 7; // Lun=0 ... Dom=6 (getDay() e' Dom=0 ... Sab=6)
      const daysInMonth = new Date(cursor.getFullYear(), cursor.getMonth() + 1, 0).getDate();
      const todayStr = new Date().toISOString().slice(0, 10);

      for (let i = 0; i < firstWeekday; i++) gridWrap.appendChild(el('<div class="calendar-cell calendar-cell-empty"></div>'));

      for (let day = 1; day <= daysInMonth; day++) {
        const dateStr = `${cursor.getFullYear()}-${String(cursor.getMonth() + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
        const cell = el(`
          <div class="calendar-cell${dateStr === todayStr ? ' calendar-cell-today' : ''}">
            <span class="calendar-daynum">${day}</span>
            <div class="calendar-entries"></div>
          </div>
        `);
        const entriesEl = cell.querySelector('.calendar-entries');
        remindersOn(dateStr).forEach((r) => {
          const chip = el(`<button type="button" class="calendar-entry">${r.time ? `<span class="calendar-entry-time">${esc(r.time)}</span> ` : ''}${escTrim(r.label, 40)}</button>`);
          chip.addEventListener('click', (e) => { e.stopPropagation(); saveEdit(r); });
          entriesEl.appendChild(chip);
        });
        cell.addEventListener('click', () => saveNew(dateStr));
        gridWrap.appendChild(cell);
      }
    }

    toolbar.querySelector('#cal-prev').addEventListener('click', () => { cursor.setMonth(cursor.getMonth() - 1); renderMonth(); });
    toolbar.querySelector('#cal-next').addEventListener('click', () => { cursor.setMonth(cursor.getMonth() + 1); renderMonth(); });
    toolbar.querySelector('#cal-today').addEventListener('click', () => { cursor.setFullYear(new Date().getFullYear(), new Date().getMonth(), 1); renderMonth(); });

    renderMonth();
  };

  // ==================================================================
  // NOTE
  // ==================================================================
  function ideaModal(existing) {
    const form = el(`
      <form class="modal-body" style="padding:0">
        <div class="form-row"><label>${esc(tr('field_title'))}</label><input type="text" name="title" required /></div>
        <div class="form-row"><label>${esc(tr('field_description'))}</label><textarea name="body" rows="5"></textarea></div>
        <div class="form-row"><label>${esc(tr('field_checklist'))}</label><textarea name="checklist" rows="4" placeholder="${esc(tr('idea_checklist_placeholder'))}"></textarea></div>
        <div class="form-row"><label>${esc(tr('field_tags'))}</label><input type="text" name="tags" /></div>
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button>
          <button type="submit" class="btn btn-primary">${esc(tr('btn_save'))}</button>
        </div>
      </form>
    `);
    if (existing) {
      form.title.value = existing.title;
      form.body.value = existing.body;
      form.checklist.value = (existing.checklist || []).map((c) => c.text).join('\n');
      form.tags.value = (existing.tags || []).join(', ');
    }
    return form;
  }

  views.ideas = async (root, opts = {}) => {
    const highlightId = opts.highlight ? String(opts.highlight) : null;
    const ideas = (await api('/ideas')).filter(onlyFilter(opts));
    root.innerHTML = '';
    root.appendChild(el(`
      <div class="view-header">
        <h2>${esc(tr('nav_ideas_title'))}</h2>
        <div class="view-header-actions">${backToDossierButtonHtml(opts)}<button class="btn btn-primary" id="new-idea">${phIcon('plus', 16)}${esc(tr('btn_new_idea'))}</button></div>
      </div>
    `));
    wireBackToDossier(root, opts);

    root.querySelector('#new-idea').addEventListener('click', () => {
      const form = ideaModal();
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const tags = parseTags(form);
        const checklist = collectChecklist(form, []);
        await api('/ideas', { method: 'POST', body: JSON.stringify({ title: form.title.value, body: form.body.value, tags, checklist }) });
        closeModal(); toast(tr('toast_idea_saved')); render('ideas');
      });
      form.querySelector('[data-cancel]').addEventListener('click', closeModal);
      openModal(tr('modal_new_idea'), form);
    });

    if (!ideas.length) {
      root.appendChild(el(`<div class="empty-state">${esc(tr('empty_ideas'))}</div>`));
      return;
    }

    // Foglietti colorati in colonne: si tocca la nota per aprirla; le spunte
    // della checklist si mettono direttamente sul foglietto.
    const NOTE_TINTS = ['note-yellow', 'note-lilac', 'note-pink', 'note-sky'];
    const board = el('<div class="note-board"></div>');
    const openEdit = (idea) => {
      const form = ideaModal(idea);
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const tags = parseTags(form);
        const checklist = collectChecklist(form, idea.checklist);
        await api(`/ideas/${idea.id}`, { method: 'PUT', body: JSON.stringify({ title: form.title.value, body: form.body.value, tags, checklist }) });
        closeModal(); toast(tr('toast_idea_updated')); render('ideas');
      });
      form.querySelector('[data-cancel]').addEventListener('click', closeModal);
      const actions = form.querySelector('.form-actions');
      const side = el(`<span class="form-actions-side"><button type="button" class="btn btn-ghost" data-link>${esc(tr('btn_link_folder'))}</button><button type="button" class="btn btn-ghost btn-danger" data-del>${esc(tr('btn_delete'))}</button></span>`);
      side.querySelector('[data-link]').addEventListener('click', () => { closeModal(); openLinkToDossierModal('idea', idea.id, idea.title); });
      const passI = passButton('idea', idea.id, idea.title);
      if (passI) side.insertBefore(passI, side.querySelector('[data-del]'));
      side.querySelector('[data-del]').addEventListener('click', async () => {
        if (!(await askConfirm(tr('confirm_delete_idea')))) return;
        await api(`/ideas/${idea.id}`, { method: 'DELETE' });
        closeModal(); toast(tr('toast_idea_deleted')); render('ideas');
      });
      actions.prepend(side);
      openModal(tr('modal_edit_idea'), form);
    };
    ideas.forEach((idea, n) => {
      const { done, total } = checklistProgress(idea.checklist);
      const card = el(`
        <article class="tile tile-note note-card ${NOTE_TINTS[n % NOTE_TINTS.length]}" tabindex="0">
          <p class="note-title"></p>
          <p class="note-body"></p>
          <div class="note-checks"></div>
          <span class="note-tags"></span>
        </article>
      `);
      card.querySelector('.note-title').textContent = idea.title;
      const body = (idea.body || '').trim();
      card.querySelector('.note-body').textContent = body && body !== idea.title ? (body.length > 220 ? body.slice(0, 220) + '…' : body) : '';
      card.querySelector('.note-tags').textContent = (idea.tags || []).map((t) => '#' + t).join(' ');
      const checks = card.querySelector('.note-checks');
      if (total) {
        checks.appendChild(el(`<span class="note-progress">${esc(tr('label_completed_count', { done, total }))}</span>`));
        (idea.checklist || []).forEach((item, i) => {
          const row = el(`<label class="check-row"><input type="checkbox" ${item.done ? 'checked' : ''} /><span></span></label>`);
          row.querySelector('span').textContent = item.text;
          row.addEventListener('click', (e) => e.stopPropagation());
          row.querySelector('input').addEventListener('change', async (e) => {
            const updated = idea.checklist.map((c, j) => (j === i ? { ...c, done: e.target.checked } : c));
            await api(`/ideas/${idea.id}`, { method: 'PUT', body: JSON.stringify({ checklist: updated }) });
            if (e.target.checked) toast(tr('toast_done_nice'));
            render('ideas', { fromHash: true });
          });
          checks.appendChild(row);
        });
      }
      card.addEventListener('click', () => openEdit(idea));
      card.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target === card) openEdit(idea); });
      if (highlightId && String(idea.id) === highlightId) card.classList.add('card-highlight');
      board.appendChild(card);
    });
    root.appendChild(board);
    if (highlightId) {
      const target = board.querySelector('.card-highlight');
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  // ==================================================================
  // PROGETTI
  // ==================================================================
  function projectModal(existing) {
    const form = el(`
      <form class="modal-body" style="padding:0">
        <div class="form-row"><label>${esc(tr('field_title'))}</label><input type="text" name="title" required /></div>
        <div class="form-row"><label>${esc(tr('field_description'))}</label><textarea name="description" rows="4"></textarea></div>
        <div class="form-row"><label>${esc(tr('field_status'))}</label>
          <select name="status">
            <option value="da_fare">${esc(tr('status_todo'))}</option>
            <option value="in_corso">${esc(tr('status_doing'))}</option>
            <option value="fatto">${esc(tr('status_done'))}</option>
          </select>
        </div>
        <div class="form-row"><label>${esc(tr('field_deadline_optional'))}</label><input type="date" name="deadline" /></div>
        <div class="form-row"><label>${esc(tr('field_checklist_required'))}</label><textarea name="checklist" rows="4" placeholder="${esc(tr('field_checklist_project_placeholder'))}"></textarea></div>
        <div class="form-row"><label>${esc(tr('field_contacts'))}</label><input type="text" name="contacts" placeholder="${esc(tr('field_contacts_placeholder'))}" /></div>
        <div class="form-row"><label>${esc(tr('field_budget'))}</label><textarea name="budget" rows="3" placeholder="${esc(tr('field_budget_placeholder'))}"></textarea></div>
        <div class="form-row"><label>${esc(tr('field_tags'))}</label><input type="text" name="tags" /></div>
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button>
          <button type="submit" class="btn btn-primary">${esc(tr('btn_save'))}</button>
        </div>
      </form>
    `);
    if (existing) {
      form.title.value = existing.title;
      form.description.value = existing.description;
      form.status.value = existing.status;
      form.deadline.value = existing.deadline ? existing.deadline.slice(0, 10) : '';
      form.checklist.value = (existing.checklist || []).map((c) => c.text).join('\n');
      form.contacts.value = (existing.contacts || []).join(', ');
      form.budget.value = (existing.budget || []).map((b) => `${b.label}, ${b.amount}`).join('\n');
      form.tags.value = (existing.tags || []).join(', ');
    }
    return form;
  }

  function parseContacts(form) {
    return form.contacts.value.split(',').map((c) => c.trim()).filter(Boolean);
  }

  // Progetti: griglia di icone (stile Esplora Risorse, come le Cartelle) —
  // aprendo un'icona si entra nel dettaglio del singolo progetto, dove si
  // vede/spunta la checklist e si cambia stato con un selettore a 3 vie che
  // riprende visivamente le vecchie colonne del kanban.
  const STATUSES = [
    { key: 'da_fare', label: tr('status_todo') },
    { key: 'in_corso', label: tr('status_doing') },
    { key: 'fatto', label: tr('status_done') },
  ];

  // Nuovo progetto: dalla pagina Progetti e dalla cattura veloce (in quel
  // caso si resta dove si e', anche chiudendo senza salvare).
  function openNewProject(onCreated) {
    const form = projectModal();
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const tags = parseTags(form);
      const contacts = parseContacts(form);
      const budget = parseBudgetLines(form.budget.value);
      const checklist = collectChecklist(form, []);
      const created = await api('/projects', { method: 'POST', body: JSON.stringify({ title: form.title.value, description: form.description.value, status: form.status.value, deadline: form.deadline.value || null, checklist, contacts, budget, tags }) });
      closeModal(); toast(tr('toast_project_saved'));
      if (onCreated) onCreated(created);
    });
    form.querySelector('[data-cancel]').addEventListener('click', closeModal);
    openModal(tr('modal_new_project'), form);
  }

  views.projects = async (root, opts = {}) => {
    const highlightId = opts.highlight ? String(opts.highlight) : null;
    const projects = (await api('/projects')).filter(onlyFilter(opts));
    root.innerHTML = '';

    const toolbar = el(`
      <div class="explorer-toolbar">
        <button type="button" class="btn" id="explorer-up" disabled>${esc(tr('btn_up'))}</button>
        <span class="explorer-path" id="explorer-path">${esc(tr('nav_projects'))}</span>
        ${backToDossierButtonHtml(opts)}
        <button type="button" class="btn btn-primary" id="new-project">${phIcon('plus', 16)}${esc(tr('btn_new_project'))}</button>
      </div>
    `);
    const bodyWrap = el('<div></div>');
    root.appendChild(toolbar);
    root.appendChild(bodyWrap);
    wireBackToDossier(toolbar, opts);

    const upBtn = toolbar.querySelector('#explorer-up');
    const pathEl = toolbar.querySelector('#explorer-path');
    const newProjectBtn = toolbar.querySelector('#new-project');

    newProjectBtn.addEventListener('click', () => openNewProject((created) => { projects.push(created); renderRoot(); }));

    function renderRoot() {
      upBtn.disabled = true;
      pathEl.textContent = tr('nav_projects');
      newProjectBtn.classList.remove('hidden');
      bodyWrap.innerHTML = '';
      if (!projects.length) {
        bodyWrap.appendChild(el(`<div class="empty-state">${esc(tr('empty_none_yet'))}</div>`));
        return;
      }
      // Una scheda per progetto: avanzamento e scadenza si leggono senza
      // aprirlo; prima quelli in corso, poi da fare, in fondo i fatti.
      const ORDER = { in_corso: 0, da_fare: 1, fatto: 2 };
      const sorted = [...projects].sort((a, b) => (ORDER[a.status] ?? 1) - (ORDER[b.status] ?? 1)
        || (a.deadline || '9999').localeCompare(b.deadline || '9999'));
      const grid = el('<div class="project-grid"></div>');
      sorted.forEach((p) => {
        const { done, total } = checklistProgress(p.checklist);
        const statusInfo = STATUSES.find((s) => s.key === p.status) || STATUSES[0];
        const card = el(`
          <div class="project-card project-${p.status}">
            <button type="button" class="project-card-main">
              <span class="project-card-top"><span class="chip-status chip-status-${p.status}"></span><span class="proj-when"></span></span>
              <span class="project-card-title"></span>
              <span class="progress"><span class="progress-fill"></span></span>
              <span class="proj-meta"></span>
            </button>
            <button type="button" class="icon-btn project-card-del" title="${esc(tr('btn_delete'))}" aria-label="${esc(tr('btn_delete'))}">${iconaLinea('cestino')}</button>
          </div>
        `);
        card.querySelector('.chip-status').textContent = statusInfo.label;
        card.querySelector('.project-card-title').textContent = p.title;
        card.querySelector('.progress-fill').style.width = total ? `${Math.round((done / total) * 100)}%` : '0%';
        card.querySelector('.proj-meta').textContent = total ? tr('label_completed_count', { done, total }) : tr('today_no_checklist');
        if (p.deadline && p.status !== 'fatto') {
          const days = calendarDaysFromToday(p.deadline);
          const when = card.querySelector('.proj-when');
          when.textContent = relativeDayLabel(days);
          when.classList.add(urgencyClass(days));
        }
        if (highlightId && String(p.id) === highlightId) card.classList.add('card-highlight');
        card.querySelector('.project-card-main').addEventListener('click', () => renderProject(p));
        card.querySelector('.project-card-del').addEventListener('click', async () => {
          if (!(await askConfirm(tr('confirm_delete_project')))) return;
          await api(`/projects/${p.id}`, { method: 'DELETE' });
          const idx = projects.findIndex((x) => x.id === p.id);
          if (idx !== -1) projects.splice(idx, 1);
          toast(tr('toast_project_deleted')); renderRoot();
        });
        grid.appendChild(card);
      });
      bodyWrap.appendChild(grid);
    }

    function renderProject(p) {
      upBtn.disabled = false;
      pathEl.textContent = p.title;
      newProjectBtn.classList.add('hidden');
      bodyWrap.innerHTML = '';

      const { done, total } = checklistProgress(p.checklist);
      const totalBudget = budgetTotal(p.budget);
      const budgetTitle = (p.budget || []).map((b) => `${b.label}: ${fmtMoney(b.amount)}`).join(', ');
      let deadlineChip = '';
      if (p.deadline) {
        const days = daysUntil(p.deadline);
        const kind = days < 0 ? 'late' : days <= 3 ? 'soon' : 'far';
        deadlineChip = `<span class="chip-deadline chip-deadline-${kind}">${esc(dueLabel(days))}</span>`;
      }

      const panel = el(`
        <div class="project-detail">
          <div class="board-card-top">
            <p class="board-card-title project-detail-title">${esc(p.title)}</p>
            ${deadlineChip}
          </div>
          <div class="status-switch">
            ${STATUSES.map((s) => `<button type="button" class="status-switch-opt${s.key === p.status ? ' active' : ''}" data-status="${s.key}">${esc(s.label)}</button>`).join('')}
          </div>
          ${p.description ? `<p class="card-body">${esc(p.description)}</p>` : ''}
          ${totalBudget ? `<p class="card-sub" title="${esc(budgetTitle)}">${tr('budget_label', { amount: fmtMoney(totalBudget) })}</p>` : ''}
          ${(p.contacts || []).length ? `<p class="card-sub">${tr('contacts_prefix', { names: escTrim(p.contacts.join(', '), 200) })}</p>` : ''}
          <div class="card-actions">
            <button class="btn btn-sm" data-edit>${esc(tr('btn_edit'))}</button>
            <button class="btn btn-sm" data-link>${esc(tr('btn_link_folder'))}</button>
            <button class="btn btn-sm btn-danger" data-del>${esc(tr('btn_delete'))}</button>
          </div>
        </div>
      `);
      bodyWrap.appendChild(panel);

      if (total) {
        const checklistWrap = el('<div class="board-checklist"></div>');
        checklistWrap.appendChild(el(`
          <div class="board-progress-row" title="${esc(tr('label_completed_count', { done, total }))}">
            <div class="board-progress"><div class="board-progress-fill" style="width:${total ? Math.round((done / total) * 100) : 0}%"></div></div>
            <span class="board-progress-label">${done}/${total}</span>
          </div>
        `));
        const itemsEl = el('<div class="idea-checklist"></div>');
        (p.checklist || []).forEach((item, idx) => {
          const row = el(`
            <label class="idea-checklist-item">
              <input type="checkbox" ${item.done ? 'checked' : ''} />
              <span>${esc(item.text)}</span>
              ${item.done ? `<span class="idea-checklist-badge" title="${esc(tr('label_completed_title'))}">${phIcon('check', 12)}</span>` : ''}
            </label>
          `);
          row.querySelector('input').addEventListener('change', async (e) => {
            const updatedChecklist = p.checklist.map((c, j) => (j === idx ? { ...c, done: e.target.checked } : c));
            const updated = await api(`/projects/${p.id}`, { method: 'PUT', body: JSON.stringify({ checklist: updatedChecklist }) });
            applyUpdate(updated);
          });
          itemsEl.appendChild(row);
        });
        checklistWrap.appendChild(itemsEl);
        panel.querySelector('.status-switch').insertAdjacentElement('afterend', checklistWrap);
      }

      function applyUpdate(updated) {
        const idx = projects.findIndex((x) => x.id === updated.id);
        if (idx !== -1) projects[idx] = updated;
        renderProject(updated);
      }

      panel.querySelectorAll('.status-switch-opt').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const newStatus = btn.dataset.status;
          if (newStatus === p.status) return;
          const updated = await api(`/projects/${p.id}`, { method: 'PUT', body: JSON.stringify({ status: newStatus }) });
          applyUpdate(updated);
        });
      });
      panel.querySelector('[data-edit]').addEventListener('click', () => {
        const form = projectModal(p);
        form.addEventListener('submit', async (e) => {
          e.preventDefault();
          const tags = parseTags(form);
          const contacts = parseContacts(form);
          const budget = parseBudgetLines(form.budget.value);
          const checklist = collectChecklist(form, p.checklist);
          const updated = await api(`/projects/${p.id}`, { method: 'PUT', body: JSON.stringify({ title: form.title.value, description: form.description.value, status: form.status.value, deadline: form.deadline.value || null, checklist, contacts, budget, tags }) });
          closeModal(); toast(tr('toast_project_updated')); applyUpdate(updated);
        });
        form.querySelector('[data-cancel]').addEventListener('click', closeModal);
        openModal(tr('modal_edit_project'), form);
      });
      panel.querySelector('[data-link]').addEventListener('click', () => openLinkToDossierModal('project', p.id, p.title));
      const passP = passButton('project', p.id, p.title);
      if (passP) panel.querySelector('[data-link]').after(passP);
      panel.querySelector('[data-del]').addEventListener('click', async () => {
        if (!(await askConfirm(tr('confirm_delete_project')))) return;
        await api(`/projects/${p.id}`, { method: 'DELETE' });
        const idx = projects.findIndex((x) => x.id === p.id);
        if (idx !== -1) projects.splice(idx, 1);
        toast(tr('toast_project_deleted')); renderRoot();
      });
    }

    upBtn.addEventListener('click', renderRoot);

    if (opts.only && projects.length) { renderProject(projects[0]); return; }
    if (highlightId) {
      const match = projects.find((p) => String(p.id) === highlightId);
      if (match) { renderProject(match); return; }
    }
    renderRoot();
  };

  // ==================================================================
  // VAULT
  // ==================================================================
  // Generatore locale: niente ambiguita' visiva (niente I/l/1/O/0), 20
  // caratteri da un alfabeto di 70 simboli sono gia' ~123 bit di entropia.
  function generatePassword(length = 20) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+';
    const bytes = new Uint32Array(length);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes, (n) => chars[n % chars.length]).join('');
  }

  // ---------------- Codici a barre e QR ----------------
  // Le librerie (public/vendor) si caricano solo quando servono.
  const loadedScripts = {};
  function loadScript(src) {
    if (!loadedScripts[src]) {
      loadedScripts[src] = new Promise((resolve, reject) => {
        const tag = document.createElement('script');
        tag.src = src; tag.onload = resolve; tag.onerror = () => reject(new Error(tr('err_unexpected')));
        document.head.appendChild(tag);
      });
    }
    return loadedScripts[src];
  }
  const ZXING_FORMATS = { QR_CODE: 'QR', CODE_128: 'CODE128', EAN_13: 'EAN13', EAN_8: 'EAN8', UPC_A: 'UPC', CODE_39: 'CODE39', ITF: 'ITF' };
  // Lettore integrato del telefono (Android: Shape Detection API).
  const NATIVE_FORMATS = { qr_code: 'QR', code_128: 'CODE128', ean_13: 'EAN13', ean_8: 'EAN8', upc_a: 'UPC', upc_e: 'CODE128', code_39: 'CODE39', itf: 'ITF', codabar: 'CODE128' };
  // Fotocamera posteriore ad alta risoluzione: i codici lunghi e fitti
  // (es. 17 cifre) a 640x480 non si leggono.
  const CAMERA = { video: { facingMode: 'environment', width: { ideal: 1920 }, height: { ideal: 1080 }, advanced: [{ focusMode: 'continuous' }] } };
  async function nativeDetector() {
    if (!('BarcodeDetector' in window)) return null;
    try {
      const supported = await window.BarcodeDetector.getSupportedFormats();
      const formats = Object.keys(NATIVE_FORMATS).filter((f) => supported.includes(f));
      return formats.length ? new window.BarcodeDetector({ formats }) : null;
    } catch (_) { return null; }
  }
  function zxingReader() {
    const Z = window.ZXing;
    const hints = new Map();
    hints.set(Z.DecodeHintType.TRY_HARDER, true);
    hints.set(Z.DecodeHintType.POSSIBLE_FORMATS, Object.keys(ZXING_FORMATS).map((k) => Z.BarcodeFormat[k]));
    return new Z.BrowserMultiFormatReader(hints, 200);
  }

  // Lettura con la fotocamera (o da una foto): risolve con { text, format }
  // oppure null se si chiude la finestra.
  function scanCode() {
    return new Promise((resolve) => {
      let reader = null, done = false, stream = null, timer = null;
      const wrap = el(`<div class="scanner">
        <div class="scanner-view"><video playsinline muted></video><span class="scanner-frame"></span></div>
        <p class="scanner-msg"></p>
        <div class="form-actions"><label class="btn btn-ghost">${esc(tr('scan_from_photo'))}<input type="file" accept="image/*" class="hidden" /></label><button type="button" class="btn" data-cancel>${esc(tr('btn_cancel'))}</button></div>
      </div>`);
      const video = wrap.querySelector('video');
      const msg = wrap.querySelector('.scanner-msg');
      const finish = (value) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        try { if (reader) reader.reset(); } catch (_) { /* gia' fermo */ }
        const st = stream || video.srcObject;
        if (st) st.getTracks().forEach((t) => t.stop());
        closeModal();
        if (value) haptic('success');
        resolve(value);
      };
      const foundZx = (result) => finish({ text: result.getText(), format: ZXING_FORMATS[window.ZXing.BarcodeFormat[result.getBarcodeFormat()]] || 'CODE128' });
      const foundNative = (code) => finish({ text: code.rawValue, format: NATIVE_FORMATS[code.format] || 'CODE128' });
      wrap.querySelector('[data-cancel]').addEventListener('click', () => finish(null));
      openModal(tr('scan_title'), wrap);
      const modalEl = wrap.closest('.modal-backdrop');
      if (modalEl) {
        modalEl.querySelector('.modal-close').addEventListener('click', () => finish(null));
        modalEl.addEventListener('click', (e) => { if (e.target === modalEl) finish(null); });
      }
      const fromPhotoZx = async (file) => {
        await loadScript('/vendor/zxing.min.js');
        reader = reader || zxingReader();
        foundZx(await reader.decodeFromImageUrl(URL.createObjectURL(file)));
      };
      (async () => {
        const detector = await nativeDetector();
        wrap.querySelector('input[type=file]').addEventListener('change', async (e) => {
          const file = e.target.files[0];
          if (!file) return;
          try {
            if (detector) {
              const codes = await detector.detect(await createImageBitmap(file));
              if (codes.length) { foundNative(codes[0]); return; }
            }
            await fromPhotoZx(file);
          } catch (_) { msg.textContent = tr('scan_not_found'); }
        });
        if (detector) {
          try {
            stream = await navigator.mediaDevices.getUserMedia(CAMERA);
          } catch (_) { msg.textContent = tr('scan_no_camera'); return; }
          if (done) { stream.getTracks().forEach((t) => t.stop()); return; }
          video.srcObject = stream;
          await video.play().catch(() => {});
          const tick = async () => {
            if (done) return;
            try {
              const codes = video.readyState >= 2 ? await detector.detect(video) : [];
              if (codes.length) { foundNative(codes[0]); return; }
            } catch (_) { /* fotogramma non pronto */ }
            timer = setTimeout(tick, 120);
          };
          tick();
          return;
        }
        await loadScript('/vendor/zxing.min.js');
        reader = zxingReader();
        reader.decodeFromConstraints(CAMERA, video, (result) => { if (result) foundZx(result); })
          .catch(() => reader.decodeFromConstraints({ video: { facingMode: 'environment' } }, video, (result) => { if (result) foundZx(result); }))
          .catch(() => { msg.textContent = tr('scan_no_camera'); });
      })().catch((err) => { msg.textContent = err.message; });
    });
  }

  // Disegna il codice di una carta (SVG su fondo bianco, come alla cassa).
  async function renderCardCode(target, card) {
    target.innerHTML = '';
    const number = String(card.number || '');
    if (!number || card.format === 'NONE') return false;
    if (card.format === 'QR') {
      await loadScript('/vendor/qrcode.js');
      const qr = window.qrcode(0, 'M');
      qr.addData(number);
      qr.make();
      target.innerHTML = qr.createSvgTag({ cellSize: 6, margin: 2, scalable: true });
      // La libreria allinea il disegno a sinistra (xMinYMin): al centro.
      const svg = target.querySelector('svg');
      if (svg) svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
      target.dataset.code = 'qr';
      return true;
    }
    await loadScript('/vendor/jsbarcode.min.js');
    const svgEl = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    target.appendChild(svgEl);
    try {
      window.JsBarcode(svgEl, number, { format: card.format, displayValue: false, height: 90, margin: 8, width: 2.4 });
    } catch (_) {
      // Numero non valido per quel formato (es. EAN con cifra di controllo
      // sbagliata): meglio un Code 128 leggibile che niente.
      window.JsBarcode(svgEl, number, { format: 'CODE128', displayValue: false, height: 90, margin: 8, width: 2.2 });
    }
    // Codice a barre: si allunga in altezza per riempire la tessera (le
    // barre restano proporzionate in larghezza, la cassa lo legge uguale).
    if (!svgEl.getAttribute('viewBox')) svgEl.setAttribute('viewBox', `0 0 ${parseFloat(svgEl.getAttribute('width'))} ${parseFloat(svgEl.getAttribute('height'))}`);
    svgEl.setAttribute('preserveAspectRatio', 'none');
    target.dataset.code = 'bar';
    return true;
  }

  // otpauth://totp/Banca:io@x.it?secret=ABC&issuer=Banca -> { secret, issuer, account }
  function parseOtpauth(text) {
    const m = String(text || '').match(/^otpauth:\/\/totp\/([^?]*)\?(.*)$/i);
    if (!m) return null;
    const params = new URLSearchParams(m[2]);
    const label = decodeURIComponent(m[1] || '');
    const [labelIssuer, account] = label.includes(':') ? label.split(/:(.*)/s) : ['', label];
    const secret = params.get('secret');
    if (!secret) return null;
    return { secret, issuer: params.get('issuer') || labelIssuer || '', account: (account || '').trim() };
  }

  function vaultModal(existing, presetType) {
    const form = el(`
      <form class="modal-body" style="padding:0">
        <div class="form-row"><label>${esc(tr('field_title'))}</label><input type="text" name="site" required /></div>
        <div class="form-row"><label>${esc(tr('field_type'))}</label>
          <select name="type">
            <option value="password">${esc(tr('vault_type_password'))}</option>
            <option value="note">${esc(tr('vault_type_note'))}</option>
            <option value="card">${esc(tr('vault_type_card'))}</option>
            <option value="code">${esc(tr('vault_type_code'))}</option>
          </select>
        </div>

        <div data-type-fields="password">
          <div class="form-row"><label>${esc(tr('field_username'))}</label><input type="text" name="username" /></div>
          <div class="form-row">
            <label>${esc(tr('field_password'))}${existing ? esc(tr('leave_blank_f')) : ''}</label>
            <div style="display:flex;gap:6px">
              <input type="text" name="password" style="flex:1" />
              <button type="button" class="btn btn-sm" id="gen-password">${esc(tr('btn_generate'))}</button>
            </div>
          </div>
          <div class="form-row"><label>${esc(tr('field_url'))}</label><input type="text" name="url" /></div>
        </div>

        <div data-type-fields="password code">
          <div class="form-row">
            <label>${esc(tr('vault_totp_code'))}${existing ? esc(tr('leave_blank_m')) : esc(tr('totp_optional'))}</label>
            <div style="display:flex;gap:6px">
              <input type="text" name="totp_secret" placeholder="${esc(tr('vault_totp_placeholder'))}" style="flex:1" />
              <button type="button" class="btn btn-sm" data-scan-totp>${esc(tr('btn_scan_qr'))}</button>
            </div>
          </div>
          <div class="form-row" id="remove-totp-row" style="display:none">
            <label style="flex-direction:row;align-items:center;gap:6px">
              <input type="checkbox" name="remove_totp" style="width:auto" /> ${esc(tr('vault_remove_totp'))}
            </label>
          </div>
        </div>

        <div data-type-fields="code">
          <div class="form-row"><label>${esc(tr('field_codes'))}${existing ? esc(tr('leave_blank_m')) : ''}</label><textarea name="codes" rows="4" placeholder="${esc(tr('field_codes_placeholder'))}"></textarea></div>
        </div>

        <div data-type-fields="note">
          <div class="form-row"><label>${esc(tr('field_content'))}${existing ? esc(tr('leave_blank_m')) : ''}</label><textarea name="secure_note" rows="6"></textarea></div>
        </div>

        <div data-type-fields="card">
          <div class="form-row"><label>${esc(tr('field_card_holder'))}</label><input type="text" name="card_holder" /></div>
          <div class="form-row"><label>${esc(tr('field_card_number'))}${existing ? esc(tr('leave_blank_m')) : ''}</label><input type="text" name="card_number" inputmode="numeric" /></div>
          <div style="display:flex;gap:10px">
            <div class="form-row" style="flex:1"><label>${esc(tr('field_card_expiry'))}</label><input type="text" name="card_expiry" placeholder="12/28" /></div>
            <div class="form-row" style="flex:1"><label>${esc(tr('field_cvv'))}${existing ? esc(tr('leave_blank_m')) : ''}</label><input type="text" name="card_cvv" inputmode="numeric" /></div>
          </div>
        </div>

        <div class="form-row"><label>${esc(tr('field_notes'))}</label><textarea name="notes" rows="3"></textarea></div>
        <div class="form-row"><label>${esc(tr('field_tags'))}</label><input type="text" name="tags" /></div>
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button>
          <button type="submit" class="btn btn-primary">${esc(tr('btn_save'))}</button>
        </div>
      </form>
    `);

    function syncTypeFields() {
      form.querySelectorAll('[data-type-fields]').forEach((group) => {
        group.classList.toggle('hidden', !group.dataset.typeFields.split(' ').includes(form.type.value));
      });
    }
    form.type.addEventListener('change', syncTypeFields);
    form.querySelector('#gen-password').addEventListener('click', () => {
      form.password.value = generatePassword();
    });
    form.querySelector('[data-scan-totp]').addEventListener('click', async () => {
      // La lettura apre la sua finestra: il modulo si tiene da parte e si
      // rimette al suo posto dopo.
      const backdrop = form.closest('.modal-backdrop');
      if (backdrop) backdrop.remove();
      const result = await scanCode();
      if (backdrop) { document.body.appendChild(backdrop); activeModal = backdrop; }
      if (!result) return;
      const otp = parseOtpauth(result.text);
      if (!otp) { toast(tr('scan_not_totp')); return; }
      form.totp_secret.value = otp.secret;
      if (!form.site.value) form.site.value = otp.issuer || otp.account;
      if (form.username && !form.username.value && otp.account) form.username.value = otp.account;
    });
    if (presetType) {
      form.type.value = presetType;
      form.type.closest('.form-row').classList.add('hidden');
    }

    if (existing) {
      form.site.value = existing.site;
      form.type.value = existing.type || 'password';
      // "username" (password) e "card_holder" (carta) sono la stessa colonna
      // lato server: precompiliamo entrambi, solo uno e' visibile alla volta.
      form.username.value = existing.username;
      form.card_holder.value = existing.username;
      form.url.value = existing.url;
      form.notes.value = existing.notes;
      form.tags.value = (existing.tags || []).join(', ');
      form.card_expiry.value = existing.card_expiry || '';
      if (existing.hasTotp) form.querySelector('#remove-totp-row').style.display = '';
      // Il tipo non si cambia dopo la creazione: in modifica i campi del
      // segreto principale restano vuoti ("lascia vuoto per non cambiarlo"),
      // e cambiare tipo a quel punto scambierebbe il significato del segreto
      // gia' salvato (es. una password che diventa "numero di carta").
      form.type.disabled = true;
      form.type.closest('.form-row').classList.add('hidden');
    }
    syncTypeFields();
    return form;
  }

  // Costruisce il corpo della richiesta in base al tipo scelto: il campo
  // "password" del form alimenta sempre l'unico segreto principale della
  // voce (password / numero carta / contenuto nota), qualunque sia il tipo.
  function collectVaultPayload(form, existing) {
    const type = form.type.value;
    const tags = parseTags(form);
    const payload = { site: form.site.value, type, notes: form.notes.value, tags };
    const primary = type === 'password' ? form.password.value : type === 'note' ? form.secure_note.value : type === 'code' ? form.codes.value : form.card_number.value;
    if (primary || !existing) payload.password = primary;

    if (type === 'password' || type === 'code') {
      if (type === 'password') { payload.username = form.username.value; payload.url = form.url.value; }
      if (form.remove_totp && form.remove_totp.checked) payload.totp_secret = '-';
      else if (form.totp_secret.value.trim()) payload.totp_secret = form.totp_secret.value.trim();
    } else if (type === 'card') {
      payload.username = form.card_holder.value;
      payload.card_expiry = form.card_expiry.value;
      if (form.card_cvv.value.trim()) payload.card_cvv = form.card_cvv.value.trim();
    }
    return payload;
  }

  function vaultPrimaryFieldError(form, existing) {
    if (existing) return null; // in modifica, vuoto = "non cambiare": mai un errore
    const type = form.type.value;
    if (type === 'password' && !form.password.value) return tr('err_password_required');
    if (type === 'note' && !form.secure_note.value) return tr('err_note_content_required');
    if (type === 'card' && !form.card_number.value) return tr('err_card_number_required');
    if (type === 'code' && !form.codes.value && !form.totp_secret.value.trim()) return tr('err_code_required');
    return null;
  }

  // QR grande da far inquadrare (passaggio diretto tra telefoni).
  async function showQr(title, text, caption, actions, opts = {}) {
    await loadScript('/vendor/qrcode.js');
    const code = window.qrcode(0, 'L');
    code.addData(text, 'Byte');
    code.make();
    const wrap = el(`<div class="qr-show"><div class="qr-big">${code.createSvgTag({ cellSize: 4, margin: 3, scalable: true })}</div><p class="qr-caption"></p><div class="form-actions"></div></div>`);
    wrap.querySelector('.qr-caption').textContent = caption || '';
    (actions || []).forEach((b) => wrap.querySelector('.form-actions').appendChild(b));
    openModal(title, wrap, opts);
    return wrap;
  }

  // ---------- Passare elementi da un telefono all'altro ----------
  // Chi riceve mostra un QR con la sua chiave pubblica e l'indirizzo PeerJS su
  // cui aspetta. Chi passa lo inquadra e manda l'elemento cifrato per quella
  // chiave direttamente (WebRTC; il server pubblico PeerJS presenta solo i due
  // telefoni). Se il collegamento non riesce: QR dell'elemento o file .memento.
  function transferEngine() { return (window.MementoBackend && window.MementoBackend.engine) || null; }
  const PEER_CHUNK = 15000; // il canale JSON di PeerJS rifiuta messaggi oltre ~16 KB
  // Server diverso da quello pubblico: localStorage "memento-peer-server" (es. peer.esempio.it:9000/app).
  function peerOptions() {
    const custom = (localStorage.getItem('memento-peer-server') || '').trim();
    const m = custom && custom.match(/^(?:(https?):\/\/)?([^/:]+)(?::(\d+))?(\/.*)?$/);
    if (!m) return { debug: 0 };
    return { host: m[2], port: Number(m[3]) || (m[1] === 'http' ? 80 : 443), path: m[4] || '/', secure: m[1] !== 'http', debug: 0 };
  }
  async function newPeer(id) {
    await loadScript('/vendor/peerjs.min.js');
    return new Promise((resolve, reject) => {
      const peer = id ? new window.Peer(id, peerOptions()) : new window.Peer(peerOptions());
      let opened = false;
      const t = setTimeout(() => { peer.destroy(); reject(new Error('timeout')); }, 10000);
      peer.on('open', () => { opened = true; clearTimeout(t); resolve(peer); });
      peer.on('error', (err) => { if (opened) return; clearTimeout(t); peer.destroy(); reject(err); });
    });
  }
  function sendOnce(peer, peerId, sealed, onProgress) {
    return new Promise((resolve, reject) => {
      const conn = peer.connect(peerId, { reliable: true, serialization: 'json' });
      let t = setTimeout(() => reject(new Error('timeout')), 12000);
      const fail = (err) => { clearTimeout(t); reject(err || new Error('peer')); };
      peer.on('error', fail);
      conn.on('error', fail);
      conn.on('close', () => fail(new Error('closed')));
      conn.on('data', (msg) => {
        if (msg && msg.t === 'ok') { clearTimeout(t); resolve(); }
        else if (msg && msg.t === 'err') fail(Object.assign(new Error(msg.m || ''), { fromPeer: true }));
      });
      conn.on('open', async () => {
        clearTimeout(t);
        const text = JSON.stringify(sealed);
        const n = Math.max(1, Math.ceil(text.length / PEER_CHUNK));
        conn.send({ t: 'begin', n });
        for (let i = 0; i < n; i++) {
          const dc = conn.dataChannel;
          while (dc && dc.bufferedAmount > 1000000) await new Promise((r) => setTimeout(r, 40));
          conn.send({ t: 'part', i, s: text.slice(i * PEER_CHUNK, (i + 1) * PEER_CHUNK) });
          if (onProgress) onProgress((i + 1) / n);
        }
        conn.send({ t: 'end' });
        t = setTimeout(() => reject(new Error('timeout')), 120000);
      });
    });
  }
  async function sendByPeer(peerId, sealed, onProgress) {
    const peer = await newPeer();
    try {
      try { await sendOnce(peer, peerId, sealed, onProgress); }
      catch (err) {
        // Chi riceve puo' non essersi ancora presentato al server: un secondo tentativo.
        if (err.fromPeer || err.type !== 'peer-unavailable') throw err;
        await new Promise((r) => setTimeout(r, 2500));
        await sendOnce(peer, peerId, sealed, onProgress);
      }
    } finally { setTimeout(() => peer.destroy(), 600); }
  }
  // Il nome del telefono si chiede una volta: e' quello che vede l'altro.
  function askPhoneName(engine) {
    if (engine.identityName()) return Promise.resolve(true);
    return new Promise((resolve) => {
      const form = el(`<form class="modal-body" style="padding:0"><div class="form-row"><label>${esc(tr('qr_name_label'))}</label><input type="text" name="name" required maxlength="60" placeholder="${esc(tr('qr_name_placeholder'))}" /></div>
        <div class="form-actions"><button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button><button type="submit" class="btn btn-primary">${esc(tr('btn_confirm'))}</button></div></form>`);
      form.addEventListener('submit', async (e) => { e.preventDefault(); await engine.setIdentityName(form.name.value); closeModal(); resolve(true); });
      form.querySelector('[data-cancel]').addEventListener('click', () => { closeModal(); resolve(false); });
      openModal(tr('qr_name_title'), form);
    });
  }
  function pickTransferFile() {
    return new Promise((resolve) => {
      const input = el('<input type="file" class="hidden" />');
      input.addEventListener('change', () => { resolve(input.files[0] || null); input.remove(); });
      document.body.appendChild(input);
      input.click();
    });
  }
  async function saveTransferFile(sealed, label) {
    const name = `${String(label || 'memento').replace(/[^\p{L}\p{N}]+/gu, '-').replace(/^-|-$/g, '').slice(0, 40) || 'memento'}.memento`;
    const blob = new Blob([JSON.stringify(sealed)], { type: 'application/octet-stream' });
    if (window.MementoShell && window.MementoShell.saveFile) { await window.MementoShell.saveFile(blob, name); return; }
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  // Ricevere: QR con chiave e indirizzo, in attesa del collegamento diretto;
  // in alternativa si inquadra il QR dell'elemento o si apre un file .memento.
  async function receiveFlow() {
    const engine = transferEngine();
    if (!engine || !(await askPhoneName(engine))) return;
    // Un avviso rimasto aperto coprirebbe il QR.
    document.querySelectorAll('.toast').forEach((t) => t.remove());
    const peerId = 'memento-' + [...crypto.getRandomValues(new Uint8Array(10))].map((b) => b.toString(16).padStart(2, '0')).join('');
    let peer = null;
    let closed = false;
    let wrap = null;
    const setStatus = (text) => { const p = wrap && wrap.querySelector('.qr-caption'); if (p) p.textContent = text; };
    const accept = async (input, conn) => {
      const got = await engine.receiveTransfer(input);
      if (conn) { try { conn.send({ t: 'ok' }); } catch (_) { /* gia' chiuso */ } await new Promise((r) => setTimeout(r, 400)); }
      closeModal();
      // Ogni elemento e' gia' nella sua sezione: l'avviso dice quale e la apre.
      const view = TYPE_TO_VIEW[got.type] || 'today';
      const where = (SECTIONS.find((x) => x.view === view) || {}).label || '';
      toast(tr(got.count > 1 ? 'transfer_received_many' : 'transfer_received', { what: got.label, from: got.from, n: got.count - 1, where }), {
        action: tr('transfer_open'), onAction: () => render(view, { highlight: got.id }), duration: 8000,
      });
      if (currentView === 'security') render('security');
    };
    const scanBtn = el(`<button type="button" class="btn btn-ghost">${esc(tr('qr_scan_item'))}</button>`);
    scanBtn.addEventListener('click', async () => {
      closeModal();
      const res = await scanCode();
      if (!res) return;
      try { await accept(res.text); } catch (err) { toast(err.message); }
    });
    const fileBtn = el(`<button type="button" class="btn btn-ghost">${esc(tr('transfer_open_file'))}</button>`);
    fileBtn.addEventListener('click', async () => {
      const file = await pickTransferFile();
      if (!file) return;
      try { await accept(await file.text()); } catch (err) { toast(err.message); }
    });
    wrap = await showQr(tr('transfer_receive_title'), await engine.identityQr(peerId), tr('transfer_waiting'), [fileBtn, scanBtn], {
      onClose: () => { closed = true; if (peer) setTimeout(() => peer.destroy(), 500); },
    });
    newPeer(peerId).then((p) => {
      if (closed) { p.destroy(); return; }
      peer = p;
      p.on('connection', (conn) => {
        let parts = [];
        conn.on('data', async (msg) => {
          if (!msg || closed) return;
          if (msg.t === 'begin') { parts = new Array(Math.min(Number(msg.n) || 1, 100000)); setStatus(tr('transfer_progress', { pct: 0 })); }
          else if (msg.t === 'part' && msg.i >= 0 && msg.i < parts.length) {
            parts[msg.i] = String(msg.s || '');
            setStatus(tr('transfer_progress', { pct: Math.round((parts.filter((x) => x !== undefined).length / parts.length) * 100) }));
          } else if (msg.t === 'end') {
            try { await accept(JSON.parse(parts.join('')), conn); }
            catch (err) { try { conn.send({ t: 'err', m: err.message }); } catch (_) { /* chiuso */ } setStatus(err.message); }
          }
        });
      });
    }).catch(() => { if (!closed) setStatus(tr('transfer_peer_off')); });
  }
  // Passare: si inquadra il QR di chi riceve e si manda l'elemento.
  async function passItem(type, id, label) {
    const engine = transferEngine();
    if (!engine) return;
    closeModal();
    if (!(await askPhoneName(engine))) return;
    toast(tr('qr_scan_recipient'));
    const res = await scanCode();
    if (!res) return;
    let who, sealed;
    try {
      who = await engine.readIdentityQr(res.text);
      sealed = await engine.sealTransfer(type, id, who);
    } catch (err) { toast(err.message); return; }
    if (who.peer) {
      const box = el(`<div class="qr-show"><p class="qr-caption"></p></div>`);
      const cap = box.querySelector('.qr-caption');
      cap.textContent = tr('transfer_sending', { who: who.label });
      let cancelled = false;
      openModal(label, box, { onClose: () => { cancelled = true; } });
      try {
        await sendByPeer(who.peer, sealed, (f) => { cap.textContent = tr('transfer_sending_pct', { who: who.label, pct: Math.round(f * 100) }); });
        if (!cancelled) { closeModal(); toast(tr('transfer_sent', { who: who.label })); }
        return;
      } catch (err) {
        if (cancelled) return;
        if (err.fromPeer) { closeModal(); toast(err.message); return; }
      }
    }
    const fileBtn = el(`<button type="button" class="btn btn-ghost">${esc(tr('transfer_send_file'))}</button>`);
    fileBtn.addEventListener('click', () => saveTransferFile(sealed, label).catch((err) => toast(err.message)));
    const done = el(`<button type="button" class="btn btn-primary">${esc(tr('qr_done'))}</button>`);
    done.addEventListener('click', closeModal);
    const qr = engine.transferQrText(sealed);
    if (qr) { await showQr(label, qr, tr('qr_pass_hint', { who: who.label }), [fileBtn, done]); return; }
    const box = el(`<div class="qr-show"><p class="qr-caption"></p><div class="form-actions"></div></div>`);
    box.querySelector('.qr-caption').textContent = tr('transfer_file_only', { who: who.label });
    box.querySelector('.form-actions').append(fileBtn, done);
    openModal(label, box);
  }
  // Icona "Condividi" delle schede (solo nell'app, modalita' "Sul telefono").
  function passButton(type, id, label) {
    if (!transferEngine()) return null;
    const b = el(`<button type="button" class="icon-btn pass-btn" data-pass title="${esc(tr('btn_pass'))}" aria-label="${esc(tr('btn_pass'))}">${phIcon('share-network', 18)}</button>`);
    b.addEventListener('click', (e) => { e.stopPropagation(); passItem(type, id, label); });
    return b;
  }

  views.vault = async (root, opts = {}) => {
    const highlightId = opts.highlight ? String(opts.highlight) : null;
    const engine = window.MementoBackend && window.MementoBackend.engine;

    const entries = (await api('/vault')).filter(onlyFilter(opts));
    root.innerHTML = '';
    root.appendChild(el(`
      <div class="view-header">
        <h2>${esc(tr('nav_vault_title'))}</h2>
        <div class="view-header-actions">${backToDossierButtonHtml(opts)}
          <label class="icon-action" title="${esc(tr('btn_import_csv'))}" aria-label="${esc(tr('btn_import_csv'))}">${phIcon('file-csv', 22)}<input type="file" id="csv-input" accept=".csv" class="hidden" /></label>
          <button type="button" class="icon-action icon-action-primary" id="new-vault" title="${esc(tr('btn_new_vault_entry'))}" aria-label="${esc(tr('btn_new_vault_entry'))}">${phIcon('plus', 22)}</button>
        </div>
      </div>
    `));
    wireBackToDossier(root, opts);

    root.querySelector('#csv-input').addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const fd = new FormData();
      fd.append('file', file);
      try {
        const result = await api('/vault/import', { method: 'POST', body: fd });
        toast(tr('toast_vault_import', { imported: result.imported, skipped: result.skipped }));
        render('vault');
      } catch (err) {
        toast(tr('toast_vault_import_failed', { msg: err.message }));
      }
    });

    // "Nuova voce": prima si sceglie il tipo, poi si apre il modulo giusto.
    const newEntry = (type) => {
      const form = vaultModal(null, type);
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const error = vaultPrimaryFieldError(form, null);
        if (error) { toast(error); return; }
        await api('/vault', { method: 'POST', body: JSON.stringify(collectVaultPayload(form, null)) });
        closeModal(); toast(tr('toast_vault_saved')); render('vault');
      });
      form.querySelector('[data-cancel]').addEventListener('click', closeModal);
      openModal(tr('modal_new_vault_entry'), form);
    };
    const VAULT_KINDS = [
      { type: 'password', label: tr('vault_kind_account'), sub: tr('vault_kind_account_sub'), icon: 'user' },
      { type: 'note', label: tr('vault_kind_note'), sub: tr('vault_kind_note_sub'), icon: 'notepad' },
      { type: 'code', label: tr('vault_kind_code'), sub: tr('vault_kind_code_sub'), icon: 'password' },
      { type: 'card', label: tr('vault_kind_card'), sub: tr('vault_kind_card_sub'), icon: 'credit-card' },
    ];
    root.querySelector('#new-vault').addEventListener('click', () => {
      const wrap = el('<div class="kind-list"></div>');
      VAULT_KINDS.forEach((k) => {
        const b = el(`<button type="button" class="kind-btn"><span class="kind-ic">${phIcon(k.icon, 24)}</span><span class="kind-text"><b></b><small></small></span></button>`);
        b.querySelector('b').textContent = k.label;
        b.querySelector('small').textContent = k.sub;
        b.addEventListener('click', () => newEntry(k.type));
        wrap.appendChild(b);
      });
      openModal(tr('modal_new_vault_entry'), wrap);
    });

    if (!entries.length) {
      root.appendChild(el(`<div class="empty-state">${esc(tr('vault_empty'))}</div>`));
      return;
    }

    const TYPE_LABEL = { password: tr('vault_kind_account'), note: tr('vault_kind_note'), card: tr('vault_kind_card'), code: tr('vault_kind_code') };
    // Schede in alto: Codici mostra i codici 2FA gia' in chiaro (si sceglie
    // la scheda apposta), le altre filtrano per tipo.
    const TABS = [
      { key: 'password', label: tr('vault_kind_account'), icon: 'user', test: (x) => x.type === 'password' },
      { key: 'note', label: tr('vault_kind_note'), icon: 'notepad', test: (x) => x.type === 'note' },
      { key: 'codes', label: tr('vault_kind_code'), icon: 'password', test: (x) => x.type === 'code' || x.hasTotp },
      { key: 'card', label: tr('vault_kind_card'), icon: 'credit-card', test: (x) => x.type === 'card' },
    ];
    let tab = sessionStorage.getItem('memento-vault-tab') || 'password';
    // Ordinamento (preferenza del dispositivo): predefinito alfabetico.
    const SORTS = {
      az: (a, b) => a.site.localeCompare(b.site, undefined, { sensitivity: 'base' }),
      za: (a, b) => b.site.localeCompare(a.site, undefined, { sensitivity: 'base' }),
      recent: (a, b) => String(b.updated_at || '').localeCompare(String(a.updated_at || '')),
      type: (a, b) => String(a.type).localeCompare(String(b.type)) || a.site.localeCompare(b.site, undefined, { sensitivity: 'base' }),
    };
    let sort = localStorage.getItem('memento-vault-sort') || 'az';
    if (!SORTS[sort]) sort = 'az';
    if (!TABS.some((t) => t.key === tab)) tab = 'password';
    // Voce aperta dalla ricerca o da una cartella: la scheda del suo tipo.
    if (highlightId) {
      const target = entries.find((x) => String(x.id) === highlightId);
      const t = target && TABS.find((x) => x.key !== 'codes' && x.test(target));
      if (t) tab = t.key;
    }

    const seg = el('<div class="seg seg-icons" role="tablist"></div>');
    const sortBar = el(`<div class="sort-bar"><label><span>${esc(tr('sort_label'))}</span><select>
      <option value="az">${esc(tr('sort_az'))}</option><option value="za">${esc(tr('sort_za'))}</option>
      <option value="recent">${esc(tr('sort_recent'))}</option><option value="type">${esc(tr('sort_type'))}</option></select></label></div>`);
    const list = el('<div class="vault-list"></div>');
    root.appendChild(seg);
    root.appendChild(sortBar);
    root.appendChild(list);
    const sortSelect = sortBar.querySelector('select');
    sortSelect.value = sort;
    sortSelect.addEventListener('change', () => { sort = sortSelect.value; localStorage.setItem('memento-vault-sort', sort); paint(); });

    const LOGO_TINTS = [['#E3E9FF', '#2448E0'], ['#FFE3DE', '#B4231A'], ['#FFE4DC', '#B2401F'], ['#F3E8FF', '#7048E8'], ['#FFF0D6', '#A85A00'], ['#FCE4EE', '#B0285A']];
    const tintFor = (name) => LOGO_TINTS[[...String(name)].reduce((a, c) => a + c.charCodeAt(0), 0) % LOGO_TINTS.length];

    async function revealFull(entry) {
      try {
        return await api(`/vault/${entry.id}/reveal`);
      } catch (err) {
        if (!(err.data && err.data.webauthnRequired)) throw err;
        return revealWithFingerprint(entry.id);
      }
    }
    async function copyText(text) {
      try {
        await navigator.clipboard.writeText(text);
        toast(tr('toast_copied'));
      } catch (_) {
        toast(tr('err_copy_failed'));
      }
    }

    // Codice 2FA che si aggiorna da solo: una richiesta al server quando il
    // codice cambia, il conto alla rovescia lo fa il telefono.
    function liveCode(entry, codeEl, barEl) {
      let remaining = 0, timer = null;
      const tick = async () => {
        if (!document.body.contains(codeEl)) { clearInterval(timer); return; }
        if (remaining <= 0) {
          try {
            const r = await api(`/vault/${entry.id}/totp`);
            codeEl.textContent = `${r.code.slice(0, 3)} ${r.code.slice(3)}`;
            remaining = r.secondsRemaining;
          } catch (_) {
            codeEl.textContent = tr('vault_code_unavailable');
            clearInterval(timer);
            return;
          }
        }
        if (barEl) barEl.style.width = `${Math.round((remaining / 30) * 100)}%`;
        remaining -= 1;
      };
      // Primo giro al prossimo ciclo: l'elemento viene messo sullo schermo
      // subito dopo questa chiamata.
      setTimeout(tick, 0);
      timer = setInterval(tick, 1000);
    }

    // Dettaglio della voce: tutto quello che serve copiare, piu' le azioni.
    function openDetail(entry) {
      const wrap = el(`<div class="vault-detail"></div>`);
      const field = (label, value, { secret = false, mono = false } = {}) => {
        const row = el(`<div class="vd-row"><span class="vd-label"></span><span class="vd-value ${mono ? 'mono' : ''}"></span><span class="vd-acts"></span></div>`);
        row.querySelector('.vd-label').textContent = label;
        const valueEl = row.querySelector('.vd-value');
        const acts = row.querySelector('.vd-acts');
        if (secret) {
          let shown = null;
          valueEl.textContent = '••••••••';
          const eye = el(`<button type="button" class="sq-btn" title="${esc(tr('title_show'))}">${iconaLinea('occhio')}</button>`);
          const copy = el(`<button type="button" class="sq-btn" title="${esc(tr('btn_copy'))}">${ICON_COPY}</button>`);
          const load = async () => { if (shown === null) shown = await value(); return shown; };
          eye.addEventListener('click', async () => {
            if (valueEl.dataset.open) { valueEl.textContent = '••••••••'; delete valueEl.dataset.open; eye.innerHTML = iconaLinea('occhio'); return; }
            try { valueEl.textContent = (await load()) || tr('vault_empty_value'); } catch (err) { toast(err.message); return; }
            valueEl.dataset.open = '1'; eye.innerHTML = iconaLinea('occhio-off');
          });
          copy.addEventListener('click', async () => { try { copyText(await load()); } catch (err) { toast(err.message); } });
          acts.append(eye, copy);
        } else {
          valueEl.textContent = value || '—';
          if (value) {
            const copy = el(`<button type="button" class="sq-btn" title="${esc(tr('btn_copy'))}">${ICON_COPY}</button>`);
            copy.addEventListener('click', () => copyText(value));
            acts.append(copy);
          }
        }
        return row;
      };
      let fullPromise = null;
      const full = () => (fullPromise = fullPromise || revealFull(entry));
      if (entry.username) wrap.appendChild(field(tr('col_username'), entry.username));
      if (entry.type === 'note') {
        wrap.appendChild(field(tr('vault_type_note'), async () => (await full()).password, { secret: true }));
      } else if (entry.type === 'code') {
        wrap.appendChild(field(tr('field_codes'), async () => (await full()).password, { secret: true, mono: true }));
      } else {
        wrap.appendChild(field(entry.type === 'card' ? tr('vault_card_number') : tr('col_password'), async () => (await full()).password, { secret: true, mono: true }));
      }
      if (entry.type === 'card') wrap.appendChild(field('CVV', async () => (await full()).cvv, { secret: true, mono: true }));
      if (entry.hasTotp) {
        const row = el(`<div class="vd-row"><span class="vd-label"></span><span class="vd-value mono vd-code">…</span><span class="vd-acts"><span class="otp-timer"><i></i></span></span></div>`);
        row.querySelector('.vd-label').textContent = tr('title_totp_code');
        const codeEl = row.querySelector('.vd-code');
        codeEl.addEventListener('click', () => copyText(codeEl.textContent.replace(/\s/g, '')));
        wrap.appendChild(row);
        liveCode(entry, codeEl, row.querySelector('.otp-timer i'));
      }
      if (entry.url) wrap.appendChild(field('URL', entry.url));
      if (entry.notes) wrap.appendChild(field(tr('field_notes'), entry.notes));

      const sh = entry.share;
      const received = !!(sh && sh.role !== 'owner');
      if (sh) {
        const line = received
          ? tr(sh.role === 'reader' ? 'share_from_read' : 'share_from_write', { who: sh.owner })
          : tr('share_with', { who: sh.members.map((m) => m.email).join(', ') });
        wrap.prepend(el(`<p class="share-line">${esc(line)}</p>`));
      }
      const canShare = window.MementoBackend && window.MementoBackend.canShare && !received;
      const actions = el(`<div class="form-actions"><span class="form-actions-side">${received ? '' : '<button type="button" class="btn btn-ghost" data-link></button>'}<button type="button" class="btn btn-ghost btn-danger" data-del></button>${canShare ? '<button type="button" class="btn btn-ghost" data-share></button>' : ''}</span>${sh && sh.role === 'reader' ? '' : '<button type="button" class="btn btn-primary" data-edit></button>'}</div>`);
      if (actions.querySelector('[data-link]')) actions.querySelector('[data-link]').textContent = tr('btn_link_folder');
      actions.querySelector('[data-del]').textContent = received ? tr('share_leave') : tr('btn_delete');
      if (actions.querySelector('[data-edit]')) actions.querySelector('[data-edit]').textContent = tr('btn_edit');
      const pass = !received && passButton('vault', entry.id, entry.site);
      if (pass) actions.querySelector('.form-actions-side').appendChild(pass);
      if (canShare) {
        actions.querySelector('[data-share]').textContent = tr('btn_share');
        actions.querySelector('[data-share]').addEventListener('click', () => { closeModal(); openShare(entry); });
      }
      if (actions.querySelector('[data-link]')) actions.querySelector('[data-link]').addEventListener('click', () => { closeModal(); openLinkToDossierModal('vault', entry.id, entry.site); });
      actions.querySelector('[data-del]').addEventListener('click', async () => {
        if (!(await askConfirm(received ? tr('share_leave_confirm') : tr('confirm_delete_vault_entry')))) return;
        await api(`/vault/${entry.id}`, { method: 'DELETE' });
        closeModal(); toast(tr('toast_vault_deleted')); render('vault');
      });
      if (actions.querySelector('[data-edit]')) actions.querySelector('[data-edit]').addEventListener('click', () => {
        closeModal();
        const form = vaultModal(entry);
        form.addEventListener('submit', async (e) => {
          e.preventDefault();
          await api(`/vault/${entry.id}`, { method: 'PUT', body: JSON.stringify(collectVaultPayload(form, entry)) });
          closeModal(); toast(tr('toast_vault_updated')); render('vault');
        });
        form.querySelector('[data-cancel]').addEventListener('click', closeModal);
        openModal(tr('modal_edit_vault_entry'), form);
      });
      wrap.appendChild(actions);
      openModal(entry.site, wrap);
    }

    // Condivisione: persone e permessi; il file arriva alla prossima
    // sincronizzazione con Google Drive.
    function openShare(entry) {
      const wrap = el(`<div class="share-box"><div class="share-people"></div>
        <form class="share-add"><input type="email" name="email" required placeholder="${esc(tr('share_email_placeholder'))}" autocomplete="email" />
        <select name="role"><option value="reader">${esc(tr('share_role_reader'))}</option><option value="writer">${esc(tr('share_role_writer'))}</option></select>
        <button type="submit" class="btn btn-primary">${esc(tr('share_add'))}</button></form></div>`);
      const people = wrap.querySelector('.share-people');
      const paintPeople = (e) => {
        people.innerHTML = '';
        ((e.share && e.share.members) || []).forEach((m) => {
          const waiting = (e.share.pending || []).includes(m.email);
          const row = el(`<div class="vd-row"><span class="vd-value"><b></b><small></small></span><span class="vd-acts"><button type="button" class="btn btn-sm btn-ghost btn-danger"></button></span></div>`);
          row.querySelector('b').textContent = m.email;
          row.querySelector('small').textContent = (m.role === 'writer' ? tr('share_role_writer') : tr('share_role_reader')) + (waiting ? ' · ' + tr('share_waiting') : '');
          const rm = row.querySelector('button');
          rm.textContent = tr('share_remove');
          rm.addEventListener('click', async () => {
            const updated = await api(`/vault/${e.id}/share/${encodeURIComponent(m.email)}`, { method: 'DELETE' });
            paintPeople(updated);
            if (window.MementoBackend.syncNow) window.MementoBackend.syncNow();
          });
          people.appendChild(row);
        });
      };
      paintPeople(entry);
      const form = wrap.querySelector('form');
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const updated = await api(`/vault/${entry.id}/share`, { method: 'POST', body: JSON.stringify({ email: form.email.value, role: form.role.value }) });
        form.email.value = '';
        form.querySelector('button[type="submit"]').disabled = false;
        paintPeople(updated);
        toast(tr('share_added'));
        if (window.MementoBackend.syncNow) window.MementoBackend.syncNow();
      });
      openModal(tr('share_title', { what: entry.site }), wrap);
    }

    function paint() {
      seg.innerHTML = '';
      TABS.forEach((t) => {
        const b = el(`<button type="button" role="tab" class="${t.key === tab ? 'on' : ''}" aria-selected="${t.key === tab}">${phIcon(t.icon, 22)}<span></span></button>`);
        b.querySelector('span').textContent = t.label;
        b.addEventListener('click', () => { tab = t.key; sessionStorage.setItem('memento-vault-tab', tab); paint(); });
        seg.appendChild(b);
      });
      list.innerHTML = '';
      const test = TABS.find((t) => t.key === tab).test;
      const shownEntries = entries.filter(test);
      if (!shownEntries.length) list.appendChild(el(`<div class="empty-state">${esc(tr('empty_none_yet'))}</div>`));
      shownEntries.sort(SORTS[sort]).forEach((entry) => {
        const [bg, fg] = tintFor(entry.site);
        const card = el(`
          <div class="vcard" tabindex="0" role="button">
            <span class="vlogo"></span>
            <span class="vtext"><b></b><small></small></span>
            <span class="vright"></span>
          </div>
        `);
        const logo = card.querySelector('.vlogo');
        logo.textContent = (entry.site || '?').trim().charAt(0).toUpperCase();
        logo.style.background = bg; logo.style.color = fg;
        card.querySelector('b').textContent = entry.site;
        card.querySelector('small').textContent = entry.username || TYPE_LABEL[entry.type] || '';
        if (entry.share) {
          const badge = el(`<span class="share-badge"></span>`);
          badge.textContent = entry.share.role === 'owner' ? tr('share_badge_out') : tr('share_badge_in', { who: entry.share.owner.split('@')[0] });
          card.querySelector('.vtext').appendChild(badge);
        }
        const right = card.querySelector('.vright');
        if (entry.hasTotp && (tab === 'codes' || entry.type === 'code')) {
          const box = el('<span class="otp-box"><span class="otp-code">…</span><span class="otp-timer"><i></i></span></span>');
          right.appendChild(box);
          box.addEventListener('click', (e) => { e.stopPropagation(); copyText(box.querySelector('.otp-code').textContent.replace(/\s/g, '')); });
          liveCode(entry, box.querySelector('.otp-code'), box.querySelector('.otp-timer i'));
        } else if (entry.type !== 'note') {
          const copy = el(`<button type="button" class="sq-btn" title="${esc(tr('btn_copy'))}" aria-label="${esc(tr('btn_copy'))}">${ICON_COPY}</button>`);
          copy.addEventListener('click', async (e) => {
            e.stopPropagation();
            try { copyText((await revealFull(entry)).password || ''); } catch (err) { toast(err.message); }
          });
          right.appendChild(copy);
        }
        card.addEventListener('click', () => { if (card.dataset.longpress) { delete card.dataset.longpress; return; } openDetail(entry); });
        card.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target === card) openDetail(entry); });
        // Pressione lunga: copia la password (o il codice 2FA) senza aprire.
        let pressTimer = null;
        card.addEventListener('pointerdown', () => {
          pressTimer = setTimeout(async () => {
            card.dataset.longpress = '1';
            haptic('medium');
            try {
              if (entry.hasTotp && (entry.type === 'code' || tab === 'codes')) {
                const t = await api(`/vault/${entry.id}/totp`);
                await navigator.clipboard.writeText(t.code); toast(tr('toast_code_copied'));
              } else if (entry.type !== 'note') {
                const full = await revealFull(entry);
                await navigator.clipboard.writeText(full.password || ''); toast(tr('toast_copied'));
              }
            } catch (err) { toast(err.message); }
          }, 550);
        });
        ['pointerup', 'pointerleave', 'pointercancel', 'pointermove'].forEach((ev) => card.addEventListener(ev, (e) => {
          if (ev === 'pointermove' && Math.abs(e.movementY || 0) < 3) return;
          clearTimeout(pressTimer);
        }));
        if (highlightId && String(entry.id) === highlightId) card.classList.add('card-highlight');
        list.appendChild(card);
      });
    }
    paint();
    if (highlightId) {
      const target = list.querySelector('.card-highlight');
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  // ==================================================================
  // CARTE (fedelta' e regalo, come un portafoglio)
  // ==================================================================
  const CARD_COLORS = ['#121318', '#2F5BFF', '#E8590C', '#D6336C', '#2F9E44', '#7048E8', '#C77700', '#1C7ED6'];
  const CARD_FORMATS = [
    ['CODE128', 'Code 128'], ['EAN13', 'EAN-13'], ['QR', 'QR'], ['EAN8', 'EAN-8'], ['UPC', 'UPC-A'], ['CODE39', 'Code 39'], ['ITF', 'ITF'], ['NONE', tr('card_format_none')],
  ];
  // Loghi dei negozi (public/brands, licenza in LICENZA.txt): si mostrano
  // senza modifiche, solo per riconoscere la tessera del negozio.
  let brandsPromise = null;
  const loadBrands = () => (brandsPromise = brandsPromise || loadScript('/brands/index.js').then(() => window.MEMENTO_BRANDS || []).catch(() => []));
  // Marchio dal nome della carta: nome uguale, nome che contiene il marchio
  // ("Carta Leroy Merlin") o inizio del marchio ("Leroy"); vince il piu' lungo.
  const GENERIC_WORDS = /\b(cinemas?|supermercati|farmacia|profumerie|store|italia|carta|tessera|card|fedelta|fedeltà)\b/gi;
  const nameWords = (t) => String(t || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').split(/[^a-z0-9]+/).filter(Boolean);
  function brandForName(brands, name) {
    const n = normName(name);
    const words = nameWords(name);
    const core = normName(String(name).replace(GENERIC_WORDS, ''));
    if (!n) return null;
    // Il marchio compare come parole intere, una dopo l'altra, nel nome.
    const hasWords = (bw) => bw.length && words.some((_, i) => bw.every((w, j) => words[i + j] === w));
    let best = null;
    for (const b of brands) {
      const bn = normName(b.name);
      const bcore = normName(b.name.replace(GENERIC_WORDS, ''));
      const ok = bn === n || (bcore && bcore === core)
        || (bn.length >= 4 && hasWords(nameWords(b.name)))
        || (core.length >= 4 && bn.startsWith(core));
      if (ok && (!best || normName(best.name).length < bn.length)) best = b;
    }
    return best;
  }
  const brandSrc = (id) => `/brands/${encodeURIComponent(id)}.png`;
  const normName = (t) => String(t || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]/g, '');
  const cardColor = (c) => c.color || CARD_COLORS[[...String(c.name)].reduce((a, ch) => a + ch.charCodeAt(0), 0) % CARD_COLORS.length];
  // Colore chiaro (es. bianco, giallo): sopra ci va testo scuro.
  const isLightColor = (hex) => {
    const m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex || '');
    if (!m) return false;
    const [r, g, b] = m.slice(1).map((x) => parseInt(x, 16) / 255);
    return 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.62;
  };
  const fmtBalance = (c) => (c.balance == null ? '' : fmtMoney(c.balance));

  function cardModal(existing) {
    const form = el(`
      <form class="modal-body" style="padding:0">
        <div class="seg seg-form" role="radiogroup">
          <button type="button" data-kind="fedelta">${esc(tr('card_kind_loyalty'))}</button>
          <button type="button" data-kind="regalo">${esc(tr('card_kind_gift'))}</button>
        </div>
        <div class="form-row brand-row"><label>${esc(tr('card_field_name'))}</label>
          <div class="brand-input"><img class="brand-chosen hidden" alt="" /><input type="text" name="name" required autocomplete="off" /><button type="button" class="icon-btn brand-clear hidden" aria-label="${esc(tr('card_brand_remove'))}">${phIcon('x', 16)}</button></div>
          <div class="brand-suggest hidden" role="listbox"></div>
        </div>
        <div class="form-row">
          <label>${esc(tr('card_field_number'))}</label>
          <div style="display:flex;gap:6px"><input type="text" name="number" style="flex:1" autocomplete="off" /><button type="button" class="btn btn-sm" data-scan>${esc(tr('btn_scan'))}</button></div>
        </div>
        <div class="form-row"><label>${esc(tr('card_field_format'))}</label><select name="format">${CARD_FORMATS.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('')}</select></div>
        <div data-gift>
          <div style="display:flex;gap:10px">
            <div class="form-row" style="flex:1"><label>${esc(tr('card_field_balance'))}</label><input type="text" name="balance" inputmode="decimal" /></div>
            <div class="form-row" style="flex:1"><label>${esc(tr('card_field_expiry'))}</label><input type="date" name="expiry_date" /></div>
          </div>
          <div class="form-row"><label>${esc(tr('card_field_pin'))}${existing && existing.hasPin ? esc(tr('leave_blank_m')) : ''}</label><input type="text" name="pin" inputmode="numeric" autocomplete="off" /></div>
        </div>
        <div class="form-row"><label>${esc(tr('card_field_color'))}</label><div class="swatches">${CARD_COLORS.map((c) => `<button type="button" class="swatch" data-color="${c}" style="background:${c}" aria-label="${c}"></button>`).join('')}</div></div>
        <div class="form-row"><label>${esc(tr('field_notes'))}</label><textarea name="notes" rows="2"></textarea></div>
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button>
          <button type="submit" class="btn btn-primary">${esc(tr('btn_save'))}</button>
        </div>
      </form>
    `);
    let kind = existing ? existing.kind : 'fedelta';
    let color = existing ? existing.color : '';
    let brand = existing ? existing.brand || '' : '';
    const chosen = form.querySelector('.brand-chosen');
    const clearBtn = form.querySelector('.brand-clear');
    const suggest = form.querySelector('.brand-suggest');
    const syncBrand = () => {
      chosen.classList.toggle('hidden', !brand);
      clearBtn.classList.toggle('hidden', !brand);
      if (brand) chosen.src = brandSrc(brand);
    };
    clearBtn.addEventListener('click', () => { brand = ''; syncBrand(); form.name.focus(); });
    // Mentre si scrive il nome compaiono i negozi con il logo.
    form.name.addEventListener('input', async () => {
      const q = normName(form.name.value);
      if (brand) { brand = ''; syncBrand(); }
      suggest.innerHTML = '';
      if (q.length < 2) { suggest.classList.add('hidden'); return; }
      const list = (await loadBrands()).filter((b) => normName(b.name).includes(q))
        .sort((a, b) => (normName(a.name).indexOf(q) - normName(b.name).indexOf(q)) || (a.name.length - b.name.length)).slice(0, 6);
      list.forEach((b) => {
        const item = el(`<button type="button" class="brand-item" role="option"><img alt="" loading="lazy" /><span></span></button>`);
        item.querySelector('img').src = brandSrc(b.id);
        item.querySelector('span').textContent = b.name;
        item.addEventListener('click', () => {
          brand = b.id; form.name.value = b.name; color = b.color; syncColor(); syncBrand();
          suggest.classList.add('hidden');
        });
        suggest.appendChild(item);
      });
      suggest.classList.toggle('hidden', !list.length);
    });
    const syncKind = () => {
      form.querySelectorAll('[data-kind]').forEach((b) => b.classList.toggle('on', b.dataset.kind === kind));
      form.querySelector('[data-gift]').classList.toggle('hidden', kind !== 'regalo');
    };
    const syncColor = () => form.querySelectorAll('.swatch').forEach((b) => b.classList.toggle('on', b.dataset.color === color));
    form.querySelectorAll('[data-kind]').forEach((b) => b.addEventListener('click', () => { kind = b.dataset.kind; syncKind(); }));
    form.querySelectorAll('.swatch').forEach((b) => b.addEventListener('click', () => { color = b.dataset.color; syncColor(); }));
    form.querySelector('[data-scan]').addEventListener('click', async () => {
      const backdrop = form.closest('.modal-backdrop');
      if (backdrop) backdrop.remove();
      const result = await scanCode();
      if (backdrop) { document.body.appendChild(backdrop); activeModal = backdrop; }
      if (!result) return;
      form.number.value = result.text;
      form.format.value = result.format;
    });
    if (existing) {
      form.name.value = existing.name;
      form.number.value = existing.number || '';
      form.format.value = existing.format || 'CODE128';
      form.balance.value = existing.balance == null ? '' : String(existing.balance).replace('.', ',');
      form.expiry_date.value = existing.expiry_date ? existing.expiry_date.slice(0, 10) : '';
      form.notes.value = existing.notes || '';
    }
    syncKind(); syncColor(); syncBrand();
    form.collect = () => {
      const body = { kind, brand, name: form.name.value.trim(), number: form.number.value.trim(), format: form.format.value, color, notes: form.notes.value };
      if (kind === 'regalo') {
        body.balance = form.balance.value.trim();
        body.expiry_date = form.expiry_date.value || null;
        if (form.pin.value.trim()) body.pin = form.pin.value.trim();
      }
      return body;
    };
    return form;
  }

  views.cards = async (root, opts = {}) => {
    const highlightId = opts.highlight ? String(opts.highlight) : null;
    const cards = await api('/cards');
    root.innerHTML = '';
    root.appendChild(el(`<div class="view-header"><h2>${esc(tr('nav_cards'))}</h2><div class="view-header-actions"><button class="btn btn-primary" id="new-card">${phIcon('plus', 16)}${esc(tr('btn_new_card'))}</button></div></div>`));

    const edit = (existing) => {
      const form = cardModal(existing);
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const body = form.collect();
        const saved = existing
          ? await api(`/cards/${existing.id}`, { method: 'PUT', body: JSON.stringify(body) })
          : await api('/cards', { method: 'POST', body: JSON.stringify(body) });
        closeModal(); toast(tr('toast_card_saved'));
        render('cards', { highlight: saved.id, replace: !!existing });
      });
      form.querySelector('[data-cancel]').addEventListener('click', closeModal);
      openModal(existing ? tr('modal_edit_card') : tr('modal_new_card'), form);
    };
    root.querySelector('#new-card').addEventListener('click', () => edit(null));

    // Pagina della carta (#/cards/ID): tessera con logo e codice grande,
    // azioni Note / Foto della tessera / Condividi, dati delle carte regalo.
    const ICON_NOTES = phIcon('notepad', 24);
    const ICON_CAMERA = phIcon('camera', 24);
    const ICON_SHARE = phIcon('share-network', 24);
    const groupNumber = (n) => {
      const v = String(n || '').trim();
      return /^\d{6,}$/.test(v) ? v.replace(/(\d{4})(?=\d)/g, '$1 ') : v;
    };
    // Foto ridimensionata (lato lungo 1200 px, JPEG): resta leggera.
    const shrinkPhoto = (file) => new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        const k = Math.min(1, 1200 / Math.max(img.width, img.height));
        const c = document.createElement('canvas');
        c.width = Math.round(img.width * k); c.height = Math.round(img.height * k);
        c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
        URL.revokeObjectURL(img.src);
        resolve(c.toDataURL('image/jpeg', 0.82));
      };
      img.onerror = () => reject(new Error(tr('err_unexpected')));
      img.src = URL.createObjectURL(file);
    });
    const pickImage = () => new Promise((resolve) => {
      const input = el('<input type="file" accept="image/*" capture="environment" class="hidden" />');
      input.addEventListener('change', () => { resolve(input.files[0] || null); input.remove(); });
      document.body.appendChild(input);
      input.click();
    });
    async function shareCard(card) {
      const text = `${card.name}\n${card.number || ''}`.trim();
      const Share = window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.Share;
      try {
        if (Share) await Share.share({ title: card.name, text });
        else if (navigator.share) await navigator.share({ title: card.name, text });
        else { await navigator.clipboard.writeText(text); toast(tr('toast_copied')); }
      } catch (_) { /* condivisione annullata */ }
    }

    async function renderCardPage(id) {
      const card = await api(`/cards/${id}`);
      if (!card.brand) {
        const b = brandForName(await loadBrands(), card.name);
        if (b) { card.brand = b.id; if (!card.color) card.color = b.color; }
      }
      viewTitle.textContent = card.name;
      root.innerHTML = '';
      const page = el(`
        <div class="card-page">
          <div class="card-page-bar">
            <a class="btn btn-ghost btn-sm btn-back" href="#/cards">${phIcon('arrow-left', 16)}${esc(tr('nav_cards'))}</a>
            <span class="card-page-tools"><button type="button" class="btn btn-ghost btn-sm card-pin" data-pin></button><button type="button" class="btn btn-ghost btn-sm" data-edit>${esc(tr('btn_edit'))}</button></span>
          </div>
          <div class="card-visual">
            <button type="button" class="cv-copy hidden"></button><button type="button" class="cv-eye"></button>
            <div class="cv-top"></div>
            <div class="cv-bottom"><div class="card-code"></div><p class="cv-number"><span class="cv-num-text"></span></p></div>
          </div>
          <div class="cv-actions">
            <button type="button" data-notes>${ICON_NOTES}<span>${esc(tr('card_notes'))}</span></button>
            <button type="button" data-photos>${ICON_CAMERA}<span>${esc(tr('card_photos'))}</span></button>
            <button type="button" data-share>${ICON_SHARE}<span>${esc(tr('card_share'))}</span></button>
          </div>
          <div class="card-facts"></div>
          <p class="card-notes-text"></p>
          <div class="card-page-foot"><button type="button" class="btn btn-ghost btn-danger btn-sm" data-del>${esc(tr('card_delete'))}</button>${card.brand ? `<p class="brands-note">${esc(tr('cards_brands_note'))}</p>` : ''}</div>
        </div>
      `);
      root.appendChild(page);
      const top = page.querySelector('.cv-top');
      top.style.background = cardColor(card);
      if (card.brand) {
        const img = el(`<img alt="" />`);
        img.src = brandSrc(card.brand); img.alt = card.name;
        img.addEventListener('error', () => { top.innerHTML = `<span class="cv-name">${esc(card.name)}</span>`; });
        top.appendChild(img);
      } else {
        top.appendChild(el(`<span class="cv-name">${esc(card.name)}</span>`));
      }
      // Numero nascosto del tutto: compare solo con l'occhio (il codice resta
      // leggibile dallo scanner della cassa). Toccando il numero si copia.
      // Senza codice disegnabile il numero e' l'unica cosa: resta visibile.
      const num = page.querySelector('.cv-num-text');
      const numRow = page.querySelector('.cv-number');
      const eye = page.querySelector('.cv-eye');
      const grouped = groupNumber(card.number);
      num.textContent = grouped || '—';
      num.addEventListener('click', async () => { try { await navigator.clipboard.writeText(card.number); toast(tr('toast_copied')); } catch (_) { /* niente appunti */ } });
      const drawn = await renderCardCode(page.querySelector('.card-code'), card).catch(() => false);
      if (!drawn) page.querySelector('.card-code').classList.add('hidden');
      let shown = !drawn;
      const copyBtn = page.querySelector('.cv-copy');
      copyBtn.innerHTML = phIcon('copy', 20);
      copyBtn.setAttribute('aria-label', tr('btn_copy'));
      copyBtn.title = tr('btn_copy');
      copyBtn.addEventListener('click', async () => { try { await navigator.clipboard.writeText(card.number); toast(tr('toast_copied')); haptic(); } catch (_) { /* niente appunti */ } });
      const paintNum = () => {
        numRow.classList.toggle('hidden', !shown);
        copyBtn.classList.toggle('hidden', !shown || !grouped);
        eye.innerHTML = phIcon(shown ? 'eye-slash' : 'eye', 22);
        eye.setAttribute('aria-label', tr(shown ? 'title_hide' : 'title_show'));
      };
      if (!grouped) eye.remove();
      eye.addEventListener('click', () => { shown = !shown; paintNum(); haptic(); });
      paintNum();
      // Luminosita' al massimo mentre la carta e' aperta: lo scanner della
      // cassa la legge al primo colpo. Si ripristina lasciando la pagina.
      const SB = window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.ScreenBrightness;
      if (SB) {
        try {
          const before = (await SB.getBrightness()).brightness;
          await SB.setBrightness({ brightness: 1 });
          window.__restoreBrightness = () => { SB.setBrightness({ brightness: before }).catch(() => {}); };
        } catch (_) { /* luminosita' non disponibile */ }
      }

      const facts = page.querySelector('.card-facts');
      const fact = (label, value, cls = '') => { const r = el(`<div class="vd-row"><span class="vd-label"></span><span class="vd-value ${cls}"></span><span class="vd-acts"></span></div>`); r.querySelector('.vd-label').textContent = label; r.querySelector('.vd-value').textContent = value; facts.appendChild(r); return r; };
      if (card.kind === 'regalo') {
        const bal = fact(tr('card_field_balance'), fmtBalance(card) || '—', 'card-balance');
        const spend = el(`<button type="button" class="btn btn-sm">${esc(tr('card_spend'))}</button>`);
        spend.addEventListener('click', async () => {
          const raw = await askValue(tr('card_spend'), { label: tr('card_spend_prompt'), inputmode: 'decimal', placeholder: '0,00' });
          if (!raw) return;
          const updated = await api(`/cards/${card.id}/spend`, { method: 'POST', body: JSON.stringify({ amount: raw }) });
          bal.querySelector('.vd-value').textContent = fmtBalance(updated);
          toast(tr('toast_card_spent'));
        });
        bal.querySelector('.vd-acts').appendChild(spend);
        if (card.expiry_date) fact(tr('card_field_expiry'), `${card.expiry_date.slice(0, 10).split('-').reverse().join('/')} · ${relativeDayLabel(calendarDaysFromToday(card.expiry_date))}`);
        if (card.hasPin) {
          const pinRow = fact(tr('card_field_pin'), '••••', 'mono');
          const eye = el(`<button type="button" class="sq-btn" title="${esc(tr('title_show'))}">${iconaLinea('occhio')}</button>`);
          eye.addEventListener('click', async () => { pinRow.querySelector('.vd-value').textContent = (await api(`/cards/${card.id}/pin`)).pin || '—'; });
          pinRow.querySelector('.vd-acts').appendChild(eye);
        }
      }
      const notesText = page.querySelector('.card-notes-text');
      notesText.textContent = card.notes || '';

      page.querySelector('[data-edit]').addEventListener('click', () => edit(card));
      const pinBtn = page.querySelector('[data-pin]');
      const paintPin = () => {
        const on = pinnedIds().includes(String(card.id));
        pinBtn.innerHTML = phIcon(on ? 'push-pin-fill' : 'push-pin', 18);
        pinBtn.classList.toggle('on', on);
        pinBtn.setAttribute('aria-pressed', on ? 'true' : 'false');
        pinBtn.setAttribute('aria-label', tr(on ? 'card_unpin' : 'card_pin'));
        pinBtn.title = tr(on ? 'card_unpin' : 'card_pin');
      };
      pinBtn.addEventListener('click', () => {
        const on = !pinnedIds().includes(String(card.id));
        setPinned(card.id, on);
        paintPin(); haptic();
        toast(tr(on ? 'card_pinned' : 'card_unpinned'));
      });
      paintPin();
      // Nell'app "Condividi" offre anche il passaggio a un altro telefono Memento.
      page.querySelector('[data-share]').addEventListener('click', () => {
        if (!transferEngine()) { shareCard(card); return; }
        const box = el(`<div class="form-actions" style="flex-direction:column;align-items:stretch"><button type="button" class="btn btn-primary" data-phone></button><button type="button" class="btn" data-text></button></div>`);
        box.querySelector('[data-phone]').textContent = tr('card_share_phone');
        box.querySelector('[data-text]').textContent = tr('card_share_text');
        box.querySelector('[data-phone]').addEventListener('click', () => passItem('card', card.id, card.name));
        box.querySelector('[data-text]').addEventListener('click', () => { closeModal(); shareCard(card); });
        openModal(tr('card_share'), box);
      });
      page.querySelector('[data-notes]').addEventListener('click', () => {
        const form = el(`<form class="modal-body" style="padding:0"><div class="form-row"><textarea name="notes" rows="5"></textarea></div>
          <div class="form-actions"><button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button><button type="submit" class="btn btn-primary">${esc(tr('btn_save'))}</button></div></form>`);
        form.notes.value = card.notes || '';
        form.addEventListener('submit', async (e) => {
          e.preventDefault();
          await api(`/cards/${card.id}`, { method: 'PUT', body: JSON.stringify({ notes: form.notes.value }) });
          card.notes = form.notes.value; notesText.textContent = card.notes; closeModal();
        });
        form.querySelector('[data-cancel]').addEventListener('click', closeModal);
        openModal(tr('card_notes'), form);
      });
      // Foto della tessera: fronte e retro, si aggiungono, si ingrandiscono, si tolgono.
      const openPhotos = () => {
        const photos = (card.photos || []).slice();
        const wrap = el('<div class="card-photos"></div>');
        const save = async () => {
          const updated = await api(`/cards/${card.id}`, { method: 'PUT', body: JSON.stringify({ photos }) });
          card.photos = photos.slice(); card.photoCount = updated.photoCount;
          paint();
        };
        const paint = () => {
          wrap.innerHTML = '';
          [tr('card_photo_front'), tr('card_photo_back')].forEach((label, i) => {
            const slot = el(`<div class="photo-slot"><span class="photo-label"></span></div>`);
            slot.querySelector('.photo-label').textContent = label;
            if (photos[i]) {
              const img = el('<img alt="" />'); img.src = photos[i];
              img.addEventListener('click', () => { const w = window.open(); if (w) { w.document.write(`<img src="${photos[i]}" style="width:100%">`); } });
              const rm = el(`<button type="button" class="btn btn-sm btn-ghost btn-danger">${esc(tr('share_remove'))}</button>`);
              rm.addEventListener('click', () => { photos.splice(i, 1); save(); });
              slot.append(img, rm);
            } else if (i === photos.length) {
              const add = el(`<button type="button" class="photo-add">${ICON_CAMERA}<span>${esc(tr('card_photo_add'))}</span></button>`);
              add.addEventListener('click', async () => {
                const file = await pickImage();
                if (!file) return;
                photos.push(await shrinkPhoto(file));
                save();
              });
              slot.appendChild(add);
            }
            wrap.appendChild(slot);
          });
        };
        paint();
        openModal(tr('card_photos'), wrap);
      };
      page.querySelector('[data-photos]').addEventListener('click', openPhotos);
      page.querySelector('[data-del]').addEventListener('click', async () => {
        if (!(await askConfirm(tr('confirm_delete_card')))) return;
        await api(`/cards/${card.id}`, { method: 'DELETE' });
        toast(tr('toast_card_deleted')); render('cards');
      });
    }
    const openCard = (c) => render('cards', { highlight: c.id });
    // Carte fissate in alto (preferenza del dispositivo, nell'ordine scelto).
    const PIN_KEY = 'memento-cards-pinned';
    const pinnedIds = () => { try { return JSON.parse(localStorage.getItem(PIN_KEY) || '[]').map(String); } catch (_) { return []; } };
    const setPinned = (id, on) => {
      const list = pinnedIds().filter((x) => x !== String(id));
      if (on) list.push(String(id));
      localStorage.setItem(PIN_KEY, JSON.stringify(list));
    };
    const USED_KEY = 'memento-cards-used';
    const usedMap = () => { try { return JSON.parse(localStorage.getItem(USED_KEY) || '{}'); } catch (_) { return {}; } };

    if (highlightId) {
      const used = usedMap(); used[highlightId] = Date.now(); localStorage.setItem(USED_KEY, JSON.stringify(used));
      await renderCardPage(highlightId);
      return;
    }

    if (!cards.length) {
      root.appendChild(el(`<div class="empty-state">${esc(tr('cards_empty'))}</div>`));
      return;
    }
    // Carte create senza scegliere il suggerimento: logo dal nome, se coincide.
    const brands = await loadBrands();
    cards.forEach((c) => {
      if (c.brand) return;
      const b = brandForName(brands, c.name);
      if (b) { c.brand = b.id; if (!c.color) c.color = b.color; }
    });
    // Le fissate restano nel loro gruppo, in cima e con la puntina.
    const pins = pinnedIds();
    const groups = [['fedelta', tr('card_kind_loyalty_pl')], ['regalo', tr('card_kind_gift_pl')]];
    groups.forEach(([kind, title]) => {
      const used = usedMap();
      const pinRank = (c) => { const i = pins.indexOf(String(c.id)); return i < 0 ? Infinity : i; };
      const list = cards.filter((c) => c.kind === kind).sort((a, b) => (pinRank(a) - pinRank(b)) || (used[b.id] || 0) - (used[a.id] || 0) || a.name.localeCompare(b.name));
      if (!list.length) return;
      root.appendChild(el(`<h3 class="group-title">${esc(title)}</h3>`));
      const grid = el('<div class="wallet-grid"></div>');
      list.forEach((c) => {
        // Come una tessera vera: logo con i margini in alto, nome in basso;
        // testo chiaro o scuro secondo il colore di fondo.
        const tile = el(c.brand
          ? `<button type="button" class="wallet-card has-logo"><span class="wc-logo-box"><img class="wc-logo" alt="" loading="lazy" /></span><span class="wc-foot"><span class="wc-label"></span></span><span class="wc-meta"></span></button>`
          : `<button type="button" class="wallet-card"><span class="wc-initial"></span><span class="wc-name"></span><span class="wc-meta"></span></button>`);
        tile.style.setProperty('--card', cardColor(c));
        if (isLightColor(cardColor(c))) tile.classList.add('on-light');
        if (c.brand) {
          tile.querySelector('.wc-label').textContent = c.name;
        }
        tile.setAttribute('aria-label', c.name);
        if (pins.includes(String(c.id))) { tile.classList.add('pinned'); tile.appendChild(el(`<span class="wc-pin" aria-hidden="true">${phIcon('push-pin-fill', 14)}</span>`)); }
        if (c.brand) {
          const img = tile.querySelector('.wc-logo');
          img.src = brandSrc(c.brand);
          img.alt = c.name;
          // Logo mancante (marchio tolto dall'elenco): torna all'iniziale.
          img.addEventListener('error', () => { tile.classList.remove('has-logo'); tile.querySelector('.wc-logo-box').remove(); tile.querySelector('.wc-foot').remove(); tile.prepend(el(`<span class="wc-name">${esc(c.name)}</span>`)); tile.prepend(el(`<span class="wc-initial">${esc(c.name.trim().charAt(0).toUpperCase())}</span>`)); });
        }
        if (!c.brand) {
          tile.querySelector('.wc-initial').textContent = c.name.trim().charAt(0).toUpperCase();
          tile.querySelector('.wc-name').textContent = c.name;
        }
        const meta = [];
        if (c.kind === 'regalo' && c.balance != null) meta.push(fmtBalance(c));
        if (c.kind === 'regalo' && c.expiry_date) meta.push(relativeDayLabel(calendarDaysFromToday(c.expiry_date)));
        tile.querySelector('.wc-meta').textContent = meta.join(' · ');
        tile.addEventListener('click', () => openCard(c));
        if (highlightId && String(c.id) === highlightId) tile.classList.add('card-highlight');
        grid.appendChild(tile);
      });
      root.appendChild(grid);
    });
    if (cards.some((c) => c.brand)) root.appendChild(el(`<p class="brands-note">${esc(tr('cards_brands_note'))}</p>`));
  };

  // ==================================================================
  // ACCOUNT
  // ==================================================================
  const BILLING_LABELS = {
    '': tr('billing_unspecified'),
    settimanale: tr('billing_weekly'),
    mensile: tr('billing_monthly'),
    trimestrale: tr('billing_quarterly'),
    semestrale: tr('billing_semiannual'),
    annuale: tr('billing_annual'),
    una_tantum: tr('billing_onetime'),
  };

  // Cosa serve per individuare il rinnovo dipende dalla cadenza: settimanale
  // vuole solo il giorno della settimana, mensile solo il giorno del mese,
  // trimestrale/semestrale/annuale vogliono giorno+mese di riferimento (per
  // sapere in quale dei periodi dell'anno cade). "day"/"month" hanno quindi
  // un significato diverso a seconda di "frequency" — vedi il form in
  // accountModal() per quali campi si vedono in ciascun caso.
  const BILLING_STEP_MONTHS = { trimestrale: 3, semestrale: 6, annuale: 12 };
  // Ricalcola la data da zero a ogni passo invece di sommare mese dopo mese
  // sulla stessa istanza: altrimenti un giorno che non esiste in un mese
  // intermedio (es. 31 a settembre, che Date normalizza a 1 ottobre) trascina
  // la ricorrenza su un giorno diverso per tutte le occorrenze successive.
  function monthlyOccurrence(anchorYear, anchorMonth0, offsetMonths, day) {
    const total = anchorYear * 12 + anchorMonth0 + offsetMonths;
    return new Date(Math.floor(total / 12), ((total % 12) + 12) % 12, day);
  }
  function nextRenewalDate(day, month, frequency) {
    if (!day) return null;
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    if (frequency === 'settimanale') {
      // day: 1 = Lunedi' ... 7 = Domenica (stessa convenzione di WEEKDAY_LABELS).
      const todayIso = ((today.getDay() + 6) % 7) + 1;
      const candidate = new Date(today);
      candidate.setDate(candidate.getDate() + ((day - todayIso + 7) % 7));
      return candidate;
    }
    if (frequency === 'mensile') {
      // day: giorno del mese, nessun mese di riferimento necessario.
      let candidate = new Date(today.getFullYear(), today.getMonth(), day);
      if (candidate < today) candidate = new Date(today.getFullYear(), today.getMonth() + 1, day);
      return candidate;
    }
    // trimestrale / semestrale / annuale (o cadenza non riconosciuta, trattata
    // come annuale in assenza di altra informazione): serve anche il mese.
    if (!month) return null;
    const stepMonths = BILLING_STEP_MONTHS[frequency] || 12;
    const anchorYear = today.getFullYear() - 1;
    const anchorMonth0 = month - 1;
    let offset = 0;
    let candidate = monthlyOccurrence(anchorYear, anchorMonth0, offset, day);
    while (candidate < today) {
      offset += stepMonths;
      candidate = monthlyOccurrence(anchorYear, anchorMonth0, offset, day);
    }
    return candidate;
  }

  // Finanziamento: piano delle rate dalla prima rata, cadenza e numero di
  // rate. Restituisce rate pagate (scadute fino a ieri compreso), mancanti,
  // quota residua, prossima e ultima rata.
  function loanInfo(a) {
    if (a.type !== 'finanziamento' || !a.installments || !a.start_date) return null;
    const start = new Date(`${String(a.start_date).slice(0, 10)}T00:00:00`);
    if (Number.isNaN(start.getTime())) return null;
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const step = { mensile: 1, trimestrale: 3, semestrale: 6, annuale: 12 }[a.billing_frequency] || 1;
    const dateAt = (i) => {
      if (a.billing_frequency === 'settimanale') { const d = new Date(start); d.setDate(d.getDate() + 7 * i); return d; }
      const total = start.getFullYear() * 12 + start.getMonth() + step * i;
      const y = Math.floor(total / 12), m = total % 12;
      return new Date(y, m, Math.min(start.getDate(), new Date(y, m + 1, 0).getDate()));
    };
    let paid = 0;
    while (paid < a.installments && dateAt(paid) < today) paid++;
    const remaining = a.installments - paid;
    return {
      total: a.installments, paid, remaining,
      residual: a.amount != null ? remaining * Number(a.amount) : null,
      next: remaining ? dateAt(paid) : null,
      end: dateAt(a.installments - 1),
    };
  }
  // Prossimo addebito di una spesa ricorrente (per un finanziamento la
  // prossima rata, niente dopo l'ultima).
  function nextChargeDate(a) {
    const loan = loanInfo(a);
    if (loan) return loan.next;
    return nextRenewalDate(a.renewal_day, a.renewal_month, a.billing_frequency);
  }

  function accountModal(existing) {
    const form = el(`
      <form class="modal-body" style="padding:0">
        <div class="form-row"><label>${esc(tr('field_service'))}</label><input type="text" name="service" required /></div>
        <div class="form-row"><label>${esc(tr('field_type'))}</label>
          <select name="type">
            <option value="digitale">${esc(tr('account_type_digital'))}</option>
            <option value="cartaceo">${esc(tr('account_type_paper'))}</option>
            <option value="finanziamento">${esc(tr('account_type_loan'))}</option>
          </select>
        </div>
        <div data-type-fields="digitale">
          <div class="form-row"><label>${esc(tr('field_email'))}</label><input type="text" name="email" /></div>
          <div class="form-row"><label>${esc(tr('field_plan'))}</label><input type="text" name="plan" /></div>
        </div>
        <div data-type-fields="cartaceo">
          <div class="form-row"><label>${esc(tr('field_location'))}</label><input type="text" name="location" placeholder="${esc(tr('field_location_placeholder'))}" /></div>
          <div class="form-row"><label>${esc(tr('field_payment_method'))}</label><input type="text" name="payment_method" placeholder="${esc(tr('field_payment_method_placeholder'))}" /></div>
        </div>
        <div data-type-fields="finanziamento">
          <div class="form-row"><label>${esc(tr('field_installments'))}</label><input type="number" name="installments" min="1" max="1200" step="1" inputmode="numeric" /></div>
        </div>
        <div class="form-row"><label>${esc(tr('field_billing_frequency'))}</label>
          <select name="billing_frequency">
            ${Object.entries(BILLING_LABELS).map(([v, label]) => `<option value="${v}">${esc(label)}</option>`).join('')}
          </select>
        </div>
        <div class="form-row"><label data-amount-label>${esc(tr('field_amount'))}</label><input type="number" name="amount" step="0.01" min="0" placeholder="${esc(tr('field_amount_placeholder'))}" /></div>
        <div class="form-row"><label data-start-label>${esc(tr('field_start_date_optional'))}</label><input type="date" name="start_date" /></div>
        <div data-billing-fields="settimanale" class="form-row">
          <label>${esc(tr('renewal_weekday_label'))}</label>
          <select name="renewal_weekday">
            <option value="">—</option>
            ${WEEKDAY_LABELS_FULL.map((w, i) => `<option value="${i + 1}">${esc(w)}</option>`).join('')}
          </select>
        </div>
        <div data-billing-fields="mensile" class="form-row">
          <label>${esc(tr('renewal_monthday_label'))}</label>
          <select name="renewal_monthday">
            <option value="">—</option>
            ${Array.from({ length: 31 }, (_, i) => i + 1).map((d) => `<option value="${d}">${d}</option>`).join('')}
          </select>
        </div>
        <div data-billing-fields="trimestrale semestrale annuale" class="form-row">
          <label>${esc(tr('renewal_daymonth_label'))}</label>
          <div style="display:flex;gap:8px">
            <select name="renewal_day" style="flex:1">
              <option value="">${esc(tr('field_day'))}</option>
              ${Array.from({ length: 31 }, (_, i) => i + 1).map((d) => `<option value="${d}">${d}</option>`).join('')}
            </select>
            <select name="renewal_month" style="flex:2">
              <option value="">${esc(tr('field_month'))}</option>
              ${MONTH_LABELS.map((m, i) => `<option value="${i + 1}">${esc(m)}</option>`).join('')}
            </select>
          </div>
        </div>
        <div class="form-row"><label>${esc(tr('field_notes'))}</label><textarea name="notes" rows="3"></textarea></div>
        <div class="form-row"><label>${esc(tr('field_tags'))}</label><input type="text" name="tags" /></div>
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button>
          <button type="submit" class="btn btn-primary">${esc(tr('btn_save'))}</button>
        </div>
      </form>
    `);
    // Finanziamento: rata, prima rata obbligatoria, giorno di addebito
    // ricavato dalla prima rata (i selettori del rinnovo non servono).
    function syncTypeFields() {
      const loan = form.type.value === 'finanziamento';
      form.querySelectorAll('[data-type-fields]').forEach((group) => {
        group.classList.toggle('hidden', group.dataset.typeFields !== form.type.value);
      });
      form.querySelector('[data-amount-label]').textContent = tr(loan ? 'field_installment_amount' : 'field_amount');
      form.querySelector('[data-start-label]').textContent = tr(loan ? 'field_first_installment' : 'field_start_date_optional');
      form.start_date.required = loan;
      form.installments.required = loan;
      syncBillingFields();
    }
    function syncBillingFields() {
      const loan = form.type.value === 'finanziamento';
      form.querySelectorAll('[data-billing-fields]').forEach((group) => {
        group.classList.toggle('hidden', loan || !group.dataset.billingFields.split(' ').includes(form.billing_frequency.value));
      });
    }
    form.type.addEventListener('change', () => {
      if (form.type.value === 'finanziamento' && !form.billing_frequency.value) form.billing_frequency.value = 'mensile';
      syncTypeFields();
    });
    form.billing_frequency.addEventListener('change', syncBillingFields);
    if (existing) {
      form.service.value = existing.service;
      form.type.value = existing.type || 'digitale';
      form.email.value = existing.email;
      form.plan.value = existing.plan;
      form.location.value = existing.location || '';
      form.payment_method.value = existing.payment_method || '';
      form.billing_frequency.value = existing.billing_frequency || '';
      form.amount.value = existing.amount != null ? existing.amount : '';
      form.start_date.value = existing.start_date ? existing.start_date.slice(0, 10) : '';
      form.installments.value = existing.installments || '';
      // "day" ha un significato diverso a seconda della frequenza: si ripopola
      // solo il campo che corrisponde a quella gia' salvata.
      if (existing.billing_frequency === 'settimanale') form.renewal_weekday.value = existing.renewal_day || '';
      else if (existing.billing_frequency === 'mensile') form.renewal_monthday.value = existing.renewal_day || '';
      else { form.renewal_day.value = existing.renewal_day || ''; form.renewal_month.value = existing.renewal_month || ''; }
      form.notes.value = existing.notes;
      form.tags.value = (existing.tags || []).join(', ');
    }
    syncTypeFields();
    syncBillingFields();
    return form;
  }

  // Scelta di una voce Vault gia' salvata da collegare a un abbonamento
  // (credenziali riusate, senza doverle riscrivere). Stesso schema del
  // selettore fascicolo esistente (openLinkToDossierModal).
  async function openLinkVaultModal(account) {
    const entries = await api('/vault');
    const wrap = el('<div></div>');
    if (account.vaultEntry) {
      const current = el(`
        <div class="trash-row row-card">
          <span>${tr('credentials_linked_label', { label: esc(account.vaultEntry.site) + (account.vaultEntry.username ? ' · ' + esc(account.vaultEntry.username) : '') })}</span>
          <button class="btn btn-sm btn-danger">${esc(tr('btn_unlink'))}</button>
        </div>
      `);
      current.querySelector('button').addEventListener('click', async () => {
        await api(`/accounts/${account.id}`, { method: 'PUT', body: JSON.stringify({ vault_entry_id: null }) });
        toast(tr('toast_credentials_unlinked'));
        closeModal(); render('accounts');
      });
      wrap.appendChild(current);
    }
    if (!entries.length) {
      wrap.appendChild(el(`<p class="card-sub">${esc(tr('vault_none_yet'))}</p>`));
    } else {
      entries.forEach((v) => {
        const row = el(`
          <div class="trash-row row-card">
            <span>${esc(v.site)}${v.username ? ' · ' + esc(v.username) : ''}</span>
            <button class="btn btn-sm btn-primary">${esc(tr('btn_link'))}</button>
          </div>
        `);
        row.querySelector('button').addEventListener('click', async () => {
          await api(`/accounts/${account.id}`, { method: 'PUT', body: JSON.stringify({ vault_entry_id: v.id }) });
          toast(tr('toast_credentials_linked', { site: v.site }));
          closeModal(); render('accounts');
        });
        wrap.appendChild(row);
      });
    }
    openModal(tr('modal_link_credentials'), wrap);
  }

  views.accounts = async (root, opts = {}) => {
    const highlightId = opts.highlight ? String(opts.highlight) : null;
    const accounts = (await api('/accounts')).filter(onlyFilter(opts));
    root.innerHTML = '';
    root.appendChild(el(`
      <div class="view-header">
        <h2>${esc(tr('nav_accounts_title'))}</h2>
        <div class="view-header-actions">${backToDossierButtonHtml(opts)}<button class="btn btn-primary" id="new-account">${phIcon('plus', 16)}${esc(tr('btn_new_account'))}</button></div>
      </div>
    `));
    wireBackToDossier(root, opts);

    // "day"/"month" hanno un significato diverso a seconda della frequenza
    // scelta (vedi accountModal): qui si sceglie quale campo del form leggere.
    function renewalPayload(form) {
      const freq = form.billing_frequency.value;
      if (freq === 'settimanale') return { renewal_day: form.renewal_weekday.value || null, renewal_month: null };
      if (freq === 'mensile') return { renewal_day: form.renewal_monthday.value || null, renewal_month: null };
      return { renewal_day: form.renewal_day.value || null, renewal_month: form.renewal_month.value || null };
    }
    function accountPayload(form) {
      return {
        service: form.service.value,
        type: form.type.value,
        email: form.email.value,
        plan: form.plan.value,
        location: form.location.value,
        payment_method: form.payment_method.value,
        billing_frequency: form.billing_frequency.value,
        amount: form.amount.value === '' ? null : form.amount.value,
        start_date: form.start_date.value || null,
        installments: form.type.value === 'finanziamento' ? (form.installments.value || null) : null,
        ...(form.type.value === 'finanziamento' ? { renewal_day: null, renewal_month: null } : renewalPayload(form)),
        notes: form.notes.value,
        tags: parseTags(form),
      };
    }

    root.querySelector('#new-account').addEventListener('click', () => {
      const form = accountModal();
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        await api('/accounts', { method: 'POST', body: JSON.stringify(accountPayload(form)) });
        closeModal(); toast(tr('toast_account_saved')); render('accounts');
      });
      form.querySelector('[data-cancel]').addEventListener('click', closeModal);
      openModal(tr('modal_new_account'), form);
    });

    if (!accounts.length) {
      root.appendChild(el(`<div class="empty-state">${esc(tr('empty_accounts'))}</div>`));
      return;
    }

    // In cima quanto si spende al mese (cadenze riportate a un mese) e il
    // prossimo rinnovo; sotto le righe, dalla scadenza piu' vicina.
    const MONTHLY = { settimanale: 52 / 12, mensile: 1, trimestrale: 1 / 3, semestrale: 1 / 6, annuale: 1 / 12 };
    const withNext = accounts.map((a) => ({ a, next: nextChargeDate(a) }));
    withNext.sort((x, y) => (x.next ? x.next.getTime() : Infinity) - (y.next ? y.next.getTime() : Infinity));
    if (!opts.only) {
      const active = (a) => { const l = loanInfo(a); return !l || l.remaining > 0; };
      const monthly = accounts.filter(active).reduce((sum, a) => sum + (a.amount != null && MONTHLY[a.billing_frequency] ? Number(a.amount) * MONTHLY[a.billing_frequency] : 0), 0);
      const soon = withNext.find((x) => x.next);
      const head = el(`<section class="tile tile-focus acc-summary"><div class="focus-head"><span class="focus-num"></span><span class="focus-label"></span></div><p class="acc-next"></p></section>`);
      head.querySelector('.focus-num').textContent = fmtMoney(monthly);
      head.querySelector('.focus-label').textContent = tr('accounts_per_month');
      head.querySelector('.acc-next').textContent = soon ? tr('accounts_next', { name: soon.a.service, when: relativeDayLabel(calendarDaysFromToday(soon.next)) }) : '';
      root.appendChild(head);
    }

    const openDetail = (a, next) => {
      const wrap = el('<div class="vault-detail"></div>');
      const fact = (label, value) => { if (!value) return; const r = el('<div class="vd-row"><span class="vd-label"></span><span class="vd-value"></span></div>'); r.querySelector('.vd-label').textContent = label; r.querySelector('.vd-value').textContent = value; wrap.appendChild(r); };
      const loan = loanInfo(a);
      fact(tr(loan ? 'field_installment_amount' : 'field_amount'), [a.amount != null ? fmtMoney(a.amount) : '', a.billing_frequency ? (BILLING_LABELS[a.billing_frequency] || a.billing_frequency) : ''].filter(Boolean).join(' · '));
      fact(tr(loan ? 'loan_next' : 'accounts_renewal'), next ? `${next.getDate()} ${MONTH_LABELS[next.getMonth()]} · ${relativeDayLabel(calendarDaysFromToday(next))}` : '');
      if (loan) {
        fact(tr('loan_paid'), tr('loan_of', { n: loan.paid, total: loan.total }));
        fact(tr('loan_remaining'), loan.remaining ? String(loan.remaining) : tr('loan_done'));
        if (loan.residual != null && loan.remaining) fact(tr('loan_residual'), fmtMoney(loan.residual));
        fact(tr('loan_end'), fmtDate(`${loan.end.getFullYear()}-${String(loan.end.getMonth() + 1).padStart(2, '0')}-${String(loan.end.getDate()).padStart(2, '0')}`));
      }
      if (a.type === 'cartaceo') { fact(tr('field_location'), a.location); fact(tr('field_payment_method'), a.payment_method); }
      else if (a.type !== 'finanziamento') { fact(tr('field_email'), a.email); fact(tr('field_plan'), a.plan); }
      fact(tr(loan ? 'field_first_installment' : 'accounts_since'), a.start_date ? fmtDate(a.start_date) : '');
      if (a.vaultEntry) fact(tr('accounts_credentials'), a.vaultEntry.site + (a.vaultEntry.username ? ' · ' + a.vaultEntry.username : ''));
      fact(tr('field_notes'), a.notes);
      const actions = el(`<div class="form-actions"><span class="form-actions-side"><button type="button" class="btn btn-ghost" data-link></button><button type="button" class="btn btn-ghost" data-vault></button><button type="button" class="btn btn-ghost btn-danger" data-del></button></span><button type="button" class="btn btn-primary" data-edit></button></div>`);
      actions.querySelector('[data-link]').textContent = tr('btn_link_folder');
      actions.querySelector('[data-vault]').textContent = a.vaultEntry ? tr('btn_change_credentials') : tr('btn_link_credentials');
      actions.querySelector('[data-del]').textContent = tr('btn_delete');
      actions.querySelector('[data-edit]').textContent = tr('btn_edit');
      actions.querySelector('[data-link]').addEventListener('click', () => { closeModal(); openLinkToDossierModal('account', a.id, a.service); });
      const passA = passButton('account', a.id, a.service);
      if (passA) actions.querySelector('[data-del]').before(passA);
      actions.querySelector('[data-vault]').addEventListener('click', () => { closeModal(); openLinkVaultModal(a); });
      actions.querySelector('[data-del]').addEventListener('click', async () => {
        closeModal();
        await api(`/accounts/${a.id}`, { method: 'DELETE' });
        undoToast(tr('toast_moved_trash'), async () => { await api(`/accounts/${a.id}/restore`, { method: 'POST' }); render('accounts', { fromHash: true }); });
        render('accounts', { fromHash: true });
      });
      actions.querySelector('[data-edit]').addEventListener('click', () => {
        closeModal();
        const form = accountModal(a);
        form.addEventListener('submit', async (e) => {
          e.preventDefault();
          await api(`/accounts/${a.id}`, { method: 'PUT', body: JSON.stringify(accountPayload(form)) });
          closeModal(); toast(tr('toast_account_updated')); render('accounts', { fromHash: true });
        });
        form.querySelector('[data-cancel]').addEventListener('click', closeModal);
        openModal(tr('modal_edit_account'), form);
      });
      wrap.appendChild(actions);
      openModal(a.service, wrap);
    };

    const list = el('<div class="vault-list acc-list"></div>');
    withNext.forEach(({ a, next }) => {
      const [bg, fg] = [['#E3E9FF', '#2448E0'], ['#F3E8FF', '#7048E8'], ['#FCE4EE', '#B0285A'], ['#FFF0D6', '#A85A00'], ['#FFE4DC', '#B2401F']][[...a.service].reduce((x, c) => x + c.charCodeAt(0), 0) % 5];
      const row = el(`<div class="vcard" tabindex="0" role="button"><span class="vlogo"></span><span class="vtext"><b></b><small></small></span><span class="date-cell"><b></b><small></small></span></div>`);
      const logo = row.querySelector('.vlogo'); logo.textContent = a.service.trim().charAt(0).toUpperCase(); logo.style.background = bg; logo.style.color = fg;
      row.querySelector('.vtext b').textContent = a.service;
      const loan = loanInfo(a);
      row.querySelector('.vtext small').textContent = loan
        ? (loan.remaining ? [tr('loan_row', { n: loan.paid, total: loan.total }), loan.residual != null ? tr('loan_row_residual', { amount: fmtMoney(loan.residual) }) : ''].filter(Boolean).join(' · ') : tr('loan_done'))
        : [a.amount != null ? fmtMoney(a.amount) : '', a.billing_frequency ? (BILLING_LABELS[a.billing_frequency] || '') : ''].filter(Boolean).join(' · ') || (a.type === 'cartaceo' ? tr('account_type_paper') : tr('account_type_digital'));
      const cell = row.querySelector('.date-cell');
      if (next) { cell.querySelector('b').textContent = next.getDate(); cell.querySelector('small').textContent = MONTH_LABELS[next.getMonth()].slice(0, 3); if (calendarDaysFromToday(next) <= 3) row.classList.add('date-soon'); }
      else cell.classList.add('hidden');
      row.addEventListener('click', () => openDetail(a, next));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter') openDetail(a, next); });
      if (highlightId && String(a.id) === highlightId) row.classList.add('card-highlight');
      list.appendChild(row);
    });
    root.appendChild(list);
    if (highlightId) {
      const target = list.querySelector('.card-highlight');
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  // ==================================================================
  // DRIVE
  // ==================================================================
  function dossierSelectOptions(dossiers, selectedId) {
    return `<option value="">${esc(tr('dossier_select_none'))}</option>` + dossiers.map((ds) =>
      `<option value="${ds.id}"${String(ds.id) === String(selectedId) ? ' selected' : ''}>${esc(ds.title)}</option>`
    ).join('');
  }

  function documentModal(existing, dossiers, currentDossierId) {
    const form = el(`
      <form class="modal-body" style="padding:0">
        <div class="form-row"><label>${esc(tr('field_display_name'))}</label><input type="text" name="display_name" placeholder="${esc(tr('field_display_name_placeholder'))}" /></div>
        <p class="card-sub" style="margin:-6px 0 0">${tr('original_file_label', { name: esc(existing.original_name) })}</p>
        <div class="form-row"><label>${esc(tr('field_folder'))}</label><select name="dossier_id">${dossierSelectOptions(dossiers, currentDossierId)}</select></div>
        <div class="form-row"><label>${esc(tr('field_expiry_optional'))}</label><input type="date" name="expiry_date" /></div>
        <div class="form-row"><label>${esc(tr('field_tags'))}</label><input type="text" name="tags" /></div>
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button>
          <button type="submit" class="btn btn-primary">${esc(tr('btn_save'))}</button>
        </div>
      </form>
    `);
    form.display_name.value = existing.display_name || '';
    form.expiry_date.value = existing.expiry_date ? existing.expiry_date.slice(0, 10) : '';
    form.tags.value = (existing.tags || []).join(', ');
    return form;
  }

  // Riallinea i collegamenti cartella di un elemento a un solo id selezionato
  // da un menu a tendina (scollega gli altri, collega quello nuovo se manca).
  async function setSingleDossierLink(itemType, itemId, currentDossierIds, newDossierId) {
    const targets = currentDossierIds.filter((id) => String(id) !== String(newDossierId));
    await Promise.all(targets.map((id) => api(`/dossiers/${id}/links/${itemType}/${itemId}`, { method: 'DELETE' })));
    if (newDossierId && !currentDossierIds.some((id) => String(id) === String(newDossierId))) {
      await api(`/dossiers/${newDossierId}/links`, { method: 'POST', body: JSON.stringify({ item_type: itemType, item_id: itemId }) });
    }
  }

  // Caricamento di un documento: dalla pagina Drive e dalla cattura veloce
  // (in quel caso si resta dove si e', anche se si chiude senza caricare).
  function openUploadDocument(dossiers, onDone) {
    const form = el(`
      <form class="modal-body" style="padding:0">
        <div class="form-row"><label>${esc(tr('field_file'))}</label><input type="file" name="file" required /></div>
        <div class="form-row"><label>${esc(tr('field_display_name'))}</label><input type="text" name="display_name" placeholder="${esc(tr('field_display_name_placeholder'))}" /></div>
        <div class="form-row"><label>${esc(tr('field_folder_optional'))}</label><select name="dossier_id">${dossierSelectOptions(dossiers, '')}</select></div>
        <div class="form-row"><label>${esc(tr('field_expiry_optional'))}</label><input type="date" name="expiry_date" /></div>
        <div class="form-row"><label>${esc(tr('field_tags'))}</label><input type="text" name="tags" /></div>
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button>
          <button type="submit" class="btn btn-primary">${esc(tr('btn_upload'))}</button>
        </div>
      </form>
    `);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const tags = parseTags(form);
      const fd = new FormData();
      fd.append('file', form.file.files[0]);
      fd.append('display_name', form.display_name.value);
      fd.append('expiry_date', form.expiry_date.value || '');
      fd.append('tags', JSON.stringify(tags));
      const doc = await api('/drive', { method: 'POST', body: fd });
      if (form.dossier_id.value) {
        await api(`/dossiers/${form.dossier_id.value}/links`, { method: 'POST', body: JSON.stringify({ item_type: 'document', item_id: doc.id }) });
      }
      closeModal(); toast(tr('toast_document_uploaded')); if (onDone) onDone();
    });
    form.querySelector('[data-cancel]').addEventListener('click', closeModal);
    openModal(tr('modal_upload_document'), form);
  }

  views.drive = async (root, opts = {}) => {
    const highlightId = opts.highlight ? String(opts.highlight) : null;
    const [docsAll, dossiers] = await Promise.all([api('/drive'), api('/dossiers')]);
    const docs = docsAll.filter(onlyFilter(opts));
    // Documento -> cartelle a cui e' collegato (di norma una sola, il menu a
    // tendina tratta il collegamento come singolo anche se il modello dati
    // sotto permetterebbe piu' cartelle per lo stesso elemento).
    const docDossiers = {};
    dossiers.forEach((ds) => {
      ds.items.forEach((it) => {
        if (it.type === 'document') (docDossiers[it.id] ||= []).push(ds);
      });
    });
    root.innerHTML = '';
    root.appendChild(el(`
      <div class="view-header">
        <h2>${esc(tr('nav_drive_title'))}</h2>
        <div class="view-header-actions">${backToDossierButtonHtml(opts)}<button class="btn btn-primary" id="new-doc">${phIcon('plus', 16)}${esc(tr('btn_upload_document'))}</button></div>
      </div>
    `));
    wireBackToDossier(root, opts);

    root.querySelector('#new-doc').addEventListener('click', () => openUploadDocument(dossiers, () => render('drive')));

    if (!docs.length) {
      root.appendChild(el(`<div class="empty-state">${esc(tr('empty_documents'))}</div>`));
      return;
    }

    docs.forEach((d) => {
      const ext = (d.original_name.includes('.') ? d.original_name.split('.').pop() : '').toUpperCase().slice(0, 4);
      const previewable = PREVIEWABLE_MIME.has(d.mime);
      const linkedDossiers = docDossiers[d.id] || [];
      const row = el(`
        <div class="doc-row row-card">
          <div style="display:flex;gap:10px;align-items:center;min-width:0">
            <div class="entry-doc${previewable ? ' entry-doc-clickable' : ''}" style="margin-top:0;flex:none">
              ${iconaLinea(fileCategoryIcon(d.mime), true)}
              <span class="entry-doc-ext">${esc(ext || 'FILE')}</span>
            </div>
            <div style="min-width:0">
              <div class="doc-name">${esc(d.display_name || d.original_name)}</div>
              ${d.display_name ? `<div class="doc-original">${esc(d.original_name)}</div>` : ''}
              <div class="doc-meta">${d.folder ? esc(d.folder) + ' · ' : ''}${fmtSize(d.size)}${d.expiry_date ? tr('doc_expiry_suffix', { date: fmtDate(d.expiry_date) }) : ''}</div>
              ${linkedDossiers.length ? `<div class="doc-dossier">${tr('doc_dossier_link', { names: linkedDossiers.map((ds) => esc(ds.title)).join(', ') })}</div>` : ''}
            </div>
          </div>
          <span class="card-actions" style="padding:0">
            <a class="btn btn-sm" href="/api/drive/${d.id}/download">${esc(tr('btn_download'))}</a>
            <button class="btn btn-sm" data-edit>${esc(tr('btn_edit'))}</button>
            <button class="btn btn-sm btn-danger" data-del>${esc(tr('btn_delete'))}</button>
          </span>
        </div>
      `);
      if (previewable) row.querySelector('.entry-doc').addEventListener('click', () => openDocumentPreview(d));
      const passD = passButton('document', d.id, d.display_name || d.original_name);
      if (passD) row.querySelector('[data-del]').after(passD);
      row.querySelector('[data-edit]').addEventListener('click', () => {
        const currentIds = linkedDossiers.map((ds) => ds.id);
        const form = documentModal(d, dossiers, currentIds[0] || '');
        form.addEventListener('submit', async (e) => {
          e.preventDefault();
          const tags = parseTags(form);
          await api(`/drive/${d.id}`, { method: 'PUT', body: JSON.stringify({ display_name: form.display_name.value, expiry_date: form.expiry_date.value || null, tags }) });
          await setSingleDossierLink('document', d.id, currentIds, form.dossier_id.value);
          closeModal(); toast(tr('toast_document_updated')); render('drive');
        });
        form.querySelector('[data-cancel]').addEventListener('click', closeModal);
        openModal(tr('modal_edit_document'), form);
      });
      row.querySelector('[data-del]').addEventListener('click', async () => {
        if (!(await askConfirm(tr('confirm_delete_document')))) return;
        await api(`/drive/${d.id}`, { method: 'DELETE' });
        toast(tr('toast_document_deleted')); render('drive');
      });
      if (highlightId && String(d.id) === highlightId) row.classList.add('card-highlight');
      root.appendChild(row);
    });
    if (highlightId) {
      const target = root.querySelector('.card-highlight');
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  // ==================================================================
  // FASCICOLI
  // ==================================================================
  // Vista Cartelle: griglia a icone stile Esplora Risorse. Livello radice =
  // icona-cartella per ogni dossier; entrando (click) si vede il contenuto
  // collegato come icone del tipo reale (documento/vault/nota/...), stesso
  // set icone gia' usato da menu Avvio/taskbar (appIcon), nessuna nuova
  // icona necessaria. Nessuna sotto-cartella: un solo livello di profondita'.
  views.dossiers = async (root, opts = {}) => {
    const highlightId = opts.highlight ? String(opts.highlight) : null;
    const dossiers = await api('/dossiers');
    root.innerHTML = '';

    function openDossierForm(existing) {
      const form = el(`
        <form class="modal-body" style="padding:0">
          <div class="form-row"><label>${esc(tr('field_title'))}</label><input type="text" name="title" required /></div>
          <div class="form-row"><label>${esc(tr('field_description'))}</label><textarea name="description" rows="3"></textarea></div>
          <div class="form-actions">
            <button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button>
            <button type="submit" class="btn btn-primary">${esc(tr(existing ? 'btn_save' : 'btn_create'))}</button>
          </div>
        </form>
      `);
      if (existing) {
        form.title.value = existing.title;
        form.description.value = existing.description || '';
      }
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const body = JSON.stringify({ title: form.title.value, description: form.description.value });
        if (existing) {
          await api(`/dossiers/${existing.id}`, { method: 'PUT', body });
          closeModal(); toast(tr('toast_dossier_updated')); render('dossiers', { highlight: existing.id, fromHash: true });
        } else {
          const created = await api('/dossiers', { method: 'POST', body });
          closeModal(); toast(tr('toast_dossier_created')); render('dossiers', { highlight: created.id });
        }
      });
      form.querySelector('[data-cancel]').addEventListener('click', closeModal);
      openModal(tr(existing ? 'modal_edit_dossier' : 'modal_new_dossier'), form);
    }

    // ---- Elenco delle cartelle: una scheda per cartella, un livello solo ----
    function renderRoot() {
      const head = el(`<div class="view-header"><div class="view-header-actions"><button type="button" class="btn btn-primary" id="new-dossier">${phIcon('plus', 16)}${esc(tr('btn_new_dossier'))}</button></div></div>`);
      head.querySelector('#new-dossier').addEventListener('click', () => openDossierForm(null));
      root.appendChild(head);
      if (!dossiers.length) {
        root.appendChild(el(`<div class="empty-state">${esc(tr('empty_dossiers'))}</div>`));
        return;
      }
      const grid = el('<div class="dossier-grid"></div>');
      dossiers.forEach((d) => {
        const n = d.items.length;
        const counts = {};
        d.items.forEach((it) => { counts[it.type] = (counts[it.type] || 0) + 1; });
        const card = el(`
          <a class="dossier-card" href="#/dossiers/${d.id}">
            ${appIcon('dossiers', 44)}
            <span class="dossier-card-body">
              <span class="dossier-card-title"></span>
              <span class="dossier-card-sub"></span>
              <span class="dossier-card-types"></span>
            </span>
          </a>
        `);
        card.querySelector('.dossier-card-title').textContent = d.title;
        card.querySelector('.dossier-card-sub').textContent = d.description || tr(n === 1 ? 'count_items_one' : 'count_items_other', { n });
        const types = card.querySelector('.dossier-card-types');
        Object.entries(counts).forEach(([type, c]) => {
          const view = TYPE_TO_VIEW[type];
          types.appendChild(el(`<span class="type-pill">${appIcon(view, 16)}${c}</span>`));
        });
        grid.appendChild(card);
      });
      root.appendChild(grid);
    }

    // ---- Una cartella: tutto quello che contiene, diviso per tipo, con le
    // sue scadenze in cima. Le voci arrivano dal server solo con tipo/id/nome:
    // i dettagli (avanzamento, date, importi) si prendono dagli elenchi delle
    // sezioni, gia' disponibili, cosi' il server non cambia. ----
    async function renderDossier(d) {
      // Le voci delle sezioni spente (Sezioni visibili) non compaiono.
      const has = (type) => !isHidden(TYPE_TO_VIEW[type]) && d.items.some((it) => it.type === type);
      const [projects, ideas, reminders, accounts, docs, vault] = await Promise.all([
        has('project') ? api('/projects') : [], has('idea') ? api('/ideas') : [],
        has('reminder') ? api('/reminders') : [], has('account') ? api('/accounts') : [],
        has('document') ? api('/drive') : [], has('vault') ? api('/vault') : [],
      ]);
      const pick = (list, type) => {
        const ids = new Set(d.items.filter((it) => it.type === type).map((it) => String(it.id)));
        return list.filter((x) => ids.has(String(x.id)));
      };
      const mine = {
        project: pick(projects, 'project'), idea: pick(ideas, 'idea'), reminder: pick(reminders, 'reminder'),
        account: pick(accounts, 'account'), document: pick(docs, 'document'), vault: pick(vault, 'vault'),
      };

      const head = el(`
        <div class="dossier-head">
          <a class="btn btn-ghost btn-sm dossier-back" href="#/dossiers"></a>
          <div class="dossier-head-main">
            <p class="dossier-desc"></p>
          </div>
          <div class="view-header-actions">
            <button type="button" class="btn btn-primary" data-add></button>
            <button type="button" class="btn" data-edit></button>
            <button type="button" class="btn btn-danger" data-del></button>
          </div>
        </div>
      `);
      head.querySelector('.dossier-back').innerHTML = `${phIcon('arrow-left', 16)}${esc(tr('nav_dossiers'))}`;
      const desc = head.querySelector('.dossier-desc');
      if (d.description) desc.textContent = d.description; else desc.remove();
      head.querySelector('[data-add]').innerHTML = `${phIcon('plus', 16)}${esc(tr('dossier_add_to', { title: d.title }))}`;
      head.querySelector('[data-edit]').textContent = tr('btn_edit');
      head.querySelector('[data-del]').textContent = tr('btn_delete');
      head.querySelector('[data-add]').addEventListener('click', () => openQuickCapture(d));
      head.querySelector('[data-edit]').addEventListener('click', () => openDossierForm(d));
      const passF = passButton('dossier', d.id, d.title);
      if (passF) head.querySelector('[data-edit]').before(passF);
      head.querySelector('[data-del]').addEventListener('click', async () => {
        if (!(await askConfirm(tr('confirm_delete_dossier')))) return;
        await api(`/dossiers/${d.id}`, { method: 'DELETE' });
        toast(tr('toast_dossier_deleted')); render('dossiers');
      });
      root.appendChild(head);
      viewTitle.textContent = d.title;
      const newLabel = btnNuovo.querySelector('span');
      if (newLabel) newLabel.textContent = tr('dossier_add_to', { title: d.title });

      // Scadenze della cartella, dalla piu' vicina.
      const due = [];
      mine.reminder.forEach((r) => due.push({ days: calendarDaysFromToday(r.date), title: r.label, open: () => render('reminders', { only: r.id, fromDossier: d.id }) }));
      mine.project.filter((p) => p.deadline && p.status !== 'fatto').forEach((p) => due.push({ days: calendarDaysFromToday(p.deadline), title: p.title, open: () => render('projects', { only: p.id, fromDossier: d.id }) }));
      mine.account.forEach((a) => {
        const next = nextChargeDate(a) || (!loanInfo(a) && a.renewal_date);
        if (next) due.push({ days: calendarDaysFromToday(next), title: tr(loanInfo(a) ? 'loan_installment_of' : 'today_renewal_of', { name: a.service }), open: () => render('accounts', { only: a.id, fromDossier: d.id }) });
      });
      mine.document.filter((x) => x.expiry_date).forEach((x) => due.push({ days: calendarDaysFromToday(x.expiry_date), title: x.display_name || x.original_name, open: () => openDocumentPreview(x) }));
      const dueSorted = due.filter((x) => x.days !== null).sort((a, b) => a.days - b.days);
      if (dueSorted.length) {
        const strip = el('<div class="due-strip"></div>');
        dueSorted.slice(0, 8).forEach((x) => {
          const chip = el(`<button type="button" class="due-chip ${urgencyClass(x.days)}"><span class="due-chip-when"></span><span class="due-chip-title"></span></button>`);
          chip.querySelector('.due-chip-when').textContent = relativeDayLabel(x.days);
          chip.querySelector('.due-chip-title').textContent = x.title;
          chip.addEventListener('click', x.open);
          strip.appendChild(chip);
        });
        root.appendChild(strip);
      }

      if (!d.items.length) {
        root.appendChild(el(`<div class="empty-state">${esc(tr('empty_dossier_items'))}</div>`));
        return;
      }

      const grid = el('<div class="dossier-sections"></div>');
      root.appendChild(grid);
      const unlinkBtn = (type, id) => {
        const b = el(`<button type="button" class="icon-btn unlink-btn" title="${esc(tr('title_unlink'))}" aria-label="${esc(tr('title_unlink'))}">${iconaLinea('chiudi')}</button>`);
        b.addEventListener('click', async (e) => {
          e.stopPropagation();
          await api(`/dossiers/${d.id}/links/${type}/${id}`, { method: 'DELETE' });
          toast(tr('toast_item_unlinked')); render('dossiers', { highlight: d.id, fromHash: true });
        });
        return b;
      };
      const section = (type, titleKey, n) => {
        const s = el(`<section class="panel dossier-section"><div class="panel-head"><h2 class="section-title-${type}"></h2></div><div class="dossier-section-body"></div></section>`);
        s.querySelector('h2').textContent = `${tr(titleKey)} · ${n}`;
        grid.appendChild(s);
        return s.querySelector('.dossier-section-body');
      };
      const row = (type, item, mainText, sideText, onOpen) => {
        const r = el('<div class="dossier-row"><button type="button" class="dossier-row-main"><span class="dossier-row-title"></span><span class="dossier-row-side"></span></button></div>');
        r.querySelector('.dossier-row-title').textContent = mainText;
        r.querySelector('.dossier-row-side').textContent = sideText || '';
        r.querySelector('.dossier-row-main').addEventListener('click', onOpen);
        r.appendChild(unlinkBtn(type, item.id));
        return r;
      };

      if (mine.project.length) {
        const body = section('project', 'nav_projects', mine.project.length);
        mine.project.forEach((p) => {
          const { done, total } = checklistProgress(p.checklist);
          const r = row('project', p, p.title, total ? `${done}/${total}` : (STATUSES.find((s) => s.key === p.status) || STATUSES[0]).label,
            () => render('projects', { only: p.id, fromDossier: d.id }));
          if (total) r.appendChild(el(`<div class="progress dossier-progress"><div class="progress-fill" style="width:${Math.round((done / total) * 100)}%"></div></div>`));
          body.appendChild(r);
        });
      }
      if (mine.reminder.length) {
        const body = section('reminder', 'nav_reminders', mine.reminder.length);
        mine.reminder.forEach((x) => body.appendChild(row('reminder', x, x.label, relativeDayLabel(calendarDaysFromToday(x.date)), () => render('reminders', { only: x.id, fromDossier: d.id }))));
      }
      if (mine.vault.length) {
        const body = section('vault', 'dossier_section_vault', mine.vault.length);
        mine.vault.forEach((v) => body.appendChild(row('vault', v, v.site, v.username || '', () => render('vault', { only: v.id, fromDossier: d.id }))));
      }
      if (mine.document.length) {
        const body = section('document', 'nav_drive', mine.document.length);
        mine.document.forEach((x) => body.appendChild(row('document', x, x.display_name || x.original_name, x.expiry_date ? relativeDayLabel(calendarDaysFromToday(x.expiry_date)) : fmtSize(x.size), () => openDocumentPreview(x))));
      }
      if (mine.account.length) {
        const body = section('account', 'nav_accounts', mine.account.length);
        mine.account.forEach((a) => body.appendChild(row('account', a, a.service, a.amount ? fmtMoney(a.amount) : (a.plan || ''), () => render('accounts', { only: a.id, fromDossier: d.id }))));
      }
      if (mine.idea.length) {
        const body = section('idea', 'nav_ideas', mine.idea.length);
        const notes = el('<div class="note-grid"></div>');
        const NOTE_TINTS = ['note-yellow', 'note-lilac', 'note-pink', 'note-sky'];
        mine.idea.forEach((idea, i) => {
          const wrap = el(`<div class="note-tile-wrap"><button type="button" class="note-tile ${NOTE_TINTS[i % NOTE_TINTS.length]}"><span class="note-text"></span></button></div>`);
          const text = idea.title || idea.body || '';
          wrap.querySelector('.note-text').textContent = text.length > 120 ? text.slice(0, 120) + '…' : text;
          wrap.querySelector('.note-tile').addEventListener('click', () => render('ideas', { only: idea.id, fromDossier: d.id }));
          wrap.appendChild(unlinkBtn('idea', idea.id));
          notes.appendChild(wrap);
        });
        body.appendChild(notes);
      }
    }

    if (highlightId) {
      const match = dossiers.find((d) => String(d.id) === highlightId);
      if (match) { await renderDossier(match); return; }
    }
    renderRoot();
  };

  // ==================================================================
  // CESTINO
  // ==================================================================
  const TYPE_LABELS = { idea: tr('type_idea'), project: tr('type_project'), vault: tr('type_vault'), account: tr('type_account'), document: tr('type_document'), dossier: tr('type_dossier'), reminder: tr('type_reminder'), card: tr('type_card') };

  views.trash = async (root) => {
    const items = await api('/trash');
    root.innerHTML = '';
    root.appendChild(el(`<div class="view-header"><h2>${esc(tr('nav_trash_title'))}</h2></div>`));

    if (!items.length) {
      root.appendChild(el(`<div class="empty-state">${esc(tr('empty_trash'))}</div>`));
      return;
    }

    items.forEach((item) => {
      const row = el(`
        <div class="trash-row row-card">
          <span><span class="chip-type">${esc(TYPE_LABELS[item.type] || item.type)}</span> &nbsp;${esc(item.label)}</span>
          <span class="card-actions" style="padding:0">
            <button class="btn btn-sm" data-restore>${esc(tr('btn_restore'))}</button>
            <button class="btn btn-sm btn-danger" data-purge>${esc(tr('btn_purge'))}</button>
          </span>
        </div>
      `);
      row.querySelector('[data-restore]').addEventListener('click', async () => {
        await api(`/trash/${item.type}/${item.id}/restore`, { method: 'POST' });
        toast(tr('toast_restored')); render('trash');
      });
      row.querySelector('[data-purge]').addEventListener('click', async () => {
        if (!(await askConfirm(tr('confirm_purge')))) return;
        await api(`/trash/${item.type}/${item.id}`, { method: 'DELETE' });
        toast(tr('toast_purged')); render('trash');
      });
      root.appendChild(row);
    });
  };

  // ==================================================================
  // SICUREZZA (verifica in due passaggi)
  // ==================================================================
  function showRecoveryCodes(codes) {
    const wrap = el('<div></div>');
    wrap.appendChild(el(`
      <p class="card-sub">${tr('recovery_codes_intro')}</p>
    `));
    const list = el('<div class="recovery-codes"></div>');
    codes.forEach((c) => list.appendChild(el(`<code>${esc(c)}</code>`)));
    wrap.appendChild(list);

    const actions = el('<div class="form-actions"></div>');
    const copy = el(`<button type="button" class="btn btn-ghost">${esc(tr('btn_copy_all'))}</button>`);
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(codes.join('\n'));
        toast(tr('toast_codes_copied'));
      } catch (e) {
        toast(tr('toast_copy_failed'));
      }
    });
    const done = el(`<button type="button" class="btn btn-primary">${esc(tr('btn_codes_saved'))}</button>`);
    done.addEventListener('click', () => { closeModal(); render('security'); });
    actions.appendChild(copy);
    actions.appendChild(done);
    wrap.appendChild(actions);
    openModal(tr('modal_recovery_codes'), wrap);
  }

  function askPassword(title, testo, onConfirm) {
    const form = el(`
      <form class="modal-body" style="padding:0">
        <p class="card-sub">${esc(testo)}</p>
        <div class="form-row"><label>${esc(tr('field_password'))}</label><input type="password" name="password" required /></div>
        <p class="form-error hidden" data-err></p>
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button>
          <button type="submit" class="btn btn-primary">${esc(tr('btn_confirm'))}</button>
        </div>
      </form>
    `);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = form.querySelector('[data-err]');
      errEl.classList.add('hidden');
      try {
        await onConfirm(form.password.value);
      } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.remove('hidden');
      }
    });
    form.querySelector('[data-cancel]').addEventListener('click', closeModal);
    openModal(title, form);
  }

  function startTotpSetup() {
    api('/security/totp/setup', { method: 'POST' }).then((data) => {
      const wrap = el('<div class="totp-setup"></div>');
      wrap.appendChild(el(`
        <ol class="totp-steps">
          <li>${tr('totp_step1')}</li>
          <li>${tr('totp_step2')}</li>
        </ol>
      `));
      const qr = el(`<div class="qr-box">${data.qr || ''}</div>`);
      wrap.appendChild(qr);
      if (!data.qr && data.otpauth) {
        loadScript('/vendor/qrcode.js').then(() => {
          const code = window.qrcode(0, 'M'); code.addData(data.otpauth); code.make();
          qr.innerHTML = code.createSvgTag({ cellSize: 5, margin: 2, scalable: true });
        });
      }
      wrap.appendChild(el(`
        <p class="card-sub">${tr('totp_manual_hint')}
        <br /><code class="totp-secret">${esc(data.secret)}</code></p>
      `));

      const form = el(`
        <form class="modal-body" style="padding:0">
          <div class="form-row">
            <label>${esc(tr('totp_code_label'))}</label>
            <input type="text" name="code" inputmode="numeric" maxlength="7" placeholder="123456" required />
          </div>
          <p class="form-error hidden" data-err></p>
          <div class="form-actions">
            <button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button>
            <button type="submit" class="btn btn-primary">${esc(tr('btn_activate'))}</button>
          </div>
        </form>
      `);
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const errEl = form.querySelector('[data-err]');
        errEl.classList.add('hidden');
        try {
          const res = await api('/security/totp/enable', {
            method: 'POST',
            body: JSON.stringify({ code: form.code.value }),
          });
          closeModal();
          toast(tr('toast_totp_enabled'));
          showRecoveryCodes(res.recoveryCodes);
        } catch (err) {
          errEl.textContent = err.message;
          errEl.classList.remove('hidden');
        }
      });
      form.querySelector('[data-cancel]').addEventListener('click', closeModal);
      wrap.appendChild(form);
      openModal(tr('modal_activate_totp'), wrap);
    });
  }

  // Blocco "Verifica in due passaggi": lo usano sia il server sia la
  // modalita' "Sul telefono" (stesse rotte /security/totp/*).
  function totpBlock(info) {
    const block = el(`<div class="section-block"><h3>${esc(tr('section_2fa'))}</h3></div>`);

    if (!info.totpEnabled) {
      block.appendChild(el(`
        <p class="card-sub">${esc(tr('totp_disabled_hint'))}</p>
      `));
      const btn = el(`<button class="btn btn-primary">${esc(tr('btn_activate_qr'))}</button>`);
      btn.addEventListener('click', startTotpSetup);
      block.appendChild(btn);
    } else {
      block.appendChild(el(`
        <p class="card-sub">${esc(tr('totp_enabled_hint'))}</p>
        <p class="card-sub">${tr('recovery_codes_left', { n: info.recoveryCodesLeft })}</p>
      `));
      const actions = el('<div class="card-actions" style="padding:12px 0 0"></div>');

      const nuovi = el(`<button class="btn btn-sm">${esc(tr('btn_new_recovery_codes'))}</button>`);
      nuovi.addEventListener('click', () => {
        askPassword(
          tr('modal_new_recovery_codes'),
          tr('confirm_new_recovery_codes'),
          async (password) => {
            const res = await api('/security/totp/recovery-codes', {
              method: 'POST',
              body: JSON.stringify({ password }),
            });
            closeModal();
            showRecoveryCodes(res.recoveryCodes);
          }
        );
      });

      const off = el(`<button class="btn btn-sm btn-danger">${esc(tr('btn_deactivate'))}</button>`);
      off.addEventListener('click', () => {
        askPassword(
          tr('modal_deactivate_totp'),
          tr('confirm_deactivate_totp'),
          async (password) => {
            await api('/security/totp/disable', { method: 'POST', body: JSON.stringify({ password }) });
            closeModal();
            toast(tr('toast_totp_disabled'));
            render('security');
          }
        );
      });

      actions.appendChild(nuovi);
      actions.appendChild(off);
      block.appendChild(actions);

      if (info.recoveryCodesLeft === 0) {
        block.appendChild(el(`
          <p class="form-error">${esc(tr('recovery_codes_zero_warning'))}</p>
        `));
      }
    }

    return block;
  }

  views.security = async (root) => {
    if (window.MementoBackend && window.MementoBackend.renderSettings) {
      if (await window.MementoBackend.renderSettings(root, window.MementoUI)) return;
    }
    const info = await api('/security');
    root.innerHTML = '';
    root.appendChild(el(`<div class="view-header"><h2>${esc(tr('nav_security_title'))}</h2></div>`));
    root.appendChild(themeBlock());
    root.appendChild(sectionsBlock());

    root.appendChild(totpBlock(info));

    const bioBlock = el(`<div class="section-block"><h3>${esc(tr('section_biometric'))}</h3></div>`);
    if (!webauthnSupported()) {
      bioBlock.appendChild(el(`<p class="card-sub">${esc(tr('biometric_not_supported'))}</p>`));
    } else {
      const bioData = await api('/security/webauthn');
      if (bioData.credentials.length) {
        const list = el('<div class="card-actions" style="flex-direction:column;align-items:stretch;gap:6px"></div>');
        bioData.credentials.forEach((c) => {
          const item = el(`
            <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">
              <span class="card-sub">${esc(c.deviceName)}</span>
            </div>
          `);
          const del = el(`<button class="btn btn-sm btn-danger">${esc(tr('btn_delete'))}</button>`);
          del.addEventListener('click', () => {
            askPassword(
              tr('modal_remove_fingerprint'),
              tr('confirm_remove_fingerprint'),
              async (password) => {
                await api(`/security/webauthn/${c.id}`, { method: 'DELETE', body: JSON.stringify({ password }) });
                closeModal();
                toast(tr('toast_fingerprint_removed'));
                render('security');
              }
            );
          });
          item.appendChild(del);
          list.appendChild(item);
        });
        bioBlock.appendChild(list);
      }
      const addBtn = el(`<button class="btn btn-sm btn-primary" style="margin-top:8px">${esc(tr('btn_add_fingerprint'))}</button>`);
      addBtn.addEventListener('click', async () => {
        try {
          await enrollFingerprint();
          toast(tr('toast_fingerprint_added'));
          render('security');
        } catch (err) {
          toast(err.message);
        }
      });
      bioBlock.appendChild(addBtn);
    }
    root.appendChild(bioBlock);

    const notifyBlock = el(`<div class="section-block"><h3>${esc(tr('section_push_notifications'))}</h3></div>`);
    const supported = 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
    if (!supported) {
      notifyBlock.appendChild(el(`<p class="card-sub">${esc(tr('push_not_supported'))}</p>`));
    } else {
      const existingSub = await getPushSubscription();
      if (Notification.permission === 'denied') {
        notifyBlock.appendChild(el(`
          <p class="card-sub">${esc(tr('push_blocked'))}</p>
        `));
      } else if (existingSub) {
        notifyBlock.appendChild(el(`
          <p class="card-sub">${esc(tr('push_active_hint'))}</p>
        `));
        const off = el(`<button class="btn btn-sm btn-danger">${esc(tr('btn_deactivate'))}</button>`);
        off.addEventListener('click', async () => {
          await disablePushNotifications();
          toast(tr('toast_push_disabled')); render('security');
        });
        notifyBlock.appendChild(off);
      } else {
        notifyBlock.appendChild(el(`
          <p class="card-sub">${esc(tr('push_inactive_hint'))}</p>
        `));
        const on = el(`<button class="btn btn-primary">${esc(tr('btn_enable_notifications'))}</button>`);
        on.addEventListener('click', async () => {
          try {
            await enablePushNotifications();
            toast(tr('toast_push_enabled')); render('security');
          } catch (err) {
            toast(err.message);
          }
        });
        notifyBlock.appendChild(on);
      }
    }
    root.appendChild(notifyBlock);

    // Backup: uno .zip con database e documenti, generato dal server con una
    // copia coerente anche mentre l'app e' in uso (vedi server/routes/backup.js).
    const backupBlock = el(`<div class="section-block"><h3>${esc(tr('section_backup'))}</h3><p class="card-sub">${esc(tr('backup_hint'))}</p><div class="card-actions" style="padding-top:10px"><a class="btn btn-primary" href="/api/backup" download>${esc(tr('btn_export_backup'))}</a><button type="button" class="btn" data-export-app>${esc(tr('btn_export_for_app'))}</button></div></div>`);
    // File .memento per l'app Android ("Sul telefono"): il server decifra il
    // vault e ricifra tutto con la password scelta qui.
    backupBlock.querySelector('[data-export-app]').addEventListener('click', () => {
      const form = el(`<form class="modal-body" style="padding:0">
        <div class="form-row"><label>${esc(tr('export_app_password'))}</label><input type="password" name="p1" required minlength="8" autocomplete="new-password" /></div>
        <div class="form-row"><label>${esc(tr('local_password_repeat'))}</label><input type="password" name="p2" required minlength="8" autocomplete="new-password" /></div>
        <div class="form-actions"><button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button><button type="submit" class="btn btn-primary">${esc(tr('btn_export'))}</button></div></form>`);
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (form.p1.value !== form.p2.value) { toast(tr('local_password_mismatch')); return; }
        toast(tr('local_exporting'));
        const envelope = await api('/backup/app', { method: 'POST', body: JSON.stringify({ password: form.p1.value }) });
        closeModal();
        const blob = new Blob([JSON.stringify(envelope)], { type: 'application/json' });
        const name = `memento-${new Date().toISOString().slice(0, 10)}.memento`;
        if (window.MementoShell && window.MementoShell.saveFile) { await window.MementoShell.saveFile(blob, name); return; }
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click();
        setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
      });
      form.querySelector('[data-cancel]').addEventListener('click', closeModal);
      openModal(tr('btn_export_for_app'), form);
    });
    root.appendChild(backupBlock);

    // Backup dell'app Android ("Sul telefono"): il telefono salva qui la sua
    // copia cifrata con la chiave creata da questo blocco.
    if (!window.MementoBackend) {
      const appBlock = el(`<div class="section-block"><h3>${esc(tr('srvbk_server_title'))}</h3><p class="card-sub" data-state></p>
        <div class="card-actions" style="padding-top:10px"><button type="button" class="btn btn-primary" data-link>${esc(tr('srvbk_link_phone'))}</button><button type="button" class="btn" data-unlink>${esc(tr('srvbk_unlink_all'))}</button></div></div>`);
      const paintApp = async () => {
        try {
          const st = await api('/app-store/status');
          appBlock.querySelector('[data-state]').textContent = st.phones || st.files
            ? tr('srvbk_server_status', { phones: st.phones, when: st.last ? fmtDate(st.last) : '—' })
            : tr('srvbk_server_none');
          appBlock.querySelector('[data-unlink]').classList.toggle('hidden', !st.phones);
        } catch (_) { appBlock.querySelector('[data-state]').textContent = ''; }
      };
      appBlock.querySelector('[data-link]').addEventListener('click', async () => {
        const { token } = await api('/app-store/keys', { method: 'POST' });
        const code = `MEMENTO-BK1 ${location.origin} ${token}`;
        const copy = el(`<button type="button" class="btn">${esc(tr('srvbk_copy_code'))}</button>`);
        copy.addEventListener('click', async () => { try { await navigator.clipboard.writeText(code); toast(tr('toast_copied')); } catch (_) { toast(tr('err_copy_failed')); } });
        const done = el(`<button type="button" class="btn btn-primary">${esc(tr('qr_done'))}</button>`);
        done.addEventListener('click', () => { closeModal(); paintApp(); });
        await showQr(tr('srvbk_link_phone'), code, '', [copy, done]);
      });
      appBlock.querySelector('[data-unlink]').addEventListener('click', async () => {
        if (!(await askConfirm(tr('srvbk_unlink_confirm')))) return;
        await api('/app-store/keys', { method: 'DELETE' });
        paintApp();
      });
      paintApp();
      root.appendChild(appBlock);
    }

    const langBlock = el(`<div class="section-block"><h3>${esc(tr('settings_language'))}</h3><p class="card-sub">${esc(tr('settings_language_hint'))}</p></div>`);
    const langRow = el('<div class="card-actions" style="padding-top:10px"></div>');
    [['it', 'Italiano'], ['en', 'English']].forEach(([code, label]) => {
      const btn = el(`<button class="btn btn-sm${code === I18N.getLang() ? ' btn-primary' : ''}" data-lang="${code}"></button>`);
      btn.textContent = label;
      btn.addEventListener('click', () => { I18N.setLang(code); location.reload(); });
      langRow.appendChild(btn);
    });
    langBlock.appendChild(langRow);
    root.appendChild(langBlock);

    const help = el(`<div class="section-block"><h3>${esc(tr('section_lost_phone'))}</h3></div>`);
    help.appendChild(el(`
      <p class="card-sub">${esc(tr('lost_phone_hint'))}</p>
      <p><code class="cmd-line">docker compose exec memento node server/disable-2fa.js</code></p>
    `));
    // Solo con la verifica in due passaggi attiva serve sapere come uscirne.
    if (info.totpEnabled) root.appendChild(help);
    if (window.MementoBackend && window.MementoBackend.extendSettings) await window.MementoBackend.extendSettings(root, window.MementoUI);
  };

  // ---------------- Global search ----------------
  const searchInput = document.getElementById('global-search');
  const searchResults = document.getElementById('search-results');
  let searchTimer = null;

  searchInput.addEventListener('input', () => {
    clearTimeout(searchTimer);
    const q = searchInput.value.trim();
    if (!q) { searchResults.classList.add('hidden'); return; }
    searchTimer = setTimeout(async () => {
      let results;
      try {
        results = await api('/search?q=' + encodeURIComponent(q));
      } catch (err) {
        searchResults.innerHTML = '';
        searchResults.appendChild(el(`<div class="search-result-item">${esc(err.message)}</div>`));
        searchResults.classList.remove('hidden');
        return;
      }
      // La ricerca puo' rispondere fuori ordine: ignoriamo i risultati vecchi.
      if (searchInput.value.trim() !== q) return;
      searchResults.innerHTML = '';
      if (!results.length) {
        searchResults.appendChild(el(`<div class="search-result-item">${esc(tr('no_results'))}</div>`));
      } else {
        // Risultati divisi per tipo, con il simbolo della sezione; sulle voci
        // del vault un tasto per copiare la password senza aprirla.
        const shown = results.filter((r) => !isHidden(TYPE_TO_VIEW[r.type])).slice(0, 40);
        const order = ['vault', 'card', 'idea', 'reminder', 'project', 'account', 'document', 'dossier'];
        order.forEach((type) => {
          const group = shown.filter((r) => r.type === type);
          if (!group.length) return;
          searchResults.appendChild(el(`<div class="search-group">${appIcon(TYPE_TO_VIEW[type], 20)}<span>${esc(TYPE_LABELS[type] || type)}</span></div>`));
          group.forEach((r) => {
            const item = el(`<div class="search-result-item"><span class="sr-label"></span></div>`);
            item.querySelector('.sr-label').textContent = r.label;
            const activate = () => {
              searchResults.classList.add('hidden');
              searchInput.value = '';
              appHeader.classList.remove('search-open');
              render(TYPE_TO_VIEW[r.type] || 'ideas', { highlight: r.id });
            };
            if (r.type === 'vault') {
              const copy = el(`<button type="button" class="sq-btn" aria-label="${esc(tr('btn_copy'))}">${ICON_COPY}</button>`);
              copy.addEventListener('click', async (e) => {
                e.stopPropagation();
                try {
                  let full;
                  try { full = await api(`/vault/${r.id}/reveal`); } catch (err) { if (!(err.data && err.data.webauthnRequired)) throw err; full = await revealWithFingerprint(r.id); }
                  await navigator.clipboard.writeText(full.password || ''); haptic(); toast(tr('toast_copied'));
                } catch (err) { toast(err.message); }
              });
              item.appendChild(copy);
            }
            item.addEventListener('click', activate);
            makeActivatable(item, 'option', activate);
            searchResults.appendChild(item);
          });
        });
      }
      searchResults.classList.remove('hidden');
    }, 250);
  });

  document.addEventListener('click', (e) => {
    if (!e.target.closest('.search-wrap')) searchResults.classList.add('hidden');
  });

  // Telefono: la casella di ricerca resta nascosta finche' non si tocca la
  // lente, cosi' la parte alta dello schermo resta al contenuto.
  const appHeader = document.querySelector('.app-header');
  const searchToggle = document.getElementById('btn-search-toggle');
  function openPhoneSearch() {
    appHeader.classList.add('search-open');
    searchInput.focus();
  }
  function closePhoneSearch() {
    if (searchInput.value.trim()) return;
    appHeader.classList.remove('search-open');
    searchResults.classList.add('hidden');
  }
  searchToggle.addEventListener('click', () => {
    if (appHeader.classList.contains('search-open') && !searchInput.value.trim()) closePhoneSearch(); else openPhoneSearch();
  });
  searchInput.addEventListener('blur', () => setTimeout(closePhoneSearch, 150));
  searchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { searchInput.value = ''; searchInput.blur(); closePhoneSearch(); }
  });

  document.addEventListener('keydown', (e) => {
    if (!(e.metaKey || e.ctrlKey) || e.key.toLowerCase() !== 'k') return;
    if (appRoot.classList.contains('hidden')) return; // non ancora autenticati
    e.preventDefault();
    searchInput.focus();
  });

  // "/" porta alla ricerca da qualunque punto, tranne mentre si scrive.
  document.addEventListener('keydown', (e) => {
    if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey) return;
    if (appRoot.classList.contains('hidden')) return;
    const t = e.target;
    if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) return;
    e.preventDefault();
    searchInput.focus();
  });

  // App Android: i collegamenti a /api/... (scarica, backup) non possono
  // aprire una pagina del server: li gestisce il motore scelto.
  document.addEventListener('click', (e) => {
    const a = e.target.closest && e.target.closest('a[href^="/api/"]');
    if (!a || !window.MementoBackend || !window.MementoBackend.download) return;
    e.preventDefault();
    window.MementoBackend.download(a.getAttribute('href')).catch((err) => toast(err.message));
  });
  window.MementoUI = { receive: () => receiveFlow(), el, esc, tr, toast, openModal, closeModal, render, sectionsBlock, totpBlock, loadScript, askConfirm, askValue, haptic, themeBlock, openQuickCapture, showQr, scanCode, isReady: () => !appRoot.classList.contains('hidden') };

  // Molti handler fanno "await api(...)" senza try/catch: senza questa rete di
  // sicurezza un errore restava solo in console e per l'utente non succedeva nulla.
  window.addEventListener('unhandledrejection', (e) => {
    const msg = e.reason && e.reason.message ? e.reason.message : tr('err_unexpected');
    if (msg !== tr('err_session_expired')) toast(msg);
    e.preventDefault();
  });

  // Versione applicativa: si vede sia prima sia dopo l'accesso. Il commit
  // (quando disponibile: non su una build locale senza GIT_SHA) si vede
  // solo qui, cosi' dopo un aggiornamento si controlla subito se il
  // container sta girando sull'ultimo codice o su una build vecchia.
  api('/health').then((health) => {
    if (!health.version || health.version === 'app') return;
    const label = health.build && health.build !== 'dev'
      ? tr('version_label_build', { version: health.version, build: health.build })
      : tr('version_label', { version: health.version });
    const authEl = document.getElementById('auth-version');
    const sidebarEl = document.getElementById('sidebar-version');
    if (authEl) authEl.textContent = label;
    if (sidebarEl) sidebarEl.textContent = label;
  }).catch(() => {});

  // ---------------- Avvio ----------------
  // La lingua si sceglie una volta sola, al primissimo avvio del
  // dispositivo, prima ancora che esista un account (non ha senso chiederla
  // di nuovo a ogni accesso di chi ha gia' scelto, ne' ha senso mostrarla a
  // chi ha gia' un account creato prima che questa schermata esistesse:
  // quelli restano semplicemente in italiano finche' non la cambiano da
  // Sicurezza).
  const langScreen = document.getElementById('lang-screen');
  function startAfterLanguage() {
    I18N.applyStaticTranslations();
    checkAuth().catch((err) => {
      authError.textContent = err.message;
      authError.classList.remove('hidden');
      showAuthScreen();
    });
  }
  if (I18N.hasChosenLang()) {
    startAfterLanguage();
  } else {
    langScreen.classList.remove('hidden');
    langScreen.querySelectorAll('[data-lang]').forEach((btn) => {
      btn.addEventListener('click', () => {
        I18N.setLang(btn.dataset.lang);
        // Un ricaricamento vero, non solo un re-render: titoli finestra, mesi,
        // giorni della settimana ecc. sono costanti calcolate una volta sola
        // all'avvio dello script (prima ancora che questa scelta esistesse),
        // quindi restano nella lingua di default finche' lo script non riparte.
        location.reload();
      });
    });
  }
})();
