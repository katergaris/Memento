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
    handle.addEventListener('pointerdown', (e) => { startY = e.clientY; dy = 0; sheet.style.transition = 'none'; handle.setPointerCapture(e.pointerId); });
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
            <button type="button" class="preview-close" aria-label="${esc(tr('btn_close'))}">✕</button>
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
  // Icone a tratto sottile (stile delle app attuali) su un quadrato appena
  // tinto del colore della sezione: si riconoscono dal colore senza le
  // tessere piene di una volta. Gli stessi simboli servono alla barra in basso.
  const APP_TILES = {
    today: { color: '#2F5BFF', path: '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6l1.4 1.4M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4 6 18M18 6l1.4-1.4"/>' },
    projects: { color: '#7048E8', path: '<path d="M4 7h16M4 12h10M4 17h7"/><circle cx="18" cy="16.5" r="3"/>' },
    ideas: { color: '#C77700', path: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h4"/>' },
    vault: { color: '#121318', path: '<rect x="4.5" y="10.5" width="15" height="10.5" rx="3"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/><path d="M12 15v2"/>' },
    cards: { color: '#D6336C', path: '<rect x="2.5" y="5.5" width="19" height="13" rx="3"/><path d="M6.5 9.5v5M9.5 9.5v5M12 9.5v5M15 9.5v5M17.5 9.5v5"/>' },
    accounts: { color: '#9C36B5', path: '<path d="M17 2.5 20.5 6 17 9.5"/><path d="M3.5 11.5V10a4 4 0 0 1 4-4h13M7 21.5 3.5 18 7 14.5"/><path d="M20.5 12.5V14a4 4 0 0 1-4 4h-13"/>' },
    drive: { color: '#E8590C', path: '<path d="M7 18a4.5 4.5 0 1 1 .9-8.9A6 6 0 0 1 19.5 11 3.5 3.5 0 0 1 18 18z"/><path d="M12 15.5v-5M9.8 12.5 12 10.3l2.2 2.2"/>' },
    dossiers: { color: '#2F9E44', path: '<path d="M3.5 7.5a2 2 0 0 1 2-2h3.6l2 2h7.4a2 2 0 0 1 2 2v7.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/>' },
    reminders: { color: '#E03131', path: '<circle cx="12" cy="13" r="8"/><path d="M12 9v4l2.5 1.6M9.5 2.5h5"/>' },
    calendar: { color: '#1C7ED6', path: '<rect x="3.5" y="5" width="17" height="15.5" rx="3"/><path d="M3.5 10h17M8 3v4M16 3v4"/>' },
    trash: { color: '#6A6C66', path: '<path d="M4.5 7h15M9.5 7V4.5h5V7M6.5 7l1 13h9l1-13"/>' },
    security: { color: '#6A6C66', path: '<path d="M12 3 19 5.8v5.4c0 4.4-3 7.7-7 9.3-4-1.6-7-4.9-7-9.3V5.8z"/><path d="m9 12 2 2 4-4.5"/>' },
    esci: { color: '#6A6C66', path: '<path d="M10 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4M15 8l4 4-4 4M9 12h10"/>' },
  };

  function appIcon(nome, size = 18) {
    const tile = APP_TILES[nome];
    if (!tile) return '';
    return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" aria-hidden="true" class="app-tile"><rect width="24" height="24" rx="7.5" fill="${tile.color}" fill-opacity="0.11"/><g transform="translate(4.8 4.8) scale(0.6)" fill="none" stroke="${tile.color}" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round">${tile.path}</g></svg>`;
  }

  // Icone vettoriali "pulite" (tratto, non pixel-art): usate solo per il
  // tasto di ricerca del telefono, l'unico punto in cui il blocco a 8 bit era
  // stato segnalato illeggibile a quella dimensione (22px). Il resto della
  // navigazione resta nello stile retro a blocchi.
  const VECTOR_ICONS = {
    cerca: '<circle cx="11" cy="11" r="6.5"/><path d="M15.8 15.8L20.5 20.5"/>',
    chiudi: '<path d="M6 6l12 12M18 6L6 18"/>',
    occhio: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
    'occhio-off': '<path d="M3 3l18 18"/><path d="M10.6 5.2A10.6 10.6 0 0 1 12 5c6.4 0 10 7 10 7a17.6 17.6 0 0 1-4 4.9M6.3 6.5C3.4 8.3 2 12 2 12s3.6 7 10 7c1.4 0 2.7-.3 3.8-.8"/><path d="M9.5 9.7a3 3 0 0 0 4.2 4.2"/>',
    matita: '<path d="M4 20l.9-4L16 4.9a1.6 1.6 0 0 1 2.3 0l.8.8a1.6 1.6 0 0 1 0 2.3L8 19.1z"/><path d="M14.5 7.5l2 2"/>',
    cartellaLinea: '<path d="M3 7a1.8 1.8 0 0 1 1.8-1.8h4l2 2h8.4A1.8 1.8 0 0 1 21 9v8.2A1.8 1.8 0 0 1 19.2 19H4.8A1.8 1.8 0 0 1 3 17.2z"/>',
    cestino: '<path d="M4.5 7h15M9.5 7V4.5h5V7M7 7l1 12.5a1.5 1.5 0 0 0 1.5 1.4h7a1.5 1.5 0 0 0 1.5-1.4L18 7"/><path d="M10.2 11v6M13.8 11v6"/>',
    codice: '<rect x="2" y="5.5" width="20" height="13" rx="1"/><text x="6" y="15" font-size="9.5" font-family="var(--font-mono, monospace)" font-weight="700" stroke="none" fill="currentColor">01</text>',
    immagine: '<rect x="3" y="4" width="18" height="15" rx="1"/><circle cx="8.5" cy="9.5" r="1.5"/><path d="M3 15l5-4.5 4 3.5 3-2.5 6 5"/>',
    musica: '<path d="M9 18V6l10-2v12"/><circle cx="6.5" cy="18" r="2.5"/><circle cx="16.5" cy="16" r="2.5"/>',
    video: '<rect x="2.5" y="5" width="19" height="14" rx="1"/><path d="M10 9.5v5l4.5-2.5z" fill="currentColor" stroke="none"/>',
    documento: '<path d="M6 2.5h8l4 4v15H6z"/><path d="M14 2.5v4h4"/><path d="M8.5 12h7M8.5 15.5h5"/>',
  };
  function iconaLinea(nome) {
    return `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
      stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${VECTOR_ICONS[nome] || ''}</svg>`;
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
  const HIDEABLE_VIEWS = ['projects', 'cards', 'accounts', 'drive', 'dossiers', 'calendar'];
  const HIDDEN_KEY = 'memento-hidden-sections';
  function hiddenViews() {
    try { return new Set(JSON.parse(localStorage.getItem(HIDDEN_KEY) || '[]')); } catch (_) { return new Set(); }
  }
  function isHidden(view) { return hiddenViews().has(view); }
  function visibleSections() { const h = hiddenViews(); return SECTIONS.filter((s) => !h.has(s.view)); }
  function sectionsBlock() {
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
      });
      list.appendChild(row);
    });
    return block;
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

  const strokeIcon = (d) => `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;

  function buildNavigation() {
    sidebarNav.innerHTML = '';
    sidebarSecondary.innerHTML = '';
    visibleSections().forEach((s) => {
      const quiet = SETTINGS_VIEWS.has(s.view);
      (quiet ? sidebarSecondary : sidebarNav).appendChild(navLink(s, quiet ? 'nav-link-quiet' : ''));
    });
    const esci = el(`<button type="button" class="nav-link nav-link-quiet">${appIcon('esci', 30)}<span class="nav-label"></span></button>`);
    esci.querySelector('.nav-label').textContent = tr('btn_logout');
    esci.addEventListener('click', logout);
    sidebarSecondary.appendChild(esci);

    // Telefono: Oggi, Note, + (cattura), Vault, Altro (tutto il resto).
    // La ricerca sta nell'intestazione (lente), non occupa un posto qui.
    tabbar.innerHTML = '';
    const tab = (view, label, path) => {
      const a = el(`<a class="tab" href="#/${view}" data-view="${view}">${strokeIcon(path)}<span></span></a>`);
      a.querySelector('span').textContent = label;
      return a;
    };
    const button = (cls, label, path, onClick) => {
      const b = el(`<button type="button" class="${cls}">${strokeIcon(path)}${label ? '<span></span>' : ''}</button>`);
      if (label) b.querySelector('span').textContent = label;
      b.addEventListener('click', onClick);
      return b;
    };
    tabbar.appendChild(tab('today', tr('nav_today'), '<rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="5" rx="2"/><rect x="13" y="10" width="8" height="11" rx="2"/><rect x="3" y="13" width="8" height="8" rx="2"/>'));
    tabbar.appendChild(tab('ideas', tr('nav_ideas'), APP_TILES.ideas.path));
    const capture = button('tab-capture', '', '<path d="M12 5v14M5 12h14"/>', () => { closeSectionsSheet(); if (quickCaptureEl.classList.contains('hidden')) openQuickCapture(); else closeQuickCapture(); });
    capture.setAttribute('aria-label', tr('title_quick_capture'));
    tabbar.appendChild(capture);
    tabbar.appendChild(tab('vault', tr('nav_vault'), APP_TILES.vault.path));
    const more = button('tab', tr('tab_sections'), '<circle cx="5" cy="12" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="19" cy="12" r="1.6"/>', () => {
      if (sectionsSheet.classList.contains('hidden')) openSectionsSheet(); else closeSectionsSheet();
    });
    more.setAttribute('aria-haspopup', 'dialog');
    tabbar.appendChild(more);

    // Foglio "Sezioni" del telefono: tutte le sezioni come tessere grandi.
    sectionsSheet.innerHTML = '';
    const grid = el('<div class="sheet-grid"></div>');
    visibleSections().forEach((s) => {
      const a = el(`<a class="sheet-tile" href="#/${s.view}" data-view="${s.view}">${appIcon(s.view, 52)}<span></span></a>`);
      a.querySelector('span').textContent = s.label;
      grid.appendChild(a);
    });
    const esciTile = el(`<button type="button" class="sheet-tile">${appIcon('esci', 52)}<span></span></button>`);
    esciTile.querySelector('span').textContent = tr('btn_logout');
    esciTile.addEventListener('click', logout);
    grid.appendChild(esciTile);
    sectionsSheet.appendChild(grid);
  }

  function openSectionsSheet() { sectionsSheet.classList.remove('hidden'); }
  function closeSectionsSheet() {
    const wasOpen = !sectionsSheet.classList.contains('hidden');
    sectionsSheet.classList.add('hidden');
    return wasOpen;
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
    const dragHandle = el(`<div class="qc-drag-handle" title="${esc(tr('qc_drag_title'))}">⋮⋮⋮</div>`);
    const composer = el(`
      <div class="composer">
        <textarea id="qc-text" placeholder="${esc(tr('qc_placeholder'))}" rows="2"></textarea>
        <div id="qc-link-badge"></div>
        <div class="composer-row">
          <div class="qc-types" role="group">
            <button type="button" class="qc-type on" data-token="/nota">${strokeIcon(APP_TILES.ideas.path)}<span>${esc(tr('type_idea'))}</span></button>
            <button type="button" class="qc-type" data-token="/scadenza">${strokeIcon(APP_TILES.reminders.path)}<span>${esc(tr('type_reminder'))}</span></button>
            ${isHidden('projects') ? '' : `<button type="button" class="qc-type" data-token="/progetto">${strokeIcon(APP_TILES.projects.path)}<span>${esc(tr('type_project'))}</span></button>`}
            ${isHidden('drive') ? '' : `<button type="button" class="qc-type" data-token="/doc">${strokeIcon(APP_TILES.drive.path)}<span>${esc(tr('type_document'))}</span></button>`}
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
      const badge = el(`<span class="composer-link-badge">→ ${esc(qcSelectedDossier.title)} <button type="button" title="${esc(tr('title_remove'))}">✕</button></span>`);
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
    // altri chiudono il riquadro e aprono la schermata di inserimento
    // completa di quel tipo — la stessa che permette anche di scegliere una
    // cartella, cosa che qui non e' mai stata replicata apposta.
    function applyTypeCommand(token) {
      if (token === '/nota') return;
      if ((token === '/progetto' && isHidden('projects')) || (token === '/doc' && isHidden('drive'))) return;
      if (token === '/scadenza') {
        const form = reminderModal();
        form.addEventListener('submit', async (e) => {
          e.preventDefault();
          await api('/reminders', { method: 'POST', body: JSON.stringify({ label: form.label.value, date: form.date.value, time: form.time.value, notes: form.notes.value }) });
          closeModal(); toast(tr('toast_reminder_saved')); closeQuickCapture(); render('reminders');
        });
        form.querySelector('[data-cancel]').addEventListener('click', closeModal);
        openModal(tr('modal_new_reminder'), form);
        return;
      }
      if (token === '/doc') {
        closeQuickCapture();
        render('drive').then(() => { const btn = document.getElementById('new-doc'); if (btn) btn.click(); });
        return;
      }
      if (token === '/progetto') {
        closeQuickCapture();
        render('projects').then(() => { const btn = document.getElementById('new-project'); if (btn) btn.click(); });
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

  btnNuovo.addEventListener('click', () => {
    if (quickCaptureEl.classList.contains('hidden')) openQuickCapture(); else closeQuickCapture();
  });
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
    currentView = view;
    closeSectionsSheet();
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
  const ICON_CHECK = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 12 5 5 9-10"/></svg>';
  const ICON_SNOOZE = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="13" r="8"/><path d="M12 9v4l2.5 2"/></svg>';
  const ICON_COPY = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="8" y="8" width="12" height="12" rx="2.5"/><path d="M16 8V5.5A1.5 1.5 0 0 0 14.5 4h-9A1.5 1.5 0 0 0 4 5.5v9A1.5 1.5 0 0 0 5.5 16H8"/></svg>';
  const ICON_ARROW = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>';

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
      const next = nextRenewalDate(a.renewal_day, a.renewal_month, a.billing_frequency) || (a.renewal_date ? a.renewal_date : null);
      if (!next) return;
      const days = calendarDaysFromToday(next);
      if (days === null) return;
      const amount = a.amount ? ` · ${fmtMoney(a.amount)}` : '';
      const iso = next instanceof Date ? `${next.getFullYear()}-${String(next.getMonth() + 1).padStart(2, '0')}-${String(next.getDate()).padStart(2, '0')}` : String(next);
      deadlines.push({ kind: 'account', item: a, days, date: iso, title: tr('today_renewal_of', { name: a.service }), sub: tr('type_account') + amount });
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

  views.reminders = async (root, opts = {}) => {
    const highlightId = opts.highlight ? String(opts.highlight) : null;
    const reminders = (await api('/reminders')).filter(onlyFilter(opts));
    root.innerHTML = '';
    root.appendChild(el(`
      <div class="view-header">
        <h2>${esc(tr('nav_reminders_title'))}</h2>
        <div class="view-header-actions">${backToDossierButtonHtml(opts)}<button class="btn btn-primary" id="new-reminder">${esc(tr('btn_new_reminder'))}</button></div>
      </div>
    `));
    wireBackToDossier(root, opts);

    root.querySelector('#new-reminder').addEventListener('click', () => {
      const form = reminderModal();
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        await api('/reminders', { method: 'POST', body: JSON.stringify({ label: form.label.value, date: form.date.value, time: form.time.value, notes: form.notes.value }) });
        closeModal(); toast(tr('toast_reminder_saved')); render('reminders');
      });
      form.querySelector('[data-cancel]').addEventListener('click', closeModal);
      openModal(tr('modal_new_reminder'), form);
    });

    if (!reminders.length) {
      root.appendChild(el(`<div class="empty-state">${esc(tr('empty_reminders'))}</div>`));
      return;
    }

    reminders
      .slice()
      .sort((a, b) => new Date(`${a.date}T${a.time || '00:00'}`) - new Date(`${b.date}T${b.time || '00:00'}`))
      .forEach((r) => {
        const days = daysUntil(r.date);
        const unit = tr(Math.abs(days) === 1 ? 'day_one' : 'day_other');
        const dayLabel = days === 0 ? tr('today_lc') : days > 0 ? tr('due_in_n', { n: days, unit }) : tr('overdue_by_passed', { n: -days, unit });
        const row = el(`
          <div class="trash-row row-card">
            <span>
              <strong>${esc(r.label)}</strong>
              <span class="card-sub" style="display:block">${fmtDate(r.date)}${r.time ? ' · ' + esc(r.time) : ''} · ${esc(dayLabel)}${r.notes ? ' · ' + escTrim(r.notes, 80) : ''}</span>
            </span>
            <span class="card-actions" style="padding:0">
              <button class="btn btn-sm" data-edit>${esc(tr('btn_edit'))}</button>
              <button class="btn btn-sm" data-link>${esc(tr('btn_link_folder'))}</button>
              <button class="btn btn-sm btn-danger" data-del>${esc(tr('btn_delete'))}</button>
            </span>
          </div>
        `);
        row.querySelector('[data-edit]').addEventListener('click', () => {
          const form = reminderModal(r);
          form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await api(`/reminders/${r.id}`, { method: 'PUT', body: JSON.stringify({ label: form.label.value, date: form.date.value, time: form.time.value, notes: form.notes.value }) });
            closeModal(); toast(tr('toast_reminder_updated')); render('reminders');
          });
          form.querySelector('[data-cancel]').addEventListener('click', closeModal);
          openModal(tr('modal_edit_reminder'), form);
        });
        row.querySelector('[data-link]').addEventListener('click', () => openLinkToDossierModal('reminder', r.id, r.label));
        row.querySelector('[data-del]').addEventListener('click', async () => {
          if (!(await askConfirm(tr('confirm_delete_reminder')))) return;
          await api(`/reminders/${r.id}`, { method: 'DELETE' });
          toast(tr('toast_reminder_deleted')); render('reminders');
        });
        if (highlightId && String(r.id) === highlightId) row.classList.add('card-highlight');
        root.appendChild(row);
      });
  };

  // Calendario: griglia mensile, riusa l'API e il modulo delle Scadenze —
  // stessi dati, vista diversa. Click su un giorno vuoto = nuova scadenza con
  // quella data precompilata; click su una voce = modifica.
  const MONTH_LABELS = ['month_0', 'month_1', 'month_2', 'month_3', 'month_4', 'month_5', 'month_6', 'month_7', 'month_8', 'month_9', 'month_10', 'month_11'].map(tr);
  const WEEKDAY_LABELS = ['weekday_short_1', 'weekday_short_2', 'weekday_short_3', 'weekday_short_4', 'weekday_short_5', 'weekday_short_6', 'weekday_short_7'].map(tr);
  const WEEKDAY_LABELS_FULL = ['weekday_1', 'weekday_2', 'weekday_3', 'weekday_4', 'weekday_5', 'weekday_6', 'weekday_7'].map(tr);

  views.calendar = async (root, opts = {}) => {
    const reminders = await api('/reminders');
    root.innerHTML = '';
    root.appendChild(el(`
      <div class="view-header">
        <h2>${esc(tr('nav_calendar_title'))}</h2>
        <div class="view-header-actions"><button class="btn btn-primary" id="new-reminder-cal">${esc(tr('btn_new_reminder'))}</button></div>
      </div>
    `));

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
        <button type="button" class="btn" id="cal-prev">◄</button>
        <span class="calendar-label" id="cal-label"></span>
        <button type="button" class="btn" id="cal-next">►</button>
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
        <div class="view-header-actions">${backToDossierButtonHtml(opts)}<button class="btn btn-primary" id="new-idea">${esc(tr('btn_new_idea'))}</button></div>
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

  views.projects = async (root, opts = {}) => {
    const highlightId = opts.highlight ? String(opts.highlight) : null;
    const projects = (await api('/projects')).filter(onlyFilter(opts));
    root.innerHTML = '';

    const toolbar = el(`
      <div class="explorer-toolbar">
        <button type="button" class="btn" id="explorer-up" disabled>${esc(tr('btn_up'))}</button>
        <span class="explorer-path" id="explorer-path">${esc(tr('nav_projects'))}</span>
        ${backToDossierButtonHtml(opts)}
        <button type="button" class="btn btn-primary" id="new-project">${esc(tr('btn_new_project'))}</button>
      </div>
    `);
    const bodyWrap = el('<div></div>');
    root.appendChild(toolbar);
    root.appendChild(bodyWrap);
    wireBackToDossier(toolbar, opts);

    const upBtn = toolbar.querySelector('#explorer-up');
    const pathEl = toolbar.querySelector('#explorer-path');
    const newProjectBtn = toolbar.querySelector('#new-project');

    newProjectBtn.addEventListener('click', () => {
      const form = projectModal();
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const tags = parseTags(form);
        const contacts = parseContacts(form);
        const budget = parseBudgetLines(form.budget.value);
        const checklist = collectChecklist(form, []);
        const created = await api('/projects', { method: 'POST', body: JSON.stringify({ title: form.title.value, description: form.description.value, status: form.status.value, deadline: form.deadline.value || null, checklist, contacts, budget, tags }) });
        projects.push(created);
        closeModal(); toast(tr('toast_project_saved')); renderRoot();
      });
      form.querySelector('[data-cancel]').addEventListener('click', closeModal);
      openModal(tr('modal_new_project'), form);
    });

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
              ${item.done ? `<span class="idea-checklist-badge" title="${esc(tr('label_completed_title'))}">✓</span>` : ''}
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

  // Lettura con la fotocamera (o da una foto): risolve con { text, format }
  // oppure null se si chiude la finestra.
  function scanCode() {
    return new Promise((resolve) => {
      let reader = null, done = false;
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
        try { if (reader) reader.reset(); } catch (_) { /* gia' fermo */ }
        const stream = video.srcObject;
        if (stream) stream.getTracks().forEach((t) => t.stop());
        closeModal();
        resolve(value);
      };
      const found = (result) => finish({ text: result.getText(), format: ZXING_FORMATS[window.ZXing.BarcodeFormat[result.getBarcodeFormat()]] || 'CODE128' });
      wrap.querySelector('[data-cancel]').addEventListener('click', () => finish(null));
      openModal(tr('scan_title'), wrap);
      const modalEl = wrap.closest('.modal-backdrop');
      if (modalEl) {
        modalEl.querySelector('.modal-close').addEventListener('click', () => finish(null));
        modalEl.addEventListener('click', (e) => { if (e.target === modalEl) finish(null); });
      }
      loadScript('/vendor/zxing.min.js').then(() => {
        reader = new window.ZXing.BrowserMultiFormatReader();
        wrap.querySelector('input[type=file]').addEventListener('change', async (e) => {
          const file = e.target.files[0];
          if (!file) return;
          try { found(await reader.decodeFromImageUrl(URL.createObjectURL(file))); } catch (_) { msg.textContent = tr('scan_not_found'); }
        });
        reader.decodeFromConstraints({ video: { facingMode: 'environment' } }, video, (result) => { if (result) found(result); })
          .catch(() => { msg.textContent = tr('scan_no_camera'); });
      }).catch((err) => { msg.textContent = err.message; });
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
  async function showQr(title, text, caption, actions) {
    await loadScript('/vendor/qrcode.js');
    const code = window.qrcode(0, 'L');
    code.addData(text, 'Byte');
    code.make();
    const wrap = el(`<div class="qr-show"><div class="qr-big">${code.createSvgTag({ cellSize: 4, margin: 3, scalable: true })}</div><p class="qr-caption"></p><div class="form-actions"></div></div>`);
    wrap.querySelector('.qr-caption').textContent = caption || '';
    (actions || []).forEach((b) => wrap.querySelector('.form-actions').appendChild(b));
    openModal(title, wrap);
    return wrap;
  }

  views.vault = async (root, opts = {}) => {
    const highlightId = opts.highlight ? String(opts.highlight) : null;
    const engine = window.MementoBackend && window.MementoBackend.engine;

    // Il nome del telefono si chiede una volta: e' quello che vede l'altro.
    function askPhoneName() {
      if (engine.identityName()) return Promise.resolve(true);
      return new Promise((resolve) => {
        const form = el(`<form class="modal-body" style="padding:0"><div class="form-row"><label>${esc(tr('qr_name_label'))}</label><input type="text" name="name" required maxlength="60" placeholder="${esc(tr('qr_name_placeholder'))}" /></div>
          <div class="form-actions"><button type="button" class="btn btn-ghost" data-cancel>${esc(tr('btn_cancel'))}</button><button type="submit" class="btn btn-primary">${esc(tr('btn_confirm'))}</button></div></form>`);
        form.addEventListener('submit', async (e) => { e.preventDefault(); await engine.setIdentityName(form.name.value); closeModal(); resolve(true); });
        form.querySelector('[data-cancel]').addEventListener('click', () => { closeModal(); resolve(false); });
        openModal(tr('qr_name_title'), form);
      });
    }

    // Ricevere: mostro il mio codice, poi inquadro la voce preparata per me.
    async function receiveWithQr() {
      if (!(await askPhoneName())) return;
      const scanBtn = el(`<button type="button" class="btn btn-primary">${esc(tr('qr_scan_item'))}</button>`);
      scanBtn.addEventListener('click', async () => {
        closeModal();
        const res = await scanCode();
        if (!res) return;
        try {
          const got = await engine.receiveTransferQr(res.text);
          toast(tr('qr_received', { what: got.site, from: got.from }));
          render('vault', { highlight: got.id, fromHash: true });
        } catch (err) { toast(err.message); }
      });
      await showQr(tr('qr_receive_title'), await engine.identityQr(), tr('qr_receive_hint'), [scanBtn]);
    }
    // Passare: inquadro il codice di chi riceve, poi mostro la voce cifrata per lui.
    async function passWithQr(entry) {
      closeModal();
      if (!(await askPhoneName())) return;
      toast(tr('qr_scan_recipient'));
      const res = await scanCode();
      if (!res) return;
      try {
        const who = await engine.readIdentityQr(res.text);
        const text = await engine.transferQr(entry.id, who);
        const done = el(`<button type="button" class="btn btn-primary">${esc(tr('qr_done'))}</button>`);
        done.addEventListener('click', closeModal);
        await showQr(entry.site, text, tr('qr_pass_hint', { who: who.label }), [done]);
      } catch (err) { toast(err.message); }
    }
    const entries = (await api('/vault')).filter(onlyFilter(opts));
    root.innerHTML = '';
    root.appendChild(el(`
      <div class="view-header">
        <h2>${esc(tr('nav_vault_title'))}</h2>
        <div class="view-header-actions">${backToDossierButtonHtml(opts)}
          <label class="btn btn-ghost" style="cursor:pointer">${esc(tr('btn_import_csv'))}<input type="file" id="csv-input" accept=".csv" class="hidden" /></label>
          ${engine ? `<button class="btn" id="receive-qr">${esc(tr('qr_receive'))}</button>` : ''}
          <button class="btn btn-primary" id="new-vault">${esc(tr('btn_new_vault_entry'))}</button>
        </div>
      </div>
    `));
    wireBackToDossier(root, opts);
    if (engine) root.querySelector('#receive-qr').addEventListener('click', () => receiveWithQr());
    if (engine && opts.receive) setTimeout(() => receiveWithQr(), 300);

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
      { type: 'password', label: tr('vault_kind_account'), sub: tr('vault_kind_account_sub'), icon: '<circle cx="12" cy="8" r="4"/><path d="M4.5 20.5a7.5 7.5 0 0 1 15 0"/>' },
      { type: 'note', label: tr('vault_kind_note'), sub: tr('vault_kind_note_sub'), icon: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h4"/>' },
      { type: 'code', label: tr('vault_kind_code'), sub: tr('vault_kind_code_sub'), icon: '<rect x="3" y="6" width="18" height="12" rx="3"/><path d="M7 12h.01M10.5 12h.01M14 12h.01M17.5 12h.01"/>' },
      { type: 'card', label: tr('vault_kind_card'), sub: tr('vault_kind_card_sub'), icon: '<rect x="2.5" y="5.5" width="19" height="13" rx="3"/><path d="M2.5 10h19M6 14.5h4"/>' },
    ];
    root.querySelector('#new-vault').addEventListener('click', () => {
      const wrap = el('<div class="kind-list"></div>');
      VAULT_KINDS.forEach((k) => {
        const b = el(`<button type="button" class="kind-btn"><span class="kind-ic">${strokeIcon(k.icon)}</span><span class="kind-text"><b></b><small></small></span></button>`);
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
      { key: 'all', label: tr('vault_tab_all'), test: () => true },
      { key: 'password', label: tr('vault_kind_account'), test: (x) => x.type === 'password' },
      { key: 'note', label: tr('vault_kind_note'), test: (x) => x.type === 'note' },
      { key: 'codes', label: tr('vault_kind_code'), test: (x) => x.type === 'code' || x.hasTotp },
      { key: 'card', label: tr('vault_kind_card'), test: (x) => x.type === 'card' },
    ].filter((t) => t.key === 'all' || entries.some(t.test));
    let tab = sessionStorage.getItem('memento-vault-tab') || 'all';
    // Ordinamento (preferenza del dispositivo): predefinito alfabetico.
    const SORTS = {
      az: (a, b) => a.site.localeCompare(b.site, undefined, { sensitivity: 'base' }),
      za: (a, b) => b.site.localeCompare(a.site, undefined, { sensitivity: 'base' }),
      recent: (a, b) => String(b.updated_at || '').localeCompare(String(a.updated_at || '')),
      type: (a, b) => String(a.type).localeCompare(String(b.type)) || a.site.localeCompare(b.site, undefined, { sensitivity: 'base' }),
    };
    let sort = localStorage.getItem('memento-vault-sort') || 'az';
    if (!SORTS[sort]) sort = 'az';
    if (!TABS.some((t) => t.key === tab)) tab = 'all';

    const seg = el('<div class="seg" role="tablist"></div>');
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

    const LOGO_TINTS = [['#E3E9FF', '#2448E0'], ['#FFE3DE', '#B4231A'], ['#EEFBC6', '#4B5E00'], ['#F3E8FF', '#7048E8'], ['#FFF0D6', '#A85A00'], ['#FCE4EE', '#B0285A']];
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
      if (engine && !received) {
        const pass = el(`<button type="button" class="btn btn-ghost" data-pass-qr></button>`);
        pass.textContent = tr('qr_pass');
        pass.addEventListener('click', () => passWithQr(entry));
        actions.querySelector('.form-actions-side').appendChild(pass);
      }
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
        const b = el(`<button type="button" role="tab" class="${t.key === tab ? 'on' : ''}" aria-selected="${t.key === tab}"></button>`);
        b.textContent = t.label;
        b.addEventListener('click', () => { tab = t.key; sessionStorage.setItem('memento-vault-tab', tab); paint(); });
        seg.appendChild(b);
      });
      list.innerHTML = '';
      const test = TABS.find((t) => t.key === tab).test;
      entries.filter(test).sort(SORTS[sort]).forEach((entry) => {
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
          <div class="brand-input"><img class="brand-chosen hidden" alt="" /><input type="text" name="name" required autocomplete="off" /><button type="button" class="icon-btn brand-clear hidden" aria-label="${esc(tr('card_brand_remove'))}">✕</button></div>
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
    root.appendChild(el(`<div class="view-header"><h2>${esc(tr('nav_cards'))}</h2><div class="view-header-actions"><button class="btn btn-primary" id="new-card">${esc(tr('btn_new_card'))}</button></div></div>`));

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
    const ICON_NOTES = '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h4"/>';
    const ICON_CAMERA = '<path d="M4 8.5A2.5 2.5 0 0 1 6.5 6h1.8l1.4-2h4.6l1.4 2h1.8A2.5 2.5 0 0 1 20 8.5v8A2.5 2.5 0 0 1 17.5 19h-11A2.5 2.5 0 0 1 4 16.5z"/><circle cx="12" cy="12.5" r="3.3"/>';
    const ICON_SHARE = '<circle cx="18" cy="5.5" r="2.5"/><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="18.5" r="2.5"/><path d="m8.2 10.8 7.6-4.1M8.2 13.2l7.6 4.1"/>';
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
            <a class="btn btn-ghost btn-sm" href="#/cards">← ${esc(tr('nav_cards'))}</a>
            <button type="button" class="btn btn-ghost btn-sm" data-edit>${esc(tr('btn_edit'))}</button>
          </div>
          <div class="card-visual">
            <div class="cv-top"></div>
            <div class="cv-bottom"><div class="card-code"></div><p class="cv-number"></p></div>
          </div>
          <div class="cv-actions">
            <button type="button" data-notes>${strokeIcon(ICON_NOTES)}<span>${esc(tr('card_notes'))}</span></button>
            <button type="button" data-photos>${strokeIcon(ICON_CAMERA)}<span>${esc(tr('card_photos'))}</span></button>
            <button type="button" data-share>${strokeIcon(ICON_SHARE)}<span>${esc(tr('card_share'))}</span></button>
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
      const num = page.querySelector('.cv-number');
      num.textContent = groupNumber(card.number) || '—';
      num.addEventListener('click', async () => { try { await navigator.clipboard.writeText(card.number); toast(tr('toast_copied')); } catch (_) { /* niente appunti */ } });
      const drawn = await renderCardCode(page.querySelector('.card-code'), card).catch(() => false);
      if (!drawn) page.querySelector('.card-code').classList.add('hidden');
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
      page.querySelector('[data-share]').addEventListener('click', () => shareCard(card));
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
              const add = el(`<button type="button" class="photo-add">${strokeIcon(ICON_CAMERA)}<span>${esc(tr('card_photo_add'))}</span></button>`);
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
    const groups = [['fedelta', tr('card_kind_loyalty_pl')], ['regalo', tr('card_kind_gift_pl')]];
    groups.forEach(([kind, title]) => {
      const used = usedMap();
      const list = cards.filter((c) => c.kind === kind).sort((a, b) => (used[b.id] || 0) - (used[a.id] || 0) || a.name.localeCompare(b.name));
      if (!list.length) return;
      root.appendChild(el(`<h3 class="group-title">${esc(title)}</h3>`));
      const grid = el('<div class="wallet-grid"></div>');
      list.forEach((c) => {
        // Come una tessera vera: logo con i margini in alto, nome e ultime
        // cifre in basso; testo chiaro o scuro secondo il colore di fondo.
        const tile = el(c.brand
          ? `<button type="button" class="wallet-card has-logo"><span class="wc-logo-box"><img class="wc-logo" alt="" loading="lazy" /></span><span class="wc-foot"><span class="wc-label"></span><span class="wc-digits"></span></span><span class="wc-meta"></span></button>`
          : `<button type="button" class="wallet-card"><span class="wc-initial"></span><span class="wc-name"></span><span class="wc-meta"></span></button>`);
        tile.style.setProperty('--card', cardColor(c));
        if (isLightColor(cardColor(c))) tile.classList.add('on-light');
        if (c.brand) {
          tile.querySelector('.wc-label').textContent = c.name;
          const digits = String(c.number || '').replace(/\s/g, '');
          tile.querySelector('.wc-digits').textContent = digits.length > 4 ? `•••• ${digits.slice(-4)}` : digits;
        }
        tile.setAttribute('aria-label', c.name);
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

  function accountModal(existing) {
    const form = el(`
      <form class="modal-body" style="padding:0">
        <div class="form-row"><label>${esc(tr('field_service'))}</label><input type="text" name="service" required /></div>
        <div class="form-row"><label>${esc(tr('field_type'))}</label>
          <select name="type">
            <option value="digitale">${esc(tr('account_type_digital'))}</option>
            <option value="cartaceo">${esc(tr('account_type_paper'))}</option>
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
        <div class="form-row"><label>${esc(tr('field_billing_frequency'))}</label>
          <select name="billing_frequency">
            ${Object.entries(BILLING_LABELS).map(([v, label]) => `<option value="${v}">${esc(label)}</option>`).join('')}
          </select>
        </div>
        <div class="form-row"><label>${esc(tr('field_amount'))}</label><input type="number" name="amount" step="0.01" min="0" placeholder="${esc(tr('field_amount_placeholder'))}" /></div>
        <div class="form-row"><label>${esc(tr('field_start_date_optional'))}</label><input type="date" name="start_date" /></div>
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
    function syncTypeFields() {
      form.querySelectorAll('[data-type-fields]').forEach((group) => {
        group.classList.toggle('hidden', group.dataset.typeFields !== form.type.value);
      });
    }
    function syncBillingFields() {
      form.querySelectorAll('[data-billing-fields]').forEach((group) => {
        group.classList.toggle('hidden', !group.dataset.billingFields.split(' ').includes(form.billing_frequency.value));
      });
    }
    form.type.addEventListener('change', syncTypeFields);
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
        <div class="view-header-actions">${backToDossierButtonHtml(opts)}<button class="btn btn-primary" id="new-account">${esc(tr('btn_new_account'))}</button></div>
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
        ...renewalPayload(form),
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

    // Prossimo rinnovo in assoluto tra tutti gli abbonamenti, per la vista
    // riassuntiva in cima. L'ordine della griglia sotto segue lo stesso
    // criterio: chi rinnova prima compare prima. Non ha senso quando si sta
    // gia' guardando un solo abbonamento arrivando da una cartella.
    if (!opts.only) {
      const withRenewal = accounts
        .map((a) => ({ a, next: nextRenewalDate(a.renewal_day, a.renewal_month, a.billing_frequency) }))
        .filter((x) => x.next);
      withRenewal.sort((x, y) => x.next - y.next);
      if (withRenewal.length) {
        const soonest = withRenewal[0];
        const days = daysUntil(soonest.next.toISOString().slice(0, 10));
        const dayLabel = days === 0 ? tr('today_lc') : days === 1 ? tr('due_tomorrow') : tr('due_in_n', { n: days, unit: tr('day_other') });
        root.appendChild(el(`
          <div class="section-block" style="margin-bottom:14px">
            <p class="card-sub" style="margin-bottom:4px">${esc(tr('next_renewal_title'))}</p>
            <p class="card-title" style="font-size:1rem">${tr('next_renewal_line', { service: esc(soonest.a.service), day: soonest.next.getDate(), month: esc(MONTH_LABELS[soonest.next.getMonth()]), when: esc(dayLabel) })}</p>
          </div>
        `));
      }
      const renewalOrder = new Map(withRenewal.map((x, i) => [x.a.id, i]));
      accounts.sort((a, b) => {
        const ra = renewalOrder.has(a.id) ? renewalOrder.get(a.id) : Infinity;
        const rb = renewalOrder.has(b.id) ? renewalOrder.get(b.id) : Infinity;
        return ra - rb;
      });
    }

    const grid = el('<div class="grid"></div>');
    accounts.forEach((a) => {
      const isCartaceo = a.type === 'cartaceo';
      const next = nextRenewalDate(a.renewal_day, a.renewal_month, a.billing_frequency);
      // "renewal_day"/"renewal_month" hanno un significato diverso a seconda
      // della frequenza (vedi nextRenewalDate): per mostrarli si usa sempre
      // la prossima data vera e propria gia' calcolata, mai i campi grezzi.
      const renewalLabel = next
        ? tr('field_renewal_label', { day: next.getDate(), month: esc(MONTH_LABELS[next.getMonth()]), when: tr('due_in_n', { n: daysUntil(next.toISOString().slice(0, 10)), unit: tr('day_other') }) })
        : '';
      const card = el(`
        <div class="card">
          <span class="tag tag-neutral" style="width:fit-content">${isCartaceo ? esc(tr('account_type_paper')) : esc(tr('account_type_digital'))}</span>
          <p class="card-title">${esc(a.service)}</p>
          ${isCartaceo
            ? `<p class="card-sub">${esc(a.location) || '—'}${a.payment_method ? ' · ' + esc(a.payment_method) : ''}</p>`
            : `<p class="card-sub">${esc(a.email) || '—'} ${a.plan ? '· ' + esc(a.plan) : ''}</p>`}
          ${a.billing_frequency || a.amount != null
            ? `<p class="card-sub">${a.billing_frequency ? esc(BILLING_LABELS[a.billing_frequency] || a.billing_frequency) : ''}${a.billing_frequency && a.amount != null ? ' · ' : ''}${a.amount != null ? fmtMoney(a.amount) : ''}</p>`
            : ''}
          ${a.start_date ? `<p class="card-sub">${tr('field_start_date_label', { date: fmtDate(a.start_date) })}</p>` : ''}
          ${renewalLabel ? `<p class="card-sub">${renewalLabel}</p>` : ''}
          ${a.vaultEntry ? `<p class="card-sub">${tr('credentials_prefix', { label: esc(a.vaultEntry.site) + (a.vaultEntry.username ? ' · ' + esc(a.vaultEntry.username) : '') })}</p>` : ''}
          <div class="tag-row">${(a.tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join('')}</div>
          <div class="card-actions">
            <button class="btn btn-sm" data-edit>${esc(tr('btn_edit'))}</button>
            <button class="btn btn-sm" data-link>${esc(tr('btn_link_folder'))}</button>
            <button class="btn btn-sm" data-vault>${a.vaultEntry ? esc(tr('btn_change_credentials')) : esc(tr('btn_link_credentials'))}</button>
            <button class="btn btn-sm btn-danger" data-del>${esc(tr('btn_delete'))}</button>
          </div>
        </div>
      `);
      card.querySelector('[data-edit]').addEventListener('click', () => {
        const form = accountModal(a);
        form.addEventListener('submit', async (e) => {
          e.preventDefault();
          await api(`/accounts/${a.id}`, { method: 'PUT', body: JSON.stringify(accountPayload(form)) });
          closeModal(); toast(tr('toast_account_updated')); render('accounts');
        });
        form.querySelector('[data-cancel]').addEventListener('click', closeModal);
        openModal(tr('modal_edit_account'), form);
      });
      card.querySelector('[data-link]').addEventListener('click', () => openLinkToDossierModal('account', a.id, a.service));
      card.querySelector('[data-vault]').addEventListener('click', () => openLinkVaultModal(a));
      card.querySelector('[data-del]').addEventListener('click', async () => {
        if (!(await askConfirm(tr('confirm_delete_account')))) return;
        await api(`/accounts/${a.id}`, { method: 'DELETE' });
        toast(tr('toast_account_deleted')); render('accounts');
      });
      if (highlightId && String(a.id) === highlightId) card.classList.add('card-highlight');
      grid.appendChild(card);
    });
    root.appendChild(grid);
    if (highlightId) {
      const target = grid.querySelector('.card-highlight');
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
        <div class="view-header-actions">${backToDossierButtonHtml(opts)}<button class="btn btn-primary" id="new-doc">${esc(tr('btn_upload_document'))}</button></div>
      </div>
    `));
    wireBackToDossier(root, opts);

    root.querySelector('#new-doc').addEventListener('click', () => {
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
        closeModal(); toast(tr('toast_document_uploaded')); render('drive');
      });
      form.querySelector('[data-cancel]').addEventListener('click', closeModal);
      openModal(tr('modal_upload_document'), form);
    });

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
              ${iconaLinea(fileCategoryIcon(d.mime))}
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
      const head = el(`<div class="view-header"><div class="view-header-actions"><button type="button" class="btn btn-primary" id="new-dossier">${esc(tr('btn_new_dossier'))}</button></div></div>`);
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
      head.querySelector('.dossier-back').textContent = '← ' + tr('nav_dossiers');
      const desc = head.querySelector('.dossier-desc');
      if (d.description) desc.textContent = d.description; else desc.remove();
      head.querySelector('[data-add]').textContent = tr('dossier_add_to', { title: d.title });
      head.querySelector('[data-edit]').textContent = tr('btn_edit');
      head.querySelector('[data-del]').textContent = tr('btn_delete');
      head.querySelector('[data-add]').addEventListener('click', () => openQuickCapture(d));
      head.querySelector('[data-edit]').addEventListener('click', () => openDossierForm(d));
      head.querySelector('[data-del]').addEventListener('click', async () => {
        if (!(await askConfirm(tr('confirm_delete_dossier')))) return;
        await api(`/dossiers/${d.id}`, { method: 'DELETE' });
        toast(tr('toast_dossier_deleted')); render('dossiers');
      });
      root.appendChild(head);
      viewTitle.textContent = d.title;

      // Scadenze della cartella, dalla piu' vicina.
      const due = [];
      mine.reminder.forEach((r) => due.push({ days: calendarDaysFromToday(r.date), title: r.label, open: () => render('reminders', { only: r.id, fromDossier: d.id }) }));
      mine.project.filter((p) => p.deadline && p.status !== 'fatto').forEach((p) => due.push({ days: calendarDaysFromToday(p.deadline), title: p.title, open: () => render('projects', { only: p.id, fromDossier: d.id }) }));
      mine.account.forEach((a) => {
        const next = nextRenewalDate(a.renewal_day, a.renewal_month, a.billing_frequency) || a.renewal_date;
        if (next) due.push({ days: calendarDaysFromToday(next), title: tr('today_renewal_of', { name: a.service }), open: () => render('accounts', { only: a.id, fromDossier: d.id }) });
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
      bioBlock.appendChild(el(`<p class="card-sub">${esc(tr('biometric_hint'))}</p>`));
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
    root.appendChild(help);
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
  window.MementoUI = { el, esc, tr, toast, openModal, closeModal, render, sectionsBlock, totpBlock, loadScript, askConfirm, askValue, haptic, themeBlock, openQuickCapture, isReady: () => !appRoot.classList.contains('hidden') };

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
