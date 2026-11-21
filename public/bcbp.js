'use strict';
// Carte d'imbarco: lettura del codice IATA BCBP (Resolution 792), lo stesso
// testo che c'e' nell'Aztec / PDF417 / QR del biglietto.
// Parte fissa: "M" + numero di tratte + nome (20) + indicatore e-ticket (1);
// poi per ogni tratta: PNR (7), da (3), a (3), compagnia (3), volo (5),
// giorno giuliano (3), classe (1), posto (4), sequenza (5), stato (1) e la
// lunghezza (2 cifre esadecimali) della parte variabile che segue.
// Usato da app.js (window.MementoBCBP) e dai test (require).
(function (root) {
  const pad = (n) => String(n).padStart(2, '0');
  const iso = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;

  // Giorno dell'anno senza anno: si sceglie l'anno che porta piu' vicino a
  // oggi (un biglietto si legge pochi giorni prima o dopo il volo).
  function julianToDate(day, today = new Date()) {
    if (!(day >= 1 && day <= 366)) return null;
    const base = new Date(today.getFullYear(), today.getMonth(), today.getDate());
    let best = null;
    for (const y of [base.getFullYear() - 1, base.getFullYear(), base.getFullYear() + 1]) {
      const d = new Date(y, 0, day);
      if (d.getFullYear() !== y) continue; // 366 in un anno non bisestile
      if (!best || Math.abs(d - base) < Math.abs(best - base)) best = d;
    }
    return best ? iso(best) : null;
  }

  // "ROSSI/MARIO MR" -> "Mario Rossi"
  function niceName(raw) {
    const [last, first = ''] = raw.trim().split('/');
    const given = first.replace(/\s+(MR|MRS|MS|MISS|MSTR|DR|CHD|INF)$/i, '').trim();
    const cap = (s) => s.toLowerCase().replace(/(^|[\s'-])\S/g, (c) => c.toUpperCase());
    return [cap(given), cap(last.trim())].filter(Boolean).join(' ');
  }

  function parse(text, today) {
    const s = String(text || '');
    if (!/^M[1-9]/.test(s) || s.length < 60) return null;
    const legsCount = Number(s[1]);
    const legs = [];
    let pos = 23;
    for (let i = 0; i < legsCount; i++) {
      if (s.length < pos + 37) break;
      const f = (start, len) => s.substr(pos + start, len).trim();
      const julian = Number(f(21, 3));
      const flight = f(16, 5).replace(/^0+(?=\d)/, '');
      const seat = f(25, 4).replace(/^0+(?=\d)/, '');
      const leg = {
        pnr: f(0, 7),
        from: f(7, 3),
        to: f(10, 3),
        carrier: f(13, 3),
        flight,
        date: julianToDate(julian, today),
        cabin: f(24, 1),
        seat,
        sequence: f(29, 5).replace(/^0+(?=\d)/, ''),
      };
      if (!/^[A-Z]{3}$/.test(leg.from) || !/^[A-Z]{3}$/.test(leg.to)) return null;
      legs.push(leg);
      const varSize = parseInt(s.substr(pos + 35, 2), 16);
      pos += 37 + (Number.isFinite(varSize) ? varSize : 0);
    }
    if (!legs.length) return null;
    const passenger = niceName(s.substr(2, 20));
    const route = [legs[0].from, ...legs.map((l) => l.to)].join(' → ');
    const flights = [...new Set(legs.map((l) => `${l.carrier} ${l.flight}`))].join(', ');
    const dates = legs.map((l) => l.date).filter(Boolean).sort();
    return {
      passenger,
      legs,
      route,
      flights,
      // nome della carta in Memento: "CTA → FCO · AZ 1754"
      title: `${route} · ${flights}`,
      firstDate: dates[0] || null,
      lastDate: dates[dates.length - 1] || null,
    };
  }

  const api = { parse, julianToDate, niceName };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.MementoBCBP = api;
})(typeof window !== 'undefined' ? window : this);
