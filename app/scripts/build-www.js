'use strict';
// Prepara app/www per Capacitor: la stessa interfaccia di public/ piu' il
// guscio dell'app (scelta della modalita' e motore locale), con i caratteri
// inclusi nell'app invece che scaricati da Google Fonts (serve offline).
const fs = require('fs');
const path = require('path');

const APP = path.join(__dirname, '..');
const PUBLIC = path.join(APP, '..', 'public');
const WWW = path.join(APP, 'www');

fs.rmSync(WWW, { recursive: true, force: true });
fs.cpSync(PUBLIC, WWW, { recursive: true, filter: (src) => !/[\\/](cli\.(html|js)|sw\.js|offline\.html)$/.test(src) });
fs.mkdirSync(path.join(WWW, 'app-src'), { recursive: true });
for (const f of ['crypto.js', 'totp.js', 'local-backend.js', 'shell.js']) {
  fs.copyFileSync(path.join(APP, 'src', f), path.join(WWW, 'app-src', f));
}

// Caratteri: file woff2 latin dai pacchetti @fontsource.
const fontsDir = path.join(WWW, 'fonts');
fs.mkdirSync(fontsDir, { recursive: true });
const fontCss = [];
const addFont = (pkg, file, family, weight) => {
  const src = path.join(APP, 'node_modules', pkg, 'files', file);
  if (!fs.existsSync(src)) { console.warn('carattere mancante:', src); return; }
  fs.copyFileSync(src, path.join(fontsDir, file));
  fontCss.push(`@font-face{font-family:'${family}';font-style:normal;font-display:swap;font-weight:${weight};src:url(/fonts/${file}) format('woff2');}`);
};
addFont('@fontsource-variable/bricolage-grotesque', 'bricolage-grotesque-latin-wght-normal.woff2', 'Bricolage Grotesque', '200 800');
addFont('@fontsource/jetbrains-mono', 'jetbrains-mono-latin-400-normal.woff2', 'JetBrains Mono', 400);
addFont('@fontsource/jetbrains-mono', 'jetbrains-mono-latin-700-normal.woff2', 'JetBrains Mono', 700);
fs.writeFileSync(path.join(fontsDir, 'fonts.css'), fontCss.join('\n') + '\n');

let html = fs.readFileSync(path.join(WWW, 'index.html'), 'utf8');
html = html
  .replace(/<link rel="preconnect" href="https:\/\/fonts\.googleapis\.com">\s*/, '')
  .replace(/<link href="https:\/\/fonts\.googleapis\.com[^>]*>/, '<link rel="stylesheet" href="/fonts/fonts.css" />')
  .replace(/<link rel="manifest"[^>]*>\s*/, '')
  .replace('<script src="/app.js"></script>', [
    '<script src="/app-src/crypto.js"></script>',
    '<script src="/app-src/totp.js"></script>',
    '<script src="/app-src/local-backend.js"></script>',
    '<script src="/app-src/shell.js"></script>',
  ].join('\n'));
if (!html.includes('/app-src/shell.js')) throw new Error('index.html: non trovo lo script di app.js da sostituire');
fs.writeFileSync(path.join(WWW, 'index.html'), html);
console.log('www pronta:', WWW);
