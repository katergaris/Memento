'use strict';
// Modifica il progetto Android generato da "npx cap add android" (in CI):
// permessi, indirizzi memento://, scorciatoie, widget, icona a tema, file
// sostitutivi in android-overrides/. Idempotente.
const fs = require('fs');
const path = require('path');

const APP = path.join(__dirname, '..');
const AND = path.join(APP, 'android', 'app', 'src', 'main');
const OVR = path.join(APP, 'android-overrides');
const PKG_DIR = path.join(AND, 'java', 'io', 'github', 'katergaris', 'memento');

// 1. Java (MainActivity con l'aggancio per Google, widget)
for (const f of fs.readdirSync(path.join(OVR, 'java'))) fs.copyFileSync(path.join(OVR, 'java', f), path.join(PKG_DIR, f));
// 2. Risorse
const copyDir = (from, to) => {
  fs.mkdirSync(to, { recursive: true });
  for (const f of fs.readdirSync(from)) {
    const src = path.join(from, f);
    if (fs.statSync(src).isDirectory()) copyDir(src, path.join(to, f)); else fs.copyFileSync(src, path.join(to, f));
  }
};
copyDir(path.join(OVR, 'res'), path.join(AND, 'res'));

// 3. Manifest
const manifestPath = path.join(AND, 'AndroidManifest.xml');
let m = fs.readFileSync(manifestPath, 'utf8');
const perms = ['CAMERA', 'USE_BIOMETRIC', 'POST_NOTIFICATIONS', 'RECEIVE_BOOT_COMPLETED'];
for (const p of perms) {
  const tag = `<uses-permission android:name="android.permission.${p}" />`;
  if (!m.includes(tag)) m = m.replace('<application', `${tag}\n    <application`);
}
if (!m.includes('usesCleartextTraffic')) m = m.replace('<application', '<application android:usesCleartextTraffic="true"');
// indirizzi memento:// e scorciatoie sull'attivita' principale
if (!m.includes('android:scheme="memento"')) {
  m = m.replace(/(<activity[^>]*\.MainActivity[\s\S]*?<\/intent-filter>)/, `$1
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="memento" />
            </intent-filter>
            <meta-data android:name="android.app.shortcuts" android:resource="@xml/shortcuts" />`);
}
// widget
if (!m.includes('MementoWidget')) {
  m = m.replace('</application>', `    <receiver android:name=".MementoWidget" android:exported="true" android:label="@string/widget_name">
            <intent-filter><action android:name="android.appwidget.action.APPWIDGET_UPDATE" /></intent-filter>
            <meta-data android:name="android.appwidget.provider" android:resource="@xml/memento_widget_info" />
        </receiver>
    </application>`);
}
fs.writeFileSync(manifestPath, m);

// 4. Icona a tema (Android 13+): strato monocromatico = il simbolo
for (const f of ['ic_launcher.xml', 'ic_launcher_round.xml']) {
  const p = path.join(AND, 'res', 'mipmap-anydpi-v26', f);
  if (!fs.existsSync(p)) continue;
  let x = fs.readFileSync(p, 'utf8');
  // capacitor-assets aggiunge un margine del 16,7% al simbolo: il nostro e'
  // gia' dimensionato per la zona sicura, quindi niente margine in piu'.
  x = x.replace(/<foreground>[\s\S]*?<\/foreground>/, '<foreground android:drawable="@mipmap/ic_launcher_foreground" />');
  x = x.replace(/<background>[\s\S]*?<\/background>/, '<background android:drawable="@mipmap/ic_launcher_background" />');
  if (!x.includes('<monochrome')) x = x.replace('</adaptive-icon>', '    <monochrome android:drawable="@mipmap/ic_launcher_foreground" />\n</adaptive-icon>');
  fs.writeFileSync(p, x);
}
console.log('progetto Android aggiornato');
