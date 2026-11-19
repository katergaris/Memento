const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const archiver = require('archiver');
const db = require('../db');
const router = express.Router();

const DATA_DIR = path.join(__dirname, '..', '..', 'data');
const UPLOAD_DIR = path.join(__dirname, '..', '..', 'uploads');

router.get('/', async (req, res, next) => {
  // Il database gira in modalita' WAL: copiare direttamente memento.db
  // avrebbe incluso uno snapshot incompleto (le scritture recenti vivono nel
  // file -wal finche' non viene fatto il checkpoint). db.backup() produce
  // invece una copia coerente anche con il server in funzione.
  const snapshot = path.join(DATA_DIR, `backup-${crypto.randomBytes(8).toString('hex')}.db`);
  try {
    await db.backup(snapshot);
  } catch (err) {
    return next(err);
  }

  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    fs.promises.unlink(snapshot).catch(() => {});
  };

  const stamp = new Date().toISOString().slice(0, 10);
  res.attachment(`memento-backup-${stamp}.zip`);

  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.on('error', (err) => {
    console.error('Errore backup:', err);
    cleanup();
    // Se l'header e' gia' partito l'unica cosa sensata e' chiudere la risposta:
    // res.status() qui solleverebbe un secondo errore.
    if (res.headersSent) res.destroy();
    else res.status(500).json({ error: 'Errore durante la creazione del backup' });
  });
  res.on('close', cleanup);
  archive.on('end', cleanup);

  archive.pipe(res);
  archive.file(snapshot, { name: 'memento.db' });
  if (fs.existsSync(UPLOAD_DIR)) archive.directory(UPLOAD_DIR, 'uploads');
  archive.finalize();
});

// Esportazione per l'app Android: file .memento cifrato con la password
// scelta (formato in server/memento-export.js), importabile da Sicurezza ->
// Dati -> Importa file nella modalita' "Sul telefono".
router.post('/app', (req, res) => {
  const { password, includeFiles = true } = req.body || {};
  if (!password || String(password).length < 8) {
    return res.status(400).json({ error: 'La password del file deve avere almeno 8 caratteri' });
  }
  const { buildPayload, seal } = require('../memento-export');
  const envelope = seal(password, buildPayload(db, UPLOAD_DIR, { includeFiles: includeFiles !== false }));
  const stamp = new Date().toISOString().slice(0, 10);
  res.attachment(`memento-${stamp}.memento`);
  res.type('application/json').send(JSON.stringify(envelope));
});

module.exports = router;
