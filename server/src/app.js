'use strict';

const fs = require('fs');
const path = require('path');
const express = require('express');

const configRoutes = require('./routes/config');
const scanRoutes = require('./routes/scans');

// In the container image `public/` is copied as a sibling of `src/`
// (/app/public, /app/src). In a local checkout it lives at the repo root
// instead (../public relative to server/), so fall back to that.
const PUBLIC_DIR = process.env.PUBLIC_DIR || [
  path.join(__dirname, '..', 'public'),
  path.join(__dirname, '..', '..', 'public')
].find((p) => fs.existsSync(p)) || path.join(__dirname, '..', 'public');

function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '256kb' }));

  app.get('/healthz', (req, res) => res.status(200).json({ status: 'ok' }));
  app.get('/readyz', (req, res) => res.status(200).json({ status: 'ok' }));

  app.use('/api/config', configRoutes);
  app.use('/api/scans', scanRoutes);

  app.use(express.static(PUBLIC_DIR));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api/')) return next();
    res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
  });

  app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
    console.error(err);
    res.status(500).json({ error: 'internal server error' });
  });

  return app;
}

module.exports = { createApp, PUBLIC_DIR };
