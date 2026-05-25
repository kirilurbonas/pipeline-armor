// =============================================================================
// pipeline-armor :: examples/nodejs-app
// -----------------------------------------------------------------------------
// Minimal Express service used as a target for the reusable workflows in this
// repo. The point of this file is not to ship features — it's to exist as a
// real Node.js application with real dependencies that SAST, container scan,
// and dependency review can chew on.
// =============================================================================
'use strict';

const express = require('express');
const helmet = require('helmet');
const pino = require('pino');

const log = pino({ level: process.env.LOG_LEVEL || 'info' });
const app = express();

// Sensible secure defaults. helmet sets a half-dozen response headers that
// remove footguns (X-Content-Type-Options, Strict-Transport-Security, etc.).
app.use(helmet());
app.use(express.json({ limit: '64kb' }));

app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.get('/version', (_req, res) => {
  res.status(200).json({
    version: process.env.APP_VERSION || 'dev',
    node: process.version,
  });
});

if (require.main === module) {
  const port = Number(process.env.PORT || 8080);
  app.listen(port, () => log.info({ port }, 'pipeline-armor example listening'));
}

module.exports = app;
