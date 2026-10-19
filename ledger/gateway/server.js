const express = require('express');
const { loadConfig } = require('./config');
const { createFabricClient } = require('./fabricClient');
const { errorHandler } = require('./errors');
const { createSystemRoutes } = require('./routes/system');
const { createRootRoutes } = require('./routes/roots');
const { createAuthRoutes } = require('./routes/auth');
const { createReportRoutes } = require('./routes/reports');
const { createTraceRoutes } = require('./routes/traces');
const { createSnapshotRoutes } = require('./routes/snapshot');
const { createOpsRoutes } = require('./routes/ops');

function createApp(fabric, config = { channelName: 'vanetchannel' }) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '1mb' }));
  app.use(createSystemRoutes(fabric));
  app.use(createRootRoutes(fabric));
  app.use(createAuthRoutes(fabric));
  app.use(createReportRoutes(fabric));
  app.use(createTraceRoutes(fabric));
  app.use(createSnapshotRoutes(fabric));
  app.use(createOpsRoutes(fabric, config));
  app.use((_request, response) => {
    response.status(404).json({
      ok: false,
      error: { code: 'ERR_NOT_FOUND', message: 'Route not found' },
    });
  });
  app.use(errorHandler);
  return app;
}

function startServer() {
  const config = loadConfig();
  const fabric = createFabricClient(config);
  const app = createApp(fabric, config);
  const server = app.listen(config.port, config.host, () => {
    console.log(`VANET ledger gateway listening on ${config.host}:${config.port}`);
  });

  const shutdown = () => {
    server.close(() => {
      fabric.close();
      process.exit(0);
    });
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
  return { app, fabric, server };
}

if (require.main === module) {
  try {
    startServer();
  } catch (_error) {
    console.error('Gateway initialization failed; check identity paths and Fabric configuration.');
    process.exitCode = 1;
  }
}

module.exports = { createApp, startServer };
