const express = require('express');
const { validateConfig } = require('../validators');
const { evaluateRoute, submitRoute, withCaller } = require('./shared');

function createSystemRoutes(fabric) {
  const router = express.Router();

  router.get('/health', withCaller(fabric, { role: 'ANY' }, async (request, response) => {
    await fabric.evaluate(request.identity.name, 'WhoAmI');
    response.json({ gateway: 'up', chaincode: 'ok', identity: request.identity.name });
  }));

  router.get('/whoami', evaluateRoute(fabric, { fn: 'WhoAmI' }));
  router.get('/config', evaluateRoute(fabric, { fn: 'GetConfig' }));
  router.put('/config', submitRoute(fabric, {
    role: 'TA',
    fn: 'SetConfig',
    validate: validateConfig,
    args: (request) => {
      const { K, traceThreshold, maxAuthTtlSec, demoMode } = request.body;
      return [K, traceThreshold, maxAuthTtlSec, demoMode];
    },
  }));


  return router;
}

module.exports = { createSystemRoutes };
