const express = require('express');
const {
  validateEpochParam,
  validatePolicy,
  validateRoot,
  validateServiceParam,
} = require('../validators');
const { evaluateRoute, submitRoute } = require('./shared');

function createRootRoutes(fabric) {
  const router = express.Router();

  router.post('/roots', submitRoute(fabric, {
    role: 'TA',
    fn: 'RegisterRoot',
    validate: validateRoot,
    args: (request) => {
      const { epoch, merkleRoot, validUntil } = request.body;
      return [epoch, merkleRoot, validUntil];
    },
  }));
  router.get('/roots', evaluateRoute(fabric, { fn: 'ListRoots' }));
  router.get('/roots/:epoch', evaluateRoute(fabric, {
    fn: 'GetRoot',
    validate: validateEpochParam,
    args: (request) => [request.params.epoch],
  }));

  router.put('/policies/:service', submitRoute(fabric, {
    role: 'TA',
    fn: 'SetPolicy',
    validate: validatePolicy,
    args: (request) => [request.params.service, JSON.stringify(request.body.classes)],
  }));
  router.get('/policies', evaluateRoute(fabric, { fn: 'ListPolicies' }));
  router.get('/policies/:service', evaluateRoute(fabric, {
    fn: 'GetPolicy',
    validate: validateServiceParam,
    args: (request) => [request.params.service],
  }));

  return router;
}

module.exports = { createRootRoutes };
