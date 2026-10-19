const express = require('express');
const {
  parseQueryInteger,
  validateAccessCheck,
  validateAuthRecord,
  validatePidParam,
  validateSince,
} = require('../validators');
const { evaluateRoute, submitRoute } = require('./shared');

function createAuthRoutes(fabric) {
  const router = express.Router();

  router.post('/auth-records', submitRoute(fabric, {
    role: 'RSU',
    fn: 'RecordAuth',
    validate: validateAuthRecord,
    args: (request) => {
      const { pid, service, class: vehicleClass, expiry } = request.body;
      return [pid, service, vehicleClass, expiry];
    },
  }));
  router.get('/auth-records/:pid', evaluateRoute(fabric, {
    fn: 'GetAuth',
    validate: validatePidParam,
    args: (request) => [request.params.pid],
  }));
  router.get('/auth-records', evaluateRoute(fabric, {
    fn: 'ListAuthsSince',
    validate: validateSince,
    args: (request) => [parseQueryInteger(request.query.since, 'since')],
  }));
  router.get('/access-check', evaluateRoute(fabric, {
    fn: 'CheckAccess',
    validate: validateAccessCheck,
    args: (request) => [request.query.pid, request.query.class, request.query.service],
  }));

  return router;
}

module.exports = { createAuthRoutes };
