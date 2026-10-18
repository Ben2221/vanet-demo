const express = require('express');
const { validateRevoke, validateTraceId, validateTraceRequest } = require('../validators');
const { evaluateRoute, submitRoute } = require('./shared');

function createTraceRoutes(fabric) {
  const router = express.Router();

  router.post('/traces', submitRoute(fabric, {
    role: 'TA_OR_RSU',
    fn: 'RequestTrace',
    validate: validateTraceRequest,
    args: (request) => [request.body.reqId, request.body.pid, request.body.reason],
  }));
  router.get('/traces', evaluateRoute(fabric, {
    fn: 'ListTraces',
    args: (request) => [request.query.status || ''],
  }));
  router.get('/traces/:id', evaluateRoute(fabric, {
    fn: 'GetTrace',
    validate: validateTraceId,
    args: (request) => [request.params.id],
  }));
  router.post('/traces/:id/approve', submitRoute(fabric, {
    role: 'RSU',
    fn: 'ApproveTrace',
    validate: validateTraceId,
    args: (request) => [request.params.id],
  }));
  router.post('/traces/:id/shares', submitRoute(fabric, {
    role: 'RSU',
    fn: 'RecordShareRelease',
    validate: validateTraceId,
    args: (request) => [request.params.id],
  }));
  router.post('/traces/:id/revoke', submitRoute(fabric, {
    role: 'TA',
    fn: 'Revoke',
    validate: (request) => {
      validateTraceId(request);
      validateRevoke(request);
    },
    args: (request) => [request.params.id, JSON.stringify(request.body.pids), request.body.reason],
  }));

  return router;
}

module.exports = { createTraceRoutes };
