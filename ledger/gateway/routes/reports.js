const express = require('express');
const { parseQueryInteger, validatePidParam, validateReport, validateSince } = require('../validators');
const { evaluateRoute, submitRoute } = require('./shared');

function createReportRoutes(fabric) {
  const router = express.Router();

  router.post('/reports', submitRoute(fabric, {
    role: 'RSU',
    fn: 'ReportMisbehaviour',
    validate: validateReport,
    args: (request) => {
      const { pid, evidenceHash, attackType = '' } = request.body;
      return [pid, evidenceHash, attackType];
    },
  }));
  router.get('/pseudonyms/:pid', evaluateRoute(fabric, {
    fn: 'GetPseudonymStatus',
    validate: validatePidParam,
    args: (request) => [request.params.pid],
  }));
  router.get('/revoked', evaluateRoute(fabric, {
    fn: 'ListRevokedSince',
    validate: validateSince,
    args: (request) => [parseQueryInteger(request.query.since, 'since')],
  }));
  router.get('/revoked/:pid', evaluateRoute(fabric, {
    fn: 'IsRevoked',
    validate: validatePidParam,
    args: (request) => [request.params.pid],
    transform: ({ queryMs, result }) => ({ queryMs, result: { revoked: Boolean(result) } }),
  }));

  return router;
}

module.exports = { createReportRoutes };
