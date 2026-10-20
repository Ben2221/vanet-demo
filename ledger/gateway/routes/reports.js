const express = require('express');
const { name, parseQueryInteger, validatePidParam, validateReport, validateSince, validateWeight } = require('../validators');
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
  // --trust-weighted: the TA lowers an RSU's report weight (per mille) after investigations
  router.put('/weights/:rsuId', submitRoute(fabric, {
    role: 'TA',
    fn: 'SetReporterWeight',
    validate: validateWeight,
    args: (request) => [request.params.rsuId, String(request.body.weightMilli)],
  }));
  router.get('/weights/:rsuId', evaluateRoute(fabric, {
    fn: 'GetReporterWeight',
    validate: (request) => name(request.params.rsuId, 'rsuId'),
    args: (request) => [request.params.rsuId],
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
