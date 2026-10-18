const express = require('express');
const { parseQueryInteger, validateSince } = require('../validators');
const { withCaller } = require('./shared');

function createSnapshotRoutes(fabric, config) {
  const router = express.Router();

  router.get('/snapshot', withCaller(fabric, { role: 'ANY' }, async (request, response) => {
    validateSince(request);
    const since = parseQueryInteger(request.query.since, 'since');
    const startedAt = Date.now();
    const identity = request.identity.name;
    const [revoked, auths, policies, roots, configResult] = await Promise.all([
      fabric.evaluate(identity, 'ListRevokedSince', [since]),
      fabric.evaluate(identity, 'ListAuthsSince', [since]),
      fabric.evaluate(identity, 'ListPolicies'),
      fabric.evaluate(identity, 'ListRoots'),
      fabric.evaluate(identity, 'GetConfig'),
    ]);
    response.json({
      ok: true,
      queryMs: Date.now() - startedAt,
      result: {
        serverTimeMs: Date.now(),
        since,
        revoked: revoked.result,
        auths: auths.result,
        policies: policies.result,
        roots: roots.result,
        config: configResult.result,
      },
    });
  }));

  router.get('/events/stream', withCaller(fabric, { role: 'ANY' }, async (_request, response) => {
    response.status(501).json({ ok: false, error: { code: 'NOT_DEPLOYED' } });
  }));

  return router;
}

module.exports = { createSnapshotRoutes };
