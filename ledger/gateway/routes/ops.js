const express = require('express');
const fabricProtos = require('@hyperledger/fabric-protos');
const { listActivity } = require('../activityLog');
const { validateActivityLimit } = require('../validators');
const { evaluateRoute, withCaller } = require('./shared');
const { HttpError } = require('../errors');

function createOpsRoutes(fabric, config) {
  const router = express.Router();

  router.get('/stats', evaluateRoute(fabric, { fn: 'GetStats' }));

  router.get('/chain', withCaller(fabric, { role: 'ANY' }, async (request, response) => {
    const { queryMs, result } = await fabric.evaluateRaw(
      request.identity.name,
      'GetChainInfo',
      [config.channelName],
      'qscc',
    );
    const info = fabricProtos.common.BlockchainInfo.deserializeBinary(result);
    response.json({
      ok: true,
      queryMs,
      height: info.getHeight(),
      currentHash: Buffer.from(info.getCurrentblockhash_asU8()).toString('hex'),
    });
  }));

  router.get('/activity', withCaller(fabric, { role: 'ANY' }, (request, response) => {
    const limit = validateActivityLimit(request);
    response.json({ ok: true, queryMs: 0, result: listActivity(limit) });
  }));

  router.get('/admin/dump', evaluateRoute(fabric, { role: 'TA', fn: 'DumpState' }));
  router.post('/admin/reset', withCaller(fabric, { role: 'TA' }, async (request, response) => {
    const startedAt = Date.now();
    let deleted = 0;
    let remaining = Number.MAX_SAFE_INTEGER;
    let lastWrite;
    let endorseMs = 0;
    let commitMs = 0;
    let retries = 0;

    while (remaining > 0) {
      const previousRemaining = remaining;
      lastWrite = await fabric.submit(request.identity.name, 'ResetDemoState');
      const result = lastWrite.result;
      const batchDeleted = Number(result?.deleted);
      remaining = Number(result?.remaining);
      if (!Number.isSafeInteger(batchDeleted) || batchDeleted < 0
          || !Number.isSafeInteger(remaining) || remaining < 0) {
        throw new HttpError(500, 'RESET_INVALID_RESULT', 'ResetDemoState returned invalid counts');
      }
      deleted += batchDeleted;
      endorseMs += lastWrite.endorseMs;
      commitMs += lastWrite.commitMs;
      retries += lastWrite.retries;
      if (remaining >= previousRemaining && remaining > 0) {
        throw new HttpError(500, 'RESET_INCOMPLETE', 'ResetDemoState made no progress');
      }
    }

    response.json({
      ok: true,
      txId: lastWrite.txId,
      blockNumber: lastWrite.blockNumber,
      endorseMs,
      commitMs,
      totalMs: Date.now() - startedAt,
      retries,
      result: { deleted, remaining: 0 },
    });
  }));

  return router;
}

module.exports = { createOpsRoutes };
