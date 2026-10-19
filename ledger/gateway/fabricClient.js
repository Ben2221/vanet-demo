const fs = require('node:fs');
const crypto = require('node:crypto');
const grpc = require('@grpc/grpc-js');
const { connect, hash, signers } = require('@hyperledger/fabric-gateway');
const { HttpError, toHttpError } = require('./errors');
const { recordActivity } = require('./activityLog');

const TIMEOUTS_MS = {
  evaluate: 5_000,
  endorse: 15_000,
  submit: 5_000,
  commitStatus: 60_000,
};
const CONFLICT_CODES = new Set([11, 12]);
const MAX_RETRIES = 3;
const READ_AFTER_WRITE_WINDOW_MS = 2_000;
const READ_AFTER_WRITE_RETRIES = 3;
const READ_AFTER_WRITE_DELAY_MS = 300;
const RECENT_READ_FUNCTIONS = new Set(['GetAuth', 'GetPseudonymStatus', 'IsRevoked']);

function callOptions(timeoutMs) {
  return { deadline: Date.now() + timeoutMs };
}

function parseResult(bytes) {
  const text = Buffer.from(bytes).toString('utf8');
  if (text.length === 0) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function encodeArgument(value) {
  if (typeof value === 'string') {
    return value;
  }
  if (value === undefined || value === null) {
    return '';
  }
  return JSON.stringify(value);
}

function statusConflict(status) {
  return CONFLICT_CODES.has(Number(status.code));
}

function statusCode(error) {
  const mapped = toHttpError(error);
  return mapped.code;
}

function createFabricClient(config) {
  const identities = new Map();
  const clientConnections = [];
  const recentWrites = new Map();

  try {
    for (const identity of config.identities) {
      const credentials = fs.readFileSync(identity.certPath);
      const privateKey = crypto.createPrivateKey(fs.readFileSync(identity.privateKeyPath));
      const tlsRootCert = fs.readFileSync(identity.tlsCertPath);
      const client = new grpc.Client(
        identity.peerEndpoint,
        grpc.credentials.createSsl(tlsRootCert),
        {
          'grpc.ssl_target_name_override': identity.hostAlias,
          'grpc.default_authority': identity.hostAlias,
        },
      );
      const gateway = connect({
        client,
        identity: { mspId: identity.mspId, credentials },
        signer: signers.newPrivateKeySigner(privateKey),
        hash: hash.sha256,
        evaluateOptions: () => callOptions(TIMEOUTS_MS.evaluate),
        endorseOptions: () => callOptions(TIMEOUTS_MS.endorse),
        submitOptions: () => callOptions(TIMEOUTS_MS.submit),
        commitStatusOptions: () => callOptions(TIMEOUTS_MS.commitStatus),
      });
      clientConnections.push({ client, gateway });
      identities.set(identity.name, {
        ...identity,
        gateway,
        network: gateway.getNetwork(config.channelName),
      });
    }
  } catch (error) {
    for (const { gateway, client } of clientConnections) {
      gateway.close();
      client.close();
    }
    throw error;
  }

  function getIdentity(name) {
    const identity = identities.get(name);
    if (!identity) {
      throw new HttpError(400, 'ERR_BAD_INPUT', `Unknown identity: ${name}`);
    }
    return identity;
  }

  function contract(identityName, chaincodeName = config.chaincodeName) {
    return getIdentity(identityName).network.getContract(chaincodeName);
  }

  async function getChaincodeEvents(identityName) {
    return getIdentity(identityName).network.getChaincodeEvents(config.chaincodeName);
  }

  async function evaluateRaw(identityName, fn, args = [], chaincodeName = config.chaincodeName) {
    const start = Date.now();
    const proposal = contract(identityName, chaincodeName).newProposal(fn, {
      arguments: args.map(encodeArgument),
    });
    const result = await proposal.evaluate(callOptions(TIMEOUTS_MS.evaluate));
    return { queryMs: Date.now() - start, result: Buffer.from(result) };
  }

  function recentWritesForRead(fn, args) {
    if (!RECENT_READ_FUNCTIONS.has(fn) || typeof args[0] !== 'string') {
      return [];
    }
    const pid = args[0];
    const now = Date.now();
    for (const [key, write] of recentWrites) {
      if (now - write.at > READ_AFTER_WRITE_WINDOW_MS) {
        recentWrites.delete(key);
      }
    }

    const sourceFunctions = fn === 'GetPseudonymStatus'
      ? ['RecordAuth', 'ReportMisbehaviour']
      : fn === 'GetAuth'
        ? ['RecordAuth', 'ReportMisbehaviour']
        : ['ReportMisbehaviour'];
    return sourceFunctions
      .map((sourceFn) => recentWrites.get(`${sourceFn}:${pid}`))
      .filter((write) => write && now - write.at <= READ_AFTER_WRITE_WINDOW_MS);
  }

  function staleRead(fn, pid, result, writes) {
    const authWrite = writes.find((write) => write.fn === 'RecordAuth');
    const reportWrite = writes.find((write) => write.fn === 'ReportMisbehaviour');
    if (fn === 'GetAuth') {
      if (reportWrite?.result?.revoked && result) {
        return true;
      }
      const expected = authWrite?.result;
      return Boolean(expected && (
        !result
        || result.pid !== pid
        || Number(result.ts) < Number(expected.ts)
        || Number(result.sessionCount) < Number(expected.sessionCount)
      ));
    }
    if (fn === 'GetPseudonymStatus') {
      const expectedReport = reportWrite?.result;
      if (expectedReport && (
        Number(result?.reportCount || 0) < Number(expectedReport.reportCount || 0)
        || (expectedReport.revoked && !result?.revoked)
      )) {
        return true;
      }
      const expectedAuth = authWrite?.result;
      if (expectedAuth && !result?.revoked) {
        const activeAuth = result?.activeAuth;
        return !activeAuth
          || activeAuth.pid !== pid
          || Number(activeAuth.ts) < Number(expectedAuth.ts)
          || Number(activeAuth.sessionCount) < Number(expectedAuth.sessionCount);
      }
      return false;
    }
    return Boolean(reportWrite?.result?.revoked && result !== true);
  }

  async function evaluateWithReadRetry(identityName, fn, args, chaincodeName) {
    const pid = args[0];
    let queryMs = 0;
    let lastResult;
    for (let attempt = 0; attempt <= READ_AFTER_WRITE_RETRIES; attempt += 1) {
      const writes = recentWritesForRead(fn, args);
      const readStartedAt = Date.now();
      try {
        const response = await evaluateRaw(identityName, fn, args, chaincodeName);
        queryMs += response.queryMs;
        lastResult = parseResult(response.result);
        const currentWrites = recentWritesForRead(fn, args);
        if (
          currentWrites.length === 0
          || !staleRead(fn, pid, lastResult, currentWrites)
          || attempt === READ_AFTER_WRITE_RETRIES
        ) {
          return { queryMs, result: lastResult };
        }
      } catch (error) {
        queryMs += Date.now() - readStartedAt;
        const currentWrites = recentWritesForRead(fn, args);
        if (
          currentWrites.length === 0
          || toHttpError(error).code !== 'ERR_NOT_FOUND'
          || attempt === READ_AFTER_WRITE_RETRIES
        ) {
          throw error;
        }
      }
      if (writes.length === 0 && recentWritesForRead(fn, args).length === 0) {
        return { queryMs, result: lastResult };
      }
      await new Promise((resolve) => setTimeout(resolve, READ_AFTER_WRITE_DELAY_MS));
    }
    return { queryMs, result: lastResult };
  }

  async function evaluate(identityName, fn, args = [], chaincodeName = config.chaincodeName) {
    if (!RECENT_READ_FUNCTIONS.has(fn)) {
      const { queryMs, result } = await evaluateRaw(identityName, fn, args, chaincodeName);
      return { queryMs, result: parseResult(result) };
    }
    return evaluateWithReadRetry(identityName, fn, args, chaincodeName);
  }

  async function submit(identityName, fn, args = [], chaincodeName = config.chaincodeName) {
    const requestStartedAt = Date.now();
    let endorseMs = 0;
    let commitMs = 0;
    let finalTxId = null;
    let finalBlockNumber = null;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt += 1) {
      const attemptStartedAt = Date.now();
      let transactionId = null;
      try {
        const proposal = contract(identityName, chaincodeName).newProposal(fn, {
          arguments: args.map(encodeArgument),
        });
        transactionId = proposal.getTransactionId();
        const transaction = await proposal.endorse(callOptions(TIMEOUTS_MS.endorse));
        const endorsedAt = Date.now();
        endorseMs = endorsedAt - attemptStartedAt;

        const submitted = await transaction.submit(callOptions(TIMEOUTS_MS.submit));
        const status = await submitted.getStatus(callOptions(TIMEOUTS_MS.commitStatus));
        const committedAt = Date.now();
        commitMs = committedAt - endorsedAt;
        finalTxId = status.transactionId || transactionId;
        finalBlockNumber = Number(status.blockNumber);

        if (status.successful) {
          const result = parseResult(transaction.getResult());
          const response = {
            txId: finalTxId,
            blockNumber: finalBlockNumber,
            endorseMs,
            commitMs,
            totalMs: committedAt - requestStartedAt,
            retries: attempt,
            result,
          };
          recordActivity({
            identity: identityName,
            fn,
            txId: finalTxId,
            blockNumber: finalBlockNumber,
            commitMs,
            ok: true,
          });
          if ((fn === 'RecordAuth' || fn === 'ReportMisbehaviour') && typeof args[0] === 'string') {
            const now = Date.now();
            for (const [key, write] of recentWrites) {
              if (now - write.at > READ_AFTER_WRITE_WINDOW_MS) {
                recentWrites.delete(key);
              }
            }
            recentWrites.set(`${fn}:${args[0]}`, { fn, at: now, result });
          }
          return response;
        }

        if (statusConflict(status) && attempt < MAX_RETRIES) {
          await new Promise((resolve) => setTimeout(resolve, 50 + Math.random() * 100 * (attempt + 1)));
          continue;
        }
        if (statusConflict(status)) {
          throw new HttpError(409, 'TX_CONFLICT', 'Transaction conflicted after retries');
        }
        throw new HttpError(500, 'TX_INVALID', `Transaction committed with validation code ${status.code}`);
      } catch (error) {
        const mapped = toHttpError(error);
        if (mapped.code === 'TX_CONFLICT' && attempt < MAX_RETRIES) {
          await new Promise((resolve) => setTimeout(resolve, 50 + Math.random() * 100 * (attempt + 1)));
          continue;
        }
        recordActivity({
          identity: identityName,
          fn,
          txId: finalTxId || transactionId,
          blockNumber: finalBlockNumber,
          commitMs,
          ok: false,
          code: mapped.code || statusCode(error),
        });
        throw error;
      }
    }

    throw new HttpError(409, 'TX_CONFLICT', 'Transaction conflicted after retries');
  }

  function close() {
    for (const { gateway, client } of clientConnections) {
      gateway.close();
      client.close();
    }
  }

  return { close, evaluate, evaluateRaw, getChaincodeEvents, getIdentity, submit };
}

module.exports = { createFabricClient, parseResult };
