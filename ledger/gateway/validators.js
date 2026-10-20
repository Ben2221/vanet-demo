const { HttpError } = require('./errors');

const PID_PATTERN = /^[a-f0-9]{64}$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;
const REQ_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

function bad(message) {
  throw new HttpError(400, 'ERR_BAD_INPUT', message);
}

function bodyObject(request) {
  const body = request.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    bad('Request body must be a JSON object');
  }
  return body;
}

function requiredString(value, name) {
  if (typeof value !== 'string' || value.length === 0) {
    bad(`${name} must be a non-empty string`);
  }
  return value;
}

function integer(value, name, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    bad(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

function pid(value, name = 'pid') {
  if (typeof value !== 'string' || !PID_PATTERN.test(value)) {
    bad(`${name} must be 64 lowercase hexadecimal characters`);
  }
  return value;
}

function name(value, field) {
  if (typeof value !== 'string' || !NAME_PATTERN.test(value)) {
    bad(`${field} must match ${NAME_PATTERN}`);
  }
  return value;
}

function reqId(value) {
  if (typeof value !== 'string' || !REQ_ID_PATTERN.test(value)) {
    bad(`reqId must match ${REQ_ID_PATTERN}`);
  }
  return value;
}

function freeText(value, field) {
  requiredString(value, field);
  if (Array.from(value).length > 128 || /[\u0000\u{10FFFF}]/u.test(value)) {
    bad(`${field} must be at most 128 characters and contain no reserved characters`);
  }
  return value;
}

function parseQueryInteger(value, field, fallback = 0) {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    bad(`${field} must be a non-negative integer`);
  }
  const parsed = Number(value);
  return integer(parsed, field);
}

function validateConfig(request) {
  const body = bodyObject(request);
  integer(body.K, 'K', { minimum: 1, maximum: 10 });
  integer(body.traceThreshold, 'traceThreshold', { minimum: 1, maximum: 10 });
  integer(body.maxAuthTtlSec, 'maxAuthTtlSec', { minimum: 60, maximum: 86400 });
  if (typeof body.demoMode !== 'boolean') {
    bad('demoMode must be a boolean');
  }
}

function validateRoot(request) {
  const body = bodyObject(request);
  integer(body.epoch, 'epoch');
  if (typeof body.merkleRoot !== 'string' || !HASH_PATTERN.test(body.merkleRoot)) {
    bad('merkleRoot must be 64 lowercase hexadecimal characters');
  }
  integer(body.validUntil, 'validUntil', { minimum: 1 });
  if (body.validUntil <= Date.now()) {
    bad('validUntil must be in the future');
  }
}

function validateEpochParam(request) {
  const value = request.params.epoch;
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    bad('epoch must be a non-negative integer');
  }
  integer(Number(value), 'epoch');
}

function validateServiceParam(request) {
  name(request.params.service, 'service');
}

function validatePolicy(request) {
  const service = name(request.params.service, 'service');
  const body = bodyObject(request);
  if (!Array.isArray(body.classes) || !body.classes.every((item) => typeof item === 'string')) {
    bad('classes must be an array of class names');
  }
  body.classes.forEach((item) => name(item, 'class'));
  return service;
}

function validatePidParam(request) {
  pid(request.params.pid);
}

function validateAuthRecord(request) {
  const body = bodyObject(request);
  pid(body.pid);
  name(body.service, 'service');
  name(body.class, 'class');
  integer(body.expiry, 'expiry', { minimum: 1 });
  if (body.expiry <= Date.now()) {
    bad('expiry must be in the future');
  }
}

function validateAccessCheck(request) {
  pid(request.query.pid);
  name(request.query.class, 'class');
  name(request.query.service, 'service');
}

function validateSince(request) {
  parseQueryInteger(request.query.since, 'since');
}

function validateActivityLimit(request) {
  if (request.query.limit === undefined) {
    return 50;
  }
  const limit = parseQueryInteger(request.query.limit, 'limit');
  if (limit < 1 || limit > 200) {
    bad('limit must be between 1 and 200');
  }
  return limit;
}

function validateReport(request) {
  const body = bodyObject(request);
  pid(body.pid);
  if (typeof body.evidenceHash !== 'string' || !HASH_PATTERN.test(body.evidenceHash)) {
    bad('evidenceHash must be 64 lowercase hexadecimal characters');
  }
  if (body.attackType !== undefined) {
    name(body.attackType, 'attackType');
  }
}

function validateWeight(request) {
  name(request.params.rsuId, 'rsuId');
  const body = bodyObject(request);
  if (!Number.isInteger(body.weightMilli) || body.weightMilli < 0 || body.weightMilli > 1000) {
    bad('weightMilli must be an integer between 0 and 1000');
  }
}

function validateTraceRequest(request) {
  const body = bodyObject(request);
  reqId(body.reqId);
  pid(body.pid);
  freeText(body.reason, 'reason');
}

function validateTraceId(request) {
  reqId(request.params.id);
}

function validateRevoke(request) {
  const body = bodyObject(request);
  if (!Array.isArray(body.pids) || body.pids.length < 1 || body.pids.length > 200) {
    bad('pids must be an array containing between 1 and 200 pseudonyms');
  }
  body.pids.forEach((value, index) => pid(value, `pids[${index}]`));
  freeText(body.reason, 'reason');
}


module.exports = {
  NAME_PATTERN,
  PID_PATTERN,
  REQ_ID_PATTERN,
  bodyObject,
  integer,
  name,
  parseQueryInteger,
  pid,
  reqId,
  validateAccessCheck,
  validateActivityLimit,
  validateAuthRecord,
  validateConfig,
  validateEpochParam,

  validatePidParam,
  validatePolicy,
  validateReport,
  validateRevoke,
  validateWeight,
  validateRoot,
  validateServiceParam,
  validateSince,
  validateTraceId,
  validateTraceRequest,
};
