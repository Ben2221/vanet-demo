const HTTP_STATUS_BY_CODE = {
  ERR_BAD_INPUT: 400,
  ERR_FORBIDDEN: 403,
  ERR_NOT_FOUND: 404,
  ERR_CONFLICT: 409,
  TX_CONFLICT: 409,
  NOT_DEPLOYED: 501,
};

class HttpError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
  }
}

function errorTextSources(error) {
  const details = Array.isArray(error.details)
    ? error.details.map((detail) => detail.message || '').join('\n')
    : String(error.details || '');
  return [details, error.message || '', error.cause?.message || ''];
}

function chaincodeErrorCode(error) {
  const match = errorTextSources(error).join('\n').match(/ERR_[A-Z_]+/);
  return match ? match[0] : null;
}

function chaincodeErrorMessage(error, code) {
  for (const source of errorTextSources(error)) {
    const match = source.match(new RegExp(`${code}\\s*:?\\s*([^\\r\\n]+)`));
    if (match) {
      const message = match[1].trim().replace(/^["']|["']$/g, '');
      if (message) {
        return message;
      }
    }
  }
  return code;
}

function isFunctionNotFound(error) {
  const details = Array.isArray(error.details)
    ? error.details.map((detail) => detail.message || '').join('\n')
    : String(error.details || '');
  const message = `${error.message || ''}\n${details}`;
  return /function [a-z0-9_]+ not found in contract|function [a-z0-9_]+ does not exist|transaction [a-z0-9_]+ not found/i.test(message);
}

function isUnavailable(error) {
  const grpcCodes = new Set([2, 4, 14]);
  const errorCode = typeof error.code === 'string' ? error.code.toUpperCase() : error.code;
  return grpcCodes.has(errorCode)
    || ['UNAVAILABLE', 'DEADLINE_EXCEEDED', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT'].includes(errorCode)
    || /connection (?:refused|failed)|timed? ?out|unavailable/i.test(error.message || '');
}

function toHttpError(error) {
  if (error instanceof HttpError) {
    return error;
  }
  if (isFunctionNotFound(error)) {
    return new HttpError(501, 'NOT_DEPLOYED');
  }
  if (error.type === 'entity.parse.failed' || error.type === 'entity.too.large') {
    return new HttpError(error.type === 'entity.too.large' ? 413 : 400, 'ERR_BAD_INPUT', 'Invalid JSON request body');
  }
  const code = chaincodeErrorCode(error);
  if (code && HTTP_STATUS_BY_CODE[code]) {
    return new HttpError(HTTP_STATUS_BY_CODE[code], code, chaincodeErrorMessage(error, code));
  }

  if (typeof error.code === 'string' && HTTP_STATUS_BY_CODE[error.code]) {
    return new HttpError(HTTP_STATUS_BY_CODE[error.code], error.code, error.message);
  }

  if (isUnavailable(error)) {
    return new HttpError(503, 'PEER_UNAVAILABLE', 'Fabric peer or orderer is unavailable');
  }

  // the two endorsing peers were a block apart and simulated against different state: transient
  // under load, like an MVCC conflict, so it is reported as the retryable TX_CONFLICT
  if (JSON.stringify((error && error.details) || []).includes('ProposalResponsePayloads do not match')) {
    return new HttpError(409, 'TX_CONFLICT', 'Endorsements differ (peer state lag); retry');
  }
  // unmapped: log the cause, the client only sees INTERNAL_ERROR
  console.error('INTERNAL_ERROR:', error && (error.stack || error.message || error),
    error && error.details ? JSON.stringify(error.details) : '');
  return new HttpError(500, 'INTERNAL_ERROR', 'Internal server error');
}

function errorHandler(error, _request, response, _next) {
  const mapped = toHttpError(error);
  const details = { code: mapped.code };
  if (mapped.code !== 'NOT_DEPLOYED') {
    details.message = mapped.message;
  }
  response.status(mapped.status).json({ ok: false, error: details });
}

module.exports = { HttpError, errorHandler, toHttpError };
