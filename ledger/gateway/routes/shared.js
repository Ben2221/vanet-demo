const { HttpError } = require('../errors');

function withCaller(fabric, options, handler) {
  return async (request, response, next) => {
    try {
      const defaultIdentity = options.defaultIdentity || (options.role === 'TA' ? 'ta1' : 'rsu1');
      const requestedIdentity = request.get('X-Identity')?.trim() || defaultIdentity;
      const identity = fabric.getIdentity(requestedIdentity);
      const roleAllowed = options.role === 'TA_OR_RSU'
        ? identity.role === 'TA' || identity.role === 'RSU'
        : !options.role || options.role === 'ANY' || options.role === identity.role;
      if (!roleAllowed) {
        throw new HttpError(
          403,
          'ERR_FORBIDDEN',
          `${identity.name} (${identity.role}) may not call this function`,
        );
      }
      request.identity = identity;
      await handler(request, response);
    } catch (error) {
      next(error);
    }
  };
}

function transactionRoute(fabric, { role = 'ANY', fn, args = () => [], validate, submit = false, transform }) {
  return withCaller(fabric, { role }, async (request, response) => {
    if (validate) {
      validate(request);
    }
    const result = submit
      ? await fabric.submit(request.identity.name, fn, args(request))
      : await fabric.evaluate(request.identity.name, fn, args(request));
    response.json({ ok: true, ...(transform ? transform(result) : result) });
  });
}

const evaluateRoute = (fabric, options) => transactionRoute(fabric, options);
const submitRoute = (fabric, options) => transactionRoute(fabric, { ...options, submit: true });

module.exports = { evaluateRoute, submitRoute, withCaller };
