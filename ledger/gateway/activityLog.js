const MAX_ENTRIES = 200;
const entries = [];

function recordActivity(entry) {
  entries.push({
    ts: Date.now(),
    identity: entry.identity,
    fn: entry.fn,
    txId: entry.txId || null,
    blockNumber: entry.blockNumber ?? null,
    commitMs: typeof entry.commitMs === 'number' ? entry.commitMs : null,
    ok: Boolean(entry.ok),
    code: entry.code || null,
  });
  if (entries.length > MAX_ENTRIES) {
    entries.splice(0, entries.length - MAX_ENTRIES);
  }
}

function listActivity(limit = MAX_ENTRIES) {
  return entries.slice(-limit).reverse();
}

module.exports = { listActivity, recordActivity };
