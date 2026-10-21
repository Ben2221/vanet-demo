const { randomBytes } = require('node:crypto');

const baseUrl = (process.env.GATEWAY_URL || 'http://127.0.0.1:3000').replace(/\/$/, '');
const durationSeconds = Number(process.env.BENCH_SECONDS || 30);
const targetRates = (process.env.BENCH_RATES || '5,10,20').split(',').map(Number);
const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function percentile(values, fraction) {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.max(0, Math.ceil(fraction * sorted.length) - 1)];
}

async function call(method, path, identity, payload) {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      'X-Identity': identity,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  const body = await response.json();
  return { status: response.status, body };
}

async function setupPolicy() {
  const service = `bench-${randomBytes(5).toString('hex')}`;
  const { status, body } = await call('PUT', `/policies/${service}`, 'ta1', {
    classes: ['private'],
  });
  if (status !== 200) {
    throw new Error(`policy setup failed (${status}): ${JSON.stringify(body)}`);
  }
  await delay(700);
  return service;
}

async function runRate(targetRate, service) {
  const scheduled = targetRate * durationSeconds;
  const latencies = [];
  let failures = 0;
  let retries = 0;
  const tasks = [];
  const startedAt = Date.now();

  for (let index = 0; index < scheduled; index += 1) {
    const dueAt = startedAt + (index * 1000) / targetRate;
    await delay(Math.max(0, dueAt - Date.now()));
    const pid = randomBytes(32).toString('hex');
    const task = call('POST', '/auth-records', 'rsu1', {
      pid,
      service,
      class: 'private',
      expiry: Date.now() + 600_000,
    }).then(({ status, body }) => {
      if (status !== 200 || typeof body.commitMs !== 'number') {
        failures += 1;
        return;
      }
      latencies.push(body.commitMs);
      retries += Number(body.retries || 0);
    }).catch(() => {
      failures += 1;
    });
    tasks.push(task);
  }

  await Promise.all(tasks);
  const successful = scheduled - failures;
  return {
    targetRate,
    achievedTps: successful / durationSeconds,
    p50Ms: percentile(latencies, 0.50),
    p95Ms: percentile(latencies, 0.95),
    failures,
    retries,
  };
}

async function main() {
  const service = await setupPolicy();
  console.log('targetRate,achievedTps,p50Ms,p95Ms,failures,retries');
  for (const rate of targetRates) {
    const result = await runRate(rate, service);
    console.log([
      result.targetRate,
      result.achievedTps.toFixed(2),
      result.p50Ms.toFixed(2),
      result.p95Ms.toFixed(2),
      result.failures,
      result.retries,
    ].join(','));
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
