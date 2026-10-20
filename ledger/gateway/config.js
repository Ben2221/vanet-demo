const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const DEFAULT_FABRIC_HOME = path.join(os.homedir(), 'fabric', 'fabric-samples');

function expandConfiguredPath(value) {
  const expanded = value.replace(/\$\{([A-Z_][A-Z0-9_]*)\}/g, (match, name) => {
    if (name === 'FABRIC_HOME') {
      return process.env.FABRIC_HOME || DEFAULT_FABRIC_HOME;
    }
    if (!process.env[name]) {
      throw new Error(`Environment variable ${name} is required to resolve an identity path`);
    }
    return process.env[name];
  }).replace(/^~(?=$|[\\/])/, os.homedir());

  return path.resolve(expanded);
}

function resolvePrivateKeyPath(configuredPath) {
  const keyPath = expandConfiguredPath(configuredPath);
  const stats = fs.statSync(keyPath);
  if (!stats.isDirectory()) {
    return keyPath;
  }

  const candidates = fs.readdirSync(keyPath)
    .filter((name) => name.endsWith('_sk'))
    .map((name) => path.join(keyPath, name));
  if (candidates.length !== 1) {
    throw new Error('Each configured keystore directory must contain exactly one private key');
  }
  return candidates[0];
}

// RSU_COUNT=N adds rsu5..rsuN, copied from rsu1 (enroll them with the same RSU_COUNT in
// ledger/network/enroll_identities.sh)
function addRsuIdentities(parsed, count) {
  const template = parsed.rsu1;
  if (!template || !(count > 0)) return parsed;
  for (let n = 2; n <= count; n += 1) {
    const name = `rsu${n}`;
    if (!parsed[name]) {
      parsed[name] = Object.fromEntries(Object.entries(template).map(([k, v]) =>
        [k, typeof v === 'string' ? v.replace(/rsu1@/g, `${name}@`) : v]));
    }
  }
  return parsed;
}

function loadIdentities(filePath = path.join(__dirname, 'identities.json')) {
  const parsed = addRsuIdentities(JSON.parse(fs.readFileSync(filePath, 'utf8')),
    Number(process.env.RSU_COUNT || 0));
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error('identities.json must contain an object keyed by identity name');
  }

  return Object.entries(parsed).map(([name, identity]) => {
    for (const field of ['mspId', 'certPath', 'keyPath', 'peerEndpoint', 'tlsCertPath', 'hostAlias']) {
      if (typeof identity[field] !== 'string' || identity[field].length === 0) {
        throw new Error(`Identity ${name} is missing ${field}`);
      }
    }

    return {
      name,
      mspId: identity.mspId,
      role: identity.mspId === 'Org1MSP' ? 'TA' : identity.mspId === 'Org2MSP' ? 'RSU' : 'UNKNOWN',
      certPath: expandConfiguredPath(identity.certPath),
      privateKeyPath: resolvePrivateKeyPath(identity.keyPath),
      peerEndpoint: identity.peerEndpoint,
      tlsCertPath: expandConfiguredPath(identity.tlsCertPath),
      hostAlias: identity.hostAlias,
    };
  });
}

function loadConfig() {
  const channelName = process.env.CHANNEL || 'vanetchannel';
  const chaincodeName = process.env.CC_NAME || 'vanetauth';
  const port = Number(process.env.PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be an integer between 1 and 65535');
  }

  return {
    channelName,
    chaincodeName,
    port,
    host: process.env.HOST || '127.0.0.1',
    identities: loadIdentities(process.env.IDENTITIES_FILE
      ? path.resolve(process.env.IDENTITIES_FILE)
      : path.join(__dirname, 'identities.json')),
  };
}

module.exports = { expandConfiguredPath, loadConfig, loadIdentities };
