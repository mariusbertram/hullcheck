'use strict';

const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || '/data';
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
// Optional mounted kubernetes.io/dockerconfigjson secret (read-only base
// credentials). Read lazily (not cached at module load) so it reflects the
// current env var - relevant for tests, harmless in production where it's
// set once at container start.
function mountedPullSecretPath() {
  return process.env.PULL_SECRET_PATH || '/etc/anchor-webui/pull-secret/.dockerconfigjson';
}

const DEFAULT_CONFIG = {
  httpProxy: process.env.HTTP_PROXY || process.env.http_proxy || '',
  httpsProxy: process.env.HTTPS_PROXY || process.env.https_proxy || '',
  noProxy: process.env.NO_PROXY || process.env.no_proxy || '',
  insecureSkipTlsVerify: false,
  insecureUseHttp: false,
  // user-managed registry credentials, in addition to whatever is mounted
  // from a kubernetes.io/dockerconfigjson secret (see mountedPullSecretPath()).
  registryAuths: []
};

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function readJsonSafe(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    return null;
  }
}

function load() {
  ensureDataDir();
  const existing = readJsonSafe(CONFIG_FILE);
  if (existing) {
    return { ...DEFAULT_CONFIG, ...existing };
  }
  save(DEFAULT_CONFIG);
  return { ...DEFAULT_CONFIG };
}

function save(config) {
  ensureDataDir();
  const toSave = {
    httpProxy: config.httpProxy || '',
    httpsProxy: config.httpsProxy || '',
    noProxy: config.noProxy || '',
    insecureSkipTlsVerify: !!config.insecureSkipTlsVerify,
    insecureUseHttp: !!config.insecureUseHttp,
    registryAuths: Array.isArray(config.registryAuths) ? config.registryAuths : []
  };
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(toSave, null, 2), { mode: 0o600 });
  return toSave;
}

// Credentials mounted from a Secret of type kubernetes.io/dockerconfigjson,
// e.g. an imagePullSecret shared with the cluster. Treated as read-only
// defaults layered underneath anything configured in the UI.
function loadMountedPullSecretAuths() {
  const raw = readJsonSafe(mountedPullSecretPath());
  if (!raw || !raw.auths) return [];
  const out = [];
  for (const [authority, entry] of Object.entries(raw.auths)) {
    let username = entry.username;
    let password = entry.password;
    if ((!username || !password) && entry.auth) {
      try {
        const decoded = Buffer.from(entry.auth, 'base64').toString('utf8');
        const idx = decoded.indexOf(':');
        if (idx !== -1) {
          username = decoded.slice(0, idx);
          password = decoded.slice(idx + 1);
        }
      } catch (err) {
        // ignore malformed entry
      }
    }
    out.push({ authority, username, password, source: 'mounted-secret' });
  }
  return out;
}

// Redacts secrets before sending config to the browser.
function toPublic(config) {
  const mounted = loadMountedPullSecretAuths().map((a) => ({
    authority: a.authority,
    username: a.username,
    password: a.password ? '********' : '',
    source: 'mounted-secret'
  }));
  const userAuths = (config.registryAuths || []).map((a) => ({
    authority: a.authority,
    username: a.username,
    password: a.password ? '********' : '',
    source: 'ui'
  }));
  return {
    httpProxy: config.httpProxy || '',
    httpsProxy: config.httpsProxy || '',
    noProxy: config.noProxy || '',
    insecureSkipTlsVerify: !!config.insecureSkipTlsVerify,
    insecureUseHttp: !!config.insecureUseHttp,
    registryAuths: [...mounted, ...userAuths]
  };
}

module.exports = {
  DATA_DIR,
  CONFIG_FILE,
  load,
  save,
  loadMountedPullSecretAuths,
  toPublic
};
