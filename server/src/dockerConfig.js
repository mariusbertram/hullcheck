'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const config = require('./config');

function b64(str) {
  return Buffer.from(str, 'utf8').toString('base64');
}

// Merges mounted-secret auths, UI-configured auths and an optional one-off
// per-scan auth (highest priority) into a single list keyed by authority.
function mergedAuths(cfg, perScanAuth) {
  const byAuthority = new Map();
  for (const a of config.loadMountedPullSecretAuths()) {
    if (a.authority) byAuthority.set(a.authority, a);
  }
  for (const a of cfg.registryAuths || []) {
    if (a.authority) byAuthority.set(a.authority, a);
  }
  if (perScanAuth && perScanAuth.authority) {
    byAuthority.set(perScanAuth.authority, perScanAuth);
  }
  return [...byAuthority.values()];
}

// Builds an isolated environment (docker config.json + syft/grype registry
// config + proxy vars) for a single scan job so concurrent jobs never share
// or leak each other's credentials. Returns { env, dir } - caller must clean
// up `dir` once the job finishes.
function buildScanEnv({ jobId, perScanAuth, insecureOverride }) {
  const cfg = config.load();
  const auths = mergedAuths(cfg, perScanAuth);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `anchor-scan-${jobId}-`));
  fs.mkdirSync(path.join(dir, '.docker'), { recursive: true });

  const dockerAuths = {};
  for (const a of auths) {
    if (!a.authority) continue;
    if (a.username && a.password) {
      dockerAuths[a.authority] = { auth: b64(`${a.username}:${a.password}`) };
    }
  }
  fs.writeFileSync(
    path.join(dir, '.docker', 'config.json'),
    JSON.stringify({ auths: dockerAuths }, null, 2),
    { mode: 0o600 }
  );

  const insecureSkipTlsVerify = insecureOverride?.insecureSkipTlsVerify ?? cfg.insecureSkipTlsVerify;
  const insecureUseHttp = insecureOverride?.insecureUseHttp ?? cfg.insecureUseHttp;

  const yamlAuthEntries = auths
    .filter((a) => a.authority)
    .map((a) => {
      const lines = [`    - authority: "${a.authority}"`];
      if (a.token) {
        lines.push(`      token: "${a.token}"`);
      } else if (a.username && a.password) {
        lines.push(`      username: "${a.username}"`);
        lines.push(`      password: "${a.password}"`);
      }
      return lines.join('\n');
    });

  const registryYaml = [
    'registry:',
    `  insecure-skip-tls-verify: ${insecureSkipTlsVerify ? 'true' : 'false'}`,
    `  insecure-use-http: ${insecureUseHttp ? 'true' : 'false'}`,
    '  auth:',
    ...(yamlAuthEntries.length ? yamlAuthEntries : ['    []'])
  ].join('\n');
  const registryYamlPath = path.join(dir, 'registry.yaml');
  fs.writeFileSync(registryYamlPath, registryYaml + '\n', { mode: 0o600 });

  const env = {
    ...process.env,
    HOME: dir,
    DOCKER_CONFIG: path.join(dir, '.docker'),
    HTTP_PROXY: cfg.httpProxy || '',
    HTTPS_PROXY: cfg.httpsProxy || '',
    NO_PROXY: cfg.noProxy || '',
    http_proxy: cfg.httpProxy || '',
    https_proxy: cfg.httpsProxy || '',
    no_proxy: cfg.noProxy || ''
  };

  return { env, dir, registryYamlPath };
}

function cleanup(dir) {
  fs.rm(dir, { recursive: true, force: true }, () => {});
}

module.exports = { buildScanEnv, cleanup };
