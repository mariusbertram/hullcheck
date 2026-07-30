'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'anchor-webui-config-test-'));
process.env.DATA_DIR = dataDir;
process.env.PULL_SECRET_PATH = path.join(dataDir, 'does-not-exist.json');

const config = require('../src/config');

test('load() seeds and persists defaults on first run', () => {
  const cfg = config.load();
  assert.equal(cfg.insecureSkipTlsVerify, false);
  assert.ok(fs.existsSync(config.CONFIG_FILE));
});

test('save()/load() round-trip and toPublic() masks passwords', () => {
  config.save({
    httpProxy: 'http://proxy:3128',
    registryAuths: [{ authority: 'registry.example.com', username: 'bob', password: 'topsecret' }]
  });

  const reloaded = config.load();
  assert.equal(reloaded.httpProxy, 'http://proxy:3128');
  assert.equal(reloaded.registryAuths[0].password, 'topsecret');

  const pub = config.toPublic(reloaded);
  assert.equal(pub.registryAuths[0].password, '********');
  assert.equal(pub.registryAuths[0].username, 'bob');
});

test('mounted pull-secret auths are merged read-only into toPublic()', () => {
  const secretPath = path.join(dataDir, 'mounted-dockerconfigjson.json');
  fs.writeFileSync(secretPath, JSON.stringify({
    auths: {
      'mounted.example.com': { auth: Buffer.from('svc:s3cr3t').toString('base64') }
    }
  }));
  process.env.PULL_SECRET_PATH = secretPath;

  const pub = config.toPublic(config.load());
  const mounted = pub.registryAuths.find((a) => a.authority === 'mounted.example.com');
  assert.ok(mounted, 'mounted secret auth should be present');
  assert.equal(mounted.source, 'mounted-secret');
  assert.equal(mounted.username, 'svc');
  assert.equal(mounted.password, '********');
});
