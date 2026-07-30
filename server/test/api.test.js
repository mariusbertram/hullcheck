'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'anchor-webui-api-test-'));

require('../src/scanner'); // registers the (real) job runner, same as production index.js
const { createApp } = require('../src/app');

let server;
let baseUrl;

test.before(async () => {
  const app = createApp();
  server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

test('GET /healthz and /readyz report ok', async () => {
  for (const path of ['/healthz', '/readyz']) {
    const res = await fetch(baseUrl + path);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { status: 'ok' });
  }
});

test('GET /api/config returns defaults, PUT updates and masks secrets', async () => {
  const before = await (await fetch(baseUrl + '/api/config')).json();
  assert.equal(before.insecureSkipTlsVerify, false);

  const put = await fetch(baseUrl + '/api/config', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      httpsProxy: 'http://proxy:3128',
      registryAuths: [{ authority: 'registry.example.com', username: 'alice', password: 'hunter2' }]
    })
  });
  assert.equal(put.status, 200);
  const updated = await put.json();
  assert.equal(updated.httpsProxy, 'http://proxy:3128');
  assert.equal(updated.registryAuths[0].password, '********');
});

test('POST /api/scans rejects an invalid image reference', async () => {
  const res = await fetch(baseUrl + '/api/scans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ image: '' })
  });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.ok(body.error);
});

test('POST /api/scans accepts a valid reference and the job shows up in history', async () => {
  const res = await fetch(baseUrl + '/api/scans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ image: 'alpine:latest' })
  });
  assert.equal(res.status, 201);
  const job = await res.json();
  assert.ok(job.id);
  assert.equal(job.image, 'alpine:latest');
  assert.deepEqual(Object.keys(job.tools).sort(), ['grant', 'grype', 'syft']);

  const detail = await (await fetch(`${baseUrl}/api/scans/${job.id}`)).json();
  assert.equal(detail.id, job.id);

  const history = await (await fetch(baseUrl + '/api/scans')).json();
  assert.ok(history.some((j) => j.id === job.id));
});

test('GET /api/scans/:id/artifacts/:name 404s for an unknown job', async () => {
  const res = await fetch(baseUrl + '/api/scans/does-not-exist/artifacts/sbom.json');
  assert.equal(res.status, 404);
});

test('static frontend is served, unknown non-API routes fall back to index.html', async () => {
  const res = await fetch(baseUrl + '/some/client/route');
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.match(text, /Anchor WebUI/);
});
