'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'anchor-webui-scanner-test-'));

const { summarizeGrype, summarizeSyft, summarizeGrant } = require('../src/scanner');

test('summarizeGrype counts matches by severity', () => {
  const summary = summarizeGrype({
    matches: [
      { vulnerability: { severity: 'Critical' } },
      { vulnerability: { severity: 'High' } },
      { vulnerability: { severity: 'High' } },
      { vulnerability: { severity: 'Low' } }
    ]
  });
  assert.equal(summary.total, 4);
  assert.deepEqual(summary.bySeverity, { critical: 1, high: 2, low: 1 });
});

test('summarizeGrype returns null for missing/malformed input', () => {
  assert.equal(summarizeGrype(null), null);
  assert.equal(summarizeGrype({}), null);
});

test('summarizeSyft counts packages by type and reads distro', () => {
  const summary = summarizeSyft({
    artifacts: [{ type: 'apk' }, { type: 'apk' }, { type: 'npm' }],
    distro: { prettyName: 'Alpine Linux', versionID: '3.20' }
  });
  assert.equal(summary.packageCount, 3);
  assert.deepEqual(summary.byType, { apk: 2, npm: 1 });
  assert.equal(summary.distro, 'Alpine Linux 3.20');
});

test('summarizeGrant aggregates license names and flags packages without one', () => {
  const summary = summarizeGrant({
    packages: [
      { licenses: ['MIT'] },
      { licenses: [{ name: 'Apache-2.0' }] },
      { licenses: ['MIT'] },
      { licenses: [] }
    ]
  });
  assert.equal(summary.packageCount, 4);
  assert.deepEqual(summary.licenseCounts, { MIT: 2, 'Apache-2.0': 1 });
  assert.equal(summary.withoutLicense, 1);
});

test('summarizeGrant degrades gracefully on an unrecognized shape', () => {
  assert.equal(summarizeGrant(null), null);
  // no packages/results array found at all -> treated as zero packages
  assert.deepEqual(summarizeGrant({ somethingElse: true }), { packageCount: 0, licenseCounts: {}, withoutLicense: 0 });
  // packages/results present but not an array -> explicit raw fallback
  assert.deepEqual(summarizeGrant({ packages: 'not-an-array' }), { raw: true });
});
