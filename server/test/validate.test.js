'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { isValidImageRef } = require('../src/validate');

test('accepts plausible image / OCI artifact references', () => {
  assert.equal(isValidImageRef('alpine:latest'), true);
  assert.equal(isValidImageRef('docker.io/library/nginx:1.27'), true);
  assert.equal(isValidImageRef('registry.example.com:5000/team/app@sha256:' + 'a'.repeat(64)), true);
  assert.equal(isValidImageRef('ghcr.io/org/artifact:oci-1.0.0'), true);
});

test('rejects empty, non-string or malformed references', () => {
  assert.equal(isValidImageRef(''), false);
  assert.equal(isValidImageRef('   '), false);
  assert.equal(isValidImageRef(undefined), false);
  assert.equal(isValidImageRef(null), false);
  assert.equal(isValidImageRef(42), false);
  assert.equal(isValidImageRef(' alpine:latest'), false);
  assert.equal(isValidImageRef('alpine latest'), false);
  assert.equal(isValidImageRef('image;rm -rf /'), false);
  assert.equal(isValidImageRef('$(whoami)'), false);
  assert.equal(isValidImageRef('`id`'), false);
});
