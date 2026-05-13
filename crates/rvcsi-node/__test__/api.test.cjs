'use strict';

// Structural smoke test for the @ruv/rvcsi JS surface.
//
// Importing the package never throws (the native addon loads lazily). This test
// asserts the public API shape; if the .node addon HAS been built (e.g. CI ran
// `npm run build` first), it also checks `rvcsiVersion()` returns a string —
// otherwise it asserts the error message is the helpful "not built" one.
//
// Run with: node --test  (Node >= 18)

const test = require('node:test');
const assert = require('node:assert/strict');
const rvcsi = require('../index.js');

test('exports the expected functions and class', () => {
  for (const fn of [
    'rvcsiVersion',
    'nexmonShimAbiVersion',
    'nexmonDecodeRecords',
    'nexmonDecodePcap',
    'inspectNexmonPcap',
    'decodeChanspec',
    'nexmonChipName',
    'nexmonProfile',
    'nexmonChips',
    'inspectCaptureFile',
    'eventsFromCaptureFile',
    'exportCaptureToRfMemory',
  ]) {
    assert.equal(typeof rvcsi[fn], 'function', `${fn} should be a function`);
  }
  assert.equal(typeof rvcsi.RvCsi, 'function', 'RvCsi should be a class');
  assert.equal(typeof rvcsi.RvCsi.openCaptureFile, 'function');
  assert.equal(typeof rvcsi.RvCsi.openNexmonFile, 'function');
  assert.equal(typeof rvcsi.RvCsi.openNexmonPcap, 'function');
});

test('native calls either work (addon built) or fail with a helpful message', () => {
  try {
    const v = rvcsi.rvcsiVersion();
    assert.equal(typeof v, 'string');
    assert.match(v, /^\d+\.\d+\.\d+/);
    assert.equal(typeof rvcsi.nexmonShimAbiVersion(), 'number');
  } catch (e) {
    assert.match(e.message, /native addon is not built/i);
  }
});
