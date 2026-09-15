'use strict';
// Every catalogue entry must: pass the lightweight schema check, have a filename
// equal to its id, actually blow up super-linearly when its attack recipe is run
// (proven by measurement in a killable worker), keep a benign input fast, and have
// an empirical complexity class that matches its declared label. This is what makes
// redos-db self-verifying rather than a hand-maintained list.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { validateEntry } = require('../lib/validate');
const { verifyEntry } = require('../lib/verify');

const DATA = path.join(__dirname, '..', 'data');
const files = fs.readdirSync(DATA).filter((f) => f.endsWith('.json'));

test('the catalogue is non-empty', () => {
  assert.ok(files.length >= 1, 'expected at least one entry');
});

const seen = new Set();
for (const f of files) {
  const e = JSON.parse(fs.readFileSync(path.join(DATA, f), 'utf8'));

  test(`${f}: schema + filename`, () => {
    const errs = validateEntry(e);
    assert.deepStrictEqual(errs, [], 'schema errors: ' + errs.join('; '));
    assert.strictEqual(path.basename(f, '.json'), e.id, 'filename must equal id');
    assert.ok(!seen.has(e.id), 'duplicate id ' + e.id);
    seen.add(e.id);
  });

  test(`${e.id}: measured ReDoS blow-up + class`, { timeout: 60000 }, async () => {
    const v = await verifyEntry(e);
    assert.ok(v.ok, `${e.id}: ${v.reason}`);
    assert.ok(v.benignMs < 30, `${e.id}: benign input too slow (${v.benignMs}ms)`);
    assert.ok(v.classAgrees, `${e.id}: empirical class ${v.empiricalClass} != declared ${v.declaredClass}`);
  });
}
