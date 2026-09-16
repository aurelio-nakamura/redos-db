'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { satisfies, compareVersions } = require('../lib/version-range');
const { matchInstalled, parsePipFreeze, auditProject, collectNpm } = require('../lib/audit');
const db = require('../index.js');

test('compareVersions handles multi-digit + missing segments', () => {
  assert.strictEqual(compareVersions('1.26.10', '1.26.9'), 1);
  assert.strictEqual(compareVersions('2.2', '2.2.0'), 0);
  assert.strictEqual(compareVersions('1.0.0', '1.0.1'), -1);
  assert.strictEqual(compareVersions('v5.0.1', '5.0.1'), 0);
});

test('prerelease sorts below its release', () => {
  assert.strictEqual(compareVersions('1.0.0-beta.1', '1.0.0'), -1);
  assert.ok(satisfies('1.0.0-beta.1', '<1.0.0'));
});

test('satisfies: OR / AND / boundaries', () => {
  const range = '<3.0.1 || >=4.0.0 <4.1.1 || >=5.0.0 <5.0.1';
  assert.ok(satisfies('4.1.0', range));
  assert.ok(!satisfies('4.1.1', range)); // exclusive upper bound
  assert.ok(!satisfies('5.0.1', range)); // patched
  assert.ok(satisfies('2.0.0', range));
  assert.ok(!satisfies('9.9.9', range)); // outside every clause
  assert.ok(satisfies('9.9.9', '*'));    // wildcard
});

test('satisfies is false for unparseable version', () => {
  assert.ok(!satisfies('not-a-version', '<1.0.0'));
});

test('parsePipFreeze extracts pinned versions only', () => {
  const rows = parsePipFreeze([
    'urllib3==1.26.4',
    'requests==2.31.0  # comment',
    '-e git+https://example.com/x.git#egg=x',
    'flask>=2.0        ', // not pinned -> skipped
    '',
    'Django == 2.2.3',
  ].join('\n'));
  const map = Object.fromEntries(rows.map((r) => [r.name.toLowerCase(), r.version]));
  assert.strictEqual(map['urllib3'], '1.26.4');
  assert.strictEqual(map['django'], '2.2.3');
  assert.ok(!('flask' in map));
});

test('matchInstalled flags vulnerable, ignores safe + patched', () => {
  const installed = [
    { ecosystem: 'npm', name: 'ansi-regex', version: '4.1.0' }, // vulnerable
    { ecosystem: 'npm', name: 'ansi-regex', version: '5.0.1' }, // patched
    { ecosystem: 'npm', name: 'totally-safe', version: '1.0.0' },
    { ecosystem: 'pypi', name: 'urllib3', version: '1.26.4' },  // vulnerable
    { ecosystem: 'pypi', name: 'urllib3', version: '1.26.5' },  // patched
  ];
  const findings = matchInstalled(installed, db.entries);
  const keys = findings.map((f) => `${f.ecosystem}:${f.package}@${f.version}`);
  assert.ok(keys.includes('npm:ansi-regex@4.1.0'));
  assert.ok(keys.includes('pypi:urllib3@1.26.4'));
  assert.ok(!keys.some((k) => k.includes('5.0.1')));
  assert.ok(!keys.some((k) => k.includes('1.26.5')));
  assert.ok(!keys.some((k) => k.includes('totally-safe')));
  for (const f of findings) {
    assert.match(f.reproduction, /^https:\/\/aurelio-nakamura\.github\.io\/redos-db\/entry\/.+\.html$/);
  }
});

test('pypi name normalization (case / underscore) matches', () => {
  // Django is stored capitalised; installed as lowercase should still match.
  const findings = matchInstalled(
    [{ ecosystem: 'pypi', name: 'django', version: '2.2.3' }], db.entries);
  assert.ok(findings.some((f) => /CVE-2019-14232/.test(f.cve || '')));
});

test('collectNpm reads a node_modules tree', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redosdb-'));
  const mk = (name, version) => {
    const d = path.join(dir, 'node_modules', name);
    fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ name, version }));
  };
  mk('ansi-regex', '4.1.0');
  fs.mkdirSync(path.join(dir, 'node_modules', '@scope', 'pkg'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'node_modules', '@scope', 'pkg', 'package.json'),
    JSON.stringify({ name: '@scope/pkg', version: '1.2.3' }));
  const deps = collectNpm(dir);
  const names = deps.map((d) => d.name);
  assert.ok(names.includes('ansi-regex'));
  assert.ok(names.includes('@scope/pkg'));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('auditProject: end-to-end exit-worthy findings', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redosdb-proj-'));
  const d = path.join(dir, 'node_modules', 'ansi-regex');
  fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ name: 'ansi-regex', version: '4.1.0' }));
  fs.writeFileSync(path.join(dir, 'requirements.txt'), 'urllib3==1.26.4\nrequests==2.31.0\n');
  const res = auditProject(dir, db.entries);
  assert.strictEqual(res.scanned.pypi, 2);
  assert.ok(res.findings.length >= 2);
  fs.rmSync(dir, { recursive: true, force: true });
});
