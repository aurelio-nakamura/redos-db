'use strict';
// `redos-db audit` core: scan a project's installed dependencies for versions
// that match a catalogued, self-verified ReDoS vulnerability.
//
// Zero runtime dependencies. Reads what is actually installed / pinned:
//   - npm:  package-lock.json (v1/v2/v3) or a node_modules/ tree
//   - pypi: a pinned requirements file (name==version) or `pip freeze` output
//
// It reports only versions that fall inside an entry's `affected` range, so a
// finding means "this exact installed version is known-vulnerable", with the
// fixed version and a link to the runnable reproduction.
const fs = require('fs');
const path = require('path');
const { satisfies } = require('./version-range');

const ENTRY_PAGE = 'https://aurelio-nakamura.github.io/redos-db/entry/';

function norm(name) { return String(name || '').toLowerCase().replace(/_/g, '-'); }

// --- dependency collectors -------------------------------------------------

// Collect {name, version} pairs from an npm project directory.
function collectNpm(dir) {
  const found = new Map(); // key `${name}@${version}`
  const add = (name, version) => {
    if (!name || !version) return;
    found.set(name + '@' + version, { ecosystem: 'npm', name, version });
  };
  const lockPath = path.join(dir, 'package-lock.json');
  if (fs.existsSync(lockPath)) {
    let lock;
    try { lock = JSON.parse(fs.readFileSync(lockPath, 'utf8')); } catch (_) { lock = null; }
    if (lock) {
      // lockfile v2/v3: `packages` keyed by path
      if (lock.packages) {
        for (const [p, meta] of Object.entries(lock.packages)) {
          if (!p) continue; // root
          const name = meta.name || p.split('node_modules/').pop();
          if (name && meta.version) add(name, meta.version);
        }
      }
      // lockfile v1: nested `dependencies`
      const walk = (deps) => {
        if (!deps) return;
        for (const [name, meta] of Object.entries(deps)) {
          if (meta && meta.version) add(name, meta.version);
          if (meta && meta.dependencies) walk(meta.dependencies);
        }
      };
      walk(lock.dependencies);
    }
  }
  // Fallback / supplement: walk an installed node_modules tree.
  const nm = path.join(dir, 'node_modules');
  if (fs.existsSync(nm)) collectNodeModules(nm, add);
  return [...found.values()];
}

function collectNodeModules(nmDir, add) {
  let entries;
  try { entries = fs.readdirSync(nmDir, { withFileTypes: true }); } catch (_) { return; }
  for (const ent of entries) {
    if (!ent.isDirectory() && !ent.isSymbolicLink()) continue;
    if (ent.name === '.bin' || ent.name === '.cache') continue;
    const full = path.join(nmDir, ent.name);
    if (ent.name.startsWith('@')) {
      let scoped;
      try { scoped = fs.readdirSync(full, { withFileTypes: true }); } catch (_) { continue; }
      for (const s of scoped) {
        readPkg(path.join(full, s.name), add);
        const nested = path.join(full, s.name, 'node_modules');
        if (fs.existsSync(nested)) collectNodeModules(nested, add);
      }
    } else {
      readPkg(full, add);
      const nested = path.join(full, 'node_modules');
      if (fs.existsSync(nested)) collectNodeModules(nested, add);
    }
  }
}

function readPkg(pkgDir, add) {
  const pj = path.join(pkgDir, 'package.json');
  if (!fs.existsSync(pj)) return;
  try {
    const meta = JSON.parse(fs.readFileSync(pj, 'utf8'));
    if (meta.name && meta.version) add(meta.name, meta.version);
  } catch (_) { /* ignore */ }
}

// Parse `pip freeze` / pinned-requirements text into {name, version} pairs.
function parsePipFreeze(text) {
  const out = [];
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line || line.startsWith('-')) continue; // skip -e / -r / options
    const m = line.match(/^([A-Za-z0-9._-]+)\s*==\s*([^\s;]+)/);
    if (m) out.push({ ecosystem: 'pypi', name: m[1], version: m[2] });
  }
  return out;
}

function collectPip(dir) {
  const out = [];
  for (const fname of ['requirements.txt', 'requirements.lock']) {
    const p = path.join(dir, fname);
    if (fs.existsSync(p)) {
      try { out.push(...parsePipFreeze(fs.readFileSync(p, 'utf8'))); } catch (_) { /* ignore */ }
    }
  }
  return out;
}

// --- matching --------------------------------------------------------------

// Given a list of installed {ecosystem,name,version} and the catalogue entries,
// return findings (one per installed version that matches an affected entry).
function matchInstalled(installed, entries) {
  const byPkg = new Map(); // `${ecosystem}:${name}` -> [entries]
  for (const e of entries) {
    if (!e.package || !e.affected) continue;
    const eco = (e.ecosystem || 'npm').toLowerCase();
    const key = eco + ':' + norm(e.package);
    if (!byPkg.has(key)) byPkg.set(key, []);
    byPkg.get(key).push(e);
  }
  const findings = [];
  for (const dep of installed) {
    const eco = (dep.ecosystem || 'npm').toLowerCase();
    const key = eco + ':' + norm(dep.name);
    const candidates = byPkg.get(key);
    if (!candidates) continue;
    for (const e of candidates) {
      if (satisfies(dep.version, e.affected)) {
        findings.push({
          package: dep.name,
          version: dep.version,
          ecosystem: eco,
          id: e.id,
          cve: e.cve || null,
          ghsa: e.ghsa || null,
          complexity: e.complexity,
          affected: e.affected,
          patched: e.patched || null,
          summary: e.description,
          reproduction: ENTRY_PAGE + e.id + '.html',
        });
      }
    }
  }
  return findings;
}

// --- top-level -------------------------------------------------------------

// Audit a project directory. Returns { installed, findings, scanned:{npm,pypi} }.
function auditProject(dir, entries) {
  dir = dir || process.cwd();
  const npm = collectNpm(dir);
  const pip = collectPip(dir);
  const installed = npm.concat(pip);
  const findings = matchInstalled(installed, entries);
  return {
    dir,
    scanned: { npm: npm.length, pypi: pip.length },
    installed,
    findings,
  };
}

module.exports = {
  auditProject,
  matchInstalled,
  collectNpm,
  collectPip,
  parsePipFreeze,
};
