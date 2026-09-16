'use strict';
// Zero-dependency version comparison + range satisfier for the `affected`
// strings in the catalogue (e.g. "<3.0.1 || >=4.0.0 <4.1.1 || >=5.0.0 <5.0.1").
//
// Supported grammar (a subset of npm semver, deliberately small and auditable):
//   range      := orClause ("||" orClause)*
//   orClause   := comparator (WS comparator)*        // implicit AND
//   comparator := ("<" | "<=" | ">" | ">=" | "=" )? version
//   version    := numeric release segments (dots/other separators), optional
//                 pre-release tail after "-" (compared "loosely").
//
// Comparison is "loose": a version is split into numeric release segments and
// compared segment-by-segment (missing segments = 0). This is correct for the
// pinned release versions that appear in security advisories across both npm
// (semver) and PyPI (PEP 440 release numbers). Pre-release ordering is
// approximated (a version WITH a pre-release tail sorts just below the same
// release without one); it is not full semver/PEP 440 pre-release precedence.
// Callers needing strict prerelease semantics should not rely on this.

function parseVersion(v) {
  if (v == null) return null;
  let s = String(v).trim();
  // strip common leading tokens
  s = s.replace(/^[vV=]+/, '').trim();
  if (!s) return null;
  // separate release from pre-release/build metadata
  let rel = s;
  let pre = '';
  const dash = s.indexOf('-');
  if (dash !== -1) { rel = s.slice(0, dash); pre = s.slice(dash + 1); }
  // PEP 440 pre-release without a dash, e.g. 1.0.0rc1 / 2.0b2 / 1.2a1 / 1.0.dev1
  const m = rel.match(/^([0-9][0-9.]*?)(?:\.)?((?:a|b|c|rc|alpha|beta|dev|post)[0-9.]*)$/i);
  if (m) { rel = m[1]; if (!pre) pre = m[2]; }
  const nums = rel.split(/[^0-9]+/).filter((x) => x !== '').map((x) => parseInt(x, 10));
  if (nums.length === 0) return null;
  return { nums, pre };
}

function compareCore(a, b) {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a[i] == null ? 0 : a[i];
    const y = b[i] == null ? 0 : b[i];
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// Compare two version strings. Returns -1 / 0 / 1, or null if either is unparseable.
function compareVersions(av, bv) {
  const a = parseVersion(av);
  const b = parseVersion(bv);
  if (!a || !b) return null;
  const c = compareCore(a.nums, b.nums);
  if (c !== 0) return c;
  // equal release: a pre-release sorts below a non-pre-release
  if (a.pre && !b.pre) return -1;
  if (!a.pre && b.pre) return 1;
  if (a.pre && b.pre) return a.pre < b.pre ? -1 : a.pre > b.pre ? 1 : 0;
  return 0;
}

function satisfiesComparator(version, comp) {
  const m = comp.match(/^(<=|>=|<|>|=|==)?\s*(.+)$/);
  if (!m) return false;
  const op = m[1] || '=';
  const c = compareVersions(version, m[2]);
  if (c == null) return false;
  switch (op) {
    case '<': return c < 0;
    case '<=': return c <= 0;
    case '>': return c > 0;
    case '>=': return c >= 0;
    case '=':
    case '==': return c === 0;
    default: return false;
  }
}

// Does `version` satisfy the advisory `range` string?
function satisfies(version, range) {
  if (!range || String(range).trim() === '' || String(range).trim() === '*') return true;
  if (!parseVersion(version)) return false;
  const orClauses = String(range).split('||');
  for (const clause of orClauses) {
    const comps = clause.trim().split(/\s+/).filter(Boolean);
    if (comps.length === 0) continue;
    let all = true;
    for (const comp of comps) {
      if (!satisfiesComparator(version, comp)) { all = false; break; }
    }
    if (all) return true;
  }
  return false;
}

module.exports = { satisfies, compareVersions, parseVersion };
