'use strict';
// Tiny dependency-free schema check for catalogue entries. Not a full JSON-Schema
// validator; it enforces exactly the invariants the catalogue relies on so the
// package stays zero-dependency. The canonical schema lives in schema/entry.schema.json.

function isStr(x) { return typeof x === 'string'; }
function isStrOrNull(x) { return x === null || typeof x === 'string'; }

const COMPLEXITY = ['quadratic', 'cubic', 'exponential'];
const TYPES = ['cve', 'classic'];
const FIX_TYPES = ['regex-rewrite', 'algorithm-change', 'input-limit', 'guidance'];
const ENGINES = ['javascript', 'python'];

function validateEntry(e) {
  const errs = [];
  const req = (cond, msg) => { if (!cond) errs.push(msg); };

  req(isStr(e.id) && /^[a-zA-Z0-9._-]+$/.test(e.id), 'id must be a slug string');
  req(isStr(e.name), 'name must be a string');
  req(TYPES.includes(e.type), 'type must be cve|classic');
  req(isStr(e.ecosystem), 'ecosystem must be a string');
  const engine = e.engine === undefined ? 'javascript' : e.engine;
  req(ENGINES.includes(engine), 'engine must be javascript|python');
  req(isStr(e.regex), 'regex must be a string');
  // JavaScript-engine entries must compile under V8's RegExp here. Python-engine
  // entries may use PCRE/Python-only syntax (e.g. (?P<name>...)); their regex is
  // compile-checked and measured by the out-of-process Python verifier instead.
  if (isStr(e.regex) && engine === 'javascript') {
    try { new RegExp(e.regex, e.flags || ''); }
    catch (err) { errs.push('regex does not compile: ' + err.message); }
  }
  req(isStr(e.flags), 'flags must be a string');
  req(COMPLEXITY.includes(e.complexity), 'complexity must be quadratic|cubic|exponential');
  req(isStr(e.benign), 'benign must be a string');
  req(isStr(e.description) && e.description.length > 20, 'description must be a non-trivial string');
  req(Array.isArray(e.references) && e.references.length >= 1 && e.references.every(isStr), 'references must be a non-empty string array');

  req(['cve', 'classic'].includes(e.type), 'type');
  if (e.type === 'cve') {
    req(isStr(e.cve) || isStr(e.ghsa), 'cve entries need a cve or ghsa id');
    req(isStr(e.package), 'cve entries need a package');
  }

  const a = e.attack;
  req(a && typeof a === 'object', 'attack must be an object');
  if (a && typeof a === 'object') {
    req(isStr(a.prefix), 'attack.prefix must be a string');
    req(isStr(a.pad) && a.pad.length >= 1, 'attack.pad must be a non-empty string');
    req(isStr(a.suffix), 'attack.suffix must be a string');
    if (a.sizes !== undefined) req(Array.isArray(a.sizes) && a.sizes.every((n) => Number.isInteger(n)), 'attack.sizes must be integers');
  }

  const f = e.fix;
  req(f && typeof f === 'object', 'fix must be an object');
  if (f && typeof f === 'object') {
    req(FIX_TYPES.includes(f.type), 'fix.type must be regex-rewrite|algorithm-change|input-limit|guidance');
    req(isStr(f.summary) && f.summary.length > 10, 'fix.summary must be a real string');
    req(f.patched_regex === undefined || isStrOrNull(f.patched_regex), 'fix.patched_regex must be string|null');
    if (isStr(f.patched_regex) && engine === 'javascript') {
      try { new RegExp(f.patched_regex, e.flags || ''); }
      catch (err) { errs.push('fix.patched_regex does not compile: ' + err.message); }
    }
    req(f.commit === undefined || isStrOrNull(f.commit), 'fix.commit must be string|null');
  }

  return errs;
}

module.exports = { validateEntry };
