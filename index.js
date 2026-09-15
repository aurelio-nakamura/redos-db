'use strict';
// Programmatic access to the catalogue.
//   const redos = require('redos-db');
//   redos.entries            -> array of entries (with verification + visualize URL)
//   redos.byId('mime-CVE-2017-16138')
//   redos.filter({ type:'cve', complexity:'exponential' })
//   redos.attackString(entry, 50000)  -> a malicious input string for an entry
//
// The data is the generated dist/redos-db.json. Regenerate with `npm run build`.
const db = require('./dist/redos-db.json');

function attackString(entry, n) {
  const a = entry.attack;
  return (a.prefix || '') + (a.pad || '').repeat(n) + (a.suffix || '');
}

function filter(opts) {
  opts = opts || {};
  return db.entries.filter((e) =>
    (opts.type == null || e.type === opts.type) &&
    (opts.complexity == null || e.complexity === opts.complexity) &&
    (opts.ecosystem == null || e.ecosystem === opts.ecosystem));
}

function byId(id) { return db.entries.find((e) => e.id === id) || null; }

module.exports = {
  meta: { name: db.name, version: db.count, generated: db.generated, verified: db.verified },
  entries: db.entries,
  count: db.count,
  countsByType: db.counts_by_type,
  countsByComplexity: db.counts_by_complexity,
  byId,
  filter,
  attackString,
};
