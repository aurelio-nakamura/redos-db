'use strict';
// Build the machine-readable database + the static-site data.
//
//   node lib/build.js             deterministic build: validates every entry and
//                                 writes the canonical dist/redos-db.json (no
//                                 timings, no timestamp — reproducible, so CI can
//                                 diff it) plus a docs/db.json for the site.
//
//   node lib/build.js --measure   additionally *runs* every entry's attack in a
//                                 killable worker, fails on anything that does not
//                                 blow up super-linearly, and writes docs/db.json
//                                 enriched with the measured timing curve. Used by
//                                 the Pages deploy so the live site shows real
//                                 numbers. The canonical dist file stays identical.
const fs = require('fs');
const path = require('path');
const { validateEntry } = require('./validate');
const { verifyEntry, buildInput } = require('./verify');
const { generatePages } = require('./gen_pages');

const ROOT = path.join(__dirname, '..');
const DATA = path.join(ROOT, 'data');
const DIST = path.join(ROOT, 'dist');
const DOCS = path.join(ROOT, 'docs');
const MELTDOWN = 'https://aurelio-nakamura.github.io/regex-meltdown/';
const DEMO_PUMP = { exponential: 28, cubic: 600, quadratic: 4000 };

function visualizeUrl(e) {
  const n = DEMO_PUMP[e.complexity] || 2000;
  return MELTDOWN + '#re=' + encodeURIComponent(e.regex) + '&in=' + encodeURIComponent(buildInput(e.attack, n));
}

function loadEntries() {
  const files = fs.readdirSync(DATA).filter((f) => f.endsWith('.json')).sort();
  const entries = [];
  const errors = [];
  const ids = new Set();
  for (const f of files) {
    let e;
    try { e = JSON.parse(fs.readFileSync(path.join(DATA, f), 'utf8')); }
    catch (err) { errors.push(`${f}: invalid JSON - ${err.message}`); continue; }
    const errs = validateEntry(e);
    if (e.id && ids.has(e.id)) errs.push('duplicate id');
    if (e.id) ids.add(e.id);
    if (path.basename(f, '.json') !== e.id) errs.push(`filename must equal id (${e.id}.json)`);
    for (const m of errs) errors.push(`${f}: ${m}`);
    entries.push(e);
  }
  return { entries, errors };
}

function canonical(entries) {
  const out = entries.map((e) => Object.assign({}, e, { visualize: visualizeUrl(e) }));
  return {
    name: 'redos-db',
    description: 'A curated, machine-readable, self-verifying catalogue of real-world ReDoS vulnerabilities.',
    homepage: 'https://github.com/aurelio-nakamura/redos-db',
    maintainer: 'Aurelio Nakamura (autonomous AI agent)',
    license: 'MIT',
    schema: 'schema/entry.schema.json',
    count: out.length,
    counts_by_type: out.reduce((m, e) => (m[e.type] = (m[e.type] || 0) + 1, m), {}),
    counts_by_complexity: out.reduce((m, e) => (m[e.complexity] = (m[e.complexity] || 0) + 1, m), {}),
    entries: out,
  };
}

async function main() {
  const measure = process.argv.includes('--measure');
  const { entries, errors } = loadEntries();
  if (errors.length) {
    console.error('SCHEMA ERRORS:\n' + errors.map((e) => '  - ' + e).join('\n'));
    process.exit(1);
  }

  // Canonical, deterministic artifact (committed + shipped on npm).
  const db = canonical(entries);
  fs.mkdirSync(DIST, { recursive: true });
  fs.writeFileSync(path.join(DIST, 'redos-db.json'), JSON.stringify(db, null, 2) + '\n');

  // Site data. Default = a copy of canonical so the page always works.
  let site = Object.assign({ generated: null, verified: false }, db);

  if (measure) {
    console.log('Measuring every entry (killable worker, benign must stay fast)…');
    const enriched = [];
    for (const e of db.entries) {
      const v = await verifyEntry(e);
      if (!v.ok) { console.error(`VERIFY FAILED: ${e.id}: ${v.reason}`); process.exit(1); }
      const tag = v.classAgrees ? 'ok' : 'CLASS MISMATCH';
      console.log(`  ${e.id.padEnd(32)} ${v.empiricalClass} (${tag})`);
      enriched.push(Object.assign({}, e, {
        verification: {
          engine: v.engineLabel || `node ${process.version}`,
          benign_ms: v.benignMs,
          curve: v.points.map((p) => ({
            input_length: e.attack.prefix.length + e.attack.pad.length * p.n + e.attack.suffix.length,
            pumps: p.n,
            ms: p.timedOut ? null : p.ms,
            timed_out: !!p.timedOut,
          })),
          empirical_class: v.empiricalClass,
          class_agrees: v.classAgrees,
        },
      }));
    }
    site = Object.assign({}, db, { generated: new Date().toISOString(), verified: true, entries: enriched });
  }

  fs.mkdirSync(DOCS, { recursive: true });
  fs.writeFileSync(path.join(DOCS, 'db.json'), JSON.stringify(site) + '\n');

  // Static, JS-free, indexable page per entry + sitemap + robots (SEO/citation).
  const { pages } = generatePages(site);

  console.log(`\nWrote dist/redos-db.json (canonical, ${db.count} entries), docs/db.json (measured=${measure}), and ${pages} static entry pages + sitemap.xml.`);
}

main().catch((e) => { console.error(e); process.exit(1); });
