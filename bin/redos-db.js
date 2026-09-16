#!/usr/bin/env node
'use strict';
// redos-db CLI. The headline command is `audit`: scan a project's installed
// dependencies for versions with a catalogued, self-verified ReDoS vulnerability.
const db = require('../index.js');
const { auditProject, matchInstalled, parsePipFreeze } = require('../lib/audit.js');

function readStdin() {
  try { return require('fs').readFileSync(0, 'utf8'); } catch (_) { return ''; }
}

const HELP = `redos-db — catalogue of real-world ReDoS vulnerabilities (${db.count} verified entries)

Usage:
  redos-db audit [dir]        Scan a project for dependencies with a known ReDoS CVE
  redos-db list               List all catalogued entries
  redos-db show <id>          Print one entry as JSON
  redos-db --version          Print the catalogue size / package version

Audit options:
  --json                      Machine-readable output
  --pip -                     Also read \`pip freeze\` output from stdin
  Exit code is 1 if any vulnerable dependency is found (CI-friendly), else 0.

Examples:
  redos-db audit
  redos-db audit ./my-project --json
  pip freeze | redos-db audit --pip -

Built and maintained by Aurelio Nakamura, an autonomous AI agent.`;

function cmdAudit(args) {
  const json = args.includes('--json');
  const pipStdin = args.includes('--pip') && args[args.indexOf('--pip') + 1] === '-';
  const dir = args.find((a) => !a.startsWith('-') && a !== '-') || process.cwd();

  const res = auditProject(dir, db.entries);
  if (pipStdin) {
    const extra = parsePipFreeze(readStdin());
    const extraFindings = matchInstalled(extra, db.entries);
    res.installed.push(...extra);
    res.scanned.pypi += extra.length;
    res.findings.push(...extraFindings);
  }

  if (json) {
    process.stdout.write(JSON.stringify(res, null, 2) + '\n');
    process.exit(res.findings.length ? 1 : 0);
  }

  const { npm, pypi } = res.scanned;
  console.log(`redos-db audit — scanned ${npm} npm + ${pypi} pypi dependencies in ${res.dir}`);
  if (res.findings.length === 0) {
    console.log('\n\u2713 No dependencies matched a catalogued ReDoS vulnerability.');
    if (npm + pypi === 0) {
      console.log('  (Nothing to scan: no package-lock.json / node_modules / requirements.txt found.)');
    }
    process.exit(0);
  }
  console.log(`\n\u2717 Found ${res.findings.length} vulnerable dependenc${res.findings.length === 1 ? 'y' : 'ies'}:\n`);
  for (const f of res.findings) {
    const id = f.cve || f.ghsa || f.id;
    console.log(`  ${f.package}@${f.version}  [${f.ecosystem}]  ${id}  (${f.complexity} backtracking)`);
    console.log(`      affected: ${f.affected}`);
    console.log(`      fixed in: ${f.patched || 'see advisory'}`);
    console.log(`      reproduction: ${f.reproduction}`);
    console.log('');
  }
  console.log('Each finding links to a runnable, measured reproduction. Upgrade to the fixed version.');
  process.exit(1);
}

function cmdList() {
  for (const e of db.entries) {
    const id = e.cve || e.ghsa || '';
    console.log(`${e.id.padEnd(34)} ${(e.ecosystem || '').padEnd(6)} ${(e.complexity || '').padEnd(11)} ${id}`);
  }
}

function cmdShow(id) {
  if (!id) { console.error('usage: redos-db show <id>'); process.exit(2); }
  const e = db.byId(id) || db.entries.find((x) => x.cve === id || x.ghsa === id);
  if (!e) { console.error(`no entry with id/cve/ghsa "${id}"`); process.exit(2); }
  console.log(JSON.stringify(e, null, 2));
}

function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const rest = argv.slice(1);
  switch (cmd) {
    case 'audit': return cmdAudit(rest);
    case 'list': return cmdList();
    case 'show': return cmdShow(rest[0]);
    case '--version':
    case '-v': console.log(`redos-db catalogue: ${db.count} entries`); return;
    case undefined:
    case '-h':
    case '--help':
    case 'help': console.log(HELP); return;
    default:
      console.error(`unknown command "${cmd}"\n`);
      console.log(HELP);
      process.exit(2);
  }
}

main();
