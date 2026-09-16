'use strict';
// Static per-entry page generator.
//
// The browse UI (docs/index.html) is a client-rendered SPA — great for humans,
// invisible to search engines. This module renders one fully-static, JS-free
// HTML page per catalogue entry (docs/entry/<id>.html) plus a sitemap.xml and
// robots.txt, so each real-world ReDoS CVE has its own indexable, linkable,
// citable page (title, meta description, the vulnerable regex, the attack, the
// fix, and — when measured — the timing curve, all present in the initial HTML).
const fs = require('fs');
const path = require('path');

const SITE = 'https://aurelio-nakamura.github.io/redos-db';
const REDOSRAY = 'https://github.com/aurelio-nakamura/redosray';

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const COMPLEXITY_LABEL = {
  exponential: 'exponential (2ⁿ)',
  cubic: 'cubic (n³)',
  quadratic: 'quadratic (n²)',
};

const CSS = `:root{--bg:#0e1116;--panel:#161b22;--line:#232a33;--fg:#e6edf3;--mut:#8b98a5;--acc:#f0883e;--red:#f85149;--amber:#e3b341;--grn:#3fb950;--blu:#58a6ff;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--blu);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:820px;margin:0 auto;padding:26px 20px 70px}
.crumb{color:var(--mut);font-size:13px;margin:0 0 18px}
h1{font-size:26px;margin:0 0 4px;letter-spacing:-.4px}
h1 .cve{color:var(--acc)}
.sub{color:var(--mut);margin:0 0 16px}
.badges{display:flex;gap:7px;flex-wrap:wrap;margin:0 0 20px}
.badge{font-size:11.5px;font-weight:600;padding:2px 9px;border-radius:999px;border:1px solid var(--line);color:var(--mut)}
.b-exp{color:var(--red);border-color:#5b2222}.b-quad{color:var(--amber);border-color:#5a4a1e}.b-cubic{color:var(--acc);border-color:#5a3a1e}
.b-cve{color:var(--blu);border-color:#20406b}.b-classic{color:var(--grn);border-color:#1e502e}.b-engine{color:#7aa2f7;border-color:#2b3a67}
.desc{color:#c9d4de;font-size:15.5px;margin:0 0 22px}
h2{font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin:24px 0 8px;font-weight:650}
.re{font-family:var(--mono);font-size:13.5px;background:#0b0e13;border:1px solid var(--line);border-radius:8px;padding:12px 14px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;color:#ffd9b3}
.re.fix{color:#b3f0c8}
table{border-collapse:collapse;width:100%;font-size:14px}
td{padding:5px 10px 5px 0;vertical-align:top}
td.k{color:var(--mut);white-space:nowrap;width:150px}
.mono{font-family:var(--mono)}
ul{margin:6px 0;padding-left:20px}li{margin:3px 0}
.curve{width:100%;border-collapse:collapse;font-size:13px;margin-top:4px}
.curve th,.curve td{border:1px solid var(--line);padding:5px 9px;text-align:right}
.curve th{color:var(--mut);font-weight:600;background:var(--panel)}
.curve td:first-child,.curve th:first-child{text-align:left}
.cta{display:flex;gap:12px;flex-wrap:wrap;margin:26px 0 0}
.cta a{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:11px 15px;font-size:14px;font-weight:600}
.cta a.hot{border-color:#5a3a1e;color:var(--acc)}
.foot{color:var(--mut);font-size:12.5px;margin-top:34px;border-top:1px solid var(--line);padding-top:16px}`;

function cxClass(c) { return c === 'exponential' ? 'b-exp' : c === 'cubic' ? 'b-cubic' : c === 'quadratic' ? 'b-quad' : 'b-classic'; }

function curveTable(v) {
  if (!v || !v.curve || !v.curve.length) return '';
  const rows = v.curve.map((p) => {
    const ms = p.timed_out ? '<b style="color:var(--red)">timed out</b>' : (p.ms != null ? p.ms.toFixed(1) + ' ms' : '—');
    return `<tr><td>${p.input_length}</td><td>${ms}</td></tr>`;
  }).join('');
  const eng = esc(v.engine || '');
  const benign = v.benign_ms != null ? v.benign_ms.toFixed(2) + ' ms' : '—';
  return `<h2>Measured blow-up</h2>
<p class="desc">Verified in CI on <span class="mono">${eng}</span>: the real regex run against a growing malicious input in a killable worker. A benign input stays fast (${benign}); the empirical complexity (<b>${esc(v.empirical_class || '')}</b>) must match the declared label or the build fails.</p>
<table class="curve"><thead><tr><th>input length (chars)</th><th>match time</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function attackText(a) {
  const parts = [];
  if (a.prefix) parts.push(esc(JSON.stringify(a.prefix)) + ' then');
  parts.push('a run of ' + esc(JSON.stringify(a.pad)));
  if (a.suffix) parts.push('then ' + esc(JSON.stringify(a.suffix)));
  return parts.join(' ');
}

function page(e) {
  const title = e.cve
    ? `${e.name} ${e.cve} — ReDoS regex, attack & fix`
    : `${e.name} — catastrophic backtracking (ReDoS) example`;
  const cxLabel = COMPLEXITY_LABEL[e.complexity] || e.complexity;
  const desc = e.cve
    ? `${e.cve} (${e.ghsa || e.cwe || 'ReDoS'}) in ${e.package} ${e.affected}: the vulnerable ${e.engine} regex backtracks ${cxLabel} on crafted input. Vulnerable pattern, a runnable attack string, the exact fix commit, and a measured timing curve.`
    : `${e.name}: a ${cxLabel} catastrophic-backtracking (ReDoS) regex, with a runnable attack string, the safe rewrite, and a measured timing curve.`;
  const url = `${SITE}/entry/${e.id}.html`;

  const badges = [`<span class="badge ${cxClass(e.complexity)}">${esc(e.complexity)}</span>`];
  if (e.type === 'cve') badges.push('<span class="badge b-cve">CVE</span>');
  else badges.push('<span class="badge b-classic">teaching</span>');
  badges.push(`<span class="badge b-engine">${esc(e.engine)}</span>`);

  const rows = [];
  if (e.cve) rows.push(['CVE', `<a href="https://nvd.nist.gov/vuln/detail/${esc(e.cve)}" rel="noopener">${esc(e.cve)}</a>`]);
  if (e.ghsa) rows.push(['GHSA', `<a href="https://github.com/advisories/${esc(e.ghsa)}" rel="noopener">${esc(e.ghsa)}</a>`]);
  if (e.cwe) rows.push(['Weakness', esc(e.cwe) + ' (Inefficient Regular Expression Complexity)']);
  if (e.package) rows.push(['Package', `<span class="mono">${esc(e.package)}</span>${e.ecosystem ? ' (' + esc(e.ecosystem) + ')' : ''}`]);
  if (e.affected) rows.push(['Affected', `<span class="mono">${esc(e.affected)}</span>`]);
  if (e.patched) rows.push(['Patched in', `<span class="mono">${esc(e.patched)}</span>`]);
  if (e.published) rows.push(['Published', esc(e.published)]);
  if (e.discovered_by) rows.push(['Discovered by', esc(e.discovered_by)]);
  rows.push(['Complexity', esc(cxLabel)]);
  const table = `<table>${rows.map((r) => `<tr><td class="k">${r[0]}</td><td>${r[1]}</td></tr>`).join('')}</table>`;

  const refs = (e.references || []).map((r) => `<li><a href="${esc(r)}" rel="noopener">${esc(r)}</a></li>`).join('');
  const fixCommit = e.fix && e.fix.commit ? `<p class="desc" style="margin-top:10px">Fix commit: <a href="${esc(e.fix.commit)}" rel="noopener" class="mono">${esc(e.fix.commit)}</a></p>` : '';

  const jsonld = {
    '@context': 'https://schema.org',
    '@type': 'TechArticle',
    headline: title,
    description: desc,
    url,
    keywords: ['ReDoS', 'catastrophic backtracking', 'regex', e.cve, e.cwe, e.package].filter(Boolean),
    author: { '@type': 'Person', name: 'Aurelio Nakamura' },
    isPartOf: { '@type': 'Dataset', name: 'redos-db', url: SITE + '/' },
  };
  if (e.published) jsonld.datePublished = e.published;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<link rel="icon" href="../favicon.svg" type="image/svg+xml" />
<title>${esc(title)} | redos-db</title>
<meta name="description" content="${esc(desc)}" />
<link rel="canonical" href="${url}" />
<meta property="og:type" content="article" />
<meta property="og:title" content="${esc(title)}" />
<meta property="og:description" content="${esc(desc)}" />
<meta property="og:url" content="${url}" />
<meta name="twitter:card" content="summary" />
<script type="application/ld+json">${JSON.stringify(jsonld)}</script>
<style>${CSS}</style>
</head>
<body>
<div class="wrap">
<p class="crumb"><a href="../">redos-db</a> &rsaquo; ${esc(e.id)}</p>
<h1>${e.cve ? `${esc(e.name)} <span class="cve">${esc(e.cve)}</span>` : esc(e.name)}</h1>
<p class="sub">Real-world ReDoS: ${esc(cxLabel)} catastrophic backtracking</p>
<div class="badges">${badges.join('')}</div>
<p class="desc">${esc(e.description || '')}</p>

<h2>Vulnerable regex</h2>
<div class="re">${esc(e.regex)}${e.flags ? '  (flags: ' + esc(e.flags) + ')' : ''}</div>

<h2>Attack</h2>
<p class="desc">Input that triggers the blow-up: ${attackText(e.attack)}. A benign input like <span class="mono">${esc(e.benign || '')}</span> matches in microseconds.</p>

<h2>Details</h2>
${table}

<h2>The fix</h2>
<p class="desc">${esc((e.fix && e.fix.summary) || '')}</p>
${e.fix && e.fix.type ? `<div class="re fix">fix type: ${esc(e.fix.type)}</div>` : ''}
${fixCommit}

${curveTable(e.verification)}

<div class="cta">
<a class="hot" href="${esc(e.visualize)}" rel="noopener">▶ Watch it melt down</a>
<a href="${REDOSRAY}" rel="noopener">Scan your own code for ReDoS</a>
<a href="../">← All ${'ReDoS'} entries</a>
</div>

${refs ? `<h2>References</h2><ul>${refs}</ul>` : ''}

<p class="foot">Part of <a href="../">redos-db</a> — a curated, self-verifying catalogue of real-world ReDoS vulnerabilities. Built and maintained by Aurelio Nakamura, an autonomous AI agent. MIT-licensed. Every entry is CI-verified: the real regex is run against a growing malicious input; if it does not actually blow up, the build fails.</p>
</div>
</body>
</html>
`;
}

function generatePages(site) {
  const dir = path.join(__dirname, '..', 'docs', 'entry');
  fs.mkdirSync(dir, { recursive: true });
  // Clear stale pages so removed entries don't linger.
  for (const f of fs.readdirSync(dir)) { if (f.endsWith('.html')) fs.unlinkSync(path.join(dir, f)); }

  const urls = [`${SITE}/`];
  for (const e of site.entries) {
    fs.writeFileSync(path.join(dir, `${e.id}.html`), page(e));
    urls.push(`${SITE}/entry/${e.id}.html`);
  }

  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
    urls.map((u) => `  <url><loc>${u}</loc></url>`).join('\n') + `\n</urlset>\n`;
  fs.writeFileSync(path.join(__dirname, '..', 'docs', 'sitemap.xml'), sitemap);

  fs.writeFileSync(path.join(__dirname, '..', 'docs', 'robots.txt'),
    `User-agent: *\nAllow: /\nSitemap: ${SITE}/sitemap.xml\n`);

  return { pages: site.entries.length };
}

module.exports = { generatePages };
