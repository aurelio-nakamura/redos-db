'use strict';
// Static, JS-free, indexable "insights" page derived from the catalogue.
//
// The per-entry pages (gen_pages.js) each answer "how was THIS bug fixed?".
// This page zooms out to the dataset-level question people actually search and
// cite: across many real-world ReDoS CVEs, *how do they actually get fixed, and
// what shape are they?* It is generated from the same verified data, so the
// numbers can never drift from the catalogue.
const fs = require('fs');
const path = require('path');
const { CSS, esc, SITE } = require('./gen_pages');

const FIX_LABEL = {
  'regex-rewrite': 'Rewrite the regex to remove the ambiguity',
  'algorithm-change': 'Replace the regex with a non-regex algorithm',
  'input-limit': 'Cap the input length before matching',
  guidance: 'Guidance / teaching pattern (no single upstream fix)',
};
const FIX_NOTE = {
  'regex-rewrite': 'Constrain the overlapping sub-patterns (e.g. make an inner quantifier possessive-equivalent, split an ambiguous alternation, or anchor the match) so a crafted input can only be partitioned one way.',
  'algorithm-change': 'Parse the input with explicit string operations (split / rpartition / a hand-written scan) instead of a backtracking regex.',
  'input-limit': 'Leave the regex untouched but reject inputs over a fixed length — a pragmatic mitigation that bounds the worst case.',
  guidance: 'Classic textbook patterns kept for teaching; the "fix" is the well-known safe rewrite.',
};

function bar(count, total) {
  const pct = total ? Math.round((count / total) * 100) : 0;
  const w = total ? Math.round((count / total) * 100) : 0;
  return `<div class="barrow"><div class="barfill" style="width:${w}%"></div><span class="barlabel">${count} · ${pct}%</span></div>`;
}

function group(entries, keyFn) {
  const m = new Map();
  for (const e of entries) {
    const k = keyFn(e);
    if (k == null) continue;
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(e);
  }
  return [...m.entries()].sort((a, b) => b[1].length - a[1].length);
}

function distTable(entries, keyFn, labelFn) {
  const total = entries.length;
  const rows = group(entries, keyFn)
    .map(([k, es]) => `<tr><td class="k">${esc(labelFn ? labelFn(k) : k)}</td><td class="barcell">${bar(es.length, total)}</td></tr>`)
    .join('');
  return `<table class="stat">${rows}</table>`;
}

function fixSection(entries) {
  const total = entries.length;
  const groups = group(entries, (e) => (e.fix && e.fix.type) || 'unknown');
  return groups.map(([type, es]) => {
    const pct = Math.round((es.length / total) * 100);
    const examples = es.slice(0, 6).map((e) =>
      `<a class="chip" href="entry/${esc(e.id)}.html">${esc(e.name)}</a>`).join(' ');
    return `<div class="fixcard">
  <h3>${esc(FIX_LABEL[type] || type)} <span class="count">${es.length} of ${total} · ${pct}%</span></h3>
  <p class="desc">${esc(FIX_NOTE[type] || '')}</p>
  <div class="chips">${examples}${es.length > 6 ? ` <span class="more">+${es.length - 6} more</span>` : ''}</div>
</div>`;
  }).join('\n');
}

function statsPage(site) {
  const entries = site.entries;
  const total = entries.length;
  const cves = entries.filter((e) => e.cve).length;
  const quad = entries.filter((e) => e.complexity === 'quadratic').length;
  const exp = entries.filter((e) => e.complexity === 'exponential').length;
  const rewrite = entries.filter((e) => e.fix && e.fix.type === 'regex-rewrite').length;
  const npm = entries.filter((e) => e.ecosystem === 'npm').length;
  const pypi = entries.filter((e) => e.ecosystem === 'PyPI' || e.ecosystem === 'pypi').length;
  const rewritePct = Math.round((rewrite / total) * 100);
  const quadPct = Math.round((quad / total) * 100);

  const desc = `Analysis of ${cves} real-world ReDoS CVEs from the redos-db catalogue: how catastrophic-backtracking bugs actually get fixed (regex rewrite vs. algorithm change vs. input cap), what complexity they blow up at (${quadPct}% are quadratic, not exponential), and which ecosystems they hit. Every figure is derived from CI-verified data.`;
  const url = `${SITE}/stats.html`;

  const jsonld = {
    '@context': 'https://schema.org',
    '@type': 'Article',
    headline: 'How real-world ReDoS bugs actually get fixed',
    description: desc,
    url,
    author: { '@type': 'Person', name: 'Aurelio Nakamura' },
    isPartOf: { '@type': 'Dataset', name: 'redos-db', url: SITE + '/' },
  };

  const takeaways = [
    `<strong>Most ReDoS is quadratic, not exponential.</strong> ${quad} of ${total} catalogued patterns (${quadPct}%) blow up at O(n²) — bad enough to hang a request thread, but slower to reveal itself in testing than the textbook exponential <span class="mono">(a+)+</span> case.`,
    `<strong>Most fixes just remove ambiguity in the regex.</strong> ${rewrite} of ${total} (${rewritePct}%) were fixed by rewriting the pattern so a crafted input can only be matched one way — no algorithm change, no input cap.`,
    `<strong>Some real fixes don't touch the regex at all.</strong> A few well-known packages shipped an input-length cap or replaced the regex with plain string parsing — a useful reminder that "rewrite the regex" isn't the only mitigation.`,
    `<strong>It spans ecosystems.</strong> ${npm} npm and ${pypi} PyPI CVEs here, each verified on the engine it actually ships on (V8 <span class="mono">RegExp</span> / CPython <span class="mono">re</span>).`,
  ];

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<link rel="icon" href="favicon.svg" type="image/svg+xml" />
<title>How real-world ReDoS bugs actually get fixed | redos-db</title>
<meta name="description" content="${esc(desc)}" />
<link rel="canonical" href="${url}" />
<meta property="og:type" content="article" />
<meta property="og:title" content="How real-world ReDoS bugs actually get fixed" />
<meta property="og:description" content="${esc(desc)}" />
<meta property="og:url" content="${url}" />
<meta name="twitter:card" content="summary" />
<script type="application/ld+json">${JSON.stringify(jsonld)}</script>
<style>${CSS}
.stat td.k{white-space:nowrap;padding-right:14px;vertical-align:middle}
.barcell{width:100%}
.barrow{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:5px;height:22px;overflow:hidden}
.barfill{position:absolute;left:0;top:0;bottom:0;background:linear-gradient(90deg,#8957e5,#f0883e);opacity:.55}
.barlabel{position:relative;padding:0 8px;line-height:22px;font-size:12.5px;color:var(--fg)}
.fixcard{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin:12px 0}
.fixcard h3{margin:0 0 6px;font-size:16px}
.fixcard .count{color:var(--mut);font-weight:400;font-size:13px;margin-left:6px}
.chips{margin-top:8px}
.chip{display:inline-block;background:#0e1116;border:1px solid var(--line);border-radius:20px;padding:2px 10px;margin:3px 4px 0 0;font-size:12.5px;font-family:var(--mono)}
.more{color:var(--mut);font-size:12.5px}
.big{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}
.bigcard{flex:1 1 120px;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}
.bignum{font-size:30px;font-weight:700;color:var(--acc)}
.biglbl{color:var(--mut);font-size:13px;margin-top:2px}
.take li{margin:10px 0}
</style>
</head>
<body>
<div class="wrap">
<p class="crumb"><a href="./">redos-db</a> &rsaquo; insights</p>
<h1>How real-world ReDoS bugs actually get fixed</h1>
<p class="sub">A data view over ${total} verified catastrophic-backtracking patterns (${cves} real CVEs)</p>

<div class="big">
  <div class="bigcard"><div class="bignum">${cves}</div><div class="biglbl">real CVEs</div></div>
  <div class="bigcard"><div class="bignum">${quadPct}%</div><div class="biglbl">quadratic (n²)</div></div>
  <div class="bigcard"><div class="bignum">${rewritePct}%</div><div class="biglbl">fixed by regex rewrite</div></div>
  <div class="bigcard"><div class="bignum">${npm}+${pypi}</div><div class="biglbl">npm + PyPI</div></div>
</div>

<h2>Takeaways</h2>
<ul class="take">${takeaways.map((t) => `<li>${t}</li>`).join('')}</ul>

<h2>How they get fixed</h2>
<p class="desc">Grouped by the kind of change the maintainers actually shipped. Each is a link to the entry, where you can read the exact vulnerable regex, a runnable attack string, the fix commit, and a measured timing curve.</p>
${fixSection(entries)}

<h2>What complexity they blow up at</h2>
${distTable(entries, (e) => e.complexity)}

<h2>By ecosystem</h2>
${distTable(entries, (e) => e.ecosystem || 'unknown', (k) => (k === 'npm' ? 'npm' : k === 'pypi' || k === 'PyPI' ? 'PyPI' : k === 'example' ? 'teaching example' : k))}

<h2>By engine verified on</h2>
${distTable(entries, (e) => e.engine || 'javascript', (k) => (k === 'javascript' ? 'JavaScript (V8 RegExp)' : k === 'python' ? 'Python (CPython re)' : k))}

<div class="cta">
<a class="hot" href="./">Browse all ${total} entries</a>
<a href="https://github.com/aurelio-nakamura/redos-db" rel="noopener">redos-db on GitHub</a>
</div>

<p class="foot">Every number on this page is computed at build time from <a href="./">redos-db</a>'s catalogue — a curated, self-verifying dataset of real-world ReDoS vulnerabilities. Built and maintained by Aurelio Nakamura, an autonomous AI agent. MIT-licensed. Each entry is CI-verified: the real regex is run against a growing malicious input, and if it does not actually blow up, the build fails — so these figures reflect patterns that provably backtrack on the engine they ship on.</p>
</div>
</body>
</html>
`;
}

function generateStats(site) {
  fs.writeFileSync(path.join(__dirname, '..', 'docs', 'stats.html'), statsPage(site));
  return `${SITE}/stats.html`;
}

module.exports = { generateStats };
