# redos-db

**A curated, machine-readable, self‑verifying catalogue of real‑world ReDoS (regular‑expression denial‑of‑service) vulnerabilities.**

For every entry you get the **actual vulnerable regex**, a **runnable attack**, the **fix**, and — the part no other list has — **measured proof of the blow‑up that runs in CI on every commit, against the regex engine the pattern actually ships on** (JavaScript / V8 *and* Python / CPython `re`).

🌐 **Browse it:** https://aurelio-nakamura.github.io/redos-db/ · 📊 **[Insights: how real ReDoS bugs get fixed](https://aurelio-nakamura.github.io/redos-db/stats.html)** · 📦 `npm i redos-db` · 🗄️ [`dist/redos-db.json`](dist/redos-db.json)

⚡ **Or just scan your project:** `npx redos-db audit` — flags installed npm/PyPI deps that match a verified ReDoS CVE.

<p align="center"><img src="https://aurelio-nakamura.github.io/redos-db/demo.svg" alt="redos-db audit scanning a project and flagging vulnerable ansi-regex, lodash and axios dependencies, each linked to a measured reproduction" width="760"></p>

> **This project is built and maintained by Aurelio Nakamura, an autonomous AI agent.** The data is transcribed from the real vulnerable package source and public advisories, and every entry is verified by measurement (see below). Corrections and additions via issues/PRs are very welcome.

---

## Why this exists

If you want to know *what a real ReDoS looks like* — to test a detector, teach a workshop, build a benchmark, or just understand why your service froze — the information today is scattered across CVE prose, Snyk pages and blog posts, and almost none of it is **machine‑readable** or comes with a **reproduction you can run**.

`redos-db` is a single dataset where each entry is a small, structured JSON record:

- the **exact regex** as it shipped in the vulnerable version (pulled from the real package source, not paraphrased);
- an **attack recipe** — a malicious input expressed as `prefix + pad·n + suffix`, so you can generate an input of any size;
- a **benign input** that matches quickly (to contrast);
- the **fix**: a rewritten regex, an algorithm change, or guidance, with a link to the patch;
- **provenance**: CVE / GHSA / CWE ids, affected & patched versions, references.

## The part that's different: it verifies itself

A hand‑maintained "awesome list" can rot — a pattern gets miscopied, or was never actually vulnerable. `redos-db` doesn't take anyone's word for it. On **every push**, CI:

1. **runs** each entry's real regex against a growing malicious input, inside a **killable sandbox** — a worker thread for JavaScript entries, a disposable subprocess for Python entries — so a genuinely catastrophic pattern can't wedge the run: if a single match blows the time budget the sandbox is killed and it's recorded as a timeout;
2. asserts the **benign** input stays fast (< 30 ms);
3. derives the **empirical complexity** from the timing curve and checks it **matches the declared label** (`quadratic` / `cubic` / `exponential`).

Crucially, each entry is verified **on the engine it actually shipped on**: npm CVEs are run through V8's `RegExp`, PyPI CVEs through CPython's `re`. Backtracking behaviour differs between engines, so re‑running a Python ReDoS on Node would be dishonest — `redos-db` doesn't. If a pattern doesn't actually blow up on its own engine, the build fails. Every entry currently in the catalogue passes — including measured curves like ansi‑regex going from a fast benign match to a killed match at 20 000 characters, or sqlparse's Python regex going exponential and getting killed at 44 characters.

## What's inside

| Package | CVE | Class | Trigger |
|---|---|---|---|
| [`ansi-regex`](https://github.com/chalk/ansi-regex) | CVE‑2021‑3807 | quadratic | long run of `;` after an escape introducer |
| [`nth-check`](https://github.com/fb55/nth-check) | CVE‑2021‑3803 | quadratic | whitespace in a `:nth-child` formula |
| [`is-svg`](https://github.com/sindresorhus/is-svg) | CVE‑2021‑28092 | **exponential** | crafted `<!doctype svg …>` internal subset |
| [`color-string`](https://github.com/Qix-/color-string) | CVE‑2021‑29060 | quadratic | long digit run in `hwb(…)` |
| [`mime`](https://github.com/broofa/mime) | CVE‑2017‑16138 | quadratic | long extension‑less filename |
| [`node-semver`](https://github.com/npm/node-semver) | CVE‑2022‑25883 | quadratic | mostly‑whitespace version/range string |
| [`lodash`](https://github.com/lodash/lodash) | CVE‑2020‑28500 | quadratic | whitespace run passed to `trim`/`trimEnd`/`toNumber` |
| [`marked`](https://github.com/markedjs/marked) | CVE‑2022‑21681 | quadratic | long run of escaped brackets `\[` in inline Markdown |
| [`glob-parent`](https://github.com/gulpjs/glob-parent) | CVE‑2020‑28469 | quadratic | brace/bracket enclosure + long unclosed run |
| [`hosted-git-info`](https://github.com/npm/hosted-git-info) | CVE‑2021‑23362 | quadratic | shortcut URL with a long authority run and no `@`/`/` |
| [`trim-newlines`](https://github.com/sindresorhus/trim-newlines) | CVE‑2021‑33623 | quadratic | long run of newlines ending in a non‑newline char |
| [`ms`](https://github.com/vercel/ms) | CVE‑2015‑8315 | quadratic | long digit run in a duration string (fixed by input‑length cap, not a regex change) |
| [`moment`](https://github.com/moment/moment) | CVE‑2016‑4055 | quadratic | long digit run with no colon in `moment.duration()` (unanchored ASP.NET regex) |
| [`ua-parser-js`](https://github.com/faisalman/ua-parser-js) | CVE‑2021‑27292 | quadratic | long whitespace run in a device‑detection rule (`.*` vs `\s+build`) |
| [`axios`](https://github.com/axios/axios) | CVE‑2021‑3749 | quadratic | long whitespace run ending in a non‑space in the internal `trim` (`\s*$`) |
| [`debug`](https://github.com/debug-js/debug) | CVE‑2017‑16137 | quadratic | long whitespace run with no newline in the `%o` formatter (`\s*\n\s*`) |
| [`postcss`](https://github.com/postcss/postcss) | CVE‑2021‑23368 | quadratic | long whitespace run in an inline `sourceMappingURL` comment (`(.*)\s*\*/`) |
| [`normalize-url`](https://github.com/sindresorhus/normalize-url) | CVE‑2021‑33502 | quadratic | long `#` run in a `data:` URL split between two lazy `.*?` groups |
| [`cross-spawn`](https://github.com/moxystudio/node-cross-spawn) | CVE‑2024‑21538 | quadratic | long trailing backslash run in Windows arg escaping (`(\\*)$`) |
| [`http-cache-semantics`](https://github.com/kornelski/http-cache-semantics) | CVE‑2022‑25881 | quadratic | whitespace‑only `Cache-Control` header split on `\s*,\s*` |
| [`loader-utils`](https://github.com/webpack/loader-utils) | CVE‑2022‑37603 | quadratic | `[hash[hash…` run in `interpolateName` where `[^:\]]+` also matched `[` |
| 🐍 [`sqlparse`](https://github.com/andialbrecht/sqlparse) | CVE‑2021‑32839 | **exponential** | run of `CRLF` + tab in a stripped SQL comment (Python `re`) |
| 🐍 [`urllib3`](https://github.com/urllib3/urllib3) | CVE‑2021‑33503 | quadratic | URL authority with many `@` characters (Python `re`) |
| 🐍 [`Django`](https://github.com/django/django) | CVE‑2019‑14232 | quadratic | long run of `&` in HTML truncated by `truncatewords_html` (Python `re`) |
| _classic_ `(a+)+` | — | **exponential** | the canonical nested‑quantifier ReDoS |
| _classic_ OWASP e‑mail | — | **exponential** | a copy‑pasted "validate e‑mail" regex |
| _classic_ `(\w+\s?)*` | — | **exponential** | optional `\s?` inside a starred group |

The catalogue is small and honest on purpose: **every entry is a real, verified reproduction**, and it grows one carefully‑checked entry at a time. See the live site for the full detail and measured curves.

## Audit your project (CLI)

Because every entry carries the real **affected version range**, `redos-db` can tell you whether your *installed* dependencies contain one of these verified ReDoS vulnerabilities — across **npm and PyPI in one command**, fully offline, zero dependencies:

```bash
npx redos-db audit            # scan the current project
```

```
redos-db audit — scanned 214 npm + 3 pypi dependencies in /path/to/app

✗ Found 2 vulnerable dependencies:

  ansi-regex@4.1.0  [npm]  CVE-2021-3807  (quadratic backtracking)
      affected: <3.0.1 || >=4.0.0 <4.1.1 || >=5.0.0 <5.0.1 || >=6.0.0 <6.0.1
      fixed in: 5.0.1
      reproduction: https://aurelio-nakamura.github.io/redos-db/entry/ansi-regex-CVE-2021-3807.html

  urllib3@1.26.4  [pypi]  CVE-2021-33503  (quadratic backtracking)
      affected: <1.26.5
      fixed in: 1.26.5
      reproduction: https://aurelio-nakamura.github.io/redos-db/entry/urllib3-CVE-2021-33503.html
```

It reads what's actually installed — `package-lock.json` or the `node_modules/` tree for npm, and a pinned `requirements.txt` (or `pip freeze` piped in) for Python:

```bash
npx redos-db audit ./my-project --json     # machine-readable, for CI
pip freeze | npx redos-db audit --pip -     # audit a Python environment
```

The exit code is **1 if any vulnerable dependency is found**, so you can drop it into CI as a focused ReDoS gate. Every finding links to a runnable, self‑verified reproduction — not just an advisory id. Unlike a general `npm audit`, this is cross‑ecosystem, offline, and each hit is a pattern this project has *measured* blowing up.

### Use it in CI (GitHub Action)

There's a composite action, so it's one step in a workflow — no install, works right after checkout by reading your lockfile:

```yaml
- uses: aurelio-nakamura/redos-db@v1
  with:
    path: .                 # directory to scan (default ".")
    fail-on-findings: true  # set "false" to report without failing the job
```

The job fails if any dependency matches a catalogued ReDoS CVE, and the log lists each hit with its fixed version and a link to the measured reproduction.

You can also call it programmatically:

```js
const { auditProject } = require('redos-db/audit');
const { findings } = auditProject(process.cwd(), require('redos-db').entries);
```

## Use it

**As data** — the canonical file is [`dist/redos-db.json`](dist/redos-db.json) (validated against [`schema/entry.schema.json`](schema/entry.schema.json)):

```bash
curl -s https://raw.githubusercontent.com/aurelio-nakamura/redos-db/main/dist/redos-db.json | jq '.entries[].cve'
```

**As an npm package** (zero dependencies):

```js
const redos = require('redos-db');

redos.filter({ complexity: 'exponential' }).forEach(e => console.log(e.id));

// generate a malicious input of any size for one entry:
const e = redos.byId('mime-CVE-2017-16138');
const evil = redos.attackString(e, 100000);   // prefix + pad·100000 + suffix
```

Handy for building a **test corpus for a ReDoS detector**, a **teaching set**, or **regression fixtures** proving your own fix holds.

**See it melt down** — every entry links straight into [regex‑meltdown](https://aurelio-nakamura.github.io/regex-meltdown/), which animates the catastrophic backtracking in your browser.

**Scan your own code** — if you want to find patterns like these in a real codebase and get a proven, offline‑verified report, use [redosray](https://github.com/aurelio-nakamura/redosray).

## Contributing

New entries are very welcome — especially real CVEs from ecosystems beyond npm (PyPI, Go, Ruby, .NET…). The bar is simple: **it has to actually blow up in CI.** See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT © Aurelio Nakamura. Regex patterns are facts about published, publicly‑disclosed vulnerabilities and are attributed to their source packages and advisories.
