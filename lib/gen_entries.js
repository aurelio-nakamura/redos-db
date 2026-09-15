const fs = require('fs');
const path = require('path');
const R = String.raw;
const OUT = process.argv[2] || path.join(__dirname, '..', 'data');

const entries = [
  {
    id: 'ansi-regex-CVE-2021-3807',
    name: 'ansi-regex',
    type: 'cve',
    cve: 'CVE-2021-3807', ghsa: 'GHSA-93q8-gq69-wqmw', cwe: 'CWE-1333',
    ecosystem: 'npm', package: 'ansi-regex',
    affected: '<3.0.1 || >=4.0.0 <4.1.1 || >=5.0.0 <5.0.1 || >=6.0.0 <6.0.1',
    patched: '5.0.1', published: '2021-09-17', discovered_by: 'Yeting Li',
    regex: R`[\u001B\u009B][[\]()#;?]*(?:(?:(?:[a-zA-Z\d]*(?:;[-a-zA-Z\d\/#&.:=?%@~_]*)*)?\u0007)|(?:(?:\d{1,4}(?:;\d{0,4})*)?[\dA-PR-TZcf-ntqry=><~]))`,
    flags: '',
    complexity: 'quadratic',
    attack: { prefix: '\u001B[', pad: ';', suffix: '' },
    benign: '\u001B[31m',
    fix: { type: 'regex-rewrite', summary: 'The ANSI matcher overlapped the character class [[\\]()#;?]* with the alternation (?:;...)*, so a long run of ";" could be partitioned two ways (quadratic). The fix constrained the sub-patterns to remove the ambiguity.', commit: 'https://github.com/chalk/ansi-regex/commit/8d1d7cdb586269882c4bdc1b7325d0c58c8f76f9' },
    description: 'ansi-regex builds the regular expression used across the npm ecosystem (chalk, strip-ansi, etc.) to match ANSI escape codes. Untrusted text containing a long run of ";" after an escape introducer forces quadratic backtracking.',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2021-3807',
      'https://github.com/advisories/GHSA-93q8-gq69-wqmw',
      'https://github.com/chalk/ansi-regex/commit/8d1d7cdb586269882c4bdc1b7325d0c58c8f76f9'
    ]
  },
  {
    id: 'nth-check-CVE-2021-3803',
    name: 'nth-check',
    type: 'cve',
    cve: 'CVE-2021-3803', ghsa: 'GHSA-rp65-9cf3-cjxr', cwe: 'CWE-1333',
    ecosystem: 'npm', package: 'nth-check',
    affected: '<2.0.1', patched: '2.0.1', published: '2021-09-17', discovered_by: 'Yeting Li',
    regex: R`^([+\-]?\d*n)?\s*(?:([+\-]?)\s*(\d+))?$`,
    flags: '',
    complexity: 'quadratic',
    attack: { prefix: '', pad: ' ', suffix: '!' },
    benign: '2n+1',
    fix: { type: 'regex-rewrite', summary: 'Two \\s* groups separated by an optional ([+-]?) that can match empty let a whitespace run be split two ways. nth-check 2.0.1 restructured parsing to avoid the overlapping optional whitespace.', commit: 'https://github.com/fb55/nth-check/security/advisories/GHSA-rp65-9cf3-cjxr' },
    description: 'nth-check parses CSS :nth-child()-style formulas and is a transitive dependency of svgo, css-select and much of the front-end build tool-chain. A crafted formula of whitespace triggers quadratic backtracking.',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2021-3803',
      'https://github.com/advisories/GHSA-rp65-9cf3-cjxr'
    ]
  },
  {
    id: 'is-svg-CVE-2021-28092',
    name: 'is-svg',
    type: 'cve',
    cve: 'CVE-2021-28092', ghsa: 'GHSA-7r28-3m3f-r2pr', cwe: 'CWE-1333',
    ecosystem: 'npm', package: 'is-svg',
    affected: '>=2.1.0 <4.3.0', patched: '4.3.0', published: '2021-03-12', discovered_by: 'Yeting Li',
    regex: R`^\s*(?:<\?xml[^>]*>\s*)?(?:<!doctype svg[^>]*\s*(?:\[?(?:\s*<![^>]*>\s*)*\]?)*[^>]*>\s*)?(?:<svg[^>]*>[^]*<\/svg>|<svg[^\/>]*\/\s*>)\s*$`,
    flags: 'i',
    complexity: 'exponential',
    attack: { prefix: '<!doctype svg ', pad: '<!x>', suffix: '' },
    benign: '<svg></svg>',
    fix: { type: 'regex-rewrite', summary: 'The DOCTYPE sub-pattern (?:\\[?(?:\\s*<![^>]*>\\s*)*\\]?)* nests two unbounded quantifiers, giving exponential backtracking on repeated internal-subset declarations. is-svg 4.3.0 replaced the check with a non-backtracking approach.', commit: 'https://github.com/sindresorhus/is-svg/releases/tag/v4.3.0' },
    description: 'is-svg reports whether a string is an SVG document and is used by cssnano / SVG optimisation pipelines. A crafted DOCTYPE with many internal declarations triggers exponential backtracking.',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2021-28092',
      'https://github.com/advisories/GHSA-7r28-3m3f-r2pr'
    ]
  },
  {
    id: 'color-string-CVE-2021-29060',
    name: 'color-string',
    type: 'cve',
    cve: 'CVE-2021-29060', ghsa: 'GHSA-257v-vj4p-3w2h', cwe: 'CWE-1333',
    ecosystem: 'npm', package: 'color-string',
    affected: '<1.5.5', patched: '1.5.5', published: '2021-04-05', discovered_by: 'Yeting Li',
    regex: R`^hwb\(\s*([+-]?\d*[\.]?\d+)(?:deg)?\s*,\s*([+-]?[\d\.]+)%\s*,\s*([+-]?[\d\.]+)%\s*(?:,\s*([+-]?[\d\.]+)\s*)?\)$`,
    flags: '',
    complexity: 'quadratic',
    attack: { prefix: 'hwb(', pad: '1', suffix: '!' },
    benign: 'hwb(120, 0%, 0%)',
    fix: { type: 'regex-rewrite', summary: 'The HWB colour parser used ([+-]?\\d*[\\.]?\\d+) where \\d* and \\d+ overlap, so a long digit run followed by an invalid character backtracks quadratically. color-string 1.5.5 tightened the numeric group.', commit: 'https://github.com/Qix-/color-string/commit/79e4a469fb81f79cb9d3d7c7eb92adc7006aa71c' },
    description: 'color-string parses CSS colour strings and underlies the "color" package used throughout Node.js styling libraries. A malformed hwb() value with a long digit run triggers quadratic backtracking.',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2021-29060',
      'https://github.com/advisories/GHSA-257v-vj4p-3w2h'
    ]
  },
  {
    id: 'mime-CVE-2017-16138',
    name: 'mime',
    type: 'cve',
    cve: 'CVE-2017-16138', ghsa: 'GHSA-wrvr-8mpx-r7pp', cwe: 'CWE-400',
    ecosystem: 'npm', package: 'mime',
    affected: '<1.4.1 || >=2.0.0 <2.0.3', patched: '1.4.1', published: '2018-05-31', discovered_by: 'Nick Starke',
    regex: R`.*[\.\/\\]`,
    flags: '',
    complexity: 'quadratic',
    attack: { prefix: '', pad: 'a', suffix: '' },
    benign: 'file.txt',
    fix: { type: 'algorithm-change', summary: 'mime.lookup() ran an unanchored /.*[./\\\\]/ over the whole path; with no separator present the greedy .* restarts at every offset (quadratic). mime 1.4.1 replaced the regex with a plain lastIndexOf scan.', commit: 'https://github.com/broofa/mime/commit/1df903fdeb9ae7eaa048795b8d580ce2c98f40b0' },
    description: 'The classic "mime" package resolves a file extension to a MIME type. mime.lookup() applied an unanchored greedy regex to the input path; a long extension-less filename forces quadratic scanning.',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2017-16138',
      'https://github.com/advisories/GHSA-wrvr-8mpx-r7pp'
    ]
  },
  {
    id: 'classic-nested-quantifier',
    name: 'Nested quantifier (a+)+',
    type: 'classic',
    cwe: 'CWE-1333',
    ecosystem: 'example', package: null,
    affected: null, patched: null, published: null, discovered_by: null,
    regex: R`^(a+)+$`,
    flags: '',
    complexity: 'exponential',
    attack: { prefix: '', pad: 'a', suffix: '!' },
    benign: 'aaaa',
    fix: { type: 'regex-rewrite', summary: 'A group with an inner + wrapped in an outer + can split the same run of "a"s exponentially many ways. Collapsing to a single ^a+$ matches the same language in linear time.', patched_regex: '^a+$' },
    description: 'The canonical textbook ReDoS: an inner-and-outer unbounded quantifier over the same character. Nearly every real-world exponential ReDoS reduces to this shape.',
    references: [
      'https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS'
    ]
  },
  {
    id: 'classic-owasp-email',
    name: 'OWASP example e-mail validator',
    type: 'classic',
    cwe: 'CWE-1333',
    ecosystem: 'example', package: null,
    affected: null, patched: null, published: null, discovered_by: null,
    regex: R`^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$`,
    flags: '',
    complexity: 'exponential',
    attack: { prefix: 'a', pad: 'a', suffix: '!' },
    benign: 'user@example.com',
    fix: { type: 'guidance', summary: 'The (([\\-.]|[_]+)?([a-zA-Z0-9]+))* group can match a run of letters in exponentially many ways. Prefer a linear pattern such as ^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$ and verify deliverability out-of-band.', patched_regex: '^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$' },
    description: 'A widely copy-pasted "validate an e-mail address" regex from public regex libraries. It is exponential: a long local part with no @ makes the engine try every partition.',
    references: [
      'https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS'
    ]
  },
  {
    id: 'classic-trailing-backtrack',
    name: 'Whitespace-tolerant word list (\\w+\\s?)*',
    type: 'classic',
    cwe: 'CWE-1333',
    ecosystem: 'example', package: null,
    affected: null, patched: null, published: null, discovered_by: null,
    regex: R`^(\w+\s?)*$`,
    flags: '',
    complexity: 'exponential',
    attack: { prefix: '', pad: 'a', suffix: '!' },
    benign: 'the quick brown fox',
    fix: { type: 'regex-rewrite', summary: 'Because \\s? is optional, each word character can belong to the current or the next iteration of the outer star, which is exponential. ^\\w+(\\s+\\w+)*$ expresses the same "words separated by spaces" idea deterministically.', patched_regex: '^\\w+(\\s+\\w+)*$' },
    description: 'A deceptively innocent "one or more words, optional spaces" pattern. The optional \\s? inside a starred group is a textbook ReDoS mistake.',
    references: [
      'https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS'
    ]
  }
];

fs.mkdirSync(OUT, { recursive: true });
for (const e of entries) {
  fs.writeFileSync(path.join(OUT, e.id + '.json'), JSON.stringify(e, null, 2) + '\n');
  console.log('wrote', e.id);
}
console.log('total', entries.length);
