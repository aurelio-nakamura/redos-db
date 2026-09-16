# Contributing to redos-db

Thank you for helping catalogue ReDoS vulnerabilities! The guiding rule:

> **Every entry must actually blow up when CI runs it.** No exceptions, no "trust me".

## Add an entry

1. Copy an existing file in [`data/`](data/) to `data/<your-id>.json`. The filename must equal the `id`.
2. Fill in the fields (validated against [`schema/entry.schema.json`](schema/entry.schema.json)):
   - `type`: `"cve"` for a real published vulnerability, `"classic"` for a well‑known teaching pattern.
   - `engine` *(optional, default `"javascript"`)*: the regex engine the pattern ships on and is verified against — `"javascript"` (V8 `RegExp`) or `"python"` (CPython `re`). Python entries are measured by an out‑of‑process Python verifier, so a PyPI ReDoS is proven on the engine it actually runs on. `flags` use the source letters (`i`, `m`, `s`, `x`, …); JS‑only `g`/`y` are ignored for Python.
   - `regex` / `flags`: the **exact** pattern, transcribed from the real vulnerable source (link a package version or commit), with no `/…/` delimiters.
   - `complexity`: `"quadratic"`, `"cubic"` or `"exponential"` — this is *checked* against the measured curve.
   - `attack`: `{ "prefix", "pad", "suffix" }`. A malicious input is `prefix + pad.repeat(n) + suffix`. Choose the `pad` that maximises backtracking. You may add `"sizes": [...]` to override the default schedule.
   - `benign`: an input that matches/scans quickly (used to prove the regex isn't just slow on everything).
   - `fix`: `type` (`regex-rewrite` / `algorithm-change` / `input-limit` / `guidance`), a `summary`, and where possible a `patched_regex` and/or `commit`. Use `input-limit` when the upstream fix only caps input length rather than changing the vulnerable regex.
   - `references`: at least one authoritative link (NVD, GHSA, the fix commit).
3. Rebuild and test:

   ```bash
   npm run build     # validates schema, writes the canonical dist/redos-db.json
   npm test          # runs every entry's attack and checks the blow-up + class
   ```

   For the measured site data (`docs/db.json`) run `node lib/build.js --measure`.
4. Commit the updated `dist/redos-db.json` and `docs/db.json` along with your entry, and open a PR.

## What gets rejected

- A pattern that doesn't exhibit super‑linear blow‑up on its declared engine (the test will fail).
- A `complexity` label that disagrees with the measured curve.
- A paraphrased or "cleaned up" regex — it must be the pattern that actually shipped.
- Entries without a credible reference.

## Notes

- The project is **zero‑dependency** by design; please keep it that way. (Python entries only need a `python3` on PATH, which CI provides.)
- Attacks run in a killable worker (JS) or subprocess (Python) with a time budget, so an exponential pattern is safe to include.
- This repository is maintained by an autonomous AI agent (Aurelio Nakamura); PRs are reviewed on their technical merits.
