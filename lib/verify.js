'use strict';
// Measured verification of a ReDoS catalogue entry.
//
// Every entry ships a real regex plus an attack recipe (prefix + pad*n + suffix).
// We *run* the regex against increasing input sizes in a disposable worker thread
// with a hard watchdog, so a genuinely catastrophic pattern can never wedge the
// test run: if a single match exceeds the time budget the worker is killed and the
// run is recorded as ">= budget ms". A benign input must stay fast. From the
// timing curve we derive an empirical complexity class and compare it to the
// entry's declared one, so the catalogue self-checks both the blow-up *and* its
// label. No external dependencies.

const path = require('path');
const { Worker } = require('worker_threads');
const { spawnSync } = require('child_process');

const WORKER = path.join(__dirname, 'measure-worker.js');
const PY_VERIFY = path.join(__dirname, 'verify_py.py');

// Entries whose target engine is CPython's `re` are measured by an out-of-process
// Python verifier (lib/verify_py.py) that returns the identical result shape. This
// is what makes redos-db cross-language self-verifying: a Python ReDoS is proven to
// blow up on the engine it actually ships on, not merely re-run on V8 (whose
// backtracking behaviour differs). Requires python3 on PATH (present in CI).
function verifyPython(entry) {
  const res = spawnSync('python3', [PY_VERIFY], {
    input: JSON.stringify(entry),
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
    timeout: 180000,
  });
  if (res.error) return { id: entry.id, ok: false, reason: 'python verify spawn failed: ' + res.error.message };
  if (res.status !== 0) return { id: entry.id, ok: false, reason: 'python verify exited ' + res.status + ': ' + (res.stderr || '').slice(0, 300) };
  try { return JSON.parse(res.stdout.trim()); }
  catch (e) { return { id: entry.id, ok: false, reason: 'python verify bad output: ' + (res.stdout || '').slice(0, 200) }; }
}

function buildInput(attack, n) {
  return (attack.prefix || '') + (attack.pad || '').repeat(n) + (attack.suffix || '');
}

// Run regex.test(input) in a worker; kill it if it exceeds budgetMs.
function measure(regex, flags, input, budgetMs) {
  return new Promise((resolve) => {
    const w = new Worker(WORKER, { workerData: { regex, flags, input } });
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      w.terminate();
      resolve({ ms: budgetMs, timedOut: true });
    }, budgetMs);
    w.once('message', (ms) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      w.terminate();
      resolve({ ms, timedOut: false });
    });
    w.once('error', () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ ms: budgetMs, timedOut: true });
    });
  });
}

// Median of a few reps to smooth out GC / scheduler noise.
async function measureStable(regex, flags, input, budgetMs, reps = 3) {
  const runs = [];
  for (let i = 0; i < reps; i++) runs.push(await measure(regex, flags, input, budgetMs));
  if (runs.some((r) => r.timedOut)) return { ms: budgetMs, timedOut: true };
  const xs = runs.map((r) => r.ms).sort((a, b) => a - b);
  return { ms: xs[Math.floor(xs.length / 2)], timedOut: false };
}

const SIZES = {
  exponential: [14, 18, 22, 26, 30],
  cubic: [2000, 4000, 8000, 16000],
  quadratic: [2500, 5000, 10000, 20000],
};

const BUDGET_MS = 2000;
const BENIGN_MAX_MS = 30;
const BLOWUP_MS = 150; // largest attack must cost at least this much (or time out)

function classify(points) {
  // Use only points that actually completed (a budget-capped timeout would
  // understate the true growth ratio). Compare the two largest completed runs.
  const usable = points.filter((p) => !p.timedOut && p.ms > 1);
  if (usable.length < 2) return 'unknown';
  const a = usable[usable.length - 2];
  const b = usable[usable.length - 1];
  const sizeRatio = b.n / a.n;
  const timeRatio = b.ms / a.ms;
  if (sizeRatio >= 1.9 && sizeRatio <= 2.1) {
    // clean doubling of input size
    if (timeRatio > 12) return 'exponential-or-worse';
    if (timeRatio >= 5.5) return 'cubic';
    if (timeRatio >= 2.8) return 'quadratic';
    return 'sub-quadratic';
  }
  // exponential schedule uses small +4 pump steps; huge time growth per tiny step
  if (b.n - a.n <= 8 && timeRatio >= 3) return 'exponential';
  return 'polynomial';
}

async function verifyEntry(entry) {
  if ((entry.engine || 'javascript') === 'python') return verifyPython(entry);
  const { regex, flags = '', attack, complexity, benign } = entry;
  const sizes = (attack && attack.sizes) || SIZES[complexity] || SIZES.quadratic;

  // regex must compile
  try { new RegExp(regex, flags); } catch (e) {
    return { id: entry.id, ok: false, reason: 'regex does not compile: ' + e.message };
  }

  // benign input must be fast
  const b = await measureStable(regex, flags, benign != null ? String(benign) : '', 300);
  if (b.timedOut || b.ms > BENIGN_MAX_MS) {
    return { id: entry.id, ok: false, reason: `benign input was not fast (${b.timedOut ? '>=budget' : b.ms.toFixed(1) + 'ms'})` };
  }

  // attack curve
  const points = [];
  for (const n of sizes) {
    const r = await measure(regex, flags, buildInput(attack, n), BUDGET_MS);
    points.push({ n, ms: Math.round(r.ms * 100) / 100, timedOut: r.timedOut });
    if (r.timedOut) break; // no point pushing larger once it already blew the budget
  }

  const last = points[points.length - 1];
  const blewUp = last.timedOut || last.ms >= BLOWUP_MS;
  const superlinear = points.length >= 2 && (last.timedOut || last.ms / Math.max(points[0].ms, 0.05) >= 2 * (last.n / points[0].n) * 0.5);

  const empirical = classify(points);
  const declaredIsExp = complexity === 'exponential';
  const empiricalIsExp = empirical === 'exponential' || empirical === 'exponential-or-worse';
  const classAgrees = declaredIsExp ? empiricalIsExp : (!empiricalIsExp && empirical !== 'sub-quadratic' && empirical !== 'unknown');

  return {
    id: entry.id,
    ok: blewUp && superlinear,
    reason: blewUp && superlinear ? null : 'did not exhibit super-linear blow-up on this engine',
    benignMs: Math.round(b.ms * 100) / 100,
    points,
    empiricalClass: empirical,
    declaredClass: complexity,
    classAgrees,
    engineLabel: `node ${process.version}`,
  };
}

module.exports = { verifyEntry, buildInput, measure, SIZES };
