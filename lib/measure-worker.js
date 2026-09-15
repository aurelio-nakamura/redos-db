'use strict';
// Disposable worker: run one regex.test() and report elapsed milliseconds.
// Lives in its own thread so the parent can kill it if the match never returns
// (which is exactly what a catastrophic ReDoS input does).
const { workerData, parentPort } = require('worker_threads');
const { regex, flags, input } = workerData;
let re;
try {
  re = new RegExp(regex, flags);
} catch (e) {
  parentPort.postMessage(0);
  process.exit(0);
}
const start = process.hrtime.bigint();
try {
  if (re.global || re.sticky) { re.lastIndex = 0; input.replace(re, ''); }
  else re.test(input);
} catch (e) { /* ignore */ }
const ms = Number(process.hrtime.bigint() - start) / 1e6;
parentPort.postMessage(ms);
