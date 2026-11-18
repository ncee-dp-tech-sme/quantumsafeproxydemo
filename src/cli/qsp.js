#!/usr/bin/env node
// Change log:
//   Wed Nov 18 15:15 CET 2026 - Initial version: sysadmin CLI for the Quantum Safe Proxy admin API
//
// Usage: npm run cli -- list | onboard <ID> | verify <ID> | rollback <ID>
'use strict';
const { loadConfig } = require('../lib/config');

const cfg = loadConfig();
const base = `http://127.0.0.1:${cfg.adminPort}`;
const [cmd, id] = process.argv.slice(2);

// Call the admin API (mutations carry the anti-CSRF header) - Wed Nov 18 15:15 CET 2026
async function call(path, method = 'GET') {
  const res = await fetch(base + path, { method, headers: method === 'POST' ? { 'X-QSP-Request': '1' } : {}, signal: AbortSignal.timeout(60000) });
  const body = await res.json();
  if (!res.ok) { console.error(`Error: ${body.error}`); (body.steps || []).forEach(printStep); process.exit(1); }
  return body;
}

const printStep = (s) => console.log(`  [${s.ok ? ' OK ' : 'FAIL'}] ${String(s.ms).padStart(4)} ms  ${s.title}\n             ${s.detail}`);
const printChecks = (v) => {
  v.checks.forEach((c) => console.log(`  [${c.pass ? 'PASS' : 'FAIL'}] ${c.title}\n         observed: ${c.actual}`));
  console.log(`\nResult: ${v.pass ? 'PQC VERIFIED' : 'NOT VERIFIED'}  (evidence sha256 ${v.sha256.slice(0, 16)}...)`);
};

(async () => {
  if (cmd === 'list') {
    const s = await call('/api/state');
    s.assets.forEach((a) => console.log(`${a.id.padEnd(12)} ${a.status.padEnd(15)} ${a.vendorModel} FW${a.firmware} (${a.firmwareYear})`));
    console.log(`\nPQC coverage: ${s.summary.protected}/${s.summary.total}`);
  } else if (cmd === 'onboard' && id) {
    const r = await call(`/api/assets/${encodeURIComponent(id)}/onboard`, 'POST');
    r.steps.forEach(printStep);
    printChecks(r.verification);
    console.log(`Changes to legacy device: ${JSON.stringify(r.changesToLegacy)}\nTotal: ${r.totalMs} ms`);
  } else if (cmd === 'verify' && id) {
    printChecks(await call(`/api/assets/${encodeURIComponent(id)}/verify`, 'POST'));
  } else if (cmd === 'rollback' && id) {
    await call(`/api/assets/${encodeURIComponent(id)}/offboard`, 'POST');
    console.log(`${id}: proxy endpoint removed, legacy device untouched.`);
  } else {
    console.log('Usage: npm run cli -- list | onboard <ID> | verify <ID> | rollback <ID>');
    process.exit(2);
  }
})().catch((e) => { console.error('Cannot reach the proxy. Is it running? (npm run demo)'); process.exit(1); void e; });
