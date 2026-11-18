// Change log:
//   Wed Nov 18 15:20 CET 2026 - Initial version: unit + integration + security tests (node:test, no dependencies)
//   Wed Nov 18 14:57 CET 2026 - Added onboarding tests for legacy devices that speak classical TLS 1.2/1.3
//   Wed Nov 18 15:48 CET 2026 - Added compliance report and evidence scoping tests for fresh, onboarded, and rolled back states
//   Wed Nov 18 15:07 CET 2026 - Assert rollback deletes evidence files from disk
//   Wed Nov 18 15:02 CET 2026 - Assert rollback archives evidence files to evidence/archive instead of deleting them
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { loadConfig, loadAssets } = require('../src/lib/config');
const { createLogger, createAudit } = require('../src/lib/logger');
const modbus = require('../src/lib/modbus');
const verifier = require('../src/lib/verifier');
const { startDevice } = require('../src/legacy/ot-simulator');
const { QuantumSafeProxy } = require('../src/proxy/qsp');
const { createAdminServer } = require('../src/proxy/server');

const base = loadConfig();
// Isolated config: separate ports, state and evidence so a running demo is not disturbed
fs.mkdirSync(path.join(base.root, 'tmp'), { recursive: true });
const tmp = fs.mkdtempSync(path.join(base.root, 'tmp', 'test-'));
const cfg = {
  ...base, adminPort: 28080, logLevel: 'ERROR',
  paths: { ...base.paths, state: path.join(tmp, 'state.json'), evidence: path.join(tmp, 'evidence'), logs: path.join(tmp, 'logs') },
};
const asset = { ...loadAssets(base)[0], legacyPort: 25021, pqcPort: 28441 };
const log = createLogger('ERROR', 'test');
const audit = createAudit(cfg.paths.logs, log);

test.before(() => {
  if (!fs.existsSync(cfg.paths.ca)) execFileSync('bash', [path.join(base.root, 'scripts', 'gen-certs.sh')]);
});
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

// Start the mock legacy device and wait until it listens - Wed Nov 18 15:20 CET 2026
async function legacy() {
  const dev = startDevice(cfg, log, asset);
  await new Promise((r) => dev.once('listening', r));
  return dev;
}

test('modbus framing round-trips and rejects non-modbus bytes', () => {
  const req = modbus.readHoldingRequest(7, 1, 0, 2);
  const { frame, rest } = modbus.extractFrame(req);
  assert.equal(frame.txId, 7);
  assert.equal(frame.fc, 3);
  assert.equal(rest.length, 0);
  assert.equal(modbus.extractFrame(req.subarray(0, 5)), null);
  assert.throws(() => modbus.extractFrame(Buffer.from([0x16, 0x03, 0x01, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00])), /not modbus/);
});

test('legacy device speaks plaintext only and drops a TLS ClientHello', async () => {
  const dev = await legacy();
  try {
    const d = await verifier.readDirect(cfg, asset);
    assert.equal(d.via, 'plaintext');
    assert.equal(d.rawRegisters.length, asset.registers.length);
    const probe = await verifier.opensslProbe(cfg, asset.legacyPort, { groups: 'X25519MLKEM768' });
    assert.equal(probe.connected, false);
  } finally { dev.close(); }
});

test('onboarding yields verified PQC key exchange, negative tests pass, device untouched, rollback works', async () => {
  const dev = await legacy();
  const proxy = new QuantumSafeProxy(cfg, [asset], log, audit);
  try {
    const r = await proxy.onboard(asset.id);
    assert.equal(r.verification.pass, true, JSON.stringify(r.verification.checks.filter((c) => !c.pass)));
    const sh = r.verification.wire.after.serverHello;
    assert.equal(sh.group, 'X25519MLKEM768');
    assert.equal(sh.pqc, true);
    assert.ok(sh.keyShareBytes > 1000, 'ML-KEM hybrid key share is >1000 bytes');
    assert.equal(r.verification.wire.before.eavesdropperReadable, true);
    assert.equal(r.verification.wire.after.eavesdropperReadable, false);
    assert.deepEqual(Object.values(r.changesToLegacy), [0, 0, 0, 0, 0]);
    assert.ok(fs.readdirSync(cfg.paths.evidence).length >= 1);
    await assert.rejects(proxy.onboard(asset.id), /already onboarded/);
    await proxy.offboard(asset.id);
    assert.equal(fs.readdirSync(cfg.paths.evidence).filter((f) => f.startsWith(`${asset.id}-`)).length, 0, 'rollback moves evidence out of the active folder');
    assert.ok(fs.readdirSync(path.join(cfg.paths.evidence, 'archive')).some((f) => f.startsWith(`${asset.id}-`)), 'rollback archives evidence files');

    await assert.rejects(verifier.readViaPqc(cfg, asset));
    assert.equal((await verifier.readDirect(cfg, asset)).via, 'plaintext');
  } finally { await proxy.shutdown(); dev.close(); }
});

test('classical-only and TLS 1.2 clients cannot complete a handshake (security)', async () => {
  const dev = await legacy();
  const proxy = new QuantumSafeProxy(cfg, [asset], log, audit);
  try {
    await proxy.onboard(asset.id);
    await assert.rejects(verifier.tlsConnect(verifier.tlsOpts(cfg, asset.pqcPort, { ecdhCurve: 'X25519' })));
    await assert.rejects(verifier.tlsConnect(verifier.tlsOpts(cfg, asset.pqcPort, { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' })));
  } finally { await proxy.offboard(asset.id).catch(() => {}); await proxy.shutdown(); dev.close(); }
});

// Onboard every classical-TLS legacy device (TLS 1.2 + TLS 1.3) and prove the upgrade to hybrid ML-KEM - Wed Nov 18 14:57 CET 2026
const tlsAssets = loadAssets(base).filter((a) => a.legacyTransport)
  .map((a, i) => ({ ...a, legacyPort: 25030 + i, pqcPort: 28450 + i }));

test('catalogue has 4 plaintext and 4 classical-TLS legacy assets', () => {
  const all = loadAssets(base);
  assert.equal(all.filter((a) => !a.legacyTransport).length, 4);
  assert.deepEqual(tlsAssets.map((a) => a.legacyTransport.version).sort(), ['TLSv1.2', 'TLSv1.2', 'TLSv1.3', 'TLSv1.3']);
});

for (const tlsAsset of tlsAssets) {
  test(`classical-TLS legacy device ${tlsAsset.id} (${tlsAsset.legacyTransport.version}) is onboarded, proven PQC and rolled back`, async () => {
    const dev = startDevice(cfg, log, tlsAsset);
    await new Promise((r) => dev.once('listening', r));
    const proxy = new QuantumSafeProxy(cfg, [tlsAsset], log, audit);
    try {
      const probe = await verifier.opensslProbe(cfg, tlsAsset.legacyPort, { groups: 'X25519MLKEM768', withCert: false });
      assert.equal(probe.connected, false, 'legacy TLS device must not negotiate ML-KEM');
      assert.equal((await verifier.readDirect(cfg, tlsAsset)).via, 'classical-tls');
      const r = await proxy.onboard(tlsAsset.id);
      assert.equal(r.verification.pass, true, JSON.stringify(r.verification.checks.filter((c) => !c.pass)));
      const before = r.verification.wire.before;
      assert.equal(before.tls, true);
      assert.equal(before.pqc, false);
      assert.equal(before.tlsVersion, tlsAsset.legacyTransport.version);
      assert.ok(before.kex.group && !/MLKEM/.test(before.kex.group), `classical group seen on the wire: ${before.kex.group}`);
      assert.equal(r.verification.wire.after.serverHello.group, 'X25519MLKEM768');
      assert.equal(r.verification.wire.after.eavesdropperReadable, false);
      assert.deepEqual(Object.values(r.changesToLegacy), [0, 0, 0, 0, 0]);
      assert.equal((await proxy.telemetry(tlsAsset.id)).registers.length, tlsAsset.registers.length);
      await proxy.offboard(tlsAsset.id);
      await assert.rejects(verifier.readViaPqc(cfg, tlsAsset));
      assert.equal((await verifier.readDirect(cfg, tlsAsset)).via, 'classical-tls');
    } finally { await proxy.shutdown(); dev.close(); }
  });
}

test('admin API enforces host allowlist, anti-CSRF header and id validation (security)', async () => {
  const proxy = new QuantumSafeProxy(cfg, [asset], log, audit);
  const server = createAdminServer(cfg, proxy, audit, log);
  await new Promise((r) => server.listen(cfg.adminPort, '127.0.0.1', r));
  const call = (method, p, headers = {}) => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: cfg.adminPort, path: p, method, headers }, (res) => {
      let b = '';
      res.on('data', (d) => { b += d; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    req.on('error', reject);
    req.end();
  });
  try {
    assert.equal((await call('GET', '/api/state', { Host: 'evil.example:28080' })).status, 403);
    assert.equal((await call('POST', `/api/assets/${asset.id}/onboard`)).status, 403);
    assert.equal((await call('POST', `/api/assets/${asset.id}/onboard`, { 'X-QSP-Request': '1', Origin: 'http://evil.example' })).status, 403);
    assert.equal((await call('POST', '/api/assets/..%2F..%2Fetc/onboard', { 'X-QSP-Request': '1' })).status, 404);
    assert.equal((await call('POST', '/api/assets/NOPE-123/verify', { 'X-QSP-Request': '1' })).status, 404);
    const ok = await call('GET', '/api/state');
    assert.equal(ok.status, 200);
    assert.match(ok.headers['content-security-policy'], /default-src/);
    assert.equal((await call('GET', '/../../.env')).status, 404);
  } finally { server.close(); }
});

test('compliance report and evidence endpoint scope strictly to protected assets', async () => {
  const dev = await legacy();
  const proxy = new QuantumSafeProxy(cfg, [asset], log, audit);
  const server = createAdminServer(cfg, proxy, audit, log);
  await new Promise((r) => server.listen(cfg.adminPort, '127.0.0.1', r));
  const get = (p) => new Promise((resolve, reject) => {
    http.get(`http://127.0.0.1:${cfg.adminPort}${p}`, (res) => {
      let b = '';
      res.on('data', (d) => { b += d; });
      res.on('end', () => resolve({ status: res.statusCode, body: b }));
    }).on('error', reject);
  });
  try {
    // 1. Initial exposed state: evidence endpoint returns 404, report has no evidence hash/group
    const rep0 = await get('/api/report');
    assert.equal(rep0.status, 200);
    assert.ok(rep0.body.includes('No verification evidence yet.'));
    assert.ok(rep0.body.includes(`<td>${asset.id}</td><td>${asset.name}</td><td>${asset.vendorModel} FW ${asset.firmware} (${asset.firmwareYear})</td>\n      <td>EXPOSED (plaintext)</td>\n      <td>-</td>\n      <td>-</td>\n      <td>-</td>`));
    const ev0 = await get(`/api/assets/${asset.id}/evidence`);
    assert.equal(ev0.status, 404);

    // 2. Onboard: report now shows PQC group, PASS, evidence hash, and detail section
    await proxy.onboard(asset.id);
    const rep1 = await get('/api/report');
    assert.equal(rep1.status, 200);
    assert.ok(rep1.body.includes('PQC protected'));
    assert.ok(rep1.body.includes('X25519MLKEM768 / TLSv1.3 / TLS_AES_256_GCM_SHA384'));
    assert.ok(rep1.body.includes('PASS'));
    const ev1 = await get(`/api/assets/${asset.id}/evidence`);
    assert.equal(ev1.status, 200);

    // 3. Rollback/Offboard: report returns to clean state and the evidence JSON files are archived
    await proxy.offboard(asset.id);
    const rep2 = await get('/api/report');
    assert.equal(rep2.status, 200);
    assert.ok(rep2.body.includes('No verification evidence yet.'));
    assert.ok(rep2.body.includes(`<td>${asset.id}</td><td>${asset.name}</td><td>${asset.vendorModel} FW ${asset.firmware} (${asset.firmwareYear})</td>\n      <td>EXPOSED (plaintext)</td>\n      <td>-</td>\n      <td>-</td>\n      <td>-</td>`));
    const ev2 = await get(`/api/assets/${asset.id}/evidence`);
    assert.equal(ev2.status, 404);
  } finally {
    server.close();
    await proxy.shutdown();
    dev.close();
  }
});

test('binding to all interfaces is refused by configuration (security)', () => {
  process.env.QSP_BIND_HOST = '0.0.0.0';
  try { assert.throws(() => loadConfig(), /all interfaces/); } finally { delete process.env.QSP_BIND_HOST; }
});
