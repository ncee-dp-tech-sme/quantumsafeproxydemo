// Change log:
//   Wed Nov 18 14:42 CET 2026 - Initial version: Quantum Safe Proxy core (PQC TLS 1.3 termination + onboarding + evidence)
//   Wed Nov 18 14:57 CET 2026 - Upstream hop can be classical TLS (legacyTransport); baseline scan reports the classical TLS the device negotiates
//
// The proxy terminates TLS 1.3 with hybrid ML-KEM key exchange on a new loopback listener and forwards the
// decrypted bytes to the UNCHANGED legacy device. Nothing is installed on or configured in the legacy system.
'use strict';
const fs = require('node:fs');
const net = require('node:net');
const tls = require('node:tls');
const crypto = require('node:crypto');
const path = require('node:path');
const verifier = require('../lib/verifier');

// Translate raw OpenSSL handshake errors into safe, generic reasons (no internals leaked to the UI) - Wed Nov 18 14:42 CET 2026
function rejectionReason(err) {
  const m = `${err.code || ''} ${err.message || ''}`.toLowerCase();
  if (m.includes('wrong version number') || m.includes('http request') || m.includes('packet length') || m.includes('record'))
    return 'non-TLS (plaintext) client';
  if (m.includes('no suitable key share') || m.includes('handshake failure') || m.includes('no shared') || m.includes('group'))
    return 'client offered no post-quantum (ML-KEM) key exchange group';
  if (m.includes('protocol version') || m.includes('unsupported protocol') || m.includes('version'))
    return 'client protocol older than TLS 1.3';
  if (m.includes('certificate') || m.includes('peer did not return'))
    return 'client certificate missing or not trusted';
  return 'TLS handshake rejected by policy';
}

class QuantumSafeProxy {
  // Create the proxy bound to a catalogue of mock assets - Wed Nov 18 14:42 CET 2026
  constructor(cfg, assets, log, audit) {
    this.cfg = cfg;
    this.assets = assets;
    this.log = log;
    this.audit = audit;
    this.listeners = new Map();
    this.busy = new Set();
    this.stats = new Map(assets.map((a) => [a.id, { sessions: 0, rejected: 0 }]));
    this.state = this.#loadState();
  }

  #loadState() {
    try { return JSON.parse(fs.readFileSync(this.cfg.paths.state, 'utf8')); } catch { return { onboarded: {} }; }
  }

  #saveState() {
    fs.writeFileSync(this.cfg.paths.state, JSON.stringify(this.state, null, 2), { mode: 0o600 });
  }

  // Look up an asset by id from the allowlisted catalogue - Wed Nov 18 14:42 CET 2026
  asset(id) {
    return this.assets.find((a) => a.id === id) || null;
  }

  // Re-open listeners for assets onboarded in a previous run - Wed Nov 18 14:42 CET 2026
  async restore() {
    for (const id of Object.keys(this.state.onboarded)) {
      const a = this.asset(id);
      if (a) await this.#listen(a).catch((e) => this.log.error('restore failed', { asset: id, code: e.code }));
    }
  }

  // Public view of one asset including onboarding state - Wed Nov 18 14:42 CET 2026
  view(a) {
    const ob = this.state.onboarded[a.id];
    const { registers, ...meta } = a;
    return {
      ...meta,
      registerCount: registers.length,
      status: ob ? 'pqc-protected' : 'legacy-exposed',
      onboarding: ob || null,
      stats: this.stats.get(a.id),
      listener: this.listeners.has(a.id) ? `127.0.0.1:${a.pqcPort}` : null,
    };
  }

  // Open the PQC TLS listener for an asset - Wed Nov 18 14:42 CET 2026
  #listen(a) {
    const cfg = this.cfg;
    const server = tls.createServer({
      key: fs.readFileSync(cfg.paths.serverKey),
      cert: fs.readFileSync(cfg.paths.serverCert),
      ca: fs.readFileSync(cfg.paths.ca),
      requestCert: cfg.requireClientCert,
      rejectUnauthorized: cfg.requireClientCert,
      minVersion: 'TLSv1.3',
      ecdhCurve: cfg.allowedGroups, // PQC hybrid groups only: classical-only clients cannot complete a handshake
      ciphers: 'TLS_AES_256_GCM_SHA384',
    }, (sock) => this.#session(a, sock));
    const conns = new Set();
    server.on('connection', (raw) => { conns.add(raw); raw.on('close', () => conns.delete(raw)); });
    server.on('tlsClientError', (err) => {
      this.stats.get(a.id).rejected++;
      this.audit.record('handshake.rejected', { asset: a.id, reason: rejectionReason(err) }, 'warn');
    });
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(a.pqcPort, cfg.bindHost, () => {
        server.off('error', reject);
        this.listeners.set(a.id, { server, conns });
        resolve();
      });
    });
  }

  // Bridge one authenticated PQC session to the legacy device - Wed Nov 18 14:42 CET 2026
  #session(a, sock) {
    const cfg = this.cfg;
    const peer = sock.getPeerCertificate()?.subject?.CN || 'anonymous';
    this.stats.get(a.id).sessions++;
    this.audit.record('session.open', { asset: a.id, client: peer, tls: sock.getProtocol(), cipher: sock.getCipher().name, kex: 'ML-KEM hybrid (policy-enforced)' });
    const up = a.legacyTransport ? tls.connect(verifier.legacyTlsClientOpts(cfg, a)) : net.connect(a.legacyPort, cfg.legacyHost);
    up.setTimeout(cfg.upstreamTimeoutMs, () => up.destroy());
    sock.setTimeout(cfg.idleTimeoutMs, () => sock.destroy());
    up.once('connect', () => up.setTimeout(cfg.idleTimeoutMs));
    sock.pipe(up);
    up.pipe(sock);
    const kill = () => { sock.destroy(); up.destroy(); };
    sock.on('error', kill).on('close', kill);
    up.on('error', (e) => {
      this.audit.record('upstream.error', { asset: a.id, code: e.code || 'ERR' }, 'warn');
      kill();
    });
  }

  // Onboard an asset: no change to the device, one new listener, then independent proof - Wed Nov 18 14:42 CET 2026
  async onboard(id) {
    const a = this.asset(id);
    if (!a) throw Object.assign(new Error('unknown asset'), { status: 404 });
    if (this.state.onboarded[id]) throw Object.assign(new Error('already onboarded'), { status: 409 });
    if (this.busy.has(id)) throw Object.assign(new Error('operation in progress'), { status: 409 });
    this.busy.add(id);
    const started = Date.now();
    const steps = [];
    const step = async (title, fn) => {
      const t0 = Date.now();
      try {
        const detail = await fn();
        steps.push({ title, detail, ok: true, ms: Date.now() - t0 });
        return detail;
      } catch (e) {
        steps.push({ title, detail: e.message, ok: false, ms: Date.now() - t0 });
        throw e;
      }
    };
    this.audit.record('onboard.start', { asset: a.id, legacy: `${this.cfg.legacyHost}:${a.legacyPort}` });
    let baseline;
    try {
      await step('Register asset in proxy catalogue', async () =>
        `${a.id} ${a.protocol} -> upstream ${this.cfg.legacyHost}:${a.legacyPort} (registry entry only, nothing changed on the device)`);
      await step('Read-only pre-flight: fingerprint legacy device', async () => {
        const d = await verifier.readDirect(this.cfg, a);
        baseline = d.slaveId;
        return `reachable, identity "${d.slaveId}"`;
      });
      await step('Baseline PQC scan of legacy endpoint', async () => {
        const t = a.legacyTransport;
        const r = await verifier.opensslProbe(this.cfg, a.legacyPort, { groups: 'X25519MLKEM768', withCert: false });
        if (r.connected) throw new Error(t ? 'unexpected: legacy endpoint already negotiates ML-KEM' : 'unexpected: legacy endpoint already speaks TLS');
        if (!t) return 'FAIL as expected: plaintext Modbus/TCP, no TLS, no ML-KEM (quantum-vulnerable)';
        const c = await verifier.opensslProbe(this.cfg, a.legacyPort, { groups: t.groups, tlsVersion: t.version === 'TLSv1.3' ? '-tls1_3' : '-tls1_2', withCert: false });
        if (!c.connected) throw new Error('legacy TLS endpoint did not answer a classical probe');
        return `FAIL as expected: ML-KEM refused (${r.alert || r.error || 'no shared group'}); device negotiates classical ${c.version} ${c.cipher} / ${c.group || t.groups} (quantum-vulnerable)`;
      });
      await step('Load PQC policy and server certificate', async () =>
        `TLS 1.3 only | ${this.cfg.allowedGroups.split(':').join(', ')} | AES-256-GCM | mTLS ${this.cfg.requireClientCert ? 'on' : 'off'}`);
      await step('Open PQC listener (new endpoint, device untouched)', async () => {
        await this.#listen(a);
        return `listening on ${this.cfg.bindHost}:${a.pqcPort}`;
      });
      await step('Smoke test: read device data through the PQC channel', async () => {
        const r = await verifier.readViaPqc(this.cfg, a);
        return `${r.protocol} ${r.cipher}: ${r.registers.slice(0, 2).map((x) => `${x.name} ${x.value}${x.unit ? ' ' + x.unit : ''}`).join(', ')}`;
      });
      this.state.onboarded[id] = { at: new Date().toISOString(), baselineIdentity: baseline, pqcPort: a.pqcPort };
      this.#saveState();
      const verification = await this.verify(id, true, steps);
      this.state.onboarded[id].totalMs = Date.now() - started;
      this.#saveState();
      this.audit.record('onboard.done', { asset: a.id, ms: Date.now() - started, verified: verification.pass });
      return {
        asset: this.view(a), steps, verification, totalMs: Date.now() - started,
        changesToLegacy: { firmware: 0, configuration: 0, restarts: 0, newSoftware: 0, portsOpenedOnDevice: 0 },
        changesElsewhere: { proxyRegistryEntries: 1, newPqcListener: `127.0.0.1:${a.pqcPort}` },
      };
    } catch (e) {
      await this.#close(id);
      delete this.state.onboarded[id];
      this.#saveState();
      this.audit.record('onboard.failed', { asset: a.id, reason: e.message }, 'warn');
      throw Object.assign(new Error(`onboarding failed: ${e.message}`), { status: 500, steps });
    } finally {
      this.busy.delete(id);
    }
  }

  // Run independent verification and persist hashed evidence - Wed Nov 18 14:42 CET 2026
  async verify(id, inOnboarding = false, steps = null) {
    const a = this.asset(id);
    if (!a) throw Object.assign(new Error('unknown asset'), { status: 404 });
    const ob = this.state.onboarded[id];
    if (!ob) throw Object.assign(new Error('asset not onboarded'), { status: 409 });
    const t0 = Date.now();
    const result = await verifier.verifyAsset(this.cfg, a, ob.baselineIdentity);
    const record = {
      asset: this.view(a), ...result,
      policy: { groups: this.cfg.allowedGroups, minTls: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384', mtls: this.cfg.requireClientCert },
    };
    fs.mkdirSync(this.cfg.paths.evidence, { recursive: true, mode: 0o700 });
    record.sha256 = crypto.createHash('sha256').update(JSON.stringify(record)).digest('hex');
    const file = `${a.id}-${record.timestamp.replace(/[:.]/g, '-')}.json`;
    fs.writeFileSync(path.join(this.cfg.paths.evidence, file), JSON.stringify(record, null, 2), { mode: 0o600 });
    ob.lastVerification = { at: record.timestamp, pass: record.pass, group: record.wire.after.serverHello?.group || null, file, sha256: record.sha256 };
    this.#saveState();
    if (steps) {
      steps.push({
        title: 'Independent verification (wire capture + OpenSSL + negative tests)',
        detail: `${result.checks.filter((c) => c.pass).length}/${result.checks.length} checks passed`,
        ok: result.pass, ms: Date.now() - t0,
      });
    }
    this.audit.record('verify.done', { asset: a.id, pass: result.pass, group: ob.lastVerification.group, evidence: file, inOnboarding }, result.pass ? 'info' : 'warn');
    return record;
  }

  // Close the PQC listener and live sessions for an asset - Wed Nov 18 14:42 CET 2026
  async #close(id) {
    const l = this.listeners.get(id);
    if (!l) return;
    this.listeners.delete(id);
    l.conns.forEach((c) => c.destroy());
    await new Promise((r) => l.server.close(r));
  }

  // Rollback: remove the proxy endpoint; the legacy device is exactly as it was - Wed Nov 18 14:42 CET 2026
  async offboard(id) {
    const a = this.asset(id);
    if (!a) throw Object.assign(new Error('unknown asset'), { status: 404 });
    if (!this.state.onboarded[id]) throw Object.assign(new Error('asset not onboarded'), { status: 409 });
    await this.#close(id);
    delete this.state.onboarded[id];
    this.#saveState();
    this.audit.record('offboard.done', { asset: a.id }, 'warn');
    return this.view(a);
  }

  // Live telemetry via the PQC channel, as the SCADA control centre would see it - Wed Nov 18 14:42 CET 2026
  async telemetry(id) {
    const a = this.asset(id);
    if (!a) throw Object.assign(new Error('unknown asset'), { status: 404 });
    if (!this.state.onboarded[id]) throw Object.assign(new Error('asset not onboarded'), { status: 409 });
    const r = await verifier.readViaPqc(this.cfg, a);
    return { id, via: r.via, protocol: r.protocol, cipher: r.cipher, registers: r.registers, at: new Date().toISOString() };
  }

  // Aggregate KPIs for the dashboard - Wed Nov 18 14:42 CET 2026
  summary() {
    const views = this.assets.map((a) => this.view(a));
    const protectedN = views.filter((v) => v.status === 'pqc-protected').length;
    return { total: views.length, protected: protectedN, exposed: views.length - protectedN, coveragePct: Math.round((protectedN / views.length) * 100) };
  }

  // Close everything on shutdown - Wed Nov 18 14:42 CET 2026
  async shutdown() {
    for (const id of [...this.listeners.keys()]) await this.#close(id);
  }
}

module.exports = { QuantumSafeProxy };
