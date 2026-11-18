// Change log:
//   Wed Nov 18 14:30 CET 2026 - Initial version: minimal .env loader and typed config (no dependencies)
//   Wed Nov 18 14:57 CET 2026 - Legacy device cert paths; validation of legacyTransport (classical TLS legacy devices)
'use strict';
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');

// Parse KEY=VALUE lines of a .env file into process.env without overriding existing vars - Wed Nov 18 14:30 CET 2026
function loadEnvFile(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (m && !line.trimStart().startsWith('#') && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
}

// Build the runtime configuration from the environment - Wed Nov 18 14:30 CET 2026
function loadConfig() {
  loadEnvFile(path.join(ROOT, '.env'));
  const e = process.env;
  const certDir = path.resolve(ROOT, e.QSP_CERT_DIR || './certs');
  const cfg = {
    root: ROOT,
    logLevel: (e.LOG_LEVEL || 'INFO').toUpperCase(),
    bindHost: e.QSP_BIND_HOST || '127.0.0.1',
    adminPort: Number(e.QSP_ADMIN_PORT || 8080),
    allowedGroups: e.QSP_ALLOWED_GROUPS || 'X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024',
    requireClientCert: (e.QSP_REQUIRE_CLIENT_CERT || 'true').toLowerCase() !== 'false',
    legacyHost: e.LEGACY_BIND_HOST || '127.0.0.1',
    upstreamTimeoutMs: Number(e.QSP_UPSTREAM_TIMEOUT_MS || 5000),
    idleTimeoutMs: Number(e.QSP_IDLE_TIMEOUT_MS || 60000),
    opensslBin: e.OPENSSL_BIN || 'openssl',
    certDir,
    paths: {
      assets: path.join(ROOT, 'data', 'assets.json'),
      state: path.join(ROOT, 'data', 'state.json'),
      evidence: path.join(ROOT, 'evidence'),
      logs: path.join(ROOT, 'logs'),
      ui: path.join(ROOT, 'ui'),
      ca: path.join(certDir, 'ca.pem'),
      serverCert: path.join(certDir, 'server.pem'),
      serverKey: path.join(certDir, 'server.key'),
      clientCert: path.join(certDir, 'client.pem'),
      clientKey: path.join(certDir, 'client.key'),
      legacyCert: path.join(certDir, 'legacy.pem'),
      legacyKey: path.join(certDir, 'legacy.key'),
    },
  };
  // Never bind to all interfaces (security policy)
  for (const h of [cfg.bindHost, cfg.legacyHost]) {
    if (h === '0.0.0.0' || h === '::') throw new Error('Binding to all interfaces is not allowed');
  }
  return cfg;
}

// Load and validate the mock asset catalogue - Wed Nov 18 14:30 CET 2026
function loadAssets(cfg) {
  const assets = JSON.parse(fs.readFileSync(cfg.paths.assets, 'utf8'));
  for (const a of assets) {
    if (!/^[A-Z0-9-]{3,20}$/.test(a.id)) throw new Error(`Invalid asset id ${a.id}`);
    for (const p of [a.legacyPort, a.pqcPort]) {
      if (!Number.isInteger(p) || p < 1024 || p > 65535) throw new Error(`Invalid port for ${a.id}`);
    }
    const t = a.legacyTransport;
    if (t && (t.mode !== 'tls' || !['TLSv1.2', 'TLSv1.3'].includes(t.version) || !/^[A-Za-z0-9:_-]+$/.test(t.ciphers) || !/^[A-Za-z0-9:_-]+$/.test(t.groups))) {
      throw new Error(`Invalid legacyTransport for ${a.id}`);
    }
  }
  return assets;
}

module.exports = { loadConfig, loadAssets, ROOT };
