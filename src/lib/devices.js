// Change log:
//   Wed Nov 18 14:32 CET 2026 - Initial version: shared mock-device helpers (values, fingerprint)
//   Wed Nov 18 14:57 CET 2026 - legacyTlsOptions/legacyDescription for legacy devices that speak classical (non-PQC) TLS
'use strict';
const crypto = require('node:crypto');

// Deterministic, slowly varying mock value for a register (same for every reader at the same second) - Wed Nov 18 14:32 CET 2026
function registerRaw(reg, idx, nowMs = Date.now()) {
  const t = Math.floor(nowMs / 1000);
  const wobble = reg.jitter ? Math.round(Math.sin(t / 7 + idx * 1.7) * reg.jitter) : 0;
  return Math.max(0, Math.min(65535, reg.base + wobble));
}

// Configuration fingerprint of a legacy device; proves the device was not modified - Wed Nov 18 14:32 CET 2026
function fingerprint(asset) {
  const basis = JSON.stringify({
    id: asset.id,
    m: asset.vendorModel,
    fw: asset.firmware,
    u: asset.unitId,
    r: asset.registers.map((r) => [r.name, r.unit, r.scale]),
  });
  return crypto.createHash('sha256').update(basis).digest('hex').slice(0, 12);
}

// Identification string returned by Report Slave ID (FC 0x11) - Wed Nov 18 14:32 CET 2026
function slaveIdString(asset) {
  return `${asset.id}|${asset.vendorModel}|FW${asset.firmware}|cfg:${fingerprint(asset)}`;
}

// Convert raw registers into engineering values for display - Wed Nov 18 14:32 CET 2026
function toEngineering(asset, raws) {
  return asset.registers.map((r, i) => ({
    name: r.name,
    unit: r.unit,
    raw: raws[i],
    value: Math.round(raws[i] * r.scale * 100) / 100,
  }));
}

// TLS options shared by the legacy device (server side) and its clients: classical TLS only, pinned to the device's capabilities - Wed Nov 18 14:57 CET 2026
function legacyTlsOptions(asset) {
  const t = asset.legacyTransport;
  return { minVersion: t.version, maxVersion: t.version, ciphers: t.ciphers, ecdhCurve: t.groups };
}

// Human readable description of what the legacy endpoint speaks - Wed Nov 18 14:57 CET 2026
function legacyDescription(asset) {
  const t = asset.legacyTransport;
  return t ? `Modbus/TCP over ${t.version.replace('TLSv', 'TLS ')} (${t.ciphers}, ${t.groups}) - classical key exchange, no ML-KEM`
    : 'plaintext Modbus/TCP, no TLS, no ML-KEM';
}

module.exports = { registerRaw, fingerprint, slaveIdString, toEngineering, legacyTlsOptions, legacyDescription };
