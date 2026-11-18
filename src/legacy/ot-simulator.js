// Change log:
//   Wed Nov 18 14:32 CET 2026 - Initial version: mock legacy OT devices (plaintext Modbus/TCP, no TLS, no PQC)
//   Wed Nov 18 14:57 CET 2026 - Devices with legacyTransport serve Modbus/TCP over classical TLS 1.2/1.3 (no ML-KEM)
//
// This process stands in for the OLD OT systems. It speaks ONLY plaintext Modbus/TCP, or - for devices with a
// legacyTransport - Modbus/TCP over classical (non-post-quantum) TLS. It is never modified when a device is
// onboarded into the Quantum Safe Proxy.
'use strict';
const fs = require('node:fs');
const net = require('node:net');
const tls = require('node:tls');
const { loadConfig, loadAssets } = require('../lib/config');
const { createLogger } = require('../lib/logger');
const { extractFrame, buildFrame } = require('../lib/modbus');
const { registerRaw, slaveIdString, legacyTlsOptions, legacyDescription } = require('../lib/devices');

// Serve one mock device on its legacy port - Wed Nov 18 14:32 CET 2026
function startDevice(cfg, log, asset) {
  const onConnection = (sock) => {
    let buf = Buffer.alloc(0);
    sock.setTimeout(30000, () => sock.destroy());
    sock.on('error', () => sock.destroy());
    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      try {
        let r;
        while ((r = extractFrame(buf))) {
          buf = r.rest;
          sock.write(handle(asset, r.frame));
        }
      } catch {
        sock.destroy(); // not Modbus (e.g. a TLS ClientHello): legacy firmware just drops it
      }
    });
  };
  const server = asset.legacyTransport
    ? tls.createServer({
      key: fs.readFileSync(cfg.paths.legacyKey), cert: fs.readFileSync(cfg.paths.legacyCert), ...legacyTlsOptions(asset),
    }, onConnection)
    : net.createServer(onConnection);
  if (asset.legacyTransport) server.on('tlsClientError', () => {}); // failed handshakes are silently dropped
  server.listen(asset.legacyPort, cfg.legacyHost, () =>
    log.info(`legacy device online (${legacyDescription(asset)})`, {
      asset: asset.id, model: asset.vendorModel, firmware: asset.firmware, port: asset.legacyPort,
    }));
  return server;
}

// Handle a Modbus request frame and build the response - Wed Nov 18 14:32 CET 2026
function handle(asset, f) {
  if (f.fc === 0x03 && f.data.length === 4) {
    const addr = f.data.readUInt16BE(0);
    const qty = f.data.readUInt16BE(2);
    if (qty < 1 || qty > 125 || addr + qty > asset.registers.length) {
      return buildFrame(f.txId, f.unitId, 0x83, Buffer.from([0x02])); // illegal data address
    }
    const d = Buffer.alloc(1 + qty * 2);
    d.writeUInt8(qty * 2, 0);
    for (let i = 0; i < qty; i++) d.writeUInt16BE(registerRaw(asset.registers[addr + i], addr + i), 1 + i * 2);
    return buildFrame(f.txId, f.unitId, 0x03, d);
  }
  if (f.fc === 0x11) {
    const s = Buffer.from(slaveIdString(asset), 'ascii');
    return buildFrame(f.txId, f.unitId, 0x11, Buffer.concat([Buffer.from([s.length]), s]));
  }
  return buildFrame(f.txId, f.unitId, f.fc | 0x80, Buffer.from([0x01])); // illegal function
}

if (require.main === module) {
  const cfg = loadConfig();
  const log = createLogger(cfg.logLevel, 'legacy-ot');
  const assets = loadAssets(cfg);
  const servers = assets.map((a) => startDevice(cfg, log, a));
  const stop = () => servers.forEach((s) => s.close());
  process.on('SIGINT', () => { stop(); process.exit(0); });
  process.on('SIGTERM', () => { stop(); process.exit(0); });
}

module.exports = { startDevice };
