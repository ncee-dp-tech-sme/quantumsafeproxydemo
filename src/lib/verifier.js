// Change log:
//   Wed Nov 18 14:36 CET 2026 - Initial version: independent PQC verification (wire tap, TLS record parsing, OpenSSL probes)
//   Wed Nov 18 14:57 CET 2026 - Support legacy devices that speak classical TLS 1.2/1.3: TLS-aware direct read, wire capture,
//                               TLS 1.2 ServerKeyExchange parsing and a "legacy endpoint is classical" check
//
// Verification does NOT trust the proxy's own claims. It observes the TLS handshake bytes on the wire
// (through a transparent tap) and corroborates with the stock OpenSSL command line client.
'use strict';
const fs = require('node:fs');
const net = require('node:net');
const tls = require('node:tls');
const { execFile } = require('node:child_process');
const modbus = require('./modbus');
const { toEngineering, slaveIdString, legacyTlsOptions } = require('./devices');

const GROUP_NAMES = {
  0x11ec: 'X25519MLKEM768', 0x11eb: 'SecP256r1MLKEM768', 0x11ed: 'SecP384r1MLKEM1024',
  0x0200: 'MLKEM512', 0x0201: 'MLKEM768', 0x0202: 'MLKEM1024',
  0x001d: 'x25519', 0x0017: 'secp256r1', 0x0018: 'secp384r1', 0x0019: 'secp521r1',
};
const PQC_GROUP_IDS = new Set([0x11ec, 0x11eb, 0x11ed, 0x0200, 0x0201, 0x0202]);
const CIPHER_NAMES = {
  0x1301: 'TLS_AES_128_GCM_SHA256', 0x1302: 'TLS_AES_256_GCM_SHA384', 0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0xc02f: 'ECDHE-RSA-AES128-GCM-SHA256', 0xc030: 'ECDHE-RSA-AES256-GCM-SHA384',
};
const groupName = (id) => GROUP_NAMES[id] || `0x${id.toString(16)}`;
const TLS_VERSIONS = { 0x0301: 'TLSv1.0', 0x0302: 'TLSv1.1', 0x0303: 'TLSv1.2', 0x0304: 'TLSv1.3' };

// Parse the first ClientHello in a captured client->server stream - Wed Nov 18 14:36 CET 2026
function parseClientHello(buf) {
  try {
    if (buf.length < 9 || buf[0] !== 0x16 || buf[5] !== 0x01) return null;
    const hs = buf.subarray(5, 5 + buf.readUInt16BE(3));
    let p = 4 + 2 + 32;
    p += 1 + hs[p];
    p += 2 + hs.readUInt16BE(p);
    p += 1 + hs[p];
    const end = p + 2 + hs.readUInt16BE(p);
    p += 2;
    const out = { offeredGroups: [], keyShares: [] };
    while (p + 4 <= end) {
      const type = hs.readUInt16BE(p);
      const len = hs.readUInt16BE(p + 2);
      const body = hs.subarray(p + 4, p + 4 + len);
      if (type === 0x000a) {
        for (let i = 2; i + 2 <= body.length; i += 2) out.offeredGroups.push(groupName(body.readUInt16BE(i)));
      } else if (type === 0x0033) {
        let q = 2;
        while (q + 4 <= body.length) {
          const g = body.readUInt16BE(q);
          const l = body.readUInt16BE(q + 2);
          out.keyShares.push({ group: groupName(g), bytes: l, pqc: PQC_GROUP_IDS.has(g) });
          q += 4 + l;
        }
      }
      p += 4 + len;
    }
    return out;
  } catch {
    return null;
  }
}

// Parse the first ServerHello in a captured server->client stream - Wed Nov 18 14:36 CET 2026
function parseServerHello(buf) {
  try {
    if (buf.length < 9 || buf[0] !== 0x16 || buf[5] !== 0x02) return null;
    const hs = buf.subarray(5, 5 + buf.readUInt16BE(3));
    let p = 4 + 2 + 32;
    p += 1 + hs[p];
    const cipherId = hs.readUInt16BE(p);
    p += 3;
    const end = p + 2 + hs.readUInt16BE(p);
    p += 2;
    const out = { cipher: CIPHER_NAMES[cipherId] || `0x${cipherId.toString(16)}`, version: TLS_VERSIONS[hs.readUInt16BE(4)] };
    while (p + 4 <= end) {
      const type = hs.readUInt16BE(p);
      const len = hs.readUInt16BE(p + 2);
      const body = hs.subarray(p + 4, p + 4 + len);
      if (type === 0x0033 && len >= 4) {
        const g = body.readUInt16BE(0);
        out.group = groupName(g);
        out.groupId = '0x' + g.toString(16).padStart(4, '0');
        out.keyShareBytes = body.readUInt16BE(2);
        out.pqc = PQC_GROUP_IDS.has(g);
      } else if (type === 0x002b && len === 2) {
        out.version = body.readUInt16BE(0) === 0x0304 ? 'TLSv1.3' : '0x' + body.readUInt16BE(0).toString(16);
      }
      p += 4 + len;
    }
    return out;
  } catch {
    return null;
  }
}

// Parse the TLS 1.2 ServerKeyExchange (sent in clear) to find the ECDHE curve - Wed Nov 18 14:57 CET 2026
function parseServerKeyExchange(buf) {
  try {
    let hs = Buffer.alloc(0);
    for (let p = 0; p + 5 <= buf.length && buf[p] === 0x16; p += 5 + buf.readUInt16BE(p + 3)) {
      hs = Buffer.concat([hs, buf.subarray(p + 5, p + 5 + buf.readUInt16BE(p + 3))]);
    }
    for (let p = 0; p + 4 <= hs.length; p += 4 + hs.readUIntBE(p + 1, 3)) {
      if (hs[p] === 0x0c && hs[p + 4] === 3) {
        const id = hs.readUInt16BE(p + 5);
        return { group: groupName(id), groupId: '0x' + id.toString(16).padStart(4, '0'), pqc: PQC_GROUP_IDS.has(id) };
      }
    }
    return null;
  } catch {
    return null;
  }
}

// Count TLS records by type in a stream - Wed Nov 18 14:36 CET 2026
function countRecords(buf) {
  let p = 0;
  const c = { handshake: 0, appData: 0, alert: 0 };
  while (p + 5 <= buf.length) {
    const t = buf[p];
    if (t === 0x16) c.handshake++;
    else if (t === 0x17) c.appData++;
    else if (t === 0x15) c.alert++;
    else if (t !== 0x14) break; // 0x14 = legacy change_cipher_spec (middlebox compatibility)
    p += 5 + buf.readUInt16BE(p + 3);
  }
  return c;
}

const hex = (b, n = 48) => [...b.subarray(0, n)].map((x) => x.toString(16).padStart(2, '0')).join(' ');

// Transparent TCP tap on an ephemeral loopback port that records both directions - Wed Nov 18 14:36 CET 2026
function startTap(targetHost, targetPort) {
  const cap = { c2s: Buffer.alloc(0), s2c: Buffer.alloc(0) };
  const LIMIT = 64 * 1024;
  const server = net.createServer((c) => {
    const u = net.connect(targetPort, targetHost);
    const rec = (k) => (d) => { if (cap[k].length < LIMIT) cap[k] = Buffer.concat([cap[k], d]); };
    c.on('data', rec('c2s')).on('data', (d) => u.write(d));
    u.on('data', rec('s2c')).on('data', (d) => c.write(d));
    c.on('error', () => u.destroy()).on('close', () => u.destroy());
    u.on('error', () => c.destroy()).on('close', () => c.destroy());
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve({ port: server.address().port, cap, close: () => server.close() })));
}

// TLS client options for a PQC-only client with the demo client certificate - Wed Nov 18 14:36 CET 2026
function tlsOpts(cfg, port, extra = {}) {
  return {
    host: '127.0.0.1', port, servername: 'localhost', ca: fs.readFileSync(cfg.paths.ca),
    cert: fs.readFileSync(cfg.paths.clientCert), key: fs.readFileSync(cfg.paths.clientKey),
    minVersion: 'TLSv1.3', ecdhCurve: 'X25519MLKEM768', ...extra,
  };
}

// Connect a TLS client with a hard timeout - Wed Nov 18 14:36 CET 2026
function tlsConnect(opts, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const s = tls.connect(opts);
    const t = setTimeout(() => { s.destroy(); reject(new Error('connect timeout')); }, timeoutMs);
    s.once('secureConnect', () => { clearTimeout(t); resolve(s); });
    s.once('error', (e) => { clearTimeout(t); reject(e); });
  });
}

// Read device data over a connected stream: registers + identification - Wed Nov 18 14:36 CET 2026
async function readDevice(stream, asset) {
  const regs = await modbus.roundTrip(stream, modbus.readHoldingRequest(1, asset.unitId, 0, asset.registers.length));
  const id = await modbus.roundTrip(stream, modbus.reportSlaveIdRequest(2, asset.unitId));
  const raw = modbus.decodeRegisters(regs.data);
  return { registers: toEngineering(asset, raw), rawRegisters: raw, slaveId: modbus.decodeSlaveId(id.data) };
}

// TLS client options towards a legacy device that speaks classical TLS (server auth only, device's own parameters) - Wed Nov 18 14:57 CET 2026
function legacyTlsClientOpts(cfg, asset, port = asset.legacyPort) {
  return { host: cfg.legacyHost, port, servername: 'localhost', ca: fs.readFileSync(cfg.paths.ca), ...legacyTlsOptions(asset) };
}

// Read directly from the legacy device (plaintext, or classical TLS for TLS-speaking devices) - Wed Nov 18 14:36 CET 2026
async function readDirect(cfg, asset) {
  if (asset.legacyTransport) {
    const t = await tlsConnect(legacyTlsClientOpts(cfg, asset));
    try { return { via: 'classical-tls', protocol: t.getProtocol(), cipher: t.getCipher().name, ...(await readDevice(t, asset)) }; } finally { t.destroy(); }
  }
  const s = net.connect(asset.legacyPort, cfg.legacyHost);
  await new Promise((res, rej) => { s.once('connect', res); s.once('error', rej); });
  try { return { via: 'plaintext', ...(await readDevice(s, asset)) }; } finally { s.destroy(); }
}

// Read through the PQC proxy listener - Wed Nov 18 14:36 CET 2026
async function readViaPqc(cfg, asset) {
  const s = await tlsConnect(tlsOpts(cfg, asset.pqcPort));
  try {
    return { via: 'pqc-tls', protocol: s.getProtocol(), cipher: s.getCipher().name, ...(await readDevice(s, asset)) };
  } finally { s.destroy(); }
}

// Run the stock OpenSSL s_client and report negotiated parameters or the failure alert - Wed Nov 18 14:36 CET 2026
function opensslProbe(cfg, port, { groups, tlsVersion = '-tls1_3', withCert = true } = {}) {
  const args = ['s_client', '-connect', `127.0.0.1:${port}`, '-servername', 'localhost', '-CAfile', cfg.paths.ca,
    '-verify_return_error', '-verify_hostname', 'localhost', tlsVersion];
  if (groups) args.push('-groups', groups);
  if (withCert) args.push('-cert', cfg.paths.clientCert, '-key', cfg.paths.clientKey);
  return new Promise((resolve) => {
    const child = execFile(cfg.opensslBin, args, { timeout: 8000, maxBuffer: 1 << 20 }, (err, stdout, stderr) => {
      const out = `${stdout}\n${stderr}`;
      const m = (re) => (re.exec(out) || [])[1];
      const alert = /alert ([a-z0-9 ]+?)(?::|\n|$)/i.exec(out);
      const cipher = m(/Cipher is (\S+)/) || m(/Cipher\s*:\s*(\S+)/);
      resolve({
        connected: !!cipher && cipher !== '(NONE)' && !alert && !/unexpected eof|no peer certificate/i.test(out),
        version: m(/Protocol\s*:\s*(\S+)/) || m(/New, (TLSv\S+),/),
        cipher,
        group: m(/Negotiated TLS1\.3 group:\s*(\S+)/) || m(/(?:Peer|Server) Temp Key:\s*([^\r\n]+)/),
        alert: alert ? alert[1].trim() : null,
        error: err && !alert ? 'no TLS response' : null,
      });
    });
    child.stdin.on('error', () => {});
    child.stdin.end('Q\n');
  });
}

// Does a raw plaintext Modbus request to the listener yield readable data? - Wed Nov 18 14:36 CET 2026
function plaintextProbe(asset, host, port) {
  return new Promise((resolve) => {
    const s = net.connect(port, host);
    let buf = Buffer.alloc(0);
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      s.destroy();
      let readable = false;
      try { readable = !!modbus.extractFrame(buf); } catch { /* not modbus */ }
      resolve({ bytes: buf.length, firstBytesHex: hex(buf, 16), tlsAlert: buf[0] === 0x15, readable });
    };
    const t = setTimeout(finish, 1500);
    s.on('connect', () => s.write(modbus.readHoldingRequest(1, asset.unitId, 0, 2)));
    s.on('data', (d) => { buf = Buffer.concat([buf, d]); });
    s.on('close', () => { clearTimeout(t); finish(); });
    s.on('error', () => {});
  });
}

// Capture what an eavesdropper sees on the legacy path (plaintext, or classical TLS handshake) - Wed Nov 18 14:36 CET 2026
async function wireBefore(cfg, asset) {
  const tap = await startTap(cfg.legacyHost, asset.legacyPort);
  try {
    if (asset.legacyTransport) {
      const s = await tlsConnect(legacyTlsClientOpts(cfg, asset, tap.port));
      const info = { protocol: s.getProtocol(), cipher: s.getCipher().name };
      await readDevice(s, asset);
      s.destroy();
      await new Promise((r) => setTimeout(r, 50));
      const sh = parseServerHello(tap.cap.s2c) || {};
      const kex = info.protocol === 'TLSv1.3'
        ? { group: sh.group, groupId: sh.groupId, pqc: !!sh.pqc }
        : parseServerKeyExchange(tap.cap.s2c) || {};
      const leaked = tap.cap.s2c.toString('latin1').includes(asset.id);
      return {
        protocol: `Modbus/TCP over ${info.protocol.replace('TLSv', 'TLS ')} (${info.cipher})`, tls: true, tlsVersion: info.protocol, pqc: !!kex.pqc,
        cipher: sh.cipher || info.cipher, kex, clientHello: parseClientHello(tap.cap.c2s), serverHello: sh,
        records: countRecords(tap.cap.s2c),
        s2cHex: hex(tap.cap.s2c, 40), c2sHex: hex(tap.cap.c2s, 24), s2cBytes: tap.cap.s2c.length,
        eavesdropperReadable: leaked,
        eavesdropperSees: `payload encrypted, but key exchange is classical ${kex.group || '?'} (${kex.groupId || '?'}): recorded traffic is decryptable by a future quantum computer`,
      };
    }
    const s = net.connect(tap.port, '127.0.0.1');
    await new Promise((res, rej) => { s.once('connect', res); s.once('error', rej); });
    await readDevice(s, asset);
    s.destroy();
    await new Promise((r) => setTimeout(r, 50));
    const leaked = tap.cap.s2c.toString('latin1').includes(asset.id);
    return {
      protocol: 'Modbus/TCP over plain TCP', tls: false, pqc: false,
      s2cHex: hex(tap.cap.s2c, 40), c2sHex: hex(tap.cap.c2s, 24), s2cBytes: tap.cap.s2c.length,
      eavesdropperReadable: leaked,
      eavesdropperSees: leaked ? `device identity in clear text: "${slaveIdString(asset)}"` : 'n/a',
    };
  } finally { tap.close(); }
}

// Capture the TLS handshake and data records on the PQC path and parse them - Wed Nov 18 14:36 CET 2026
async function wireAfter(cfg, asset) {
  const tap = await startTap('127.0.0.1', asset.pqcPort);
  try {
    const s = await tlsConnect(tlsOpts(cfg, tap.port));
    const info = { protocol: s.getProtocol(), cipher: s.getCipher().name };
    const data = await readDevice(s, asset);
    s.destroy();
    await new Promise((r) => setTimeout(r, 50));
    const leaked = tap.cap.s2c.toString('latin1').includes(asset.id) || tap.cap.c2s.toString('latin1').includes(asset.id);
    return {
      protocol: info.protocol, tls: true,
      clientHello: parseClientHello(tap.cap.c2s), serverHello: parseServerHello(tap.cap.s2c),
      records: countRecords(tap.cap.s2c),
      s2cHex: hex(tap.cap.s2c, 40), c2sHex: hex(tap.cap.c2s, 24), s2cBytes: tap.cap.s2c.length, c2sBytes: tap.cap.c2s.length,
      eavesdropperReadable: leaked, data,
    };
  } finally { tap.close(); }
}

// Full independent verification of an onboarded asset - Wed Nov 18 14:36 CET 2026
async function verifyAsset(cfg, asset, baselineFingerprint) {
  const checks = [];
  const add = (id, title, expected, actual, pass) => checks.push({ id, title, expected, actual, pass: !!pass });

  const before = await wireBefore(cfg, asset);
  const after = await wireAfter(cfg, asset);
  const sh = after.serverHello || {};
  if (asset.legacyTransport) {
    add('legacy-classical', 'Legacy endpoint negotiates only classical (quantum-vulnerable) key exchange', 'TLS without ML-KEM',
      `${before.tlsVersion} / ${before.cipher} / ${before.kex.group || '?'} (${before.kex.groupId || '?'})`, before.tls && !before.pqc && !!before.kex.group);
  }
  add('wire-group', 'Key exchange on the wire is hybrid ML-KEM (ServerHello key_share)',
    'X25519MLKEM768 (0x11ec)', sh.group ? `${sh.group} (${sh.groupId}), ${sh.keyShareBytes} B key share` : 'not found', sh.pqc);
  add('tls13', 'Protocol and cipher', 'TLSv1.3 / AES-256-GCM', `${after.protocol} / ${sh.cipher}`,
    after.protocol === 'TLSv1.3' && sh.cipher === 'TLS_AES_256_GCM_SHA384');
  add('no-leak', 'Eavesdropper cannot read device data on the wire', 'no cleartext asset identity',
    after.eavesdropperReadable ? 'cleartext found' : 'encrypted records only', !after.eavesdropperReadable && after.records.appData > 0);

  const os = await opensslProbe(cfg, asset.pqcPort, { groups: cfg.allowedGroups });
  add('openssl', 'Independent corroboration: stock OpenSSL client', 'Negotiated TLS1.3 group: ML-KEM hybrid',
    `${os.version || '?'} / ${os.group || os.error || os.alert || '?'}`, os.connected && /MLKEM/i.test(os.group || ''));

  const classical = await opensslProbe(cfg, asset.pqcPort, { groups: 'X25519' });
  add('reject-classical', 'Classical-only client (X25519, no ML-KEM) is refused', 'handshake rejected',
    classical.connected ? 'ACCEPTED' : `rejected (${classical.alert || classical.error})`, !classical.connected);

  const tls12 = await opensslProbe(cfg, asset.pqcPort, { tlsVersion: '-tls1_2' });
  add('reject-tls12', 'TLS 1.2 client is refused', 'handshake rejected',
    tls12.connected ? 'ACCEPTED' : `rejected (${tls12.alert || tls12.error})`, !tls12.connected);

  if (cfg.requireClientCert) {
    let outcome = 'ACCEPTED';
    try {
      const s = await tlsConnect(tlsOpts(cfg, asset.pqcPort, { cert: undefined, key: undefined }));
      await modbus.roundTrip(s, modbus.readHoldingRequest(1, asset.unitId, 0, 1), 2000);
      s.destroy();
    } catch (e) { outcome = `rejected (${(e.code || e.message || '').toString().slice(0, 60)})`; }
    add('reject-nocert', 'Client without certificate is refused (mutual TLS)', 'rejected', outcome, outcome.startsWith('rejected'));
  }

  const plain = await plaintextProbe(asset, '127.0.0.1', asset.pqcPort);
  add('reject-plain', 'Plaintext Modbus on the PQC port returns no data', 'no Modbus response',
    plain.readable ? 'DATA RETURNED' : `no data (${plain.tlsAlert ? 'TLS alert' : 'connection closed'})`, !plain.readable);

  const direct = await readDirect(cfg, asset);
  const viaPqc = after.data;
  const tolerant = viaPqc.rawRegisters.every((v, i) => Math.abs(v - direct.rawRegisters[i]) <= asset.registers[i].jitter * 2 + 1);
  add('parity', 'Same OT data through PQC channel as direct from device', `${asset.registers.length} registers match`,
    tolerant ? `${asset.registers.length} registers match` : 'mismatch', tolerant);

  const fp = direct.slaveId;
  add('untouched', 'Legacy device unchanged (firmware + config fingerprint)', baselineFingerprint || fp, fp,
    !baselineFingerprint || fp === baselineFingerprint);

  return { assetId: asset.id, timestamp: new Date().toISOString(), pass: checks.every((c) => c.pass), checks, wire: { before, after }, legacyIdentity: fp };
}

module.exports = {
  parseClientHello, parseServerHello, parseServerKeyExchange, legacyTlsClientOpts, countRecords, startTap, readDirect, readViaPqc, readDevice,
  opensslProbe, plaintextProbe, verifyAsset, tlsConnect, tlsOpts, wireBefore, wireAfter, groupName,
};
