// Change log:
//   Wed Nov 18 14:30 CET 2026 - Initial version: minimal Modbus/TCP framing (FC 0x03, 0x11)
'use strict';

const MAX_PDU = 253;

// Build a Modbus/TCP ADU (MBAP header + PDU) - Wed Nov 18 14:30 CET 2026
function buildFrame(txId, unitId, fc, data = Buffer.alloc(0)) {
  const b = Buffer.alloc(8 + data.length);
  b.writeUInt16BE(txId, 0);
  b.writeUInt16BE(0, 2); // protocol id
  b.writeUInt16BE(data.length + 2, 4); // unit + fc + data
  b.writeUInt8(unitId, 6);
  b.writeUInt8(fc, 7);
  data.copy(b, 8);
  return b;
}

// Request: read holding registers - Wed Nov 18 14:30 CET 2026
function readHoldingRequest(txId, unitId, addr, qty) {
  const d = Buffer.alloc(4);
  d.writeUInt16BE(addr, 0);
  d.writeUInt16BE(qty, 2);
  return buildFrame(txId, unitId, 0x03, d);
}

// Request: report slave id (device identification) - Wed Nov 18 14:30 CET 2026
function reportSlaveIdRequest(txId, unitId) {
  return buildFrame(txId, unitId, 0x11);
}

// Extract one complete frame from a buffer; returns {frame, rest} or null; throws on malformed MBAP - Wed Nov 18 14:30 CET 2026
function extractFrame(buf) {
  if (buf.length < 8) return null;
  if (buf.readUInt16BE(2) !== 0) throw new Error('not modbus');
  const len = buf.readUInt16BE(4);
  if (len < 2 || len > MAX_PDU + 1) throw new Error('bad length');
  if (buf.length < 6 + len) return null;
  return {
    frame: {
      txId: buf.readUInt16BE(0),
      unitId: buf.readUInt8(6),
      fc: buf.readUInt8(7),
      data: buf.subarray(8, 6 + len),
    },
    rest: buf.subarray(6 + len),
  };
}

// Decode a read-holding-registers response payload into uint16 values - Wed Nov 18 14:30 CET 2026
function decodeRegisters(data) {
  const n = data.readUInt8(0) / 2;
  const out = [];
  for (let i = 0; i < n; i++) out.push(data.readUInt16BE(1 + i * 2));
  return out;
}

// Decode a report-slave-id response payload into text - Wed Nov 18 14:30 CET 2026
function decodeSlaveId(data) {
  return data.subarray(1, 1 + data.readUInt8(0)).toString('ascii');
}

// One-shot request over any connected duplex stream (plain TCP or TLS) - Wed Nov 18 14:30 CET 2026
function roundTrip(stream, request, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => done(new Error('timeout')), timeoutMs);
    const onData = (c) => {
      buf = Buffer.concat([buf, c]);
      try {
        const r = extractFrame(buf);
        if (r) done(null, r.frame);
      } catch (e) {
        done(e);
      }
    };
    const onErr = (e) => done(e);
    const onEnd = () => done(new Error('closed'));
    function done(err, val) {
      clearTimeout(timer);
      stream.off('data', onData).off('error', onErr).off('close', onEnd);
      err ? reject(err) : resolve(val);
    }
    stream.on('data', onData).on('error', onErr).on('close', onEnd);
    stream.write(request);
  });
}

module.exports = { buildFrame, readHoldingRequest, reportSlaveIdRequest, extractFrame, decodeRegisters, decodeSlaveId, roundTrip };
