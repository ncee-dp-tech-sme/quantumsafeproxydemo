// Change log:
//   Wed Nov 18 14:30 CET 2026 - Initial version: structured JSON logger + in-memory/on-disk audit trail
'use strict';
const fs = require('node:fs');
const path = require('node:path');

const LEVELS = { DEBUG: 10, INFO: 20, WARN: 30, ERROR: 40 };

// Create a JSON-line logger honouring LOG_LEVEL; never pass secrets to it - Wed Nov 18 14:30 CET 2026
function createLogger(level, component) {
  const min = LEVELS[level] || LEVELS.INFO;
  const log = (lvl, msg, extra = {}) => {
    if (LEVELS[lvl] < min) return;
    process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), level: lvl, component, msg, ...extra }) + '\n');
  };
  return {
    debug: (m, e) => log('DEBUG', m, e),
    info: (m, e) => log('INFO', m, e),
    warn: (m, e) => log('WARN', m, e),
    error: (m, e) => log('ERROR', m, e),
  };
}

// Audit trail: ring buffer for the dashboard + append-only file (retention is the operator's job) - Wed Nov 18 14:30 CET 2026
function createAudit(logDir, logger, max = 500) {
  fs.mkdirSync(logDir, { recursive: true, mode: 0o700 });
  const file = path.join(logDir, 'audit.log');
  const events = [];
  let seq = 0;
  return {
    record(type, data = {}, severity = 'info') {
      const ev = { seq: ++seq, ts: new Date().toISOString(), type, severity, ...data };
      events.push(ev);
      if (events.length > max) events.shift();
      fs.appendFile(file, JSON.stringify(ev) + '\n', { mode: 0o600 }, () => {});
      logger[severity === 'warn' ? 'warn' : 'info'](type, data);
      return ev;
    },
    since(n = 0) {
      return events.filter((e) => e.seq > n);
    },
  };
}

module.exports = { createLogger, createAudit };
