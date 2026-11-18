// Change log:
//   Wed Nov 18 14:48 CET 2026 - Initial version: start legacy OT simulator + Quantum Safe Proxy together
'use strict';
const { spawn } = require('node:child_process');
const path = require('node:path');

const kids = ['legacy/ot-simulator.js', 'proxy/server.js'].map((f) =>
  spawn(process.execPath, [path.join(__dirname, f)], { stdio: 'inherit' }));

// Stop both children and exit - Wed Nov 18 14:48 CET 2026
const stop = () => { kids.forEach((k) => k.kill('SIGTERM')); setTimeout(() => process.exit(0), 300); };
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
kids.forEach((k) => k.on('exit', (c) => { if (c) { console.error('child exited with', c); stop(); } }));
