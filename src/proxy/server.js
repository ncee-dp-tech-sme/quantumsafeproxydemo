// Change log:
//   Wed Nov 18 14:48 CET 2026 - Initial version: admin API + dashboard host + compliance report (loopback only)
//   Wed Nov 18 14:57 CET 2026 - Report distinguishes plaintext from classical-TLS exposed assets
'use strict';
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { loadConfig, loadAssets } = require('../lib/config');
const { createLogger, createAudit } = require('../lib/logger');
const { QuantumSafeProxy } = require('./qsp');

const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8'],
};
const ID_RE = /^[A-Z0-9-]{3,20}$/;
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Cost model from mock data: classic rip-and-replace vs Quantum Safe Proxy - Wed Nov 18 14:48 CET 2026
function economics(cfg, summary) {
  const e = JSON.parse(fs.readFileSync(path.join(cfg.root, 'data', 'economics.json'), 'utf8'));
  const n = summary.total;
  const rr = e.rip_and_replace;
  const q = e.quantum_safe_proxy;
  const replaceCost = n * (rr.perAssetHardwareAndEngineering + rr.perAssetRecertification);
  const replaceOutage = n * rr.outageDaysPerAsset * e.outageCostPerDay;
  const proxyCost = q.platformYear1 + n * q.perAssetOnboarding;
  const proxyOutage = n * q.outageDaysPerAsset * e.outageCostPerDay;
  return {
    currency: e.currency, disclaimer: e.disclaimer, assets: n, frameworks: e.frameworks,
    replace: { capex: replaceCost, outageCost: replaceOutage, total: replaceCost + replaceOutage, outageDays: n * rr.outageDaysPerAsset, months: rr.programMonths },
    proxy: { capex: proxyCost, outageCost: proxyOutage, total: proxyCost + proxyOutage, outageDays: n * q.outageDaysPerAsset, minutesPerAsset: q.minutesPerAsset },
    savings: replaceCost + replaceOutage - (proxyCost + proxyOutage),
  };
}

// Latest evidence file per asset - Wed Nov 18 14:48 CET 2026
function latestEvidence(cfg) {
  const out = {};
  let files = [];
  try { files = fs.readdirSync(cfg.paths.evidence).filter((f) => f.endsWith('.json')).sort(); } catch { /* none yet */ }
  for (const f of files) {
    try {
      const r = JSON.parse(fs.readFileSync(path.join(cfg.paths.evidence, f), 'utf8'));
      out[r.assetId] = { ...r, file: f };
    } catch { /* skip unreadable */ }
  }
  return out;
}

// Render the static compliance evidence report (all values HTML-escaped) - Wed Nov 18 14:48 CET 2026
function renderReport(cfg, proxy) {
  const ev = latestEvidence(cfg);
  const eco = economics(cfg, proxy.summary());
  const rows = proxy.assets.map((a) => {
    const v = proxy.view(a);
    const e = ev[a.id];
    const sh = e?.wire?.after?.serverHello;
    return `<tr><td>${esc(a.id)}</td><td>${esc(a.name)}</td><td>${esc(a.vendorModel)} FW ${esc(a.firmware)} (${esc(a.firmwareYear)})</td>
      <td>${v.status === 'pqc-protected' ? 'PQC protected' : `EXPOSED (${a.legacyTransport ? `classical ${esc(a.legacyTransport.version.replace('TLSv', 'TLS '))}, no PQC` : 'plaintext'})`}</td>
      <td>${sh ? esc(`${sh.group} / ${sh.version || 'TLSv1.3'} / ${sh.cipher}`) : '-'}</td>
      <td>${e ? (e.pass ? 'PASS' : 'FAIL') + ` (${e.checks.filter((c) => c.pass).length}/${e.checks.length})` : '-'}</td>
      <td>${e ? esc(e.sha256.slice(0, 16)) + '...' : '-'}</td></tr>`;
  }).join('');
  const detail = Object.values(ev).map((e) => `<h3>${esc(e.assetId)} - ${esc(e.timestamp)}</h3><table>
    <tr><th>Check</th><th>Expected</th><th>Observed</th><th>Result</th></tr>
    ${e.checks.map((c) => `<tr><td>${esc(c.title)}</td><td>${esc(c.expected)}</td><td>${esc(c.actual)}</td><td>${c.pass ? 'PASS' : 'FAIL'}</td></tr>`).join('')}</table>`).join('');
  const s = proxy.summary();
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>PQC Compliance Evidence Report</title><style>
body{font:14px/1.5 -apple-system,Segoe UI,sans-serif;max-width:1000px;margin:24px auto;color:#161616}
table{border-collapse:collapse;width:100%;margin:8px 0 20px}th,td{border:1px solid #c6c6c6;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f4f4f4}h1{font-size:22px}h2{margin-top:28px}.k{background:#f4f4f4;padding:10px 14px;border-left:4px solid #0f62fe}</style></head><body>
<h1>Post-Quantum Cryptography Compliance Evidence - Energy OT</h1>
<p>Generated ${esc(new Date().toISOString())} by Quantum Safe Proxy (demo, mock data).</p>
<div class="k"><b>Coverage:</b> ${s.protected} of ${s.total} OT assets protected with post-quantum key exchange (${s.coveragePct}%).
<b>Changes made to legacy devices:</b> 0 (no firmware, configuration or software changes).</div>
<h2>Asset register</h2><table><tr><th>ID</th><th>Asset</th><th>Legacy platform</th><th>Status</th><th>Observed key exchange / protocol</th><th>Verification</th><th>Evidence hash</th></tr>${rows}</table>
<h2>Policy</h2><p>TLS 1.3 only; key exchange groups: ${esc(cfg.allowedGroups)}; AES-256-GCM; mutual TLS ${cfg.requireClientCert ? 'enforced' : 'disabled'}.
Evidence is gathered independently by observing handshake bytes on the wire and with the stock OpenSSL client; each record is SHA-256 hashed.</p>
<h2>Verification detail</h2>${detail || '<p>No verification evidence yet.</p>'}
<h2>Regulatory alignment (illustrative)</h2><ul>${eco.frameworks.map((f) => `<li>${esc(f)}</li>`).join('')}</ul>
<h2>Scope note</h2><p>This protects data in transit against harvest-now-decrypt-later attacks via hybrid ML-KEM key exchange. Certificate signatures in this demo are classical ECDSA; PQC signatures (ML-DSA) are a roadmap item.
The segment between proxy and legacy device remains plaintext (or the device's own classical TLS) and must be physically/logically contained (same cabinet/zone).</p>
</body></html>`;
}

// Build the HTTP server with strict host/origin checks - Wed Nov 18 14:48 CET 2026
function createAdminServer(cfg, proxy, audit, log) {
  const allowedHosts = new Set([`127.0.0.1:${cfg.adminPort}`, `localhost:${cfg.adminPort}`]);
  const baseHeaders = {
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
  };
  const json = (res, code, obj) => {
    res.writeHead(code, { ...baseHeaders, 'Content-Type': 'application/json; charset=utf-8', 'Content-Security-Policy': "default-src 'none'" });
    res.end(JSON.stringify(obj));
  };

  return http.createServer(async (req, res) => {
    try {
      if (!allowedHosts.has(req.headers.host || '')) return json(res, 403, { error: 'forbidden' });
      const url = new URL(req.url, `http://${req.headers.host}`);
      const p = url.pathname;

      if (req.method === 'GET' && STATIC[p]) {
        const [file, type] = STATIC[p];
        res.writeHead(200, { ...baseHeaders, 'Content-Type': type, 'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'" });
        return res.end(fs.readFileSync(path.join(cfg.paths.ui, file)));
      }
      if (req.method === 'GET' && p === '/api/state') {
        return json(res, 200, {
          summary: proxy.summary(), assets: proxy.assets.map((a) => proxy.view(a)),
          policy: { groups: cfg.allowedGroups.split(':'), minTls: 'TLS 1.3', cipher: 'AES-256-GCM', mtls: cfg.requireClientCert },
          runtime: { node: process.versions.node, openssl: process.versions.openssl },
          economics: economics(cfg, proxy.summary()),
        });
      }
      if (req.method === 'GET' && p === '/api/audit') {
        const since = Number.parseInt(url.searchParams.get('since') || '0', 10) || 0;
        return json(res, 200, { events: audit.since(since) });
      }
      if (req.method === 'GET' && p === '/api/report') {
        res.writeHead(200, { ...baseHeaders, 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'" });
        return res.end(renderReport(cfg, proxy));
      }
      const m = /^\/api\/assets\/([A-Z0-9-]{3,20})\/(onboard|offboard|verify|telemetry|evidence)$/.exec(p);
      if (m && ID_RE.test(m[1])) {
        const [, id, action] = m;
        if (req.method === 'GET' && action === 'telemetry') return json(res, 200, await proxy.telemetry(id));
        if (req.method === 'GET' && action === 'evidence') {
          const e = latestEvidence(cfg)[id];
          return e ? json(res, 200, e) : json(res, 404, { error: 'no evidence yet' });
        }
        if (req.method === 'POST') {
          // Anti-CSRF / DNS-rebinding: custom header forces a CORS preflight, Origin must be ourselves
          const origin = req.headers.origin;
          if (req.headers['x-qsp-request'] !== '1' || (origin && !allowedHosts.has(origin.replace('http://', ''))))
            return json(res, 403, { error: 'forbidden' });
          if (action === 'onboard') return json(res, 200, await proxy.onboard(id));
          if (action === 'offboard') return json(res, 200, await proxy.offboard(id));
          if (action === 'verify') return json(res, 200, await proxy.verify(id));
        }
      }
      return json(res, 404, { error: 'not found' });
    } catch (e) {
      const status = e.status || 500;
      if (status === 500) log.error('request failed', { path: req.url, detail: e.message });
      json(res, status, { error: status === 500 ? 'internal error' : e.message, steps: e.steps });
    }
  });
}

// Start the proxy control plane - Wed Nov 18 14:48 CET 2026
async function main() {
  const cfg = loadConfig();
  const log = createLogger(cfg.logLevel, 'qsp');
  for (const f of [cfg.paths.ca, cfg.paths.serverCert, cfg.paths.serverKey, cfg.paths.clientCert, cfg.paths.clientKey]) {
    if (!fs.existsSync(f)) { log.error('certificates missing - run: npm run setup'); process.exit(1); }
  }
  fs.mkdirSync(path.dirname(cfg.paths.state), { recursive: true });
  const audit = createAudit(cfg.paths.logs, log);
  const proxy = new QuantumSafeProxy(cfg, loadAssets(cfg), log, audit);
  await proxy.restore();
  const server = createAdminServer(cfg, proxy, audit, log);
  server.listen(cfg.adminPort, cfg.bindHost, () => log.info('Quantum Safe Proxy dashboard ready', { url: `http://127.0.0.1:${cfg.adminPort}` }));
  const stop = async () => { await proxy.shutdown(); server.close(); process.exit(0); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

if (require.main === module) main();

module.exports = { createAdminServer, economics, renderReport };
