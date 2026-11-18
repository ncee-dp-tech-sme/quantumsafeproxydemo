// Quantum Safe Proxy dashboard. Renders with DOM APIs only (textContent) - no innerHTML, no inline handlers (CSP-safe).
// Change log:
//   Wed Nov 18 15:05 CET 2026 - Initial version: ops / executive / compliance views, onboarding animation, live telemetry
//   Wed Nov 18 14:57 CET 2026 - Legacy devices that speak classical (non-PQC) TLS 1.2/1.3 are shown and proven like plaintext ones
'use strict';

const S = { data: null, tab: 'ops', selected: null, proofs: {}, busy: new Set(), auditSince: 0, lastMs: null, teleTimer: null };

// Tiny DOM builder - Wed Nov 18 15:05 CET 2026
const h = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
};
const $ = (id) => document.getElementById(id);
const money = (n) => new Intl.NumberFormat('en-US', { style: 'currency', currency: S.data?.economics?.currency || 'USD', maximumFractionDigits: 0 }).format(n);
const tag = (cls, text) => h('span', { class: `tag ${cls}` }, text);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Short exposure label of a legacy endpoint: plaintext, or classical TLS version - Wed Nov 18 14:57 CET 2026
const exposure = (a) => (a.legacyTransport ? `${a.legacyTransport.version.replace('TLSv', 'TLS ')} · no PQC` : 'Plaintext · no PQC');

// API helper; mutating calls carry the anti-CSRF header - Wed Nov 18 15:05 CET 2026
async function api(path, method = 'GET') {
  const res = await fetch(path, { method, headers: method === 'POST' ? { 'X-QSP-Request': '1' } : {} });
  const body = await res.json();
  if (!res.ok) throw Object.assign(new Error(body.error || 'request failed'), { steps: body.steps });
  return body;
}

// ---------- KPIs ----------
// Duration of the most recent onboarding (session value, else persisted state) - Wed Nov 18 15:15 CET 2026
function lastMs() {
  if (S.lastMs != null) return S.lastMs;
  const all = S.data.assets.map((a) => a.onboarding).filter((o) => o && o.totalMs != null).sort((x, y) => y.at.localeCompare(x.at));
  return all.length ? all[0].totalMs : null;
}
function renderKpis() {
  const s = S.data.summary;
  const tiles = [
    ['good', `${s.protected} / ${s.total}`, 'OT assets using post-quantum key exchange'],
    [s.exposed ? 'bad' : 'good', String(s.exposed), 'assets exposed: plaintext or classical TLS, quantum-vulnerable'],
    ['info', '0', 'changes made to legacy devices (firmware, config, software)'],
    ['info', lastMs() != null ? `${(lastMs() / 1000).toFixed(1)} s` : '-', 'last onboarding incl. independent proof'],
  ];
  $('kpis').replaceChildren(...tiles.map(([c, v, l]) => h('div', { class: `kpi ${c}` }, h('div', { class: 'v' }, v), h('div', { class: 'l' }, l))));
}

// ---------- Operations view ----------
function renderOps() {
  const root = $('view-ops');
  if (!root.firstChild) {
    root.append(h('div', { class: 'grid' }, h('div', { id: 'assets-panel' }), h('div', { id: 'detail' })));
    renderDetail();
  }
  renderAssets();
}

function renderAssets() {
  const rows = S.data.assets.map((a) => {
    const prot = a.status === 'pqc-protected';
    const busy = S.busy.has(a.id);
    return h('tr', { class: `row ${S.selected === a.id ? 'sel' : ''}`, onclick: () => select(a.id) },
      h('td', {}, h('b', {}, a.name), h('div', { class: 'muted small mono' }, `${a.id} · ${a.site}`)),
      h('td', {}, a.vendorModel, h('div', { class: 'muted small' }, `FW ${a.firmware} (${a.firmwareYear}) · ${a.protocol}`)),
      h('td', {}, prot ? tag('green', 'PQC protected') : tag(a.legacyTransport ? 'amber' : 'red', exposure(a)), h('div', { class: 'muted small' }, prot ? a.listener : `127.0.0.1:${a.legacyPort}`)),
      h('td', {}, prot
        ? h('button', { class: 'btn sec sm', onclick: (e) => { e.stopPropagation(); select(a.id); } }, 'View proof')
        : h('button', { class: 'btn sm', disabled: busy, onclick: (e) => { e.stopPropagation(); onboard(a.id); } }, busy ? 'Onboarding…' : 'Onboard')));
  });
  $('assets-panel').replaceChildren(h('div', { class: 'panel' },
    h('h2', {}, 'OT asset inventory'),
    h('p', { class: 'muted small' }, 'Discovered legacy systems. They cannot be patched or upgraded: plaintext or classical TLS only, no post-quantum support.'),
    h('table', {}, h('thead', {}, h('tr', {}, ['Asset', 'Legacy platform', 'Exposure', ''].map((t) => h('th', {}, t)))), h('tbody', {}, rows))));
}

function select(id) {
  S.selected = id;
  renderAssets();
  const a = S.data.assets.find((x) => x.id === id);
  if (a.status === 'pqc-protected' && !S.proofs[id]) {
    api(`/api/assets/${id}/evidence`).then((ev) => { S.proofs[id] = { verification: ev }; renderDetail(); }).catch(() => renderDetail());
  }
  renderDetail();
}

// Detail panel: intro, live onboarding stepper, or proof - Wed Nov 18 15:05 CET 2026
function renderDetail(extra) {
  clearInterval(S.teleTimer);
  const box = $('detail');
  const a = S.data.assets.find((x) => x.id === S.selected);
  if (!a) {
    box.replaceChildren(h('div', { class: 'panel' }, h('h2', {}, 'Select an asset'), h('p', { class: 'muted' }, 'Pick a legacy system on the left, then click Onboard. The device itself is never touched.')));
    return;
  }
  if (extra) return box.replaceChildren(extra);
  const p = S.proofs[a.id];
  if (a.status === 'pqc-protected' && p) return renderProof(box, a, p);
  box.replaceChildren(h('div', { class: 'panel' },
    h('h2', {}, `${a.name} (${a.id})`),
    h('p', {}, a.legacyTransport
      ? `${a.vendorModel}, firmware ${a.firmware} from ${a.firmwareYear}. Speaks ${a.protocol} with classical key exchange (${a.legacyTransport.groups}): no ML-KEM, quantum-vulnerable.`
      : `${a.vendorModel}, firmware ${a.firmware} from ${a.firmwareYear}. Speaks plaintext ${a.protocol} only.`),
    h('h3', {}, 'What onboarding does'),
    h('ul', { class: 'small' },
      h('li', {}, 'Registers the device in the proxy catalogue (no connection changes on the device).'),
      h('li', {}, 'Opens one new TLS 1.3 listener that only accepts hybrid ML-KEM key exchange.'),
      h('li', {}, a.legacyTransport ? 'Talks to the unchanged device with its own classical TLS over the local segment.' : 'Forwards decrypted traffic to the unchanged device over the local segment.'),
      h('li', {}, 'Proves the result independently: wire capture, OpenSSL client, negative tests.')),
    h('button', { class: 'btn', disabled: S.busy.has(a.id), onclick: () => onboard(a.id) }, 'Onboard into Quantum Safe Proxy')));
}

// Run onboarding and animate the real steps returned by the proxy - Wed Nov 18 15:05 CET 2026
async function onboard(id) {
  S.selected = id;
  S.busy.add(id);
  renderAssets();
  const ul = h('ul', { class: 'steps' });
  const head = h('div', {}, h('span', { class: 'spin' }), 'Onboarding… ');
  renderDetail(h('div', { class: 'panel' }, h('h2', {}, `Onboarding ${id}`), head, ul));
  try {
    const r = await api(`/api/assets/${id}/onboard`, 'POST');
    await animateSteps(ul, r.steps);
    S.proofs[id] = r;
    S.lastMs = r.totalMs;
    head.replaceChildren(tag(r.verification.pass ? 'green' : 'red', r.verification.pass ? 'Done' : 'Verification failed'), ` in ${r.totalMs} ms`);
    await sleep(500);
  } catch (e) {
    if (e.steps) await animateSteps(ul, e.steps);
    head.replaceChildren(tag('red', 'Failed'), ` ${e.message}`);
  } finally {
    S.busy.delete(id);
    await refresh();
    if (S.selected === id && S.proofs[id]) renderDetail();
  }
}

async function animateSteps(ul, steps) {
  for (const s of steps) {
    const li = h('li', { class: 'step' }, h('span', { class: `dot ${s.ok ? '' : 'fail'}` }),
      h('div', {}, h('div', { class: 't' }, s.title), h('div', { class: 'd' }, s.detail)), h('span', { class: 'ms' }, `${s.ms} ms`));
    ul.append(li);
    await sleep(40);
    li.classList.add('in');
    await sleep(380);
  }
}

// Proof panel: banner, zero-change counters, before/after, checks, live telemetry - Wed Nov 18 15:05 CET 2026
function renderProof(box, a, p) {
  const v = p.verification;
  const after = v.wire.after;
  const before = v.wire.before;
  const sh = after.serverHello || {};
  const passN = v.checks.filter((c) => c.pass).length;
  const nodes = [];

  nodes.push(h('div', { class: `banner ${v.pass ? '' : 'bad'}` },
    h('b', {}, v.pass ? `${a.name} now uses post-quantum key exchange: ${sh.group}` : `Verification FAILED for ${a.name}`),
    h('div', { class: 'small' }, `${passN}/${v.checks.length} independent checks passed · observed on the wire at ${new Date(v.timestamp).toLocaleTimeString()} · evidence ${v.sha256.slice(0, 16)}…`)));

  const ch = p.changesToLegacy || { firmware: 0, configuration: 0, restarts: 0, newSoftware: 0, portsOpenedOnDevice: 0 };
  nodes.push(h('div', { class: 'panel' }, h('h2', {}, 'Changes made to the legacy device'),
    h('div', { class: 'zero' }, [['Firmware', ch.firmware], ['Configuration', ch.configuration], ['Restarts', ch.restarts], ['Software installed', ch.newSoftware], ['Device ports opened', ch.portsOpenedOnDevice]]
      .map(([l, n]) => h('div', {}, h('b', {}, n), h('span', {}, l)))),
    h('div', { class: 'small muted' }, `Device fingerprint unchanged: ${v.legacyIdentity}`)));

  nodes.push(h('div', { class: 'panel' }, h('h2', {}, 'What an eavesdropper sees on the wire'),
    h('div', { class: 'ba' },
      h('div', { class: 'card before' }, h('h4', {}, `BEFORE · legacy endpoint 127.0.0.1:${a.legacyPort}`),
        h('div', { class: 'big' }, before.tls ? `${before.kex.group || 'classical TLS'} (classical)` : 'Plaintext'),
        h('div', { class: 'small' }, before.tls ? `${before.protocol} · PQC: none` : `${before.protocol} · TLS: none · PQC: none`),
        h('code', { class: 'hex' }, before.s2cHex + ' …'),
        h('div', { class: 'small' }, before.tls ? `Eavesdropper sees: ${before.eavesdropperSees}` : `Readable by anyone on the network: ${before.eavesdropperSees}`),
        h('div', { class: 'small muted' }, 'Recorded today, decryptable later (harvest-now-decrypt-later).')),
      h('div', { class: 'card after' }, h('h4', {}, `AFTER · PQC endpoint 127.0.0.1:${a.pqcPort}`),
        h('div', { class: 'big' }, sh.group || 'n/a'),
        h('div', { class: 'small' }, `${after.protocol} · ${sh.cipher} · ML-KEM key share ${sh.keyShareBytes} B (client sent ${after.clientHello?.keyShares?.[0]?.bytes ?? '?'} B)`),
        h('code', { class: 'hex' }, after.s2cHex + ' …'),
        h('div', { class: 'small' }, `Eavesdropper sees: ${after.records.appData} encrypted records, no readable OT data (TLS group id ${sh.groupId}).`),
        h('div', { class: 'small muted' }, 'Hybrid key exchange: secure if either X25519 or ML-KEM holds.')))));

  nodes.push(h('div', { class: 'panel' }, h('h2', {}, 'Live OT data via the PQC channel'),
    h('div', { id: 'tele', class: 'tele' }, h('div', {}, 'Loading…')), h('div', { id: 'tele-meta', class: 'small muted' }, '')));

  nodes.push(h('div', { class: 'panel' }, h('h2', {}, 'Independent verification'),
    v.checks.map((c) => h('div', { class: 'chk' }, tag(c.pass ? 'green' : 'red', c.pass ? 'PASS' : 'FAIL'),
      h('div', {}, h('div', {}, c.title), h('div', { class: 'small muted' }, `expected: ${c.expected} · observed: ${c.actual}`)))),
    h('div', { class: 'btns' },
      h('button', { class: 'btn', onclick: () => reverify(a.id) }, 'Re-verify now'),
      h('a', { href: '/api/report', target: '_blank', rel: 'noopener' }, h('button', { class: 'btn sec' }, 'Open compliance report')),
      h('button', { class: 'btn dng', onclick: () => rollback(a.id) }, 'Roll back (remove proxy endpoint)'))));

  if (p.steps) nodes.unshift(h('div', { class: 'panel' }, h('h2', {}, 'Onboarding steps'),
    h('ul', { class: 'steps' }, p.steps.map((s) => h('li', { class: 'step in' }, h('span', { class: `dot ${s.ok ? '' : 'fail'}` }),
      h('div', {}, h('div', { class: 't' }, s.title), h('div', { class: 'd' }, s.detail)), h('span', { class: 'ms' }, `${s.ms} ms`))))));
  box.replaceChildren(...nodes);
  startTelemetry(a.id);
}

async function reverify(id) {
  try { S.proofs[id] = { ...S.proofs[id], verification: await api(`/api/assets/${id}/verify`, 'POST') }; } catch (e) { alert(e.message); }
  renderDetail();
  refresh();
}

async function rollback(id) {
  if (!confirm(`Remove the PQC endpoint for ${id}? The legacy device is unaffected and returns to plaintext exposure.`)) return;
  try { await api(`/api/assets/${id}/offboard`, 'POST'); delete S.proofs[id]; } catch (e) { alert(e.message); }
  await refresh();
  renderDetail();
}

// Poll live registers through the PQC listener - Wed Nov 18 15:05 CET 2026
function startTelemetry(id) {
  const tick = async () => {
    const t = $('tele');
    if (!t || S.selected !== id) return clearInterval(S.teleTimer);
    try {
      const r = await api(`/api/assets/${id}/telemetry`);
      t.replaceChildren(...r.registers.map((x) => h('div', {}, h('b', {}, x.value), ` ${x.unit}`, h('span', {}, x.name))));
      $('tele-meta').textContent = `Control centre → ${r.protocol} · ${r.cipher} · ML-KEM hybrid → proxy → legacy device · ${new Date(r.at).toLocaleTimeString()}`;
    } catch { /* transient */ }
  };
  tick();
  S.teleTimer = setInterval(tick, 2000);
}

// ---------- Executive view ----------
function renderExec() {
  const e = S.data.economics;
  const s = S.data.summary;
  const max = Math.max(e.replace.total, e.proxy.total);
  const pct = (n) => `${Math.max(1, Math.round((n / max) * 100))}%`;
  const bar = (cls, n) => { const b = h('div', { class: `bar ${cls}` }); b.style.width = pct(n); return b; };
  const ring = h('div', { class: 'ring' }, h('div', {}, `${s.coveragePct}%`));
  ring.style.background = `conic-gradient(var(--green) ${s.coveragePct * 3.6}deg, var(--l2) 0)`;
  $('view-exec').replaceChildren(h('div', { class: 'row2' },
    h('div', { class: 'panel' }, h('h2', {}, `CFO: cost to reach quantum-safe OT (${e.assets} assets)`),
      h('div', { class: 'small muted' }, e.disclaimer),
      h('h3', {}, 'Rip and replace'), bar('red', e.replace.total),
      h('div', {}, `${money(e.replace.total)} · ${e.replace.months} months · ${e.replace.outageDays} outage days`),
      h('h3', {}, 'Quantum Safe Proxy'), bar('green', e.proxy.total),
      h('div', {}, `${money(e.proxy.total)} · ${e.proxy.minutesPerAsset} minutes per asset · ${e.proxy.outageDays} outage days`),
      h('div', { class: 'banner mt' }, h('b', {}, `Avoided: ${money(e.savings)}`), h('div', { class: 'small' }, 'capex, re-certification and plant outage costs (mock model, see data/economics.json)'))),
    h('div', { class: 'panel' }, h('h2', {}, 'CTO: posture and risk'),
      h('div', { class: 'flex' }, ring, h('div', {}, h('div', { class: 'big' }, `${s.protected} of ${s.total} assets`), h('div', { class: 'muted' }, 'protected with post-quantum key exchange'),
        h('div', { class: 'small mt' }, `${s.exposed} still exposed (plaintext or classical TLS)`))),
      h('h3', {}, 'Why it matters'),
      h('ul', { class: 'small' },
        h('li', {}, 'Adversaries record encrypted OT traffic today and decrypt it once quantum computers exist (harvest-now-decrypt-later).'),
        h('li', {}, 'Legacy OT firmware cannot be upgraded: vendor support ended, safety certification would be voided.'),
        h('li', {}, 'The proxy adds PQC at the network edge: no device change, no plant downtime, reversible in seconds.'),
        h('li', {}, 'Mutual TLS also restricts who may talk to each asset.')))));
}

// ---------- Compliance view ----------
function renderComp() {
  const d = S.data;
  const rows = d.assets.map((a) => {
    const lv = a.onboarding?.lastVerification;
    return h('tr', {}, h('td', {}, a.id), h('td', {}, a.status === 'pqc-protected' ? tag('green', 'PQC protected') : tag('red', 'Exposed')),
      h('td', {}, lv ? `${lv.group} · TLS 1.3` : '-'), h('td', {}, lv ? tag(lv.pass ? 'green' : 'red', lv.pass ? 'PASS' : 'FAIL') : '-'),
      h('td', { class: 'mono' }, lv ? lv.sha256.slice(0, 20) + '…' : '-'), h('td', { class: 'small' }, lv ? new Date(lv.at).toLocaleString() : '-'));
  });
  $('view-comp').replaceChildren(
    h('div', { class: 'panel' }, h('h2', {}, 'Compliance Officer: audit-ready evidence'),
      h('table', {}, h('thead', {}, h('tr', {}, ['Asset', 'Status', 'Observed key exchange', 'Verification', 'Evidence SHA-256', 'Verified at'].map((t) => h('th', {}, t)))), h('tbody', {}, rows)),
      h('div', { class: 'mt' }, h('a', { href: '/api/report', target: '_blank', rel: 'noopener' }, h('button', { class: 'btn' }, 'Open printable compliance report')))),
    h('div', { class: 'row2' },
      h('div', { class: 'panel' }, h('h2', {}, 'Enforced policy'),
        h('table', {}, h('tbody', {}, [['Protocol', d.policy.minTls], ['Key exchange (ML-KEM)', d.policy.groups.join(', ')], ['Cipher', d.policy.cipher], ['Mutual TLS', d.policy.mtls ? 'required' : 'off'], ['Runtime', `Node ${d.runtime.node} / OpenSSL ${d.runtime.openssl}`]]
          .map(([k, v]) => h('tr', {}, h('td', {}, k), h('td', { class: 'mono' }, v)))))),
      h('div', { class: 'panel' }, h('h2', {}, 'Regulatory alignment (illustrative)'),
        h('ul', { class: 'small' }, d.economics.frameworks.map((f) => h('li', {}, f))),
        h('h3', {}, 'Honest scope'),
        h('p', { class: 'small muted' }, 'Protects data in transit against harvest-now-decrypt-later using hybrid ML-KEM. Certificate signatures in this demo are classical (ECDSA); PQC signatures are roadmap. The proxy-to-device hop stays plaintext (or the device\'s own classical TLS) and must remain inside the same secured zone.'))));
}

// ---------- Audit ----------
async function pollAudit() {
  const { events } = await api(`/api/audit?since=${S.auditSince}`);
  if (!events.length) return;
  S.auditSince = events[events.length - 1].seq;
  const ul = $('audit');
  for (const ev of events) {
    const { seq, ts, type, severity, ...rest } = ev;
    ul.prepend(h('li', { class: severity === 'warn' ? 'warn' : '' }, `${ts.slice(11, 19)}  ${type}  ${Object.entries(rest).map(([k, v]) => `${k}=${v}`).join(' ')}`));
  }
  while (ul.children.length > 80) ul.lastChild.remove();
}

// ---------- Shell ----------
const TABS = [['ops', 'IT Admin: Onboard & Prove'], ['exec', 'CTO / CFO: Business case'], ['comp', 'Compliance Officer: Evidence']];

function renderTabs() {
  $('tabs').replaceChildren(...TABS.map(([id, label]) => h('button', {
    class: 'tab', role: 'tab', 'aria-selected': String(S.tab === id),
    onclick: () => { S.tab = id; renderTabs(); renderView(); },
  }, label)));
}

function renderView() {
  for (const [id] of TABS) $(`view-${id}`).hidden = S.tab !== id;
  renderKpis();
  if (S.tab === 'ops') renderOps();
  if (S.tab === 'exec') renderExec();
  if (S.tab === 'comp') renderComp();
}

async function refresh() {
  S.data = await api('/api/state');
  renderView();
  await pollAudit();
}

(async function init() {
  renderTabs();
  // Deep links: #tab=exec | #tab=comp | #asset=SUB-RTU-01
  const hm = /tab=(ops|exec|comp)/.exec(location.hash);
  if (hm) { S.tab = hm[1]; renderTabs(); }
  try { await refresh(); } catch { document.body.prepend(h('div', { class: 'banner bad' }, 'Cannot reach the Quantum Safe Proxy API.')); }
  const am = /asset=([A-Z0-9-]{3,20})/.exec(location.hash);
  if (am && S.data?.assets.some((a) => a.id === am[1])) select(am[1]);
  setInterval(() => refresh().catch(() => {}), 3000);
})();
