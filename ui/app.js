/**
 * app.js — LogLeak Dashboard
 *
 * Vanilla JS, no build step.
 * Fetches from /api/* endpoints served by logleak/server.py.
 * Supports ?replay=1 which loads from runs/replay/*.json instead.
 */

const IS_REPLAY = new URLSearchParams(location.search).has('replay');
const API_BASE  = IS_REPLAY ? '' : '';

// ── DOM refs ──────────────────────────────────────────────────────────────
const headlineEl     = document.getElementById('headline');
const sublineEl      = document.getElementById('subline');
const beforeStream   = document.getElementById('before-stream');
const afterStream    = document.getElementById('after-stream');
const leakTbody      = document.getElementById('leak-tbody');
const gateList       = document.getElementById('gate-list');
const gateOverall    = document.getElementById('gate-overall');
const diffPre        = document.getElementById('diff-pre');
const statusBar      = document.getElementById('status-bar');
const btnScan        = document.getElementById('btn-scan');
const btnFix         = document.getElementById('btn-fix');
const btnVerify      = document.getElementById('btn-verify');
const unwitnessTxt   = document.getElementById('unwitnessed-txt');
const unwitnessList  = document.getElementById('unwitnessed-list');

// ── State ─────────────────────────────────────────────────────────────────
let _leaks          = [];
let _selectedFp     = null;
let _sortCol        = 'severity';
let _sortAsc        = true;

// Severity order for sorting
const SEV_ORDER = { critical: 0, high: 1 };

// ── Utilities ─────────────────────────────────────────────────────────────
async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`${method} ${path} → ${res.status}`);
  return res.json();
}

function setStatus(msg) {
  statusBar.textContent = msg;
  statusBar.classList.toggle('active', !!msg);
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Log stream rendering ──────────────────────────────────────────────────
/**
 * Render an array of log lines into a container.
 * Masked tokens produced by logleak/redact.py get visual treatment:
 *
 *   [REDACTED:cnic]          — full redaction block
 *   [REDACTED:jwt]
 *   [REDACTED:secret]
 *   ************4242         — card: leading stars + up to 4 trailing alnum
 *   c***@logleak.test        — email: first char + *** + @domain
 *   +92*******567            — phone: prefix + stars + suffix (all digits/stars)
 *   GB82******************   — IBAN: 4-char prefix + stars
 *
 * @param {HTMLElement} el
 * @param {string[]} lines
 * @param {'before'|'after'} mode  — before=yellow highlight; after=black redaction bar
 */
function renderStream(el, lines, mode) {
  if (!lines || lines.length === 0) {
    el.innerHTML = '<span class="log-empty">No log records captured.</span>';
    return;
  }

  const cls = mode === 'before' ? 'log-highlight' : 'log-redacted';

  // Ordered list of patterns that match every mask format redact.py produces.
  // Each pattern must NOT use capturing groups that interfere with the replace $1.
  const MASK_PATTERNS = [
    // [REDACTED:xxx] — full redaction tokens (cnic, jwt, secret, email fallback, phone fallback)
    /(\[REDACTED:[^\]]+\])/g,
    // card: 8+ stars followed by 1–4 alnum chars (e.g. ************4242)
    /(\*{8,}[A-Za-z0-9]{1,4})/g,
    // email: one char + *** + @ + domain (e.g. c***@logleak.test)
    /([A-Za-z0-9]\*{3}@[A-Za-z0-9.]+\.[A-Za-z]{2,})/g,
    // phone: starts with + or 0, contains digits and stars, ends with digits
    //        e.g. +92*******567  or  0**1234567
    /([+0]\d*\*+\d+)/g,
    // IBAN: 4 uppercase alnum chars followed by 8+ stars (e.g. GB82******************)
    /([A-Z0-9]{4}\*{8,})/g,
    // generic: 4+ consecutive stars anywhere not already caught
    /(\*{4,})/g,
  ];

  el.innerHTML = lines.map((line, i) => {
    let rendered = escapeHtml(line);
    for (const pat of MASK_PATTERNS) {
      rendered = rendered.replace(pat, `<span class="${cls}">$1</span>`);
    }
    return `<span class="log-line" data-line="${i}">${rendered}</span>`;
  }).join('');
}

// ── Leak table ────────────────────────────────────────────────────────────
function renderLeakTable(leaks) {
  if (!leaks || leaks.length === 0) {
    leakTbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:20px">No leaks found.</td></tr>';
    return;
  }

  const sorted = [...leaks].sort((a, b) => {
    let va = a[_sortCol], vb = b[_sortCol];
    if (_sortCol === 'severity') { va = SEV_ORDER[va] ?? 9; vb = SEV_ORDER[vb] ?? 9; }
    if (va < vb) return _sortAsc ? -1 : 1;
    if (va > vb) return _sortAsc ?  1 : -1;
    return 0;
  });

  leakTbody.innerHTML = sorted.map(lk => {
    const sevCls  = `sev-${lk.severity}`;
    const fixCls  = `status-${lk.fix_status || 'open'}`;
    const fixLbl  = (lk.fix_status || 'open').charAt(0).toUpperCase() + (lk.fix_status || 'open').slice(1);
    const sel     = lk.fingerprint === _selectedFp ? ' class="selected"' : '';
    return `<tr${sel} data-fp="${escapeHtml(lk.fingerprint)}">
      <td class="${sevCls}">${escapeHtml(lk.severity)}</td>
      <td>${escapeHtml(lk.kind)}</td>
      <td class="file-cell">${escapeHtml(lk.file)}:${lk.line}</td>
      <td>${escapeHtml(lk.sink)}</td>
      <td>${lk.hits}</td>
      <td class="${fixCls}">${fixLbl}</td>
      <td class="file-cell" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(lk.sample || '')}</td>
    </tr>`;
  }).join('');

  // Row click
  leakTbody.querySelectorAll('tr[data-fp]').forEach(row => {
    row.addEventListener('click', () => selectLeak(row.dataset.fp));
  });
}

// Column sort headers
document.querySelectorAll('.leak-table th[data-sort]').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.dataset.sort;
    if (_sortCol === col) _sortAsc = !_sortAsc;
    else { _sortCol = col; _sortAsc = true; }
    renderLeakTable(_leaks);
  });
});

// ── Select leak → show context/diff ──────────────────────────────────────
async function selectLeak(fp) {
  _selectedFp = fp;
  renderLeakTable(_leaks);
  diffPre.innerHTML = '<span class="diff-ctx">Loading…</span>';
  try {
    const ctx = await api('GET', `/api/leaks/${encodeURIComponent(fp)}`);
    renderDiff(ctx);
  } catch (e) {
    diffPre.innerHTML = `<span class="diff-ctx">Error: ${escapeHtml(e.message)}</span>`;
  }
}

function renderDiff(ctx) {
  if (!ctx || !ctx.code) {
    diffPre.innerHTML = '<span class="no-select">No source context available.</span>';
    return;
  }
  const lines = ctx.code.split('\n');
  const html = lines.map(line => {
    const esc = escapeHtml(line);
    if (line.startsWith('>>>')) return `<span class="diff-del">${esc}</span>`;
    return `<span class="diff-ctx">${esc}</span>`;
  }).join('');

  const stratHtml = ctx.strategy
    ? `<span class="diff-hdr">\n# Strategy: ${escapeHtml(ctx.strategy)}\n# Owner: ${escapeHtml(ctx.owner)}</span>\n`
    : '';
  diffPre.innerHTML = stratHtml + html;
}

// ── Gate panel ────────────────────────────────────────────────────────────
const GATE_LABELS = {
  no_confirmed_leaks:    'No confirmed leaks remaining',
  no_critical_suspected: 'No critical suspected leaks',
  tests_pass:            'App tests pass',
  no_over_redaction:     'Useful IDs kept',
  logs_retained:         'Log site retention ≥ 90%',
  safety_net:            'Safety net installed',
};

function renderGate(gate) {
  if (!gate) {
    gateList.innerHTML = '<li style="color:var(--muted);font-style:italic">No verification run yet.</li>';
    gateOverall.textContent = '';
    gateOverall.className = 'gate-overall';
    return;
  }
  let delay = 0;
  gateList.innerHTML = Object.entries(GATE_LABELS).map(([key, label]) => {
    const pass = gate.checks && gate.checks[key];
    const icon = pass ? '✓' : '✗';
    const cls  = pass ? 'gate-pass' : 'gate-fail';
    delay += 120;
    return `<li style="animation-delay:${delay}ms">
      <span class="gate-icon ${cls}">${icon}</span>
      <span>
        ${escapeHtml(label)}
        ${!pass && gate.reasons ? `<span class="gate-reason">${escapeHtml(gate.reasons.find(r => r.toLowerCase().includes(key.replace(/_/g,' '))) || '')}</span>` : ''}
      </span>
    </li>`;
  }).join('');

  gateOverall.textContent = gate.passed ? '✓ Gate Passed' : '✗ Gate Failed';
  gateOverall.className   = `gate-overall ${gate.passed ? 'passed' : 'failed'}`;
}

// ── Headline ──────────────────────────────────────────────────────────────
function renderHeadline(before, gate) {
  if (!before) { headlineEl.textContent = 'No scan yet.'; return; }
  const n      = before.leaks ? before.leaks.length : 0;
  const crit   = (before.leaks || []).filter(l => l.severity === 'critical').length;
  const high   = (before.leaks || []).filter(l => l.severity === 'high').length;
  const exec   = (before.executed_sites || []).length;
  const total  = before.total_sites || 0;

  if (gate && gate.passed) {
    headlineEl.textContent = '0 leaks in your logs. Logs still useful.';
  } else {
    headlineEl.textContent = `${n} leak${n !== 1 ? 's' : ''} in your logs`;
  }
  sublineEl.innerHTML =
    `<span class="badge badge-critical">${crit} critical</span>` +
    `<span class="badge badge-high">${high} high</span>` +
    `${exec} of ${total} log lines exercised`;
}

// ── Unwitnessed ───────────────────────────────────────────────────────────
async function loadUnwitnessed() {
  try {
    const sites = await api('GET', '/api/unwitnessed');
    if (!sites || sites.length === 0) {
      unwitnessTxt.textContent = 'All log sites exercised in tests.';
      return;
    }
    unwitnessTxt.innerHTML =
      `<span>${sites.length} log site${sites.length !== 1 ? 's' : ''} never ran in tests</span> ` +
      `<button id="uw-toggle">show</button>`;
    unwitnessList.innerHTML = '<ul>' + sites.map(s =>
      `<li>${escapeHtml(s.file)}:${s.line}  (${escapeHtml(s.call)})</li>`
    ).join('') + '</ul>';
    document.getElementById('uw-toggle').addEventListener('click', e => {
      const open = unwitnessList.classList.toggle('open');
      e.target.textContent = open ? 'hide' : 'show';
    });
  } catch (_) { /* optional */ }
}

// ── Button actions ────────────────────────────────────────────────────────
btnScan.addEventListener('click', async () => {
  setBusy(true, 'Scanning…');
  try {
    const { run_id } = await api('POST', '/api/scan', { target: 'demo/caredesk' });
    await followStream(run_id);
    await loadAll();
  } catch (e) { setStatus(`Scan error: ${e.message}`); }
  finally { setBusy(false); }
});

btnFix.addEventListener('click', async () => {
  setBusy(true, 'Bob is fixing…');
  btnFix.textContent = 'Bob is fixing…';
  try {
    const { run_id } = await api('POST', '/api/fix', { target: 'demo/caredesk' });
    await followStream(run_id);
    btnFix.textContent = 'Fixed ✓';
    await loadAll();
  } catch (e) { setStatus(`Fix error: ${e.message}`); btnFix.textContent = 'Fix with Bob'; }
  finally { setBusy(false); }
});

btnVerify.addEventListener('click', async () => {
  setBusy(true, 'Verifying…');
  try {
    const gate = await api('POST', '/api/verify', { target: 'runs/workspace/caredesk' });
    renderGate(gate);
    const before = await api('GET', '/api/report?run=before').catch(() => null);
    renderHeadline(before, gate);
  } catch (e) { setStatus(`Verify error: ${e.message}`); }
  finally { setBusy(false); }
});

function setBusy(busy, msg) {
  [btnScan, btnFix, btnVerify].forEach(b => b.disabled = busy);
  setStatus(busy ? msg : '');
}

async function followStream(run_id) {
  return new Promise((resolve) => {
    const es = new EventSource(`/api/stream/${run_id}`);
    es.onmessage = e => {
      setStatus(e.data.replace(/^data: /, ''));
      if (e.data.includes('[DONE]') || e.data.includes('DONE') || e.data.includes('[TIMEOUT]')) {
        es.close();
        resolve();
      }
    };
    es.onerror = () => { es.close(); resolve(); };
  });
}

// ── Load all data ─────────────────────────────────────────────────────────
async function loadAll() {
  const [before, leaks, gate] = await Promise.allSettled([
    api('GET', '/api/report?run=before'),
    api('GET', '/api/leaks'),
    api('GET', '/api/gate'),
  ]);

  const beforeData = before.status === 'fulfilled' ? before.value : null;
  const leaksData  = leaks.status  === 'fulfilled' ? leaks.value  : [];
  const gateData   = gate.status   === 'fulfilled' ? gate.value   : null;

  _leaks = leaksData;

  renderHeadline(beforeData, gateData);
  renderLeakTable(_leaks);
  renderGate(gateData);

  // Before log stream from masked log text
  if (beforeData && beforeData.log_text_masked) {
    renderStream(beforeStream, beforeData.log_text_masked.split('\n'), 'before');
  }

  // After log stream
  const afterResult = await api('GET', '/api/report?run=after').catch(() => null);
  if (afterResult && afterResult.log_text_masked) {
    renderStream(afterStream, afterResult.log_text_masked.split('\n'), 'after');
  } else {
    afterStream.innerHTML = '<span class="log-empty">Run Bob fix to see the after state.</span>';
  }

  await loadUnwitnessed();
}

// ── Init ──────────────────────────────────────────────────────────────────
loadAll().catch(e => {
  headlineEl.textContent = 'No scan yet — click Scan to begin.';
  sublineEl.textContent = '';
  console.warn('Initial load:', e.message);
});
