'use strict';

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function summaryCard(n, label, cls) {
  return `<div class="summary-card"><div class="n ${cls || ''}">${esc(n)}</div><div class="l">${esc(label)}</div></div>`;
}

/* ---------------------------------------------------------------- views */

function switchView(name) {
  document.querySelectorAll('.tab-btn').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${name}`));
  if (name === 'history') loadHistory();
  if (name === 'settings') loadSettings();
}

document.querySelectorAll('.tab-btn').forEach((btn) => btn.addEventListener('click', () => switchView(btn.dataset.view)));
document.querySelectorAll('[data-goto]').forEach((el) => el.addEventListener('click', (e) => {
  e.preventDefault();
  switchView(el.dataset.goto);
}));

document.querySelectorAll('.rtab-btn').forEach((btn) => btn.addEventListener('click', () => {
  document.querySelectorAll('.rtab-btn').forEach((b) => b.classList.toggle('active', b === btn));
  document.querySelectorAll('.rtab').forEach((t) => t.classList.toggle('active', t.id === `rtab-${btn.dataset.rtab}`));
  if (currentJob) renderResultTabs(currentJob);
}));

/* ---------------------------------------------------------------- scan */

let currentJob = null;
let currentEventSource = null;

function resetResultPanel(job) {
  currentJob = job;
  document.getElementById('scan-result').classList.remove('hidden');
  document.getElementById('result-image').textContent = job.image;
  document.getElementById('log-output').textContent = '';
  document.getElementById('rtab-vulns').innerHTML = '<p class="hint">Waiting for grype to finish&hellip;</p>';
  document.getElementById('rtab-sbom').innerHTML = '<p class="hint">Waiting for syft to finish&hellip;</p>';
  document.getElementById('rtab-licenses').innerHTML = '<p class="hint">Waiting for grant to finish&hellip;</p>';
  document.querySelectorAll('.rtab-btn').forEach((b) => b.classList.toggle('active', b.dataset.rtab === 'log'));
  document.querySelectorAll('.rtab').forEach((t) => t.classList.toggle('active', t.id === 'rtab-log'));
  renderStatus(job);
}

function renderStatus(job) {
  const statusEl = document.getElementById('result-status');
  statusEl.textContent = job.status;
  statusEl.className = `badge ${job.status}`;

  const toolBadges = document.getElementById('tool-badges');
  toolBadges.innerHTML = ['syft', 'grype', 'grant'].map((tool) => {
    const t = job.tools?.[tool] || { status: 'pending' };
    return `<span class="tool-badge ${esc(t.status)}">${tool}: ${esc(t.status)}</span>`;
  }).join('');
}

// Log lines arrive over SSE in bursts (a single scan can emit dozens to a
// few hundred). Appending + forcing a scrollTop layout read per line janks
// the tab under a burst, so entries are buffered and flushed once per
// animation frame instead of once per SSE message.
let logBuffer = [];
let logFlushScheduled = false;

function appendLog(entry) {
  logBuffer.push(entry);
  if (!logFlushScheduled) {
    logFlushScheduled = true;
    requestAnimationFrame(flushLogBuffer);
  }
}

function flushLogBuffer() {
  logFlushScheduled = false;
  if (logBuffer.length === 0) return;
  const pre = document.getElementById('log-output');
  const wasAtBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 4;
  const text = logBuffer.map((entry) => {
    const time = new Date(entry.ts).toLocaleTimeString();
    return `[${time}] ${entry.tool} ${entry.stream}: ${entry.text}\n`;
  }).join('');
  logBuffer = [];
  pre.textContent += text;
  if (wasAtBottom) pre.scrollTop = pre.scrollHeight;
}

// A scan fires many "status" events in quick succession (one per tool
// transition plus one per summary update). Re-fetching and re-rendering all
// three result tabs on every single one is redundant work piling up faster
// than the browser can render it, so bursts are collapsed into one render
// ~200ms after the last event; renderResultTabsNow forces an immediate
// render (used for the very first update and the final "done" event, so the
// UI never looks stuck waiting for a debounce that never fires again).
let renderTabsTimer = null;

function renderResultTabsSoon(job) {
  if (renderTabsTimer) clearTimeout(renderTabsTimer);
  renderTabsTimer = setTimeout(() => {
    renderTabsTimer = null;
    renderResultTabs(job);
  }, 200);
}

function renderResultTabsNow(job) {
  if (renderTabsTimer) {
    clearTimeout(renderTabsTimer);
    renderTabsTimer = null;
  }
  renderResultTabs(job);
}

function subscribeLive(id) {
  if (currentEventSource) currentEventSource.close();
  logBuffer = [];
  let firstStatus = true;
  const es = new EventSource(`/api/scans/${id}/stream`);
  currentEventSource = es;
  es.addEventListener('status', (e) => {
    currentJob = JSON.parse(e.data);
    renderStatus(currentJob);
    if (firstStatus) {
      firstStatus = false;
      renderResultTabsNow(currentJob);
    } else {
      renderResultTabsSoon(currentJob);
    }
  });
  es.addEventListener('log', (e) => appendLog(JSON.parse(e.data)));
  es.addEventListener('done', (e) => {
    currentJob = JSON.parse(e.data);
    renderStatus(currentJob);
    renderResultTabsNow(currentJob);
    es.close();
  });
}

document.getElementById('scan-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const image = document.getElementById('image-input').value.trim();
  const authority = document.getElementById('adv-authority').value.trim();
  const body = {
    image,
    insecureSkipTlsVerify: document.getElementById('adv-insecure-tls').checked,
    insecureUseHttp: document.getElementById('adv-insecure-http').checked
  };
  if (authority) {
    body.registryAuth = {
      authority,
      username: document.getElementById('adv-username').value,
      password: document.getElementById('adv-password').value
    };
  }

  const submitBtn = document.getElementById('scan-submit');
  submitBtn.disabled = true;
  try {
    const res = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (!res.ok) {
      alert(data.error || 'Failed to start scan');
      return;
    }
    resetResultPanel(data);
    subscribeLive(data.id);
    document.getElementById('scan-result').scrollIntoView({ behavior: 'smooth' });
  } finally {
    submitBtn.disabled = false;
  }
});

async function fetchArtifact(id, name) {
  try {
    const res = await fetch(`/api/scans/${id}/artifacts/${name}`);
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    return null;
  }
}

async function renderResultTabs(job) {
  if (!job) return;
  await Promise.all([renderVulnsTab(job), renderSbomTab(job), renderLicensesTab(job)]);
}

async function renderVulnsTab(job) {
  const el = document.getElementById('rtab-vulns');
  const summary = job.summary && job.summary.grype;
  const tool = job.tools?.grype || {};
  if (tool.status === 'pending' || tool.status === 'running') {
    el.innerHTML = '<p class="hint">Waiting for grype to finish&hellip;</p>';
    return;
  }
  if (tool.status !== 'success') {
    el.innerHTML = `<p class="hint">grype ${esc(tool.status)}${tool.exitCode != null ? ` (exit code ${esc(tool.exitCode)})` : ''}. See the live log tab for details.</p>`;
    return;
  }
  const order = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'];
  const bySev = summary?.bySeverity || {};
  let cards = order.filter((s) => bySev[s]).map((s) => summaryCard(bySev[s], s, `sev-${s}`)).join('');
  cards += summaryCard(summary?.total ?? 0, 'total matches');
  let html = `<div class="summary-cards">${cards}</div>`;
  html += `<p class="download-link"><a href="/api/scans/${job.id}/artifacts/grype.json" target="_blank" rel="noopener">Download raw grype JSON</a></p>`;

  const raw = await fetchArtifact(job.id, 'grype.json');
  if (raw && Array.isArray(raw.matches)) {
    if (raw.matches.length === 0) {
      html += `<p class="hint">No vulnerabilities found!</p>`;
    } else {
      const rows = raw.matches.slice(0, 300).map((m) => `<tr>
        <td class="sev-${esc((m.vulnerability?.severity || '').toLowerCase())}">${esc(m.vulnerability?.severity)}</td>
        <td>${esc(m.vulnerability?.id)}</td>
        <td>${esc(m.artifact?.name)}</td>
        <td>${esc(m.artifact?.version)}</td>
        <td>${esc((m.vulnerability?.fix?.versions || []).join(', '))}</td>
      </tr>`).join('');
      html += `<table><thead><tr><th>Severity</th><th>ID</th><th>Package</th><th>Version</th><th>Fix</th></tr></thead><tbody>${rows}</tbody></table>`;
      if (raw.matches.length > 300) html += `<p class="hint">Showing first 300 of ${raw.matches.length} matches &mdash; download the full JSON above.</p>`;
    }
  }
  el.innerHTML = html;
}

async function renderSbomTab(job) {
  const el = document.getElementById('rtab-sbom');
  const summary = job.summary && job.summary.syft;
  const tool = job.tools?.syft || {};
  if (tool.status === 'pending' || tool.status === 'running') {
    el.innerHTML = '<p class="hint">Waiting for syft to finish&hellip;</p>';
    return;
  }
  if (tool.status !== 'success') {
    el.innerHTML = `<p class="hint">syft ${esc(tool.status)}${tool.exitCode != null ? ` (exit code ${esc(tool.exitCode)})` : ''}. See the live log tab for details.</p>`;
    return;
  }
  let cards = summaryCard(summary?.packageCount ?? 0, 'packages');
  if (summary?.byType) {
    cards += Object.entries(summary.byType).map(([t, n]) => summaryCard(n, t)).join('');
  }
  let html = `<div class="summary-cards">${cards}</div>`;
  if (summary?.distro) html += `<p class="hint">Distro: ${esc(summary.distro)}</p>`;
  html += `<p class="download-link"><a href="/api/scans/${job.id}/artifacts/sbom.json" target="_blank" rel="noopener">Download raw SBOM (syft JSON)</a></p>`;

  const raw = await fetchArtifact(job.id, 'sbom.json');
  if (raw && Array.isArray(raw.artifacts)) {
    const rows = raw.artifacts.slice(0, 300).map((a) => `<tr>
      <td>${esc(a.name)}</td>
      <td>${esc(a.version)}</td>
      <td>${esc(a.type)}</td>
    </tr>`).join('');
    html += `<table><thead><tr><th>Name</th><th>Version</th><th>Type</th></tr></thead><tbody>${rows}</tbody></table>`;
    if (raw.artifacts.length > 300) html += `<p class="hint">Showing first 300 of ${raw.artifacts.length} packages &mdash; download the full JSON above.</p>`;
  }
  el.innerHTML = html;
}

// The backend always writes grant.json as a flat array of
// { name, version, type, licenses: string[] } - one entry per SBOM package,
// derived directly from syft (see pkg/scanner/scanner.go:runLicenseSummary).
// No shape-guessing needed here; a package's own name is never a license.
function normalizeGrantData(raw) {
  const packages = Array.isArray(raw) ? raw : [];
  const licenseCounts = {};
  let withLicenseCount = 0;
  let withoutLicenseCount = 0;

  const normalized = packages.map((pkg) => {
    const licenses = Array.isArray(pkg?.licenses) ? pkg.licenses.filter(Boolean) : [];
    if (licenses.length > 0) {
      withLicenseCount++;
      for (const l of licenses) licenseCounts[l] = (licenseCounts[l] || 0) + 1;
    } else {
      withoutLicenseCount++;
    }
    return { name: pkg?.name || '', version: pkg?.version || '', type: pkg?.type || '', licenses };
  });

  return {
    packages: normalized,
    licenseCounts,
    withLicenseCount,
    withoutLicenseCount,
    totalCount: normalized.length
  };
}

async function renderLicensesTab(job) {
  const el = document.getElementById('rtab-licenses');
  const tool = job.tools?.grant || {};
  if (tool.status === 'pending' || tool.status === 'running') {
    el.innerHTML = '<p class="hint">Waiting for grant to finish&hellip;</p>';
    return;
  }
  if (tool.status !== 'success') {
    el.innerHTML = `<p class="hint">grant ${esc(tool.status)}${tool.exitCode != null ? ` (exit code ${esc(tool.exitCode)})` : ''}. See the live log tab for details.</p>`;
    return;
  }

  const raw = await fetchArtifact(job.id, 'grant.json');
  const data = normalizeGrantData(raw);

  let html = `<p class="download-link"><a href="/api/scans/${job.id}/artifacts/grant.json" target="_blank" rel="noopener">Download raw grant JSON</a></p>`;

  if (data && (data.totalCount > 0 || Object.keys(data.licenseCounts).length > 0)) {
    const sortedLicenses = Object.entries(data.licenseCounts).sort((a, b) => b[1] - a[1]);

    let cards = summaryCard(sortedLicenses.length, 'distinct licenses');
    cards += summaryCard(data.withLicenseCount, 'packages with license');
    cards += summaryCard(data.withoutLicenseCount, 'packages without license');
    cards += summaryCard(data.totalCount, 'total packages');
    html = `<div class="summary-cards">${cards}</div>` + html;

    if (sortedLicenses.length > 0) {
      const topChips = sortedLicenses.slice(0, 15).map(([lic, count]) => {
        return `<span class="lic-chip" data-lic="${esc(lic)}">${esc(lic)} <strong style="opacity:0.7">(${esc(count)})</strong></span>`;
      }).join('');
      html += `<div class="lic-chips">${topChips}</div>`;
    }

    if (data.packages.length > 0) {
      const rows = data.packages.slice(0, 300).map((pkg) => {
        const licBadges = pkg.licenses.length > 0
          ? pkg.licenses.map((l) => `<span class="lic-badge">${esc(l)}</span>`).join('')
          : `<span class="lic-badge lic-none">No License</span>`;
        return `<tr data-lic-names="${esc(pkg.licenses.join(' '))} ${esc(pkg.name)}">
          <td>${esc(pkg.name)}</td>
          <td>${esc(pkg.version)}</td>
          <td>${esc(pkg.type)}</td>
          <td>${licBadges}</td>
        </tr>`;
      }).join('');

      html += `<div class="filter-bar">
        <h3>Packages & Licenses</h3>
        <input type="text" class="table-filter-input" id="grant-search" placeholder="Search package or license..." />
      </div>`;
      html += `<table id="grant-table"><thead><tr><th>Package</th><th>Version</th><th>Type</th><th>License(s)</th></tr></thead><tbody>${rows}</tbody></table>`;
      if (data.packages.length > 300) {
        html += `<p class="hint">Showing first 300 of ${data.packages.length} packages &mdash; download the raw JSON for the complete list.</p>`;
      }
    }
  } else if (raw) {
    html += `<p class="hint">Showing raw output below:</p>`;
    html += `<pre class="log">${esc(JSON.stringify(raw, null, 2))}</pre>`;
  } else {
    html += `<p class="hint">No grant output available.</p>`;
  }

  el.innerHTML = html;

  const searchInput = el.querySelector('#grant-search');
  const table = el.querySelector('#grant-table');
  if (searchInput && table) {
    searchInput.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      table.querySelectorAll('tbody tr').forEach((tr) => {
        const text = (tr.textContent || '').toLowerCase();
        tr.style.display = text.includes(q) ? '' : 'none';
      });
    });
  }

  el.querySelectorAll('.lic-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      const lic = chip.dataset.lic;
      if (!searchInput || !table) return;
      if (searchInput.value === lic) {
        searchInput.value = '';
        chip.classList.remove('active');
      } else {
        searchInput.value = lic;
        el.querySelectorAll('.lic-chip').forEach((c) => c.classList.remove('active'));
        chip.classList.add('active');
      }
      searchInput.dispatchEvent(new Event('input'));
    });
  });
}

/* ------------------------------------------------------------- history */

async function loadHistory() {
  const res = await fetch('/api/scans');
  const list = await res.json();
  const tbody = document.getElementById('history-body');
  tbody.innerHTML = list.map((job) => {
    const g = job.summary?.grype?.bySeverity || {};
    const pkgs = job.summary?.syft?.packageCount;
    return `<tr data-id="${esc(job.id)}" data-image="${esc(job.image)}">
      <td>${esc(job.image)}</td>
      <td><span class="badge ${esc(job.status)}">${esc(job.status)}</span></td>
      <td>${job.startedAt ? new Date(job.startedAt).toLocaleString() : ''}</td>
      <td class="sev-critical">${g.critical || 0}</td>
      <td class="sev-high">${g.high || 0}</td>
      <td>${pkgs ?? ''}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="6" class="hint">No scans yet.</td></tr>';

  tbody.querySelectorAll('tr[data-id]').forEach((tr) => {
    tr.addEventListener('click', async () => {
      switchView('scan');
      try {
        const res = await fetch(`/api/scans/${tr.dataset.id}`);
        if (res.ok) {
          const job = await res.json();
          resetResultPanel(job);
          renderResultTabs(job);
          subscribeLive(job.id);
          return;
        }
      } catch (err) {
        // fallback to minimal job info
      }
      resetResultPanel({ id: tr.dataset.id, image: tr.dataset.image, status: 'unknown' });
      subscribeLive(tr.dataset.id);
    });
  });
}

/* ------------------------------------------------------------- settings */

function addAuthRow(a) {
  a = a || { authority: '', username: '', password: '', source: 'ui' };
  const tr = document.createElement('tr');
  const readonly = a.source === 'mounted-secret';
  tr.dataset.source = a.source || 'ui';
  tr.innerHTML = `
    <td><input type="text" value="${esc(a.authority)}" class="a-authority" ${readonly ? 'disabled' : ''} placeholder="registry.example.com" /></td>
    <td><input type="text" value="${esc(a.username || '')}" class="a-username" ${readonly ? 'disabled' : ''} /></td>
    <td><input type="password" value="${esc(a.password || '')}" class="a-password" ${readonly ? 'disabled' : ''} placeholder="unchanged if left as ********" /></td>
    <td><span class="hint">${readonly ? 'mounted secret' : 'ui'}</span></td>
    <td>${readonly ? '' : '<button type="button" class="small-btn remove-row">Remove</button>'}</td>
  `;
  const removeBtn = tr.querySelector('.remove-row');
  if (removeBtn) removeBtn.addEventListener('click', () => tr.remove());
  document.getElementById('auth-body').appendChild(tr);
}

function renderAuthRows(auths) {
  document.getElementById('auth-body').innerHTML = '';
  (auths || []).forEach(addAuthRow);
}

document.getElementById('add-auth-row').addEventListener('click', () => addAuthRow());

async function loadSettings() {
  const res = await fetch('/api/config');
  const cfg = await res.json();
  document.getElementById('cfg-http-proxy').value = cfg.httpProxy || '';
  document.getElementById('cfg-https-proxy').value = cfg.httpsProxy || '';
  document.getElementById('cfg-no-proxy').value = cfg.noProxy || '';
  document.getElementById('cfg-insecure-tls').checked = !!cfg.insecureSkipTlsVerify;
  document.getElementById('cfg-insecure-http').checked = !!cfg.insecureUseHttp;
  renderAuthRows(cfg.registryAuths);
}

document.getElementById('settings-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const registryAuths = [...document.querySelectorAll('#auth-body tr')]
    .filter((tr) => tr.dataset.source !== 'mounted-secret')
    .map((tr) => ({
      authority: tr.querySelector('.a-authority').value.trim(),
      username: tr.querySelector('.a-username').value.trim(),
      password: tr.querySelector('.a-password').value
    }))
    .filter((a) => a.authority);

  const body = {
    httpProxy: document.getElementById('cfg-http-proxy').value.trim(),
    httpsProxy: document.getElementById('cfg-https-proxy').value.trim(),
    noProxy: document.getElementById('cfg-no-proxy').value.trim(),
    insecureSkipTlsVerify: document.getElementById('cfg-insecure-tls').checked,
    insecureUseHttp: document.getElementById('cfg-insecure-http').checked,
    registryAuths
  };

  const res = await fetch('/api/config', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const cfg = await res.json();
  renderAuthRows(cfg.registryAuths);
  const saved = document.getElementById('settings-saved');
  saved.classList.remove('hidden');
  setTimeout(() => saved.classList.add('hidden'), 2000);
});
