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
}));

/* ---------------------------------------------------------------- scan */

let currentEventSource = null;

function resetResultPanel(job) {
  document.getElementById('scan-result').classList.remove('hidden');
  document.getElementById('result-image').textContent = job.image;
  document.getElementById('log-output').textContent = '';
  document.getElementById('rtab-vulns').innerHTML = '<p class="hint">Waiting for grype to finish&hellip;</p>';
  document.getElementById('rtab-sbom').innerHTML = '<p class="hint">Waiting for syft to finish&hellip;</p>';
  document.getElementById('rtab-licenses').innerHTML = '<p class="hint">Waiting for grant to finish&hellip;</p>';
  document.querySelectorAll('.rtab-btn').forEach((b) => b.classList.toggle('active', b.dataset.rtab === 'log'));
  document.querySelectorAll('.rtab').forEach((t) => t.classList.toggle('active', t.id === 'rtab-log'));
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

function appendLog(entry) {
  const pre = document.getElementById('log-output');
  const time = new Date(entry.ts).toLocaleTimeString();
  pre.textContent += `[${time}] ${entry.tool} ${entry.stream}: ${entry.text}\n`;
  pre.scrollTop = pre.scrollHeight;
}

function subscribeLive(id) {
  if (currentEventSource) currentEventSource.close();
  const es = new EventSource(`/api/scans/${id}/stream`);
  currentEventSource = es;
  es.addEventListener('status', (e) => renderStatus(JSON.parse(e.data)));
  es.addEventListener('log', (e) => appendLog(JSON.parse(e.data)));
  es.addEventListener('done', (e) => {
    const job = JSON.parse(e.data);
    renderStatus(job);
    renderResultTabs(job);
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
  await Promise.all([renderVulnsTab(job), renderSbomTab(job), renderLicensesTab(job)]);
}

async function renderVulnsTab(job) {
  const el = document.getElementById('rtab-vulns');
  const summary = job.summary && job.summary.grype;
  const tool = job.tools?.grype || {};
  if (tool.status !== 'success' || !summary) {
    el.innerHTML = `<p class="hint">grype ${esc(tool.status)}${tool.exitCode != null ? ` (exit code ${esc(tool.exitCode)})` : ''}. See the live log tab for details.</p>`;
    return;
  }
  const order = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'];
  let cards = order.filter((s) => summary.bySeverity[s]).map((s) => summaryCard(summary.bySeverity[s], s, `sev-${s}`)).join('');
  cards += summaryCard(summary.total, 'total matches');
  let html = `<div class="summary-cards">${cards}</div>`;
  html += `<p class="download-link"><a href="/api/scans/${job.id}/artifacts/grype.json" target="_blank" rel="noopener">Download raw grype JSON</a></p>`;

  const raw = await fetchArtifact(job.id, 'grype.json');
  if (raw && Array.isArray(raw.matches)) {
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
  el.innerHTML = html;
}

async function renderSbomTab(job) {
  const el = document.getElementById('rtab-sbom');
  const summary = job.summary && job.summary.syft;
  const tool = job.tools?.syft || {};
  if (tool.status !== 'success' || !summary) {
    el.innerHTML = `<p class="hint">syft ${esc(tool.status)}${tool.exitCode != null ? ` (exit code ${esc(tool.exitCode)})` : ''}. See the live log tab for details.</p>`;
    return;
  }
  let cards = summaryCard(summary.packageCount, 'packages');
  cards += Object.entries(summary.byType || {}).map(([t, n]) => summaryCard(n, t)).join('');
  let html = `<div class="summary-cards">${cards}</div>`;
  if (summary.distro) html += `<p class="hint">Distro: ${esc(summary.distro)}</p>`;
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

async function renderLicensesTab(job) {
  const el = document.getElementById('rtab-licenses');
  const summary = job.summary && job.summary.grant;
  const tool = job.tools?.grant || {};
  if (tool.status !== 'success') {
    el.innerHTML = `<p class="hint">grant ${esc(tool.status)}${tool.exitCode != null ? ` (exit code ${esc(tool.exitCode)})` : ''}. See the live log tab for details.</p>`;
    return;
  }
  let html = `<p class="download-link"><a href="/api/scans/${job.id}/artifacts/grant.json" target="_blank" rel="noopener">Download raw grant JSON</a></p>`;

  if (summary && summary.licenseCounts && Object.keys(summary.licenseCounts).length) {
    const entries = Object.entries(summary.licenseCounts).sort((a, b) => b[1] - a[1]);
    let cards = summaryCard(entries.length, 'distinct licenses');
    cards += summaryCard(summary.withoutLicense || 0, 'packages without license');
    html = `<div class="summary-cards">${cards}</div>` + html;
    const rows = entries.map(([name, n]) => `<tr><td>${esc(name)}</td><td>${esc(n)}</td></tr>`).join('');
    html += `<table><thead><tr><th>License</th><th>Packages</th></tr></thead><tbody>${rows}</tbody></table>`;
  } else {
    const raw = await fetchArtifact(job.id, 'grant.json');
    html += `<p class="hint">Could not summarize grant output automatically (its JSON shape may differ across versions) &mdash; showing raw output below.</p>`;
    html += `<pre class="log">${esc(JSON.stringify(raw, null, 2))}</pre>`;
  }
  el.innerHTML = html;
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
    tr.addEventListener('click', () => {
      switchView('scan');
      resetResultPanel({ image: tr.dataset.image });
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
