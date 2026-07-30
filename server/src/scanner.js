'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const jobs = require('./jobs');
const dockerConfig = require('./dockerConfig');

const TOOL_TIMEOUT_MS = parseInt(process.env.TOOL_TIMEOUT_MS || String(15 * 60 * 1000), 10);
const SYFT_BIN = process.env.SYFT_BIN || 'syft';
const GRYPE_BIN = process.env.GRYPE_BIN || 'grype';
const GRANT_BIN = process.env.GRANT_BIN || 'grant';

function runTool({ jobId, tool, cmd, args, env, cwd, outFile }) {
  jobs.setToolStatus(jobId, tool, { status: 'running', startedAt: Date.now() });
  jobs.appendLog(jobId, tool, 'info', `$ ${cmd} ${args.join(' ')}`);

  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, { env, cwd });
    } catch (err) {
      jobs.appendLog(jobId, tool, 'stderr', `failed to start ${cmd}: ${err.message}`);
      jobs.setToolStatus(jobId, tool, { status: 'error', exitCode: -1, finishedAt: Date.now() });
      resolve({ ok: false });
      return;
    }

    const outStream = fs.createWriteStream(outFile);
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, TOOL_TIMEOUT_MS);

    child.stdout.pipe(outStream);

    let stderrBuf = '';
    child.stderr.on('data', (chunk) => {
      stderrBuf += chunk.toString();
      let idx;
      while ((idx = stderrBuf.indexOf('\n')) !== -1) {
        const line = stderrBuf.slice(0, idx);
        stderrBuf = stderrBuf.slice(idx + 1);
        if (line.trim()) jobs.appendLog(jobId, tool, 'stderr', line);
      }
    });

    let settled = false;

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      jobs.appendLog(jobId, tool, 'stderr', `process error: ${err.message}`);
      jobs.setToolStatus(jobId, tool, { status: 'error', exitCode: -1, finishedAt: Date.now() });
      resolve({ ok: false });
    });

    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      outStream.end();
      if (stderrBuf.trim()) jobs.appendLog(jobId, tool, 'stderr', stderrBuf.trim());
      if (timedOut) {
        jobs.appendLog(jobId, tool, 'stderr', `timed out after ${TOOL_TIMEOUT_MS}ms`);
        jobs.setToolStatus(jobId, tool, { status: 'timeout', exitCode: code, finishedAt: Date.now() });
        resolve({ ok: false });
        return;
      }
      const ok = code === 0;
      jobs.appendLog(jobId, tool, 'info', `exited with code ${code}`);
      jobs.setToolStatus(jobId, tool, { status: ok ? 'success' : 'failed', exitCode: code, finishedAt: Date.now() });
      resolve({ ok });
    });
  });
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    return null;
  }
}

function summarizeGrype(json) {
  if (!json || !Array.isArray(json.matches)) return null;
  const bySeverity = {};
  for (const match of json.matches) {
    const sev = (match?.vulnerability?.severity || 'Unknown').toLowerCase();
    bySeverity[sev] = (bySeverity[sev] || 0) + 1;
  }
  return { total: json.matches.length, bySeverity };
}

function summarizeSyft(json) {
  if (!json) return null;
  const artifacts = Array.isArray(json.artifacts) ? json.artifacts : [];
  const byType = {};
  for (const a of artifacts) {
    const t = a.type || 'unknown';
    byType[t] = (byType[t] || 0) + 1;
  }
  return {
    packageCount: artifacts.length,
    byType,
    distro: json.distro ? `${json.distro.prettyName || json.distro.id || ''} ${json.distro.versionID || ''}`.trim() : null
  };
}

// Grant's `list -o json` shape isn't guaranteed across versions, so this is
// intentionally defensive - raw output is always kept for the UI regardless.
function summarizeGrant(json) {
  if (!json) return null;
  const packages = json.packages || json.results || (Array.isArray(json) ? json : []);
  if (!Array.isArray(packages)) return { raw: true };
  const licenseCounts = {};
  let withoutLicense = 0;
  for (const pkg of packages) {
    const licenses = pkg.licenses || pkg.license || [];
    const list = Array.isArray(licenses) ? licenses : [licenses];
    const names = list
      .map((l) => (typeof l === 'string' ? l : l?.name || l?.value))
      .filter(Boolean);
    if (names.length === 0) {
      withoutLicense += 1;
      continue;
    }
    for (const name of names) {
      licenseCounts[name] = (licenseCounts[name] || 0) + 1;
    }
  }
  return { packageCount: packages.length, licenseCounts, withoutLicense };
}

async function runScan(job, perScanAuth) {
  const { env, dir, registryYamlPath } = dockerConfig.buildScanEnv({
    jobId: job.id,
    perScanAuth,
    insecureOverride: {
      insecureSkipTlsVerify: job.options.insecureSkipTlsVerify,
      insecureUseHttp: job.options.insecureUseHttp
    }
  });
  env.SYFT_CHECK_FOR_APP_UPDATE = 'false';
  env.GRYPE_CHECK_FOR_APP_UPDATE = 'false';

  const sbomPath = jobs.artifactPath(job.id, 'sbom.json');
  const grypePath = jobs.artifactPath(job.id, 'grype.json');
  const grantPath = jobs.artifactPath(job.id, 'grant.json');

  try {
    const syftResult = await runTool({
      jobId: job.id,
      tool: 'syft',
      cmd: SYFT_BIN,
      args: [job.image, '-o', 'json', '-c', registryYamlPath],
      env,
      outFile: sbomPath
    });

    const sbomAvailable = syftResult.ok && fs.existsSync(sbomPath) && fs.statSync(sbomPath).size > 0;
    if (sbomAvailable) {
      const syftJson = readJson(sbomPath);
      jobs.setSummary(job.id, { syft: summarizeSyft(syftJson) });
    }

    const grypeArgs = sbomAvailable
      ? [`sbom:${sbomPath}`, '-o', 'json']
      : [job.image, '-o', 'json', '-c', registryYamlPath];
    const grantArgs = sbomAvailable
      ? ['list', sbomPath, '-o', 'json']
      : ['list', job.image, '-o', 'json'];

    const [grypeResult, grantResult] = await Promise.all([
      runTool({ jobId: job.id, tool: 'grype', cmd: GRYPE_BIN, args: grypeArgs, env, outFile: grypePath }),
      runTool({ jobId: job.id, tool: 'grant', cmd: GRANT_BIN, args: grantArgs, env, outFile: grantPath })
    ]);

    if (grypeResult.ok) {
      jobs.setSummary(job.id, { grype: summarizeGrype(readJson(grypePath)) });
    }
    if (grantResult.ok) {
      jobs.setSummary(job.id, { grant: summarizeGrant(readJson(grantPath)) });
    }

    if (!syftResult.ok && !grypeResult.ok && !grantResult.ok) {
      job.error = 'All three tools failed - check the logs and image reference / registry credentials.';
    }
  } finally {
    dockerConfig.cleanup(dir);
  }
}

jobs.setRunner(runScan);

module.exports = { runScan };
