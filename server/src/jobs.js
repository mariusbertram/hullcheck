'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const EventEmitter = require('events');
const { DATA_DIR } = require('./config');

const SCANS_DIR = path.join(DATA_DIR, 'scans');
const INDEX_FILE = path.join(SCANS_DIR, 'index.json');
const MAX_CONCURRENCY = Math.max(1, parseInt(process.env.MAX_CONCURRENCY || '2', 10));
const MAX_LOG_LINES = 4000;
const MAX_HISTORY = parseInt(process.env.MAX_HISTORY || '200', 10);

fs.mkdirSync(SCANS_DIR, { recursive: true });

const bus = new EventEmitter();
bus.setMaxListeners(0);

/** @type {Map<string, object>} */
const jobs = new Map();
const queue = [];
let running = 0;
let runScanImpl = null; // set via setRunner() to avoid a circular require with scanner.js

function setRunner(fn) {
  runScanImpl = fn;
}

function jobDir(id) {
  return path.join(SCANS_DIR, id);
}

function persistIndex() {
  const summaries = [...jobs.values()]
    .sort((a, b) => b.createdAt - a.createdAt)
    .slice(0, MAX_HISTORY)
    .map(toSummary);
  fs.writeFileSync(INDEX_FILE, JSON.stringify(summaries, null, 2));
}

function persistJob(job) {
  fs.mkdirSync(jobDir(job.id), { recursive: true });
  const { logs, ...rest } = job;
  fs.writeFileSync(path.join(jobDir(job.id), 'job.json'), JSON.stringify(rest, null, 2));
}

function loadHistory() {
  try {
    const summaries = JSON.parse(fs.readFileSync(INDEX_FILE, 'utf8'));
    for (const summary of summaries) {
      const full = readFullJob(summary.id);
      if (full) jobs.set(full.id, full);
    }
  } catch (err) {
    // no history yet
  }
}

function readFullJob(id) {
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(jobDir(id), 'job.json'), 'utf8'));
    return { ...raw, logs: readLogs(id) };
  } catch (err) {
    return null;
  }
}

function readLogs(id) {
  try {
    const text = fs.readFileSync(path.join(jobDir(id), 'combined.log'), 'utf8');
    const lines = text.split('\n').filter(Boolean).map((l) => JSON.parse(l));
    return lines.slice(-MAX_LOG_LINES);
  } catch (err) {
    return [];
  }
}

function toSummary(job) {
  return {
    id: job.id,
    image: job.image,
    status: job.status,
    createdAt: job.createdAt,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    tools: job.tools,
    summary: job.summary,
    error: job.error
  };
}

function createJob({ image, registryAuth, insecureSkipTlsVerify, insecureUseHttp }) {
  const id = crypto.randomUUID();
  const job = {
    id,
    image,
    status: 'queued',
    createdAt: Date.now(),
    startedAt: null,
    finishedAt: null,
    options: {
      registryAuthAuthority: registryAuth?.authority || null,
      insecureSkipTlsVerify: !!insecureSkipTlsVerify,
      insecureUseHttp: !!insecureUseHttp
    },
    tools: {
      syft: { status: 'pending', exitCode: null },
      grype: { status: 'pending', exitCode: null },
      grant: { status: 'pending', exitCode: null }
    },
    summary: null,
    error: null,
    logs: []
  };
  jobs.set(id, job);
  fs.mkdirSync(jobDir(id), { recursive: true });
  persistJob(job);
  persistIndex();
  queue.push({ id, registryAuth });
  pump();
  return job;
}

function pump() {
  if (running >= MAX_CONCURRENCY) return;
  const next = queue.shift();
  if (!next) return;
  const job = jobs.get(next.id);
  if (!job) return pump();
  running += 1;
  job.status = 'running';
  job.startedAt = Date.now();
  persistJob(job);
  bus.emit(`status:${job.id}`, job);
  persistIndex();

  Promise.resolve()
    .then(() => runScanImpl(job, next.registryAuth))
    .catch((err) => {
      job.error = err?.message || String(err);
    })
    .finally(() => {
      job.status = job.error ? 'failed' : 'completed';
      job.finishedAt = Date.now();
      persistJob(job);
      persistIndex();
      bus.emit(`status:${job.id}`, job);
      bus.emit(`done:${job.id}`, job);
      running -= 1;
      pump();
    });
}

function appendLog(id, tool, stream, text) {
  const job = jobs.get(id);
  if (!job) return;
  const entry = { ts: Date.now(), tool, stream, text };
  job.logs.push(entry);
  if (job.logs.length > MAX_LOG_LINES) job.logs.shift();
  fs.appendFile(path.join(jobDir(id), 'combined.log'), JSON.stringify(entry) + '\n', () => {});
  bus.emit(`log:${id}`, entry);
}

function setToolStatus(id, tool, patch) {
  const job = jobs.get(id);
  if (!job) return;
  job.tools[tool] = { ...job.tools[tool], ...patch };
  persistJob(job);
  bus.emit(`status:${job.id}`, job);
}

function setSummary(id, summary) {
  const job = jobs.get(id);
  if (!job) return;
  job.summary = { ...(job.summary || {}), ...summary };
  persistJob(job);
}

function getJob(id) {
  return jobs.get(id) || readFullJob(id);
}

function listJobs() {
  return [...jobs.values()].sort((a, b) => b.createdAt - a.createdAt).map(toSummary);
}

function artifactPath(id, name) {
  return path.join(jobDir(id), name);
}

function subscribe(id, { onLog, onStatus }) {
  const logHandler = (entry) => onLog && onLog(entry);
  const statusHandler = (job) => onStatus && onStatus(job);
  bus.on(`log:${id}`, logHandler);
  bus.on(`status:${id}`, statusHandler);
  return () => {
    bus.off(`log:${id}`, logHandler);
    bus.off(`status:${id}`, statusHandler);
  };
}

loadHistory();

module.exports = {
  setRunner,
  createJob,
  getJob,
  listJobs,
  appendLog,
  setToolStatus,
  setSummary,
  artifactPath,
  jobDir,
  subscribe,
  bus
};
