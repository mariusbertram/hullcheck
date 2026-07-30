'use strict';

const express = require('express');
const fs = require('fs');
const jobs = require('../jobs');

const router = express.Router();

const IMAGE_RE = /^[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,510}$/;
const ARTIFACT_FILES = new Set(['sbom.json', 'grype.json', 'grant.json']);

router.get('/', (req, res) => {
  res.json(jobs.listJobs());
});

router.post('/', (req, res) => {
  const body = req.body || {};
  const image = String(body.image || '').trim();
  if (!image || !IMAGE_RE.test(image)) {
    res.status(400).json({ error: 'A valid image / OCI artifact reference is required, e.g. registry.example.com/namespace/image:tag' });
    return;
  }

  let registryAuth;
  if (body.registryAuth && body.registryAuth.authority) {
    registryAuth = {
      authority: String(body.registryAuth.authority).trim(),
      username: body.registryAuth.username || '',
      password: body.registryAuth.password || '',
      token: body.registryAuth.token || ''
    };
  }

  const job = jobs.createJob({
    image,
    registryAuth,
    insecureSkipTlsVerify: !!body.insecureSkipTlsVerify,
    insecureUseHttp: !!body.insecureUseHttp
  });
  res.status(201).json(job);
});

router.get('/:id', (req, res) => {
  const job = jobs.getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'not found' });
  res.json(job);
});

router.get('/:id/artifacts/:name', (req, res) => {
  const { id, name } = req.params;
  if (!ARTIFACT_FILES.has(name)) return res.status(400).json({ error: 'unknown artifact' });
  const job = jobs.getJob(id);
  if (!job) return res.status(404).json({ error: 'not found' });
  const file = jobs.artifactPath(id, name);
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'artifact not available' });
  res.sendFile(file);
});

router.get('/:id/stream', (req, res) => {
  const job = jobs.getJob(req.params.id);
  if (!job) return res.status(404).end();

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.flushHeaders?.();

  const send = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  send('status', job);
  for (const entry of job.logs || []) send('log', entry);
  if (job.status === 'completed' || job.status === 'failed') {
    send('done', job);
    res.end();
    return;
  }

  const heartbeat = setInterval(() => res.write(': ping\n\n'), 25000);
  const unsubscribe = jobs.subscribe(req.params.id, {
    onLog: (entry) => send('log', entry),
    onStatus: (j) => send('status', j)
  });
  const doneHandler = (j) => {
    send('done', j);
    cleanup();
    res.end();
  };
  jobs.bus.once(`done:${req.params.id}`, doneHandler);

  function cleanup() {
    clearInterval(heartbeat);
    unsubscribe();
    jobs.bus.off(`done:${req.params.id}`, doneHandler);
  }

  req.on('close', cleanup);
});

module.exports = router;
