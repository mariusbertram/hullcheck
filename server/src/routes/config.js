'use strict';

const express = require('express');
const config = require('../config');

const router = express.Router();

router.get('/', (req, res) => {
  res.json(config.toPublic(config.load()));
});

router.put('/', (req, res) => {
  const current = config.load();
  const body = req.body || {};
  const currentByAuthority = new Map((current.registryAuths || []).map((a) => [a.authority, a]));

  const registryAuths = (Array.isArray(body.registryAuths) ? body.registryAuths : [])
    .filter((a) => a && a.source !== 'mounted-secret' && a.authority)
    .map((a) => {
      const prev = currentByAuthority.get(a.authority);
      const password = a.password === '********' ? prev?.password || '' : a.password || '';
      return { authority: String(a.authority).trim(), username: a.username || '', password };
    });

  const saved = config.save({
    httpProxy: body.httpProxy,
    httpsProxy: body.httpsProxy,
    noProxy: body.noProxy,
    insecureSkipTlsVerify: !!body.insecureSkipTlsVerify,
    insecureUseHttp: !!body.insecureUseHttp,
    registryAuths
  });
  res.json(config.toPublic(saved));
});

module.exports = router;
