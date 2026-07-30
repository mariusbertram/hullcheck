'use strict';

require('./scanner'); // registers the job runner with jobs.js
const { createApp } = require('./app');

const PORT = parseInt(process.env.PORT || '8080', 10);
const app = createApp();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`anchor-webui listening on :${PORT}`);
});
