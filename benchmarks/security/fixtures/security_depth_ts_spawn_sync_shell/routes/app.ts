import express from 'express';
import * as cp from 'node:child_process';
const app = express();
app.get('/probe', (req, res) => {
  cp.spawnSync('printf', [req.query.value], {shell: '/bin/sh'});
  res.end();
});
