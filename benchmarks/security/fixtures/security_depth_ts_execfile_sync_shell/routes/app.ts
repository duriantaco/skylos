import express from 'express';
import * as cp from 'node:child_process';
const app = express();
app.get('/probe', (req, res) => {
  cp.execFileSync('printf', [req.query.value], {shell: true});
  res.end();
});
