import express from 'express';
import * as cp from 'node:child_process';
const app = express();
app.get('/probe', (req, res) => {
  const base={shell: true}; cp.spawn('printf', [req.query.value], {...base, shell: false});
  res.end();
});
