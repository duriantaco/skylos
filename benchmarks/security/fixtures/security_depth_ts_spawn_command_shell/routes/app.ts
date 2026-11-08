import express from 'express';
import * as cp from 'node:child_process';
const app = express();
app.get('/probe', (req, res) => {
  cp.spawn(req.query.command, [], {shell: true});
  res.end();
});
