// Execute pure Cloud regression tests, compiling TypeScript in memory.
// All generated evidence is written under --output; Cloud sources are read only.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

let cloudRoot = process.env.SKYLOS_CLOUD_CHECKOUT || path.join(__dirname, '..', '..', 'skylos-cloud', 'skylos-cloud');
let outputDir = '/private/tmp/skylos-product-audit/fixed/cloud';
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--cloud-root' && args[i + 1]) cloudRoot = args[++i];
  else if (args[i] === '--output' && args[i + 1]) outputDir = args[++i];
  else if (args[i] === '--help') {
    console.log('node scripts/product_cloud_backend_evidence.cjs [--cloud-root PATH] [--output PATH]');
    process.exit(0);
  } else {
    console.error('Unknown or incomplete argument:', args[i]);
    process.exit(2);
  }
}
cloudRoot = path.resolve(cloudRoot);
outputDir = path.resolve(outputDir);
fs.mkdirSync(outputDir, { recursive: true });
const logPath = path.join(outputDir, 'cloud-backend-tests.log');
fs.writeFileSync(logPath, '');
const originalWrite = process.stdout.write.bind(process.stdout);
process.stdout.write = (chunk, ...rest) => {
  fs.appendFileSync(logPath, chunk);
  return originalWrite(chunk, ...rest);
};

const ts = require(path.join(cloudRoot, 'node_modules', 'typescript'));
// Some tests inspect relative source paths; those operations are reads.
process.chdir(cloudRoot);
const tested = [
  'tests/logic/report-suppressions-core.test.ts',
  'tests/logic/scan-gate-core.test.ts',
  'tests/logic/policy-config.test.ts',
  'tests/logic/scan-policy-receipt.test.ts',
  'tests/logic/scan-policy-receipt-view.test.ts',
  'tests/logic/required-scan-coverage.test.ts',
  'tests/logic/github-skylos-workflow.test.ts',
  'tests/logic/github-workflow-rule-artifacts.test.ts',
];

// These pure tests must never contact an external service.
for (const protocol of ['node:http', 'node:https']) {
  const module = require(protocol);
  for (const method of ['request', 'get']) {
    module[method] = () => { throw new Error('Network is forbidden in this proof harness'); };
  }
}
global.fetch = async () => { throw new Error('Network is forbidden in this proof harness'); };

require.extensions['.ts'] = (module, filename) => {
  const source = fs.readFileSync(filename, 'utf8');
  const compiled = ts.transpileModule(source, {
    fileName: filename,
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
  });
  module._compile(compiled.outputText, filename);
};

for (const relative of tested) {
  const filename = path.join(cloudRoot, relative);
  console.log('# source', relative, 'sha256=' + crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex'));
  require(filename);
}
