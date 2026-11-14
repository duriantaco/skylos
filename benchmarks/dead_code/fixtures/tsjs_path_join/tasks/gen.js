const path = require('path');
const shared = require(path.join(__dirname, '..', 'lib', 'shared.js'));
const input = path.join(__dirname, '..', 'tools', 'input.ts');
const root = path.resolve(__dirname, '..');
const entry = path.join(root, 'src/bundle.ts');
// path.join(__dirname, '..', 'lib', 'commented.js')
const label = ['lib', 'joined.js'].join('/');
const fake = { join: (...parts) => parts.join('-') };
const other = fake.join(__dirname, '..', 'lib', 'fake.js');
shared.run(input, entry, label, other);
