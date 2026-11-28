import { PGlite } from '@electric-sql/pglite';
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';

const db = await PGlite.create();
console.log((await db.query('SELECT version() AS build')).rows);
await db.exec(`
  CREATE ROLE tenant_a;
  CREATE ROLE tenant_b;
  CREATE ROLE backup_reader BYPASSRLS;
  CREATE TABLE tenant_notes (owner_name name NOT NULL);
  INSERT INTO tenant_notes VALUES ('tenant_a'), ('tenant_b');
  ALTER TABLE tenant_notes ENABLE ROW LEVEL SECURITY;
  CREATE POLICY tenant_rows ON tenant_notes
    USING (owner_name = current_user) WITH CHECK (owner_name = current_user);
  GRANT SELECT ON tenant_notes TO tenant_a, tenant_b, backup_reader;
  GRANT INSERT ON tenant_notes TO tenant_b;
`);
for (const check of JSON.parse(await readFile(new URL('role-access.json', import.meta.url)))) {
  await db.exec('RESET ROLE');
  assert.ok(['tenant_a','tenant_b','backup_reader'].includes(check.role));
  await db.exec('SET ROLE ' + check.role);
  let actual;
  try {
    if (check.operation === 'select') {
      actual = (await db.query('SELECT owner_name FROM tenant_notes ORDER BY owner_name')).rows.map(r => r.owner_name);
    } else {
      const owner = check.operation === 'insert-own' ? check.role : 'tenant_a';
      await db.query('INSERT INTO tenant_notes VALUES ($1)', [owner]);
      actual = 'ok';
    }
  } catch (error) {
    actual = error.code;
  }
  assert.deepEqual(actual, check.expected);
  console.log(check.role, check.operation, JSON.stringify(actual));
}
// Compare the 18 fixed transaction fixtures against PostgreSQL's own privilege
// functions. Both revisions start with fresh tables and a role with no grants.
await db.exec('RESET ROLE; CREATE ROLE access_probe; CREATE ROLE ingest;');
async function publicWrites(sql) {
  await db.exec(`
    DROP SCHEMA IF EXISTS app CASCADE;
    CREATE SCHEMA app;
    CREATE TABLE app.a (a int, b int);
    CREATE TABLE app.b (a int, b int);
    CREATE TABLE app.other (a int, b int);
    GRANT USAGE ON SCHEMA app TO access_probe;
  `);
  // Each fixture contains only simple statements with no quoted semicolons.
  // Send them individually so PostgreSQL uses autocommit outside explicit BEGIN.
  for (const statement of sql.split(';').map(part => part.trim()).filter(Boolean)) {
    await db.exec(statement);
  }
  const { rows } = await db.query(`
    SELECT c.relname AS target, a.attname AS column_name, p.right_name
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0
    CROSS JOIN (VALUES ('UPDATE'), ('INSERT')) p(right_name)
    WHERE n.nspname = 'app'
      AND has_column_privilege('access_probe', c.oid, a.attnum, p.right_name)
    UNION ALL
    SELECT c.relname, NULL, p.right_name
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    CROSS JOIN (VALUES ('DELETE'), ('TRUNCATE')) p(right_name)
    WHERE n.nspname = 'app'
      AND has_table_privilege('access_probe', c.oid, p.right_name)
  `);
  return new Set(rows.map(row => JSON.stringify(row)));
}

for (const label of JSON.parse(await readFile(new URL('transactions.json', import.meta.url)))) {
  const before = await publicWrites(label.base);
  const after = await publicWrites(label.head);
  const gainedAccess = [...after].some(right => !before.has(right));
  assert.equal(gainedAccess, label.violations > 0, label.id);
  console.log(label.id, gainedAccess ? 'gained a write privilege' : 'no added write privilege');
}
await db.close();
