import { join } from 'node:path';

export function register(hooksDir: string, outDir: string) {
  return {
    command: `node ${join(hooksDir, 'session-start.js')}`,
    report: join(outDir, 'report.js'),
    note: 'see archived-hook.js for history',
  };
}
