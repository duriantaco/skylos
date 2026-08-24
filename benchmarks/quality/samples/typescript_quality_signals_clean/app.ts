/* eslint-disable no-console */

export interface Payload {
  [key: string]: unknown;
}

export function normalize(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null) {
    return {};
  }
  return { value };
}

async function saveAll(values: number[]): Promise<void> {
  const jobs = values.map(async (value) => saveValue(value));
  await Promise.all(jobs);
}

new Promise((resolve) => resolve(loadRemote()));
[1, 2, 3].forEach((value) => saveValue(value));

try {
  refreshCache();
} catch (error) {
  console.warn("Cache refresh failed", error);
}
