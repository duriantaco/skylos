/* eslint-disable */

export interface LegacyPayload {
  [key: string]: any;
}

export function acceptLegacy(value: any): unknown {
  return value;
}

export function loadLegacy(): Record<string, any> {
  return {};
}

function unfinished(): never {
  throw new Error("Not implemented");
}

try {
  refreshCache();
} catch {
}

new Promise(async (resolve) => {
  resolve(await loadRemote());
});

const values = [1, 2, 3];
values.forEach(async (value) => {
  await saveValue(value);
});
const mappedValues = [1, 2, 3];
mappedValues.map(async (value) => saveValue(value));
