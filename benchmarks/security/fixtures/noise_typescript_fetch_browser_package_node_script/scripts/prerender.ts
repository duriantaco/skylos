import { writeFileSync } from "node:fs";

export async function snapshot(target: string, out: string) {
  const response = await fetch(target);
  writeFileSync(out, await response.text());
}
