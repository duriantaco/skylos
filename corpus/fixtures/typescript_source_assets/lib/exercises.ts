import fs from "node:fs/promises";
import path from "node:path";
const ROOT = path.join(process.cwd(), "content", "exercises");
const EXT = { vanilla: "js", typed: "ts" };
export async function getExercise(slug: string) {
  const dir = path.join(ROOT, slug);
  const ext = EXT["vanilla"];
  const [starter, solution, tests] = await Promise.all([
    fs.readFile(path.join(dir, `starter.${ext}`), "utf8"),
    fs.readFile(path.join(dir, `solution.${ext}`), "utf8"),
    fs.readFile(path.join(dir, `tests.${ext}`), "utf8"),
  ]);
  return { starter, solution, tests };
}
