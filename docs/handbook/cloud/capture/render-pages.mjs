import { mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

const [pdf, first, last, outDir, repo] = process.argv.slice(2);
if (!pdf || !first || !last || !outDir || !repo) {
  console.error("usage: node render-pages.mjs <pdf> <first page> <last page> <out dir> <checkout with @playwright/test>");
  process.exit(2);
}
const require = createRequire(path.join(repo, "package.json"));
const { chromium } = require("@playwright/test");
mkdirSync(outDir, { recursive: true });
const browser = await chromium.launch({ channel: process.env.SKYLOS_BROWSER_CHANNEL || "chrome", headless: true, args: ["--headless=new"] });
const page = await browser.newPage({ viewport: { width: 794, height: 1123 }, deviceScaleFactor: 1.6 });
const url = "file://" + path.resolve(pdf);
for (let number = Number(first); number <= Number(last); number += 1) {
  await page.goto(`about:blank`);
  await page.goto(`${url}#page=${number}&toolbar=0&navpanes=0&view=Fit`, { waitUntil: "load" });
  await page.waitForTimeout(1800);
  await page.screenshot({ path: path.join(outDir, `page-${String(number).padStart(3, "0")}.png`) });
}
await browser.close();
console.log(`rendered pages ${first}-${last}`);
