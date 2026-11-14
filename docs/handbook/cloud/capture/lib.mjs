import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function need(name) {
  const value = process.env[name];
  if (!value) throw new Error(`set ${name} (see README.md)`);
  return value;
}

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const CLOUD_REPO = need("HANDBOOK_CLOUD_REPO");
export const BASE = process.env.HANDBOOK_CLOUD_BASE || "http://localhost:3911";
export const PSQL = need("HANDBOOK_CLOUD_PSQL");
export const WORK = need("HANDBOOK_CLOUD_WORK");
export const RAW_DIR = path.join(WORK, "raw");
export const TEXT_DIR = path.join(WORK, "text");
const ACCENT = "#d6336c";
const MAIN_LEFT = 254;

const require = createRequire(path.join(CLOUD_REPO, "package.json"));
const { chromium } = require("@playwright/test");

export function uid(n) {
  return `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
}

export const USERS = {
  owner: { id: uid(1001), email: "dana@example.com", name: "Dana Reyes" },
  admin: { id: uid(1002), email: "sam@example.com", name: "Sam Okafor" },
  member: { id: uid(1003), email: "priya@example.com", name: "Priya Nair" },
  viewer: { id: uid(1004), email: "lee@example.com", name: "Lee Carter" },
  fresh: { id: uid(1010), email: "alex@example.com", name: "Alex Morgan" },
  free: { id: uid(1020), email: "jo@example.com", name: "Jo Bell" },
};

export function sqlRaw(source) {
  const result = spawnSync(PSQL, ["-v", "ON_ERROR_STOP=1", "-Atq"], {
    input: source,
    encoding: "utf8",
    maxBuffer: 1 << 29,
  });
  return {
    ok: result.status === 0,
    out: (result.stdout || "").trim(),
    err: (result.stderr || "").trim(),
  };
}

export function sql(source) {
  const result = sqlRaw(source);
  if (!result.ok) throw new Error(result.err || result.out);
  return result.out;
}

export function one(source) {
  const lines = sql(source).split("\n");
  return lines[lines.length - 1] || "";
}

export function q(value) {
  if (value === null || value === undefined) return "NULL";
  return `'${String(value).replaceAll("'", "''")}'`;
}

export function qj(value) {
  return `${q(JSON.stringify(value))}::jsonb`;
}

function b64u(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

export function cookieFor(user) {
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const profile = {
    id: user.id,
    aud: "authenticated",
    role: "authenticated",
    email: user.email,
    app_metadata: {},
    user_metadata: { full_name: user.name, user_name: user.email.split("@")[0] },
    created_at: "2026-11-01T00:00:00Z",
  };
  const claims = {
    sub: user.id,
    aud: "authenticated",
    role: "authenticated",
    email: user.email,
    exp,
    iat: exp - 3700,
    aal: "aal1",
    session_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
  };
  const jwt = `${b64u({ alg: "HS256", typ: "JWT" })}.${b64u(claims)}.ZmFrZXNpZw`;
  const session = {
    access_token: jwt,
    refresh_token: "local-capture-refresh",
    token_type: "bearer",
    expires_in: 3600,
    expires_at: exp,
    user: profile,
  };
  const value = "base64-" + Buffer.from(JSON.stringify(session)).toString("base64url");
  return { name: "sb-127-auth-token", value };
}

export async function call(method, route, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.user) {
    const cookie = cookieFor(options.user);
    headers.cookie = `${cookie.name}=${cookie.value}`;
  }
  let body;
  if (options.body !== undefined) {
    headers["content-type"] = "application/json";
    headers.origin = BASE;
    body = JSON.stringify(options.body);
  }
  const response = await fetch(BASE + route, { method, headers, body, redirect: "manual" });
  const buffer = Buffer.from(await response.arrayBuffer());
  let json = null;
  try {
    json = JSON.parse(buffer.toString("utf8"));
  } catch {
    json = null;
  }
  return { status: response.status, buffer, text: buffer.toString("utf8"), json };
}

export async function open(options = {}) {
  const width = options.width || 1440;
  const height = options.height || 1000;
  mkdirSync(RAW_DIR, { recursive: true });
  mkdirSync(TEXT_DIR, { recursive: true });
  const browser = await chromium.launch({
    channel: process.env.SKYLOS_BROWSER_CHANNEL || "chrome",
    headless: true,
  });
  const context = await browser.newContext({
    viewport: { width, height },
    deviceScaleFactor: 2,
    acceptDownloads: true,
    timezoneId: "UTC",
    locale: "en-US",
  });
  const page = await context.newPage();
  const host = new URL(BASE).hostname;
  const blocked = [];
  await page.route("**/*", (route) => {
    const target = new URL(route.request().url());
    if (target.hostname === "127.0.0.1" || target.hostname === "localhost") return route.continue();
    blocked.push(`${route.request().method()} ${target.origin}${target.pathname}`);
    return route.abort();
  });
  page.on("response", (response) => {
    if (response.status() >= 400) {
      console.log(`   HTTP ${response.status()} ${response.request().method()} ${response.url().replace(BASE, "").slice(0, 160)}`);
    }
  });
  page.on("pageerror", (error) => console.log("   pageerror: " + error.message.slice(0, 200)));

  async function signIn(user) {
    const cookie = cookieFor(user);
    await context.clearCookies();
    await context.addCookies([{ name: cookie.name, value: cookie.value, domain: host, path: "/" }]);
  }

  async function settle(wait = 1200) {
    await page.waitForLoadState("networkidle", { timeout: 60000 }).catch(() => {});
    await page.waitForTimeout(wait);
  }

  async function go(route, wait = 1200) {
    let target = route;
    if (!route.startsWith("http")) target = BASE + route;
    const response = await page.goto(target, { waitUntil: "domcontentloaded", timeout: 300000 });
    await settle(wait);
    let status = "?";
    if (response) status = String(response.status());
    console.log(`GO ${route} -> ${status} ${page.url().replace(BASE, "")}`);
    return response;
  }

  async function tidy() {
    await page.evaluate(() => {
      document.querySelectorAll("nextjs-portal").forEach((node) => node.remove());
      document.querySelectorAll("[data-handbook-mark]").forEach((node) => node.remove());
    });
  }

  async function docBox(locator) {
    await locator.scrollIntoViewIfNeeded({ timeout: 6000 }).catch(() => {});
    const box = await locator.boundingBox({ timeout: 6000 });
    if (!box) throw new Error("no box for locator");
    const scroll = await page.evaluate(() => ({ x: window.scrollX, y: window.scrollY }));
    return { x: box.x + scroll.x, y: box.y + scroll.y, width: box.width, height: box.height };
  }

  async function mark(locator, label, placement = "left") {
    let box = null;
    try {
      box = await docBox(locator.first());
    } catch (error) {
      console.log(`   MARK MISSED ${label}: ${String(error.message).split("\n")[0]}`);
      return;
    }
    await page.evaluate(
      ({ box, label, placement, accent }) => {
        const frame = document.createElement("div");
        frame.setAttribute("data-handbook-mark", "1");
        frame.style.cssText = `position:absolute;z-index:2147483000;pointer-events:none;box-sizing:border-box;left:${box.x - 5}px;top:${box.y - 5}px;width:${box.width + 10}px;height:${box.height + 10}px;border:3px solid ${accent};border-radius:8px;`;
        document.body.appendChild(frame);
        if (label === null) return;
        const badge = document.createElement("div");
        badge.setAttribute("data-handbook-mark", "1");
        let left = box.x - 5 - 30;
        let top = box.y + box.height / 2 - 13;
        if (placement === "right") left = box.x + box.width + 9;
        if (placement === "top") {
          left = box.x - 5;
          top = box.y - 5 - 30;
        }
        if (placement === "inside") {
          left = box.x + box.width - 24;
          top = box.y - 18;
        }
        if (left < 2) left = 2;
        if (top < 2) top = 2;
        badge.textContent = String(label);
        badge.style.cssText = `position:absolute;z-index:2147483001;pointer-events:none;left:${left}px;top:${top}px;width:26px;height:26px;border-radius:13px;background:${accent};color:#fff;font:700 15px/26px Helvetica,Arial,sans-serif;text-align:center;box-shadow:0 0 0 2px #fff;`;
        document.body.appendChild(badge);
      },
      { box, label, placement, accent: ACCENT },
    );
  }

  async function shot(name, options = {}) {
    await page.evaluate(() => document.querySelectorAll("nextjs-portal").forEach((node) => node.remove()));
    const pad = options.pad ?? 12;
    const size = await page.evaluate(() => ({
      width: document.documentElement.scrollWidth,
      height: document.documentElement.scrollHeight,
    }));
    let clip = { x: 0, y: 0, width: size.width, height: Math.min(size.height, options.maxHeight || 1400) };
    if (options.clip) {
      const boxes = [];
      for (const locator of [].concat(options.clip)) boxes.push(await docBox(locator.first()));
      const x0 = Math.max(0, Math.min(...boxes.map((box) => box.x)) - pad);
      const y0 = Math.max(0, Math.min(...boxes.map((box) => box.y)) - pad);
      const x1 = Math.min(size.width, Math.max(...boxes.map((box) => box.x + box.width)) + pad);
      let y1 = Math.min(size.height, Math.max(...boxes.map((box) => box.y + box.height)) + pad);
      if (options.maxHeight && y1 - y0 > options.maxHeight) y1 = y0 + options.maxHeight;
      clip = { x: x0, y: y0, width: x1 - x0, height: y1 - y0 };
    }
    if (options.band) {
      clip = { x: MAIN_LEFT, y: clip.y, width: size.width - MAIN_LEFT, height: clip.height };
    }
    if (options.region) clip = options.region;
    const file = path.join(RAW_DIR, `${name}.png`);
    if (options.viewport) {
      const box = await [].concat(options.clip)[0].first().boundingBox({ timeout: 6000 });
      clip = { x: Math.max(0, box.x - pad), y: Math.max(0, box.y - pad), width: box.width + pad * 2, height: box.height + pad * 2 };
      await page.screenshot({ path: file, clip });
    } else {
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.waitForTimeout(150);
      await page.screenshot({ path: file, fullPage: true, clip });
    }
    const text = await page.locator("body").innerText().catch(() => "");
    writeFileSync(path.join(TEXT_DIR, `${name}.txt`), `URL: ${page.url()}\n\n${text}`);
    console.log(`SHOT ${name} ${Math.round(clip.width)}x${Math.round(clip.height)}`);
    await tidy();
  }

  async function unstick() {
    await page.evaluate(() => {
      document.querySelectorAll("main *").forEach((node) => {
        const position = getComputedStyle(node).position;
        if (position === "sticky" || position === "fixed") node.style.position = "static";
      });
    });
  }

  async function dump(name) {
    const text = await page.locator("body").innerText().catch(() => "");
    writeFileSync(path.join(TEXT_DIR, `${name}.txt`), `URL: ${page.url()}\n\n${text}`);
    return text;
  }

  return { browser, context, page, signIn, go, settle, mark, shot, dump, tidy, unstick, blocked };
}
