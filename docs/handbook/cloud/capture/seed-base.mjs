import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";
import { BASE, CLOUD_REPO, HERE, USERS, WORK, call, one, q, sql } from "./lib.mjs";

const require = createRequire(path.join(CLOUD_REPO, "package.json"));
const yaml = require("yaml");

const SKYLOS = process.env.HANDBOOK_CLOUD_SKYLOS;
if (!SKYLOS) throw new Error("set HANDBOOK_CLOUD_SKYLOS to a released skylos command");

const STATE_FILE = path.join(WORK, "state.json");
const REPOS_DIR = path.join(WORK, "repos");
const demo = yaml.parse(readFileSync(path.join(HERE, "demo-repos.yaml"), "utf8"));

function expand(text) {
  let out = text;
  for (const [name, parts] of Object.entries(demo.fragments)) {
    out = out.replaceAll(`{{${name}}}`, parts.join(""));
  }
  return out;
}

function git(cwd, ...args) {
  const env = {
    PATH: process.env.PATH,
    HOME: path.join(WORK, "cli-home"),
    GIT_AUTHOR_NAME: "Dana Reyes",
    GIT_AUTHOR_EMAIL: "dana@example.com",
    GIT_COMMITTER_NAME: "Dana Reyes",
    GIT_COMMITTER_EMAIL: "dana@example.com",
    GIT_CONFIG_NOSYSTEM: "1",
  };
  const result = spawnSync("git", args, { cwd, env, encoding: "utf8" });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")}: ${result.stderr}`);
  return result.stdout.trim();
}

function writeState(dir, files) {
  for (const [name, content] of Object.entries(files)) {
    const target = path.join(dir, name);
    if (content === null) {
      rmSync(target, { force: true });
      continue;
    }
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, expand(content));
  }
}

function buildRepo(name, stateName, branch) {
  const dir = path.join(REPOS_DIR, name);
  const spec = demo.repos[name];
  if (!existsSync(path.join(dir, ".git"))) {
    mkdirSync(dir, { recursive: true });
    git(dir, "init", "-q", "-b", "main");
    git(dir, "remote", "add", "origin", spec.remote);
    writeState(dir, spec.states.main.files);
    git(dir, "add", "-A");
    git(dir, "commit", "-q", "-m", "Initial import");
  }
  if (stateName !== "main") {
    git(dir, "checkout", "-q", "-B", branch);
    writeState(dir, spec.states[stateName].files);
    git(dir, "add", "-A");
    git(dir, "commit", "-q", "-m", "Fix injection findings and upgrade dependencies");
  } else {
    git(dir, "checkout", "-q", "main");
  }
  return dir;
}

function upload(dir, token, label, extraEnv = {}, args = ["cloud"]) {
  const home = path.join(WORK, "cli-home");
  mkdirSync(home, { recursive: true });
  const env = {
    PATH: `${path.dirname(SKYLOS)}:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin`,
    HOME: home,
    TERM: "dumb",
    NO_COLOR: "1",
    COLUMNS: "160",
    SKYLOS_API_URL: BASE,
    ...extraEnv,
  };
  if (token) env.SKYLOS_TOKEN = token;
  const result = spawnSync(SKYLOS, args, { cwd: dir, env, encoding: "utf8", input: "", timeout: 600000 });
  const log = path.join(WORK, "logs", `cli-${label}.log`);
  writeFileSync(log, `${result.stdout}\n${result.stderr}\nexit ${result.status}\n`);
  console.log(`upload ${label}: exit ${result.status} (log ${log})`);
}

function ensureUsers() {
  for (const user of Object.values(USERS)) {
    sql(`INSERT INTO auth.users (id, email, email_confirmed_at) VALUES (${q(user.id)}, ${q(user.email)}, now()) ON CONFLICT DO NOTHING;
         INSERT INTO public.profiles (id, email, full_name) VALUES (${q(user.id)}, ${q(user.email)}, ${q(user.name)}) ON CONFLICT (id) DO NOTHING;`);
  }
}

async function ensureWorkspace(user, name) {
  const existing = one(`SELECT o.id FROM organizations o JOIN organization_members m ON m.org_id = o.id WHERE m.user_id = ${q(user.id)} AND o.name = ${q(name)} LIMIT 1`);
  if (existing) return existing;
  const response = await call("POST", "/api/workspaces", { user, body: { name } });
  if (response.status !== 200) throw new Error(`workspace ${name}: ${response.status} ${response.text.slice(0, 300)}`);
  return response.json.org_id;
}

async function ensureProject(user, orgId, name, repoUrl) {
  const existing = one(`SELECT id FROM projects WHERE org_id = ${q(orgId)} AND name = ${q(name)} LIMIT 1`);
  if (existing) return existing;
  const response = await call("POST", "/api/projects", {
    user,
    body: { org_id: orgId, name, repo_url: repoUrl.replace(/\.git$/, "") },
  });
  if (response.status >= 300) throw new Error(`project ${name}: ${response.status} ${response.text.slice(0, 300)}`);
  return one(`SELECT id FROM projects WHERE org_id = ${q(orgId)} AND name = ${q(name)} LIMIT 1`);
}

async function ciToken(user, projectId, label = "github-actions", ciTrusted = true) {
  const response = await call("POST", `/api/projects/${projectId}/api-keys`, {
    user,
    body: { label, ci_trusted: ciTrusted },
  });
  if (response.status !== 200) throw new Error(`token: ${response.status} ${response.text.slice(0, 300)}`);
  return response.json.apiKey;
}

function addMember(orgId, user, role) {
  sql(`INSERT INTO organization_members (org_id, user_id, email, role) VALUES (${q(orgId)}, ${q(user.id)}, ${q(user.email)}, ${q(role)}) ON CONFLICT DO NOTHING;`);
}

ensureUsers();
const state = {};
state.org = await ensureWorkspace(USERS.owner, "Example Co");
addMember(state.org, USERS.admin, "admin");
addMember(state.org, USERS.member, "member");
addMember(state.org, USERS.viewer, "viewer");
state.projects = {};
state.tokens = {};
for (const name of Object.keys(demo.repos)) {
  state.projects[name] = await ensureProject(USERS.owner, state.org, name, demo.repos[name].remote);
}
writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
if (process.argv.includes("--no-upload")) process.exit(0);
let scanned = Object.keys(demo.repos);
if (process.argv.includes("--extras-only")) scanned = [];
for (const name of scanned) {
  const token = await ciToken(USERS.owner, state.projects[name]);
  const dir = buildRepo(name, "main", "main");
  upload(dir, token, `${name}-main`, { CI: "true" });
  if (demo.repos[name].states.fixed) {
    const fixedDir = buildRepo(name, "fixed", "fix/injection-findings");
    upload(fixedDir, token, `${name}-fixed`, { CI: "true" });
    git(fixedDir, "checkout", "-q", "main");
  }
}
const defendToken = await ciToken(USERS.owner, state.projects["support-assistant"]);
upload(buildRepo("support-assistant", "main", "main"), defendToken, "support-assistant-defend", { CI: "true" }, ["defend", ".", "--upload"]);
const laptopToken = await ciToken(USERS.owner, state.projects["web-checkout"], "dana-laptop", false);
const laptopDir = buildRepo("web-checkout", "main", "main");
git(laptopDir, "checkout", "-q", "-B", "try/cart-rounding");
upload(laptopDir, laptopToken, "web-checkout-laptop");
git(laptopDir, "checkout", "-q", "main");
console.log(sql("SELECT p.name, s.branch, s.upload_trust, s.quality_gate_passed, s.created_at FROM scans s JOIN projects p ON p.id = s.project_id ORDER BY s.created_at"));
