import { readFileSync } from "node:fs";
import path from "node:path";
import { USERS, WORK, one, open, q, qj, sql } from "./lib.mjs";

const state = JSON.parse(readFileSync(path.join(WORK, "state.json"), "utf8"));
const STORE = state.projects["storefront-api"];
const WEB = state.projects["web-checkout"];

function scanOf(project, branch) {
  return one(`SELECT id FROM scans WHERE project_id = ${q(project)} AND branch = ${q(branch)} ORDER BY created_at DESC LIMIT 1`);
}

function forgetWorkspaces(user) {
  const owned = `SELECT org_id FROM organization_members WHERE user_id = ${q(user.id)}`;
  sql(`CREATE TEMP TABLE gone AS ${owned};
       DELETE FROM analytics_events WHERE org_id IN (SELECT org_id FROM gone);
       DELETE FROM workspace_trial_grants WHERE user_id = ${q(user.id)};
       DELETE FROM organizations WHERE id IN (SELECT org_id FROM gone);`);
}

const GROUPS = {};

function group(name, run) {
  GROUPS[name] = run;
}

group("start", async (s) => {
  const page = s.page;
  if (process.env.SKIP_ONBOARDING) return startWorkspace(s);
  await s.context.clearCookies();
  await s.go("/login");
  await s.mark(page.getByRole("button", { name: /Continue with GitHub/ }), 1);
  await s.shot("start-sign-in", { clip: await dialogPanel(page, "Welcome to Skylos"), pad: 30 });

  forgetWorkspaces(USERS.fresh);
  await s.signIn(USERS.fresh);
  await s.go("/dashboard/get-started");
  await page.locator("#setup-workspace-name").fill("Example Co");
  await s.mark(page.locator("#setup-workspace-name"), 1);
  await s.mark(page.getByRole("button", { name: "Create workspace" }), 2);
  await s.shot("start-create-workspace", { clip: [page.getByRole("heading", { name: "Create your workspace" }), text(page, /This workspace starts with a Workspace trial/), text(page, "One email a week")], pad: 40 });

  await page.getByRole("button", { name: "Create workspace" }).click();
  await page.getByRole("button", { name: "Add a repository" }).waitFor({ timeout: 60000 });
  await s.settle();
  await s.mark(page.getByRole("button", { name: "Add a repository" }), 1);
  await s.mark(page.locator("summary", { hasText: "Prefer the CLI or CI?" }), 2);
  await s.shot("first-scan-add-repository", { clip: [page.getByRole("heading", { name: "Get started" }), page.locator("summary", { hasText: "Prefer the CLI or CI?" })], pad: 40 });
  await page.locator("summary", { hasText: "Prefer the CLI or CI?" }).click();
  await page.getByLabel("Project name").waitFor({ timeout: 20000 });
  await s.dump("x-name-repository");
  await page.getByLabel("Project name").fill("storefront-api");
  await s.mark(page.getByLabel("Project name"), 1);
  await s.mark(page.getByRole("button", { name: /Add the repository/ }), 2);
  await s.shot("first-scan-name-repository", { clip: [page.locator("summary", { hasText: "Prefer the CLI or CI?" }), page.getByRole("button", { name: /Add the repository/ })], pad: 40 });

  await page.getByRole("button", { name: /Add the repository/ }).click();
  await page.waitForURL(/project=/, { timeout: 60000 });
  await s.settle(2500);
  await s.dump("x-upload-step");
  await s.shot("first-scan-setup", { clip: [page.locator("summary", { hasText: "Prefer the CLI or CI?" }), page.getByRole("button", { name: /Refresh upload status/ })], pad: 40 });

  await startWorkspace(s);
});

async function startWorkspace(s) {
  const page = s.page;
  await s.signIn(USERS.owner);
  await s.go("/dashboard");
  await s.mark(page.getByText("Example Co", { exact: true }).first().locator("xpath=ancestor::*[self::button or self::a or self::div][2]"), 1, "right");
  await s.mark(page.getByText("New workspace").first(), 2, "right");
  await s.shot("start-sidebar", { region: { x: 0, y: 0, width: 300, height: 470 } });

  await s.go("/dashboard/settings/members");
  await page.getByPlaceholder("email@example.com").fill("morgan@example.com");
  await s.mark(page.getByPlaceholder("email@example.com"), 1, "top");
  await s.mark(page.getByLabel("Invitee role"), 2, "top");
  await s.mark(page.getByRole("button", { name: "Invite", exact: true }), 3, "top");
  await s.shot("start-members", { clip: [page.getByRole("heading", { name: "Members & teams" }), text(page, "Skylos shows a secure link")], pad: 30 });
}

async function dialogPanel(page, title) {
  await page.evaluate((wanted) => {
    document.querySelectorAll("[data-handbook-panel]").forEach((node) => node.removeAttribute("data-handbook-panel"));
    function floats(node) {
      let current = node;
      while (current && current !== document.body) {
        if (getComputedStyle(current).position === "fixed") return true;
        current = current.parentElement;
      }
      return false;
    }
    const matches = [...document.querySelectorAll("body *")].filter(
      (node) => node.children.length === 0 && node.textContent.trim() === wanted && node.offsetParent !== null,
    );
    const floating = matches.filter(floats);
    let node = matches[matches.length - 1];
    if (floating.length > 0) node = floating[floating.length - 1];
    if (!node) return;
    while (node.parentElement && node.parentElement.getBoundingClientRect().width < window.innerWidth * 0.85) node = node.parentElement;
    node.setAttribute("data-handbook-panel", "1");
  }, title);
  return page.locator("[data-handbook-panel]");
}

async function step(name, run) {
  try {
    await run();
  } catch (error) {
    console.log(`STEP FAILED ${name}: ${String(error.message).split("\n").slice(0, 3).join(" / ")}`);
  }
}

async function openScan(s, project, scanId) {
  await s.go(`/dashboard/projects/${project}/scans/${scanId}`, 2000);
  await s.page.getByText("Loading issues").waitFor({ state: "detached", timeout: 60000 }).catch(() => {});
  await s.page.waitForTimeout(800);
}

function mainScan(project, branch) {
  return one(`SELECT id FROM scans WHERE project_id = ${q(project)} AND branch = ${q(branch)} AND NOT (stats ? 'handbook_clone') ORDER BY created_at DESC LIMIT 1`);
}

group("first-scan", async (s) => {
  const page = s.page;
  await s.signIn(USERS.owner);
  await step("tokens", async () => {
    await s.go(`/dashboard/projects/${STORE}/settings`, 2500);
    const section = page.locator("#cli-credentials");
    await section.getByText("Loading project tokens").waitFor({ state: "detached", timeout: 60000 }).catch(() => {});
    await section.locator("input[type=text], input:not([type])").first().fill("github-actions");
    await s.mark(section.locator("input[type=text], input:not([type])").first(), 1, "top");
    await s.mark(section.getByLabel(/CI project token/), 2);
    await s.mark(section.getByRole("button", { name: "Create project token" }), 3, "right");
    await s.shot("first-scan-ci-token", { clip: section });
  });
  await step("unverified", async () => {
    await openScan(s, WEB, scanOf(WEB, "try/cart-rounding"));
    await s.dump("x-unverified-scan");
    await s.shot("x-unverified-full", { maxHeight: 1500 });
  });
  await step("home", async () => {
    await s.go("/dashboard", 2500);
    await s.mark(page.getByRole("link", { name: "storefront-api" }).first(), 1);
    await s.shot("first-scan-home", { clip: [page.getByRole("heading", { name: "Home" }), page.getByText("web-checkout").last()], pad: 40 });
  });
});

group("scan", async (s) => {
  const page = s.page;
  await s.signIn(USERS.owner);
  await step("list", async () => {
    await openScan(s, STORE, mainScan(STORE, "main"));
    await s.mark(page.getByPlaceholder(/Search/).first(), 1);
    await s.mark(page.getByRole("button", { name: /^Security/ }).first(), 2, "inside");
    await s.mark(page.getByRole("button", { name: /SKY-D212/ }).first(), 3);
    await s.shot("scan-issue-list", { clip: [page.getByText("All issues").first(), page.getByRole("button", { name: /SKY-D212/ }).first()], pad: 34 });
  });
  await step("finding", async () => {
    await page.getByRole("button", { name: /SKY-D211/ }).first().click();
    await page.getByText("Why this was flagged").waitFor({ timeout: 30000 });
    await page.waitForTimeout(1500);
    await s.dump("x-finding");
    await s.mark(page.getByRole("button", { name: "Fix", exact: true }), 1, "top");
    await s.mark(page.getByRole("button", { name: "Not fixing this" }), 2);
    await s.mark(page.getByRole("button", { name: "This looks wrong" }), 3);
    await s.shot("scan-finding-why", { clip: [page.getByRole("button", { name: /Back to the issue list/ }), page.getByText("Avoid", { exact: true }).locator("xpath=following::li[1]")], pad: 30 });
    await s.mark(page.getByRole("button", { name: "View flow" }).last(), 1);
    await s.mark(page.getByRole("button", { name: "Show more of this file" }), 2);
    await s.shot("scan-finding-evidence", { clip: [page.getByText("Security evidence", { exact: true }), page.getByText("Open this line on GitHub"), page.getByRole("button", { name: "Show more of this file" })], pad: 30 });
  });
  await step("flow", async () => {
    await page.getByRole("button", { name: "View flow" }).first().click();
    await page.waitForTimeout(2500);
    await s.dump("x-flow");
    await s.shot("scan-flow", { clip: await dialogPanel(page, "Possible SQL injection: identified input reaches SQL query text."), pad: 10, viewport: true });
    await page.keyboard.press("Escape");
  });
});

function text(page, value, exact = false) {
  return page.getByText(value, { exact }).first();
}

async function band(s, name, top, bottom, options = {}) {
  await s.shot(name, { clip: [top, bottom], band: true, pad: 24, ...options });
}

function resetDecisions() {
  sql(`DELETE FROM finding_suppressions WHERE project_id = ${q(STORE)};
       DELETE FROM policy_exception_requests WHERE org_id = ${q(state.org)};
       UPDATE scans SET is_overridden = false, override_reason = NULL, overridden_at = NULL, overridden_by = NULL, quality_gate_passed = false
        WHERE project_id = ${q(STORE)} AND branch = 'feature/bulk-export';`);
}

async function pickFinding(s, rule) {
  const page = s.page;
  const back = page.getByRole("button", { name: /Back to the issue list/ });
  if (await back.count()) {
    await back.click();
    await page.waitForTimeout(400);
  }
  await page.getByRole("button", { name: new RegExp(rule) }).first().click();
  await page.getByText("Why this was flagged").waitFor({ timeout: 30000 });
  await page.waitForTimeout(900);
}

async function notFixing(s, rule, choice, reason, shotName) {
  const page = s.page;
  await pickFinding(s, rule);
  await page.getByRole("button", { name: "Not fixing this" }).click();
  await page.waitForTimeout(500);
  await page.getByRole("radio", { name: new RegExp(choice) }).check();
  await page.waitForTimeout(600);
  const panel = page.getByText(/Why aren.t you fixing it/).locator("xpath=../..");
  await panel.locator("textarea").fill(reason);
  const tell = panel.getByRole("checkbox");
  if (await tell.count()) await tell.first().uncheck();
  if (shotName) {
    await s.mark(page.getByRole("radio", { name: new RegExp(choice) }).locator("xpath=.."), 1);
    await s.mark(panel.locator("textarea"), 2);
    await s.mark(panel.getByText("Until when?").locator("xpath=.."), 3);
    await s.mark(panel.getByRole("button", { name: /Send to an admin/ }), 4, "top");
    await s.shot(shotName, { clip: panel, pad: 44 });
  }
  await panel.getByRole("button", { name: /Send to an admin|Accept the risk|Hide as/ }).click();
  await page.waitForTimeout(2500);
}

group("gate", async (s) => {
  const page = s.page;
  resetDecisions();
  await s.signIn(USERS.owner);
  await step("overview", async () => {
    await s.go(`/dashboard/projects/${STORE}`, 2500);
    await band(s, "scan-project-overview", text(page, "Can we ship?"), text(page, "What wasn't checked"));
    await band(s, "gate-fail-overview", page.getByText("Quality gate", { exact: true }).first(), text(page, /Gate history/), { pad: 60 });
  });
  await s.signIn(USERS.admin);
  await step("fail", async () => {
    await openScan(s, STORE, scanOf(STORE, "feature/bulk-export"));
    await s.mark(text(page, "FAIL", true).locator("xpath=ancestor::div[2]"), 1);
    await s.mark(text(page, "Critical security issues (all code)").locator("xpath=ancestor::tr[1]"), 2);
    await s.mark(page.getByRole("button", { name: /Fix these/ }), 3, "top");
    await band(s, "gate-fail-scan", text(page, "Quality gate", false), page.locator("summary", { hasText: "More actions" }), { pad: 40 });
  });
  await step("merge-anyway", async () => {
    await page.locator("summary", { hasText: "More actions" }).click();
    await page.waitForTimeout(500);
    await page.getByRole("button", { name: "Merge anyway" }).first().click();
    await page.waitForTimeout(700);
    const reason = page.locator("textarea").first();
    await reason.fill("Hotfix for the checkout outage. The injection fixes follow in pull request #42.");
    await s.mark(page.locator("summary", { hasText: "More actions" }), 1);
    await s.mark(reason, 2);
    await s.mark(page.getByRole("button", { name: "Merge anyway" }).last(), 3, "top");
    await band(s, "gate-merge-anyway", text(page, "Quality gate", false), page.getByRole("button", { name: "Merge anyway" }).last(), { pad: 40 });
    await page.getByRole("button", { name: "Merge anyway" }).last().click();
    await page.waitForTimeout(3500);
    await s.dump("x-merged-anyway");
    await band(s, "gate-merged-anyway", text(page, "Quality gate", false), page.getByText(/Passed conditions|More actions|Hotfix/).last(), { pad: 40 });
  });
  await step("pass", async () => {
    await openScan(s, STORE, scanOf(STORE, "fix/injection-findings"));
    await band(s, "gate-pass-scan", text(page, "Quality gate", false), page.locator("summary", { hasText: "Passed conditions" }), { pad: 40 });
  });
  await step("blocking", async () => {
    await s.go(`/dashboard/projects/${STORE}/settings`, 2500);
    await s.mark(page.getByRole("button", { name: "Connect GitHub" }).first(), 1);
    await band(s, "gate-merge-blocking-steps", text(page, "Merge blocking on GitHub"), text(page, "require the “Skylos Quality Gate” check before merging"));
  });
  await s.signIn(USERS.owner);
  await step("unverified", async () => {
    await openScan(s, WEB, scanOf(WEB, "try/cart-rounding"));
    await s.mark(text(page, "Unverified: not a CI project token").locator("xpath=ancestor::div[2]"), null);
    await band(s, "first-scan-unverified", text(page, "Quality gate", false), text(page, "Shown here only"), { pad: 40 });
  });
});

group("decide", async (s) => {
  const page = s.page;
  sql(`DELETE FROM finding_suppressions WHERE project_id = ${q(STORE)};
       DELETE FROM policy_exception_requests WHERE org_id = ${q(state.org)};
       UPDATE issue_groups SET status = 'open' WHERE project_id = ${q(STORE)} AND status = 'suppressed';
       UPDATE findings SET is_suppressed = false WHERE is_suppressed AND scan_id IN (SELECT id FROM scans WHERE project_id = ${q(STORE)});`);
  await s.signIn(USERS.member);
  await openScan(s, STORE, mainScan(STORE, "main"));
  await step("request", async () => {
    await notFixing(s, "SKY-D207", "Accepted risk", "Only used for cache keys, never for passwords. Replaced in the January cleanup.", "decide-not-fixing");
    await s.dump("x-request-sent");
    await openScan(s, STORE, mainScan(STORE, "main"));
    await notFixing(s, "SKY-D206", "False positive", "The config endpoint only accepts files that our own deploy job writes.", null);
    await openScan(s, STORE, mainScan(STORE, "main"));
    await notFixing(s, "SKY-L011", "Accepted risk", "Debug mode is switched off by the production environment file.", null);
    await openScan(s, STORE, mainScan(STORE, "main"));
  });
  await step("looks-wrong", async () => {
    await pickFinding(s, "SKY-D209");
    await page.getByRole("button", { name: "This looks wrong" }).click();
    await page.waitForTimeout(800);
    await page.getByRole("radio", { name: "Wrong explanation" }).check();
    await page.locator("[role=dialog] textarea, textarea").last().fill("The message should say which argument is tainted.");
    const dialog = text(page, "Tell Skylos this looks wrong").locator("xpath=ancestor::div[2]");
    await s.shot("decide-looks-wrong", { clip: await dialogPanel(page, "Tell Skylos this looks wrong"), pad: 10, viewport: true });
    await page.getByRole("button", { name: "Send to the founder" }).click();
    await page.waitForTimeout(3000);
    await s.dump("x-looks-wrong-sent");
    await page.keyboard.press("Escape");
  });
  await s.signIn(USERS.admin);
  await step("waiting", async () => {
    await s.go("/dashboard/exceptions", 2000);
    await s.mark(text(page, "Waiting for approval"), 1, "top");
    await s.mark(page.getByRole("link", { name: /Review and decide/ }).first(), 2);
    await band(s, "decide-waiting", page.getByRole("heading", { name: "Not fixing" }), page.getByRole("link", { name: /Review and decide/ }).last());
  });
  await step("approve", async () => {
    await page.locator("main a[href*='/dashboard/exceptions/']", { hasText: "Review and decide" }).first().click();
    await s.settle(2000);
    await s.mark(page.getByRole("button", { name: /^Approve/ }).first(), 1);
    await s.mark(page.getByRole("button", { name: /^Reject/ }).first(), 2);
    await band(s, "decide-approve", page.getByRole("heading", { name: /Request to not fix/ }), page.getByRole("button", { name: /^Reject/ }).first(), { pad: 40 });
    await approveOpenRequest(s, "Agreed. Reviewed with the platform team.");
    await s.go("/dashboard/exceptions", 2000);
    await page.locator("main a[href*='/dashboard/exceptions/']", { hasText: "Review and decide" }).first().click();
    await s.settle(2000);
    await approveOpenRequest(s, "Confirmed with the deploy job owner.");
  });
  await step("list", async () => {
    await s.go("/dashboard/exceptions", 2000);
    await page.getByRole("link", { name: /Recorded/ }).first().click();
    await s.settle(1500);
    await s.dump("x-exceptions-recorded");
    await s.mark(page.getByRole("link", { name: /Recorded/ }).first(), 1, "top");
    await band(s, "decide-list", page.getByRole("heading", { name: "Not fixing" }), page.locator("main").getByText(/Asked by|Approved by|Decided/).last(), { pad: 50 });
    await page.getByRole("link", { name: /Merged anyway/ }).first().click();
    await s.settle(1500);
    await s.dump("x-exceptions-merged");
    await band(s, "decide-merged-anyway", page.getByRole("heading", { name: "Not fixing" }), page.locator("main").getByText(/Hotfix for the checkout outage/).last(), { pad: 50 });
  });
  await step("badge", async () => {
    await s.signIn(USERS.member);
    await openScan(s, STORE, mainScan(STORE, "main"));
    await s.dump("x-scan-after-decisions");
    await s.shot("x-scan-after-decisions", { maxHeight: 2000 });
  });
});

async function approveOpenRequest(s, note) {
  const page = s.page;
  await page.getByRole("button", { name: /^Approve/ }).first().click();
  await page.waitForTimeout(1200);
  const field = page.locator("textarea").last();
  if (await field.count()) await field.fill(note);
  await page.getByRole("button", { name: /^Approve until/ }).last().click();
  await page.waitForTimeout(2500);
}

group("policy", async (s) => {
  const page = s.page;
  await page.setViewportSize({ width: 1440, height: 2600 });
  sql(`DELETE FROM policy_versions WHERE org_id = ${q(state.org)}; UPDATE organizations SET policy_config = '{}'::jsonb WHERE id = ${q(state.org)};`);
  await s.signIn(USERS.owner);
  await s.go("/dashboard/policy", 2500);
  await step("overview", async () => {
    await s.mark(page.getByRole("button", { name: "Edit conditions" }), 1);
    await band(s, "policy-overview", page.getByRole("heading", { name: "Policy" }).first(), text(page, "Which repositories use it"));
  });
  await step("edit", async () => {
    await page.getByRole("button", { name: "Edit conditions" }).click();
    await page.waitForTimeout(1200);
    await s.unstick();
    await s.mark(page.getByLabel("Quality gate on"), 1);
    await s.mark(page.getByLabel(/Always block exposed secrets/), 2);
    await s.mark(text(page, "Fail on AI-code issues").locator("xpath=.."), 3);
    await s.mark(text(page, "Required scan coverage").locator("xpath=.."), 4);
    await band(s, "policy-always-block", text(page, "Always block", true), text(page, "Require workspace custom-rule checks"), { pad: 30 });
  });
  await step("new-issues", async () => {
    const rule = page.getByLabel("Rule for new issues");
    await rule.selectOption({ label: "Allow a set number of new issues per severity" });
    await page.waitForTimeout(800);
    await s.mark(rule, 1);
    await band(s, "policy-new-issues", text(page, "Start from a preset"), text(page, "Advanced", true), { pad: 30 });
    await rule.selectOption({ label: "Block any new issue" });
    await page.waitForTimeout(500);
  });
  await step("advanced", async () => {
    await page.getByRole("button", { name: /Advanced/ }).or(page.locator("summary", { hasText: "Advanced" })).first().click();
    await page.waitForTimeout(1000);
    for (const name of ["Which checks run", "Code-quality limits", "Fix deadlines"]) {
      await page.getByRole("button", { name: new RegExp(name) }).or(page.locator("summary", { hasText: name })).first().click();
      await page.waitForTimeout(400);
    }
    await band(s, "policy-checks-limits", text(page, "Which checks run", true), text(page, "Most parameters in one function"), { pad: 30 });
    await text(page, "Use fix deadlines", true).click();
    await page.waitForTimeout(600);
    await s.mark(text(page, "Use fix deadlines", true), 1);
    await band(s, "policy-fix-deadlines", text(page, "Fix deadlines", true), text(page, "No deadline", true), { pad: 30 });
  });
  await step("save", async () => {
    const reason = page.getByPlaceholder("e.g. SOC 2: block every new secret");
    await reason.fill("Add fix deadlines before the audit period starts.");
    await s.mark(reason, 1, "inside");
    await s.shot("policy-save", { clip: [reason], band: true, pad: 70 });
    await page.getByRole("button", { name: "Save policy" }).click();
    await page.waitForTimeout(3000);
    await s.go("/dashboard/policy", 2500);
    await s.unstick();
    await s.dump("x-policy-saved");
    await band(s, "policy-history", text(page, "Policy history", true), page.locator("main").getByText(/Add fix deadlines before/).last(), { pad: 40 });
    await band(s, "policy-agents", page.getByRole("heading", { name: "Coding agents" }).last(), text(page, "References code that does not exist"), { pad: 30 });
    await band(s, "policy-supply-chain", page.getByRole("heading", { name: "Supply chain" }).last(), text(page, "See Supply chain"), { pad: 30 });
  });
  await step("project", async () => {
    await s.go(`/dashboard/projects/${STORE}/settings`, 2500);
    await s.mark(page.getByRole("button", { name: "Give this project its own policy" }), 1);
    await band(s, "policy-project", page.getByRole("heading", { name: "Project policy" }), text(page, "Excluded paths", true), { pad: 50 });
  });
  await step("rules", async () => {
    await s.go("/dashboard/rules", 2500);
    await page.getByRole("button", { name: /Create a rule/ }).or(page.getByRole("link", { name: /Create a rule/ })).first().click();
    await page.waitForTimeout(1500);
    await s.dump("x-rules");
    await page.getByRole("button", { name: "Require Auth Decorator" }).click();
    await page.waitForTimeout(800);
    await s.mark(page.getByRole("button", { name: "Require Auth Decorator" }), 1, "top");
    await s.mark(page.getByRole("button", { name: "Create rule for future scans" }), 2);
    await s.shot("policy-custom-rule", { clip: await dialogPanel(page, "Create a rule"), pad: 10, viewport: true });
  });
  await page.setViewportSize({ width: 1440, height: 1100 });
});

group("work", async (s) => {
  const page = s.page;
  await s.signIn(USERS.owner);
  await step("home", async () => {
    await s.go("/dashboard", 2500);
    await s.mark(page.getByRole("link", { name: /Fix storefront-api/ }).first(), 1);
    await s.mark(page.getByRole("link", { name: "storefront-api", exact: true }).first(), 2);
    await band(s, "first-scan-home", page.getByRole("heading", { name: "Home" }).first(), text(page, "Last 30 days", true), { pad: 30 });
    await band(s, "work-home-trends", text(page, "Last 12 weeks", true), text(page, "Issues opened and fixed").locator("xpath=following::*[contains(text(),'Show as a table')][1]"), { pad: 30 });
  });
  await step("prs", async () => {
    await s.go("/dashboard/pull-requests", 2500);
    await s.mark(page.getByRole("link", { name: "Board" }).or(page.getByRole("button", { name: "Board" })).first().locator("xpath=.."), 1, "top");
    await band(s, "work-prs-list", page.getByRole("heading", { name: "Pull requests" }).first(), text(page, "feature/header-total"), { pad: 40 });
    await page.getByRole("link", { name: "Board" }).or(page.getByRole("button", { name: "Board" })).first().click();
    await s.settle(2000);
    await band(s, "work-prs-board", page.getByRole("heading", { name: "Pull requests" }).first(), text(page, "Add account statement endpoint").locator("xpath=following::*[3]"), { pad: 40 });
    await page.getByRole("link", { name: "Pipeline" }).or(page.getByRole("button", { name: "Pipeline" })).first().click();
    await s.settle(2000);
    await band(s, "work-prs-pipeline", text(page, /Each pull request.s path from scan to merge/), text(page, "Fix injection findings and upgrad").locator("xpath=following::*[4]"), { pad: 50 });
  });
  await step("issues", async () => {
    await s.go("/dashboard/issues", 2500);
    await s.mark(page.getByPlaceholder(/Search issue/), 1, "left");
    await s.mark(text(page, "Status", true).locator("xpath=.."), 2, "top");
    await s.mark(text(page, "Owner", true).locator("xpath=.."), 3, "top");
    await band(s, "work-issues", page.getByRole("heading", { name: "Issues" }).first(), text(page, "Server-side request forgery"), { pad: 30 });
    const issue = one(`SELECT id FROM issue_groups WHERE project_id = ${q(STORE)} AND rule_id = 'SKY-D211' ORDER BY last_seen_at DESC LIMIT 1`);
    await s.go(`/dashboard/issues/${issue}`, 2500);
    await s.dump("x-issue");
    await s.mark(page.getByRole("button", { name: "Save owner" }).locator("xpath=ancestor::div[3]"), 1, "inside");
    await s.mark(page.getByRole("button", { name: "Not fixing this" }).locator("xpath=ancestor::div[2]"), 2, "inside");
    await band(s, "work-issue-detail", page.locator("main h1").first(), text(page, "Details", true), { pad: 30, maxHeight: 1500 });
  });
  await step("supply", async () => {
    await s.go("/dashboard/supply-chain", 2500);
    await s.mark(page.getByRole("link", { name: "Set supply-chain policy" }).or(page.getByRole("button", { name: "Set supply-chain policy" })).first(), 1);
    await band(s, "work-supply-chain", page.getByRole("heading", { name: "Supply chain" }).first(), text(page, "support-assistant").last().locator("xpath=following::*[14]"), { pad: 30, maxHeight: 1350 });
  });
  await step("ai", async () => {
    await s.go("/dashboard/ai-app-safety", 2500);
    await band(s, "work-ai-app-safety", page.getByRole("heading", { name: "AI app safety" }).first(), text(page, "Not checked yet"), { pad: 30 });
    await page.getByRole("link", { name: "support-assistant" }).first().click();
    await s.settle(2500);
    await s.dump("x-defense");
    await band(s, "work-ai-app-safety-detail", page.getByRole("heading", { name: "AI app safety" }).first(), text(page, /files scanned/i), { pad: 30 });
    await s.go("/dashboard/agents", 2500);
    await band(s, "work-coding-agents", page.getByRole("heading", { name: "Coding agents" }).first(), text(page, "Each pull request push then adds a scan here"), { pad: 40 });
  });
});

group("fixes", async (s) => {
  const page = s.page;
  await s.signIn(USERS.owner);
  await step("dialog", async () => {
    await openScan(s, STORE, mainScan(STORE, "main"));
    await pickFinding(s, "SKY-D211");
    await page.getByRole("button", { name: "Fix", exact: true }).click();
    await page.waitForTimeout(1500);
    const dialog = text(page, "How do you want to fix this?").locator("xpath=ancestor::div[3]");
    await s.mark(page.getByRole("button", { name: "Show the fix brief" }), 1, "top");
    await s.mark(page.getByRole("button", { name: "Create fix PR" }), 2, "top");
    await s.shot("fixes-dialog", { clip: await dialogPanel(page, "How do you want to fix this?"), pad: 10, viewport: true });
    await page.getByRole("button", { name: "Show the fix brief" }).click();
    await page.waitForTimeout(1500);
    await s.dump("x-fix-brief");
    await s.shot("fixes-brief", { clip: await dialogPanel(page, "Fix brief"), pad: 10, viewport: true });
    await page.keyboard.press("Escape");
  });
  await step("cleanup", async () => {
    await s.go(`/dashboard/projects/${STORE}`, 2500);
    await band(s, "fixes-weekly-cleanup", text(page, "Weekly cleanup PRs", true), text(page, "Cleanup PRs are opened through the Skylos GitHub App"), { pad: 40 });
    await s.go(`/dashboard/projects/${STORE}/cleanup`, 2500);
    await s.dump("x-cleanup");
    await band(s, "fixes-cleanup-page", page.getByRole("heading", { name: "Dead-code cleanup" }).first(), text(page, "Current task"), { pad: 40, maxHeight: 1300 });
  });
});

group("evidence", async (s) => {
  const page = s.page;
  await s.signIn(USERS.owner);
  await step("page", async () => {
    await s.go("/dashboard/evidence", 2500);
    await band(s, "evidence-page", page.getByRole("heading", { name: "Audit evidence" }).first(), page.getByRole("link", { name: "Download CSV" }).or(page.getByRole("button", { name: "Download CSV" })).first(), { pad: 40 });
  });
  await step("log", async () => {
    await s.go("/dashboard/activity", 2500);
    await s.mark(page.getByRole("link", { name: /Download these events \(CSV\)/ }).or(page.getByRole("button", { name: /Download these events/ })).first(), 1, "top");
    await band(s, "evidence-audit-log", page.getByRole("heading", { name: "Audit log" }).first(), page.locator("main").getByText(/uploaded a scan|approved|overrode|merged/).nth(3), { pad: 40, maxHeight: 900 });
  });
  await step("access", async () => {
    await s.go("/dashboard/access-review", 2500);
    await band(s, "evidence-access-review", page.getByRole("heading", { name: "Access review" }).first(), text(page, "lee@example.com"), { pad: 50 });
  });
  await step("export", async () => {
    await openScan(s, STORE, mainScan(STORE, "main"));
    await page.getByRole("button", { name: "Download issues" }).click();
    await page.waitForTimeout(800);
    await s.dump("x-export");
    await s.mark(page.getByRole("button", { name: "Download issues" }), 1);
    await band(s, "scan-export", text(page, "Download or share", true), text(page, "Details", true).last(), { pad: 30 });
  });
});

group("settings", async (s) => {
  const page = s.page;
  await s.signIn(USERS.owner);
  await step("integrations", async () => {
    await s.go("/dashboard/settings/integrations", 2500);
    await s.dump("x-integrations");
    await s.mark(page.getByRole("link", { name: "Connect a GitHub organization" }).or(page.getByRole("button", { name: "Connect a GitHub organization" })).first(), 1);
    await band(s, "settings-integrations-github-webhooks", page.getByRole("heading", { name: "Integrations" }).first(), page.getByRole("button", { name: "Add webhook" }), { pad: 40 });
    await band(s, "settings-integrations-jira", page.getByRole("heading", { name: "Jira" }).last(), page.getByRole("button", { name: "Test connection" }), { pad: 40 });
  });
  await step("general", async () => {
    await s.go("/dashboard/settings", 2500);
    await band(s, "settings-digest", text(page, "Weekly digest", true).last(), text(page, "Turn off the digest for everyone"), { pad: 40 });
    await band(s, "settings-retention", text(page, "Data retention", true).last(), page.getByRole("button", { name: "Save retention" }), { pad: 40 });
  });
  await step("project", async () => {
    await s.go(`/dashboard/projects/${STORE}/settings`, 2500);
    await band(s, "settings-project-repository", text(page, "Repository & connection", true).last(), page.getByRole("button", { name: "Unlink" }), { pad: 40 });
    await band(s, "settings-project-notifications", text(page, "Slack Notifications", true), text(page, "Server Settings"), { pad: 60 });
  });
  await step("keys", async () => {
    await s.go("/dashboard/settings/api-keys", 2500);
    await band(s, "settings-api-tokens", page.getByRole("heading", { name: "API & keys" }).first(), page.getByRole("button", { name: "Create token" }), { pad: 40 });
    await s.go("/dashboard/settings/security", 2500);
    await band(s, "settings-security", page.getByRole("heading", { name: "Security" }).first(), text(page, "To change this, first turn on two-factor"), { pad: 40 });
  });
  await step("business", async () => {
    await s.go("/dashboard/repositories", 2500);
    await band(s, "settings-repositories", page.getByRole("heading", { name: "Repositories" }).first(), page.getByText("Open overview").nth(1), { pad: 40 });
  });
});

function ensureCredits(minimum) {
  const credits = Number(one(`SELECT credits FROM organizations WHERE id = ${q(state.org)}`));
  if (credits >= minimum) return;
  sql(`SELECT add_credits(${q(state.org)}, 1000, 'purchase', 'Purchased 1000 credits (team pack)', ${qj({ pack_id: "team", ls_order_id: `local-handbook-${Date.now()}` })}, ${q(USERS.owner.id)});`);
}

function latestReport() {
  return one(`SELECT id FROM compliance_report_artifacts WHERE org_id = ${q(state.org)} AND framework_code = 'SOC2' ORDER BY created_at DESC LIMIT 1`);
}

group("compliance", async (s) => {
  const page = s.page;
  ensureCredits(550);
  await s.signIn(USERS.owner);
  await step("answers", async () => {
    await s.go("/dashboard/compliance/soc2", 2500);
    await s.dump("x-soc2");
    const tab = page.locator("#soc2-tab-description");
    await tab.click();
    await page.waitForTimeout(800);
    const field = page.getByRole("textbox", { name: /DC 1 Services you provide/ }).first();
    await field.fill("Example Co runs a hosted checkout and order service for online shops, with email support during business hours.");
    await s.mark(field, 1);
    const save = field.locator("xpath=following::button[normalize-space()='Save'][1]");
    await s.mark(save, 2, "right");
    await band(s, "compliance-soc2-answers", tab, save, { pad: 40 });
    if (await save.isEnabled()) await save.click();
    await page.waitForTimeout(2000);
  });
  await s.go("/dashboard/compliance", 3500);
  await step("readiness", async () => {
    await s.dump("x-compliance");
    await s.mark(page.getByTestId("readiness-count"), 1, "top");
    await s.mark(page.getByTestId("readiness-row").filter({ hasText: "Not ready" }).first(), 2);
    await band(s, "compliance-readiness", text(page, /Check your scans/), text(page, "How to get a scan that counts"), { pad: 30 });
  });
  await step("generate", async () => {
    await page.getByRole("button", { name: /Generate readiness report/ }).first().click();
    await page.waitForTimeout(1500);
    await s.dump("x-generate-panel");
    await s.mark(text(page, "Which projects", true), 1);
    await s.mark(text(page, /^Prepared for/), 2);
    await s.mark(page.getByRole("button", { name: /charge 500 credits/ }).first(), 3, "left");
    await band(s, "compliance-generate", text(page, "Which projects", true), page.getByRole("button", { name: "Cancel" }).last(), { pad: 50 });
    await page.getByRole("button", { name: /charge 500 credits/ }).first().click();
    await page.getByText(/Your report is ready|Report not generated/).first().waitFor({ timeout: 120000 });
    await page.waitForTimeout(1500);
    await s.dump("x-report-ready");
    await s.dump("x-report-ready-panel");
  });
  await step("latest", async () => {
    await s.go("/dashboard/compliance", 3500);
    const card = text(page, "Your latest report", true);
    const more = page.locator("summary", { hasText: "More formats" }).first();
    await more.click();
    await page.waitForTimeout(800);
    await s.dump("x-latest-report");
    await s.mark(page.getByRole("link", { name: /PDF for your auditor/ }).first(), 1, "top");
    await s.mark(more, 2);
    await band(s, "compliance-latest-report", card, page.getByRole("button", { name: "Request a change" }).first(), { pad: 40 });
  });
  await step("request-change", async () => {
    await page.setViewportSize({ width: 1440, height: 1600 });
    await page.getByRole("button", { name: "Request a change" }).first().click();
    await page.waitForTimeout(1200);
    await page.getByRole("radio", { name: "Wrong company or project name" }).check();
    await s.shot("compliance-request-change", { clip: await dialogPanel(page, "Request a change to this report"), pad: 10, viewport: true });
    await page.keyboard.press("Escape");
    await page.setViewportSize({ width: 1440, height: 1100 });
  });
  const report = latestReport();
  await step("verify", async () => {
    await s.go(`/verify/report/${report}`, 3000);
    await s.dump("x-verify");
    await band(s, "compliance-verify", text(page, "Verify a Skylos evidence report"), text(page, "Check the JSON file", true), { pad: 30, maxHeight: 1500 });
  });
  await step("sample", async () => {
    await s.go(`/dashboard/compliance/sample/${report}`, 3000);
    await page.getByText("Draw a sample for me").first().click();
    await page.waitForTimeout(1200);
    await s.dump("x-sample");
    await s.mark(text(page, "Draw a sample for me"), 1);
    await band(s, "compliance-sample-packet", page.locator("main h1").first(), page.getByRole("button", { name: /Full packet/ }).first(), { pad: 40, maxHeight: 1700 });
  });
  await step("questionnaire", async () => {
    await s.go(`/dashboard/compliance/questionnaire/${report}`, 3000);
    await s.dump("x-questionnaire");
    await band(s, "compliance-questionnaire", page.locator("main h1").first(), page.locator("main").getByText(/What you add/).nth(1), { pad: 40, maxHeight: 1500 });
  });
});

group("billing", async (s) => {
  const page = s.page;
  await s.signIn(USERS.owner);
  await s.go("/dashboard/billing", 3000);
  await step("plans", async () => {
    await band(s, "billing-plans", page.getByRole("heading", { name: "Billing" }).first(), page.getByRole("button", { name: "Buying is paused" }).first(), { pad: 40 });
    await band(s, "billing-costs", text(page, "What each action costs", true), text(page, "Compliance report", true).last(), { pad: 40 });
  });
  await step("history", async () => {
    await s.go("/dashboard/billing/history", 2500);
    await band(s, "billing-history", page.getByRole("heading", { name: "Credit history" }).first(), text(page, "Balance after"), { pad: 40 });
  });
  await step("feedback", async () => {
    await s.go("/dashboard", 2000);
    await page.getByRole("button", { name: "Send feedback" }).first().click();
    await page.waitForTimeout(1200);
    await page.getByText("Idea", { exact: true }).last().click();
    await page.locator("textarea").last().fill("Let us pick which branch the Home page shows for each repository.");
    await s.shot("billing-send-feedback", { clip: await dialogPanel(page, "Send feedback"), pad: 10, viewport: true });
  });
});

async function main() {
  const wanted = process.argv.slice(2);
  let names = Object.keys(GROUPS);
  if (wanted.length > 0) names = wanted;
  const s = await open({ height: 1100 });
  for (const name of names) {
    if (!GROUPS[name]) throw new Error(`no capture group ${name}`);
    console.log(`== ${name}`);
    await GROUPS[name](s);
  }
  await s.browser.close();
}

await main();
