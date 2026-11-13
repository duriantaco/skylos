import { readFileSync } from "node:fs";
import path from "node:path";
import { USERS, WORK, one, q, qj, sql } from "./lib.mjs";

const state = JSON.parse(readFileSync(path.join(WORK, "state.json"), "utf8"));

function latestScan(project, branch) {
  return one(`SELECT id FROM scans WHERE project_id = ${q(state.projects[project])} AND branch = ${q(branch)} AND NOT (stats ? 'handbook_clone') ORDER BY created_at DESC LIMIT 1`);
}

function cloneScan(sourceId, overrides, extraStats, withFindings) {
  const id = one("SELECT gen_random_uuid()");
  const patch = { id, share_token: null, ...overrides };
  sql(`INSERT INTO scans SELECT (jsonb_populate_record(NULL::scans, to_jsonb(src) || ${qj(patch)} || jsonb_build_object('stats', src.stats || ${qj({ handbook_clone: true, ...extraStats })}))).* FROM scans src WHERE src.id = ${q(sourceId)};`);
  if (!("verified_pr_number" in extraStats)) {
    sql(`UPDATE scans SET stats = stats - 'verified_pr_number', diff_context = NULL WHERE id = ${q(id)};`);
  }
  if (withFindings) {
    const columns = one("SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'findings' AND is_generated = 'NEVER'");
    sql(`INSERT INTO findings (${columns}) SELECT ${columns} FROM (SELECT (jsonb_populate_record(NULL::findings, to_jsonb(f) || jsonb_build_object('id', gen_random_uuid(), 'scan_id', ${q(id)}::uuid))).* FROM findings f WHERE f.scan_id = ${q(sourceId)}) copy;`);
  }
  return id;
}

function daysAgo(days, hours = 0) {
  return new Date(Date.now() - days * 86400000 - hours * 3600000).toISOString();
}

function pullRequest(project, number, title, author, prState, headSha, mergedDays) {
  let mergedAt = null;
  if (mergedDays !== null) mergedAt = daysAgo(mergedDays);
  sql(`INSERT INTO pull_request_states (project_id, org_id, pr_number, title, author_login, state, draft, head_sha, merged_at, closed_at, github_updated_at)
       VALUES (${q(state.projects[project])}, ${q(state.org)}, ${number}, ${q(title)}, ${q(author)}, ${q(prState)}, false, ${q(headSha)}, ${q(mergedAt)}, ${q(mergedAt)}, now())
       ON CONFLICT DO NOTHING;`);
}

function commitOf(scanId) {
  return one(`SELECT commit_hash FROM scans WHERE id = ${q(scanId)}`);
}

sql(`DELETE FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE stats ? 'handbook_clone'); DELETE FROM scans WHERE stats ? 'handbook_clone'; DELETE FROM pull_request_states WHERE org_id = ${q(state.org)};`);

const storefrontMain = latestScan("storefront-api", "main");
const storefrontFixed = latestScan("storefront-api", "fix/injection-findings");
const webMain = latestScan("web-checkout", "main");
const ledgerMain = latestScan("ledger-service", "main");
const assistantMain = latestScan("support-assistant", "main");

for (let week = 1; week <= 9; week += 1) {
  cloneScan(webMain, { created_at: daysAgo(week * 7, 3) }, {}, false);
  cloneScan(ledgerMain, { created_at: daysAgo(week * 7, 5) }, {}, false);
  cloneScan(assistantMain, { created_at: daysAgo(week * 7, 6) }, {}, false);
  let source = storefrontFixed;
  if (week <= 2) source = storefrontMain;
  cloneScan(source, { created_at: daysAgo(week * 7, 2), branch: "main" }, {}, false);
}

sql(`UPDATE scans SET stats = stats || ${qj({ verified_pr_number: 42 })}, diff_context = ${qj({ prNumber: 42 })} WHERE id = ${q(storefrontFixed)};`);
pullRequest("storefront-api", 42, "Fix injection findings and upgrade dependencies", "priya-example", "open", commitOf(storefrontFixed), null);

const failingPr = cloneScan(
  storefrontMain,
  { created_at: daysAgo(0, 1), branch: "feature/bulk-export", commit_hash: "7c41d9e0a5b24f6f8e3d1c2b9a7f605e4d3c2b1a", diff_context: { prNumber: 45 } },
  { verified_pr_number: 45 },
  true,
);
pullRequest("storefront-api", 45, "Add bulk order export endpoint", "sam-example", "open", "7c41d9e0a5b24f6f8e3d1c2b9a7f605e4d3c2b1a", null);

cloneScan(
  storefrontMain,
  { created_at: daysAgo(0, 3), branch: "feature/coupon-codes", commit_hash: "4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5", diff_context: { prNumber: 47 } },
  { verified_pr_number: 47 },
  true,
);
pullRequest("storefront-api", 47, "Add coupon codes to checkout", "lee-example", "open", "4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5", null);

cloneScan(
  webMain,
  { created_at: daysAgo(3, 2), branch: "feature/header-total", commit_hash: "1f2e3d4c5b6a79880716253443526170a8b9c0d1", diff_context: { prNumber: 17 } },
  { verified_pr_number: 17 },
  true,
);
pullRequest("web-checkout", 17, "Show the cart total in the header", "lee-example", "merged", "1f2e3d4c5b6a79880716253443526170a8b9c0d1", 3);

cloneScan(
  ledgerMain,
  { created_at: daysAgo(1, 4), branch: "feature/statements", commit_hash: "9a8b7c6d5e4f30211203f4e5d6c7b8a99a8b7c6d", diff_context: { prNumber: 8 } },
  { verified_pr_number: 8 },
  true,
);
pullRequest("ledger-service", 8, "Add account statement endpoint", "priya-example", "open", "9a8b7c6d5e4f30211203f4e5d6c7b8a99a8b7c6d", null);

const purchased = one(`SELECT count(*) FROM credit_transactions WHERE org_id = ${q(state.org)} AND transaction_type = 'purchase'`);
if (purchased === "0") {
  sql(`SELECT add_credits(${q(state.org)}, 1000, 'purchase', 'Purchased 1000 credits (team pack)', ${qj({ pack_id: "team", ls_order_id: "local-handbook-order" })}, ${q(USERS.owner.id)});`);
}

console.log(JSON.stringify({ failingPr, owner: USERS.owner.email }));
console.log(sql("SELECT p.name, s.branch, s.quality_gate_passed, s.created_at::date, s.stats->>'verified_pr_number' FROM scans s JOIN projects p ON p.id = s.project_id ORDER BY p.name, s.created_at"));
