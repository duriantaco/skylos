import os
from pathlib import Path

import pytest

from skylos.visitors.languages.typescript import scan_typescript_file


AUTH_GUARD_PROOF = "route-local rejecting authentication guard before mutation"
WEBHOOK_GUARD_PROOF = "provider signature verification of request payload before body trust or side effect"


def _scan_typescript(tmp_path: Path, relative_path: str, source: str) -> list[dict]:
    file_path = tmp_path / relative_path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(  # skylos: ignore[SKY-D324] pytest-owned temporary fixture path
        source,
        encoding="utf-8",
    )
    *_, danger, _, _, _, _, _ = scan_typescript_file(str(file_path))
    return danger


def _rule_findings(findings: list[dict], rule_id: str) -> list[dict]:
    return [finding for finding in findings if finding["rule_id"] == rule_id]


def _one_rule_finding(findings: list[dict], rule_id: str) -> dict:
    matches = _rule_findings(findings, rule_id)
    assert len(matches) == 1
    return matches[0]


def _security_evidence(finding: dict) -> dict:
    evidence = finding["metadata"]["security_evidence"]
    assert isinstance(evidence, dict)
    return evidence


def _mutating_next_route(*, preamble: str = "", decoy: str = "") -> str:
    return (
        preamble
        + "export async function POST(request: Request) {\n"
        + decoy
        + "  const body = await request.json();\n"
        + "  await db.user.create({ data: body });\n"
        + "  return Response.json({ ok: true });\n"
        + "}\n"
    )


@pytest.mark.parametrize(
    ("case", "preamble", "decoy"),
    [
        ("comment", "// auth session headers cookies\n", ""),
        ("unused_import", 'import { auth } from "@/auth";\n\n', ""),
        (
            "headers_call",
            'import { headers } from "next/headers";\n\n',
            "  headers();\n",
        ),
        (
            "cookies_call",
            'import { cookies } from "next/headers";\n\n',
            "  cookies();\n",
        ),
    ],
)
def test_d280_auth_shaped_decoys_do_not_hide_unguarded_mutation(
    tmp_path: Path, case: str, preamble: str, decoy: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        f"app/api/{case}/route.ts",
        _mutating_next_route(preamble=preamble, decoy=decoy),
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    evidence = _security_evidence(finding)
    assert evidence["evidence_kind"] == "authorization_guard"
    assert evidence["guards_seen"] == []
    assert evidence["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d280_route_local_rejecting_auth_guard_before_mutation_is_safe(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/account/route.ts",
        """
import { getServerSession } from "next-auth";

export async function POST(request: Request) {
  const session = await getServerSession();
  if (!session) {
    return new Response("Unauthorized", { status: 401 });
  }

  const body = await request.json();
  await db.user.create({ data: body });
  return Response.json({ ok: true });
}
""",
    )

    assert _rule_findings(findings, "SKY-D280") == []


def test_d280_aliased_next_auth_import_with_rejecting_guard_is_safe(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/aliased-session/route.ts",
        """
import { getServerSession as loadSession } from "next-auth";

export async function POST(request: Request) {
  const session = await loadSession();
  if (!session) {
    return new Response("Unauthorized", { status: 401 });
  }

  const body = await request.json();
  await db.user.create({ data: body });
  return Response.json({ ok: true });
}
""",
    )

    assert _rule_findings(findings, "SKY-D280") == []


def test_d280_same_aliased_helper_from_local_module_does_not_prove_auth(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/shadowed-session/route.ts",
        """
import { getServerSession as loadSession } from "./session-utils";

export async function POST(request: Request) {
  const session = await loadSession();
  if (!session) {
    return new Response("Unauthorized", { status: 401 });
  }

  const body = await request.json();
  await db.user.create({ data: body });
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    evidence = _security_evidence(finding)
    assert evidence["evidence_kind"] == "authorization_guard"
    assert isinstance(evidence["guards_seen"], list)
    assert evidence["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d280_rejecting_auth_guard_after_mutation_is_too_late(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/late-session/route.ts",
        """
import { getServerSession } from "next-auth";

export async function POST(request: Request) {
  const session = await getServerSession();
  const body = await request.json();
  await db.user.create({ data: body });

  if (!session) {
    return new Response("Unauthorized", { status: 401 });
  }
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    evidence = _security_evidence(finding)
    assert evidence["evidence_kind"] == "authorization_guard"
    assert isinstance(evidence["guards_seen"], list)
    assert evidence["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d280_auth_check_without_exiting_rejection_does_not_guard_mutation(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/non-exiting-session/route.ts",
        """
import { getServerSession } from "next-auth";

export async function POST(request: Request) {
  const session = await getServerSession();
  if (!session) {
    Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();
  await db.user.create({ data: body });
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    evidence = _security_evidence(finding)
    assert evidence["evidence_kind"] == "authorization_guard"
    assert isinstance(evidence["guards_seen"], list)
    assert evidence["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d280_guard_for_a_lookalike_binding_does_not_protect_session(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/lookalike-session/route.ts",
        """
import { getServerSession } from "next-auth";

export async function POST(request: Request) {
  const session = await getServerSession();
  const sessionBackup = { user: { id: "fixture" } };
  if (!sessionBackup) {
    return new Response("Unauthorized", { status: 401 });
  }
  await db.user.create({ data: await request.json() });
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d280_pages_api_top_level_auth_guard_dominates_post_branch(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "pages/api/account.ts",
        """
import { getServerSession } from "next-auth";

export default async function handler(req, res) {
  const session = await getServerSession(req, res);
  if (!session) return res.status(401).json({ error: "Unauthorized" });

  if (req.method === "POST") {
    await db.user.create({ data: req.body });
    return res.status(200).json({ ok: true });
  }
  return res.status(405).end();
}
""",
    )

    assert _rule_findings(findings, "SKY-D280") == []


def test_d280_auth_guard_in_get_branch_does_not_protect_post_branch(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "pages/api/account-branches.ts",
        """
import { getServerSession } from "next-auth";

export default async function handler(req, res) {
  if (req.method === "GET") {
    const session = await getServerSession(req, res);
    if (!session) return res.status(401).end();
    return res.status(200).json({ account: session.user });
  }
  if (req.method === "POST") {
    await db.user.create({ data: req.body });
    return res.status(200).json({ ok: true });
  }
  return res.status(405).end();
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


def _unsafe_stripe_webhook(*, preamble: str = "", route_steps: str) -> str:
    return (
        preamble
        + "\nexport async function POST(request: Request) {\n"
        + "  const payload = await request.text();\n"
        + '  const signature = request.headers.get("stripe-signature");\n'
        + route_steps
        + '  return new Response("ok");\n'
        + "}\n"
    )


@pytest.mark.parametrize(
    ("case", "preamble", "route_steps"),
    [
        (
            "unused_verifier",
            """import { createHmac } from "node:crypto";

function unusedVerifier(value: string) {
  return createHmac("sha256", "not-the-webhook-secret").update(value).digest();
}
""",
            "  await enqueueStripeEvent(payload);\n",
        ),
        (
            "wrong_payload",
            "",
            """  stripe.webhooks.constructEvent(
    "constant-unrelated-payload",
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await enqueueStripeEvent(payload);
""",
        ),
        (
            "verification_after_effect",
            "",
            """  await enqueueStripeEvent(payload);
  stripe.webhooks.constructEvent(
    payload,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
""",
        ),
    ],
)
def test_d282_unrelated_or_late_verification_does_not_hide_unsafe_webhook(
    tmp_path: Path, case: str, preamble: str, route_steps: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        f"app/api/webhooks/stripe-{case}/route.ts",
        _unsafe_stripe_webhook(preamble=preamble, route_steps=route_steps),
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    evidence = _security_evidence(finding)
    assert evidence["evidence_kind"] == "webhook_signature_guard"
    assert isinstance(evidence["guards_seen"], list)
    assert evidence["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_matching_provider_verification_before_trust_and_effect_is_safe(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/stripe/route.ts",
        """
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  const payload = await request.text();
  const signature = request.headers.get("stripe-signature");
  const event = stripe.webhooks.constructEvent(
    payload,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await enqueueStripeEvent(event);
  return new Response("ok");
}
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []


def test_d282_throwing_provider_verifier_with_terminating_catch_is_safe(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/stripe-try-catch/route.ts",
        """
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  const payload = await request.text();
  const signature = request.headers.get("stripe-signature");
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      payload,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET,
    );
  } catch {
    return new Response("bad signature", { status: 400 });
  }
  await enqueueStripeEvent(event);
  return new Response("ok");
}
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []


def test_d282_svix_verifier_with_request_headers_and_server_secret_is_safe(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/svix-webhook-verified.ts",
        """
import { Webhook } from "svix";
import express from "express";

app.post("/svix/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const body = req.body;
  const headers = req.headers;
  const webhook = new Webhook(process.env.SVIX_WEBHOOK_SECRET!);
  const event = webhook.verify(body, headers);
  await applySvixEvent(event);
  return res.json({ ok: true });
});
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []


@pytest.mark.parametrize(
    ("case", "preamble", "signature_expression"),
    [
        ("constant_signature", "", '"constant-signature"'),
        (
            "wrong_sdk_import",
            'import Stripe from "./local-stripe";\nconst stripe = new Stripe();\n',
            "signature",
        ),
    ],
)
def test_d282_verifier_requires_request_signature_and_trusted_sdk(
    tmp_path: Path, case: str, preamble: str, signature_expression: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        f"app/api/webhooks/stripe-{case}/route.ts",
        preamble
        + f"""
export async function POST(request: Request) {{
  const payload = await request.text();
  const signature = request.headers.get("stripe-signature");
  const event = stripe.webhooks.constructEvent(
    payload,
    {signature_expression},
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await enqueueStripeEvent(event);
  return new Response("ok");
}}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


@pytest.mark.parametrize(
    ("case", "expected_expression"),
    [
        ("expected_compared_to_itself", "expected"),
        (
            "hmac_of_wrong_payload",
            'createHmac("sha256", process.env.GITHUB_WEBHOOK_SECRET)'
            '.update("constant-unrelated-payload").digest()',
        ),
    ],
)
def test_d282_manual_hmac_must_compare_signature_to_hmac_of_request_payload(
    tmp_path: Path, case: str, expected_expression: str
) -> None:
    expected_setup = (
        'const expected = createHmac("sha256", process.env.GITHUB_WEBHOOK_SECRET)'
        ".update(req.body).digest();"
        if case == "expected_compared_to_itself"
        else f"const expected = {expected_expression};"
    )
    compared_value = "expected" if case == "expected_compared_to_itself" else "provided"
    findings = _scan_typescript(
        tmp_path,
        f"src/github-webhook-{case}.ts",
        f"""
app.post("/github/webhook", async (req, res) => {{
  const provided = Buffer.from(req.headers["x-hub-signature-256"] ?? "", "hex");
  {expected_setup}
  if (!timingSafeEqual({compared_value}, expected)) {{
    return res.status(401).send("bad signature");
  }}

  await applyGithubEvent(req.body);
  return res.json({{ ok: true }});
}});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    evidence = _security_evidence(finding)
    assert evidence["evidence_kind"] == "webhook_signature_guard"
    assert isinstance(evidence["guards_seen"], list)
    assert evidence["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d252_explicit_false_cookie_flags_are_reported(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "cookies/false-options.ts",
        'res.cookie("session", token, { secure: false, httpOnly: false });\n',
    )

    finding = _one_rule_finding(findings, "SKY-D252")
    evidence = _security_evidence(finding)
    assert evidence["evidence_kind"] == "cookie_security_options"
    assert evidence["options"] == {"httpOnly": "false", "secure": "false"}


def test_d252_later_spread_can_override_safe_cookie_flags(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "cookies/spread-override.ts",
        'res.cookie("session", token, { httpOnly: true, secure: true, ...overrides });\n',
    )

    finding = _one_rule_finding(findings, "SKY-D252")
    evidence = _security_evidence(finding)
    assert evidence["evidence_kind"] == "cookie_security_options"
    assert evidence["options"] == {"httpOnly": "unknown", "secure": "unknown"}


def test_d252_explicit_true_flags_after_unknown_spread_are_safe(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "cookies/spread-before-safe-overrides.ts",
        'res.cookie("session", token, { ...defaults, httpOnly: true, secure: true });\n',
    )

    assert _rule_findings(findings, "SKY-D252") == []


def test_d252_immutable_bound_literal_options_are_safe(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "cookies/immutable-bound-options.ts",
        """
const cookieOptions = Object.freeze({ httpOnly: true, secure: true });
res.cookie("session", token, cookieOptions);
""",
    )

    assert _rule_findings(findings, "SKY-D252") == []


def test_d252_later_property_write_invalidates_safe_bound_options(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "cookies/mutated-bound-options.ts",
        """
const cookieOptions = { httpOnly: true, secure: true };
cookieOptions.secure = false;
res.cookie("session", token, cookieOptions);
""",
    )

    finding = _one_rule_finding(findings, "SKY-D252")
    assert _security_evidence(finding)["options"] == {
        "httpOnly": "true",
        "secure": "false",
    }


def test_d252_unconditional_true_writes_inside_function_are_safe(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "cookies/unconditional-safe-writes.ts",
        """
function setSessionCookie(res, token) {
  const options = { httpOnly: false, secure: false };
  options.httpOnly = true;
  options.secure = true;
  res.cookie("session", token, options);
}
""",
    )

    assert _rule_findings(findings, "SKY-D252") == []


def test_d252_block_shadow_does_not_replace_outer_unsafe_options(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "cookies/block-shadow.ts",
        """
function setSessionCookie(res, token) {
  const options = { httpOnly: false, secure: false };
  {
    const options = { httpOnly: true, secure: true };
    console.log(options);
  }
  res.cookie("session", token, options);
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D252")
    assert set(_security_evidence(finding)["options"].values()) != {"true"}


@pytest.mark.parametrize(
    ("case", "options_source", "expected_options"),
    [
        (
            "later_secure_false",
            "{ httpOnly: true, secure: true, secure: false }",
            {"httpOnly": "true", "secure": "false"},
        ),
        (
            "later_httponly_false",
            "{ httpOnly: true, secure: true, httpOnly: false }",
            {"httpOnly": "false", "secure": "true"},
        ),
    ],
)
def test_d252_duplicate_cookie_options_use_last_value(
    tmp_path: Path, case: str, options_source: str, expected_options: dict[str, str]
) -> None:
    findings = _scan_typescript(
        tmp_path,
        f"cookies/{case}.ts",
        f'res.cookie("session", token, {options_source});\n',
    )

    finding = _one_rule_finding(findings, "SKY-D252")
    evidence = _security_evidence(finding)
    assert evidence["evidence_kind"] == "cookie_security_options"
    assert evidence["options"] == expected_options


def test_d252_literal_true_cookie_flags_are_safe(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "cookies/literal-safe.ts",
        'res.cookie("session", token, { httpOnly: true, secure: true });\n',
    )

    assert _rule_findings(findings, "SKY-D252") == []


def test_d252_unresolved_dynamic_options_are_reported_as_unknown(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "cookies/dynamic-options.ts",
        'res.cookie("session", token, cookieOptions);\n',
    )

    finding = _one_rule_finding(findings, "SKY-D252")
    evidence = _security_evidence(finding)
    assert evidence["evidence_kind"] == "cookie_security_options"
    assert evidence["options"] == {"httpOnly": "unknown", "secure": "unknown"}


@pytest.mark.parametrize(
    "route_body",
    [
        """
  let session = await getServerSession();
  session = { attackerChosen: true };
  if (!session) return new Response("Unauthorized", { status: 401 });
""",
        """
  const session = request.headers.get("x-auth-bypass")
    ? { attackerChosen: true }
    : await getServerSession();
  if (!session) return new Response("Unauthorized", { status: 401 });
""",
    ],
    ids=["reassigned_result", "trusted_call_nested_in_mixed_rhs"],
)
def test_d280_auth_result_must_remain_exact_and_unmodified_before_guard(
    tmp_path: Path, route_body: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/auth-state/route.ts",
        """
import { getServerSession } from "next-auth";

export async function POST(request: Request) {
"""
        + route_body
        + """
  await db.user.create({ data: await request.json() });
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d280_clerk_auth_object_truthiness_does_not_prove_authentication(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/clerk-object/route.ts",
        """
import { auth } from "@clerk/nextjs/server";

export async function POST(request: Request) {
  const authState = await auth();
  if (!authState) return new Response("Unauthorized", { status: 401 });
  await db.user.create({ data: await request.json() });
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


@pytest.mark.parametrize(
    "guard_source",
    [
        """
  const { isAuthenticated } = await auth();
  if (!isAuthenticated) return new Response("Unauthorized", { status: 401 });
""",
        "  await auth.protect();\n",
    ],
    ids=["is_authenticated_guard", "protect_call"],
)
def test_d280_clerk_provider_specific_guards_are_safe(
    tmp_path: Path, guard_source: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/clerk-protected/route.ts",
        """
import { auth } from "@clerk/nextjs/server";

export async function POST(request: Request) {
"""
        + guard_source
        + """
  await db.user.create({ data: await request.json() });
  return Response.json({ ok: true });
}
""",
    )

    assert _rule_findings(findings, "SKY-D280") == []


def test_d280_auth_guard_text_in_comment_does_not_protect_route(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/commented-guard/route.ts",
        """
import { getServerSession } from "next-auth";

export async function POST(request: Request) {
  const session = await getServerSession();
  // if (!session) return new Response("Unauthorized", { status: 401 });
  await db.user.create({ data: await request.json() });
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d280_provider_words_in_comment_do_not_reclassify_user_route(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/account-reset/route.ts",
        """
// Stripe webhook migration is tracked elsewhere.
export async function POST() {
  await db.user.delete({ where: { id: "fixed-account" } });
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d280_non_call_mutation_before_auth_is_not_protected(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/global-state/route.ts",
        """
import { getServerSession } from "next-auth";

const globalState: { lastBody?: unknown } = {};

export async function POST(request: Request) {
  globalState.lastBody = await request.json();
  const session = await getServerSession();
  if (!session) return new Response("Unauthorized", { status: 401 });
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


@pytest.mark.parametrize(
    "verification_source",
    [
        """
  if (request.headers.get("x-run-verifier")) {
    stripe.webhooks.constructEvent(payload, signature, webhookSecret);
  }
""",
        """
  try {
    stripe.webhooks.constructEvent(payload, signature, webhookSecret);
  } catch (_) {
    // Swallowing verification failure lets an invalid request continue.
  }
""",
    ],
    ids=["optional_branch", "swallowed_failure"],
)
def test_d282_provider_verification_must_dominate_effect_and_reject_failure(
    tmp_path: Path, verification_source: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/stripe-control-flow/route.ts",
        """
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);
const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET!;

export async function POST(request: Request) {
  const payload = await request.text();
  const signature = request.headers.get("stripe-signature");
"""
        + verification_source
        + """
  await enqueueStripeEvent(payload);
  return new Response("ok");
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_unresolved_global_provider_is_not_trusted(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/fake-stripe/route.js",
        """
globalThis.stripe = {
  webhooks: {
    constructEvent(payload, _signature, _secret) {
      return JSON.parse(payload);
    },
  },
};

export async function POST(request) {
  const payload = await request.text();
  const signature = request.headers.get("stripe-signature");
  const event = stripe.webhooks.constructEvent(
    payload,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await enqueueStripeEvent(event);
  return new Response("ok");
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


@pytest.mark.parametrize(
    "secret_setup,secret_expression",
    [
        ("", "process.env.NEXT_PUBLIC_STRIPE_WEBHOOK_SECRET"),
        (
            """
function readWebhookSecret(request: Request) {
  return request.headers.get("x-attacker-selected-secret");
}
""",
            "readWebhookSecret(request)",
        ),
    ],
    ids=["public_environment_secret", "request_derived_named_helper"],
)
def test_d282_provider_verifier_requires_server_only_secret_provenance(
    tmp_path: Path, secret_setup: str, secret_expression: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/stripe-secret/route.ts",
        """
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);
"""
        + secret_setup
        + f"""
export async function POST(request: Request) {{
  const payload = await request.text();
  const signature = request.headers.get("stripe-signature");
  const event = stripe.webhooks.constructEvent(
    payload,
    signature,
    {secret_expression},
  );
  await enqueueStripeEvent(event);
  return new Response("ok");
}}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_block_shadowed_signature_is_not_used_outside_the_block(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/stripe-shadowed-signature/route.ts",
        """
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  const payload = await request.text();
  const signature = "attacker-chosen";
  {
    const signature = request.headers.get("stripe-signature");
    console.log(Boolean(signature));
  }
  const event = stripe.webhooks.constructEvent(
    payload,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await enqueueStripeEvent(event);
  return new Response("ok");
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_raw_body_reassignment_invalidates_earlier_verification(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/stripe-reassigned-body/route.ts",
        """
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  let payload = await request.text();
  const signature = request.headers.get("stripe-signature");
  stripe.webhooks.constructEvent(
    payload,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  payload = request.headers.get("x-unverified-payload") ?? "";
  await enqueueStripeEvent(payload);
  return new Response("ok");
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_alias_derived_effect_before_verification_is_detected(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/stripe-webhook-late-alias.ts",
        """
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);

app.post("/stripe/webhook", async (req, res) => {
  const original = req.body;
  const accountId = original.accountId;
  await db.accounts.save(accountId);
  const signature = req.headers["stripe-signature"];
  stripe.webhooks.constructEvent(
    req.body,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  return res.json({ ok: true });
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_database_update_is_not_webhook_verification_setup(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/stripe-webhook-database-update.ts",
        """
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);

app.post("/stripe/webhook", async (req, res) => {
  const payload = req.body;
  await db.events.update(payload);
  const signature = req.headers["stripe-signature"];
  stripe.webhooks.constructEvent(
    payload,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  return res.json({ ok: true });
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


@pytest.mark.parametrize(
    "key_expression,update_expression,guard_expression",
    [
        (
            'req.headers["x-attacker-selected-key"] ?? ""',
            "body",
            "!timingSafeEqual(provided, expected)",
        ),
        (
            "process.env.GITHUB_WEBHOOK_SECRET",
            '"body"',
            "!timingSafeEqual(provided, expected)",
        ),
        (
            "process.env.GITHUB_WEBHOOK_SECRET",
            "body",
            "!timingSafeEqual(provided, expected) && false",
        ),
        (
            "process.env.GITHUB_WEBHOOK_SECRET",
            "body",
            "!!timingSafeEqual(provided, expected)",
        ),
    ],
    ids=[
        "attacker_selected_key",
        "raw_name_only_inside_string",
        "compound_guard_never_rejects",
        "double_negation_rejects_valid_only",
    ],
)
def test_d282_manual_hmac_requires_exact_key_update_and_rejecting_guard(
    tmp_path: Path,
    key_expression: str,
    update_expression: str,
    guard_expression: str,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/github-webhook-manual-hmac.ts",
        f"""
import {{ createHmac, timingSafeEqual }} from "node:crypto";

app.post("/github/webhook", async (req, res) => {{
  const body = req.body;
  const provided = Buffer.from(
    req.headers["x-hub-signature-256"] ?? "",
    "hex",
  );
  const expected = createHmac("sha256", {key_expression})
    .update({update_expression})
    .digest();
  if ({guard_expression}) return res.status(401).end();
  await applyGithubEvent(body);
  return res.json({{ ok: true }});
}});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_hmac_does_not_cover_a_later_reassigned_body(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/github-webhook-reassigned-hmac-body.ts",
        """
import { createHmac, timingSafeEqual } from "node:crypto";

app.post("/github/webhook", async (req, res) => {
  let body = req.body;
  const provided = Buffer.from(
    req.headers["x-hub-signature-256"] ?? "",
    "hex",
  );
  const expected = createHmac("sha256", process.env.GITHUB_WEBHOOK_SECRET)
    .update(body)
    .digest();
  if (!timingSafeEqual(provided, expected)) return res.status(401).end();
  body = req.headers["x-unverified-body"] ?? "";
  await applyGithubEvent(body);
  return res.json({ ok: true });
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_octokit_verify_boolean_must_be_enforced(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/github-webhook-octokit-ignored.ts",
        """
import { Webhooks } from "@octokit/webhooks";
import express from "express";

const webhooks = new Webhooks({
  secret: process.env.GITHUB_WEBHOOK_SECRET!,
});

app.post("/github/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const signature = req.headers["x-hub-signature-256"];
  await webhooks.verify(req.body, signature);
  await applyGithubEvent(req.body);
  return res.json({ ok: true });
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_octokit_rejecting_boolean_guard_is_safe(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/github-webhook-octokit-guarded.ts",
        """
import { Webhooks } from "@octokit/webhooks";
import express from "express";

const webhooks = new Webhooks({
  secret: process.env.GITHUB_WEBHOOK_SECRET!,
});

app.post("/github/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const signature = req.headers["x-hub-signature-256"];
  const verified = await webhooks.verify(req.body, signature);
  if (!verified) return res.status(401).end();
  await applyGithubEvent(req.body);
  return res.json({ ok: true });
});
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []


def test_d282_verifier_constructor_requires_trusted_secret_provenance(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/svix-webhook-attacker-secret.ts",
        """
import { Webhook } from "svix";

app.post("/svix/webhook", async (req, res) => {
  const webhook = new Webhook(req.headers["x-attacker-selected-key"]);
  const signature = req.headers["svix-signature"];
  const event = webhook.verify(req.body, signature);
  await applySvixEvent(event);
  return res.json({ ok: true });
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


@pytest.mark.parametrize(
    "options_setup",
    [
        """
const options = { httpOnly: false, secure: false };
if (process.env.NODE_ENV === "production") {
  options.httpOnly = true;
  options.secure = true;
}
""",
        """
let options = { httpOnly: true, secure: true };
options = { httpOnly: false, secure: false };
""",
        """
const options = { httpOnly: true, secure: true };
const alias = options;
alias.httpOnly = false;
alias.secure = false;
""",
        """
const Object = {
  freeze(options) {
    options.httpOnly = false;
    options.secure = false;
    return options;
  },
};
const options = Object.freeze({ httpOnly: true, secure: true });
""",
    ],
    ids=[
        "conditional_upgrade",
        "whole_object_reassignment",
        "alias_mutation",
        "shadowed_object_freeze",
    ],
)
def test_d252_mutable_options_are_not_proven_safe(
    tmp_path: Path, options_setup: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "cookies/mutable-options.ts",
        options_setup + 'res.cookie("session", token, options);\n',
    )

    finding = _one_rule_finding(findings, "SKY-D252")
    evidence = _security_evidence(finding)
    assert evidence["guards_missing"]
    assert set(evidence["options"].values()) != {"true"}


@pytest.mark.parametrize(
    "relative_path,tail,rule_id",
    [
        (
            "cookies/budget-exhaustion.ts",
            'res.cookie("session", token, { httpOnly: false, secure: false });\n',
            "SKY-D252",
        ),
        (
            "src/stripe-webhook-budget-exhaustion.ts",
            """
app.post("/stripe/webhook", async (req, res) => {
  await applyStripeEvent(req.body);
  return res.json({ ok: true });
});
""",
            "SKY-D282",
        ),
    ],
    ids=["cookie_candidate", "webhook_route"],
)
def test_security_flow_budget_exhaustion_does_not_drop_candidate(
    tmp_path: Path, relative_path: str, tail: str, rule_id: str
) -> None:
    source = ("0;\n" * 26_000) + tail
    findings = _scan_typescript(tmp_path, relative_path, source)

    finding = _one_rule_finding(findings, rule_id)
    evidence = _security_evidence(finding)
    assert evidence["analysis_complete"] is False
    assert evidence["analysis_diagnostics"]


def test_d280_false_comparison_does_not_reject_missing_next_auth_session(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/false-session/route.ts",
        """
import { getServerSession } from "next-auth";

export async function POST(request: Request) {
  const session = await getServerSession();
  if (session === false) return new Response("Unauthorized", { status: 401 });
  await db.user.create({ data: await request.json() });
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d280_pages_post_fallthrough_is_not_protected_by_non_post_branch(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "pages/api/accounts.ts",
        """
import { getServerSession } from "next-auth";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    const session = await getServerSession();
    if (!session) return res.status(401).end();
    return res.status(405).end();
  }

  await db.accounts.delete({ where: { id: req.body.id } });
  return res.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


@pytest.mark.parametrize(
    "pre_auth_effect",
    [
        "  globalAuditFlag = true;\n",
        "  JSON.parse(await request.text());\n",
    ],
    ids=["module_identifier_assignment", "shadowed_json_parse"],
)
def test_d280_effect_before_auth_cannot_hide_behind_local_looking_syntax(
    tmp_path: Path, pre_auth_effect: str
) -> None:
    preamble = "let globalAuditFlag = false;\n"
    if "JSON.parse" in pre_auth_effect:
        preamble += """
const JSON = {
  parse(value) {
    globalAuditFlag = true;
    return value;
  },
};
"""
    findings = _scan_typescript(
        tmp_path,
        "app/api/pre-auth-effect/route.ts",
        preamble
        + """
import { getServerSession } from "next-auth";

export async function POST(request: Request) {
"""
        + pre_auth_effect
        + """
  const session = await getServerSession();
  if (!session) return new Response("Unauthorized", { status: 401 });
  await db.audit.create({ data: { ok: true } });
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d280_webhook_named_route_without_request_body_still_requires_auth(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/stripe/webhook/route.ts",
        """
import Stripe from "stripe";

export async function POST() {
  await db.accounts.deleteMany();
  return new Response("ok");
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d282_reassigned_stripe_instance_is_not_a_trusted_verifier(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/stripe/webhook/route.ts",
        """
import Stripe from "stripe";

let stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  const payload = await request.text();
  const signature = request.headers.get("stripe-signature");
  stripe = attackerControlledVerifier;
  stripe.webhooks.constructEvent(
    payload,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await enqueueStripeEvent(payload);
  return new Response("ok");
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


@pytest.mark.parametrize(
    "secret_expression,extra_parameter",
    [
        ("process.env.NODE_ENV", ""),
        ("process.env.STRIPE_WEBHOOK_SECRET", ", process"),
    ],
    ids=["non_secret_environment_value", "shadowed_process_binding"],
)
def test_d282_environment_value_must_be_a_real_server_secret(
    tmp_path: Path, secret_expression: str, extra_parameter: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/stripe/webhook/route.ts",
        f"""
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request{extra_parameter}) {{
  const payload = await request.text();
  const signature = request.headers.get("stripe-signature");
  stripe.webhooks.constructEvent(payload, signature, {secret_expression});
  await enqueueStripeEvent(payload);
  return new Response("ok");
}}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_side_effect_in_verifier_argument_happens_before_verification(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/stripe/webhook/route.ts",
        """
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  const payload = await request.text();
  const signature = request.headers.get("stripe-signature");
  stripe.webhooks.constructEvent(
    payload,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
    await db.audit.update({ data: payload }),
  );
  await enqueueStripeEvent(payload);
  return new Response("ok");
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_shadowed_buffer_cannot_turn_hmac_check_into_self_comparison(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/github-webhook-shadowed-buffer.ts",
        """
import { createHmac, timingSafeEqual } from "node:crypto";

app.post("/github/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const body = req.body;
  const expected = createHmac("sha256", process.env.GITHUB_WEBHOOK_SECRET)
    .update(body)
    .digest();
  const Buffer = { from() { return expected; } };
  const provided = Buffer.from(req.headers["x-hub-signature-256"] ?? "");
  if (!timingSafeEqual(provided, expected)) return res.status(401).end();
  await applyGithubEvent(body);
  return res.json({ ok: true });
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


@pytest.mark.parametrize(
    "mutation",
    [
        "delete options.secure;",
        "(() => { options.secure = false; })();",
        "const box = { options }; mutate(box);",
    ],
    ids=["delete_property", "iife_closure_mutation", "container_alias_escape"],
)
def test_d252_indirect_option_mutation_invalidates_literal_true_proof(
    tmp_path: Path, mutation: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "cookies/indirect-option-mutation.ts",
        f"""
const options = {{ httpOnly: true, secure: true }};
{mutation}
res.cookie("session", token, options);
""",
    )

    finding = _one_rule_finding(findings, "SKY-D252")
    assert set(_security_evidence(finding)["options"].values()) != {"true"}


def test_d280_clerk_protect_arguments_execute_before_authentication(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/clerk-argument-order/route.ts",
        """
import { auth } from "@clerk/nextjs/server";

export async function POST(request: Request) {
  await auth.protect(
    await db.audit.create({ data: await request.json() }),
  );
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d282_deployable_next_route_named_test_is_not_a_test_fixture(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/test/stripe-webhook/route.ts",
        """
export async function POST(request: Request) {
  const payload = await request.text();
  await enqueueStripeEvent(payload);
  return new Response("ok");
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d252_named_closure_mutation_invalidates_literal_true_proof(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "cookies/named-closure-mutation.ts",
        """
const options = { httpOnly: true, secure: true };
function weakenCookie() {
  options.secure = false;
}
weakenCookie();
res.cookie("session", token, options);
""",
    )

    finding = _one_rule_finding(findings, "SKY-D252")
    assert set(_security_evidence(finding)["options"].values()) != {"true"}


def test_d252_budget_fallback_recognizes_bracket_cookie_call(tmp_path: Path) -> None:
    source = ("0;\n" * 26_000) + (
        'res["cookie"]("session", token, { httpOnly: false, secure: false });\n'
    )
    findings = _scan_typescript(
        tmp_path,
        "cookies/bracket-cookie-after-budget.ts",
        source,
    )

    finding = _one_rule_finding(findings, "SKY-D252")
    evidence = _security_evidence(finding)
    assert evidence["analysis_complete"] is False
    assert evidence["analysis_diagnostics"]


def test_d252_pure_local_cookie_helper_is_not_an_http_cookie_sink(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/local-cookie-helper.ts",
        """
function cookie(value: string) {
  return { value };
}

const descriptor = cookie(token);
console.log(descriptor);
""",
    )

    assert _rule_findings(findings, "SKY-D252") == []


def test_d282_non_http_local_app_post_is_not_a_webhook_route(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/local-job-registry.ts",
        """
const app = {
  post(name, handler) {
    return { name, handler };
  },
};

app.post("/stripe/webhook", (job) => {
  archiveJob(job.body);
});
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []


def test_d280_positive_authenticated_branch_contains_mutation_is_safe(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/positive-auth-branch/route.ts",
        """
import { getServerSession } from "next-auth";

export async function POST(request: Request) {
  const session = await getServerSession();
  if (session) {
    await db.user.create({ data: await request.json() });
    return Response.json({ ok: true });
  }
  return new Response("Unauthorized", { status: 401 });
}
""",
    )

    assert _rule_findings(findings, "SKY-D280") == []


def test_d280_namespace_next_auth_import_with_rejecting_guard_is_safe(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/namespace-next-auth/route.ts",
        """
import * as NextAuth from "next-auth";

export async function POST(request: Request) {
  const session = await NextAuth.getServerSession();
  if (!session) return new Response("Unauthorized", { status: 401 });
  await db.user.create({ data: await request.json() });
  return Response.json({ ok: true });
}
""",
    )

    assert _rule_findings(findings, "SKY-D280") == []


def test_d282_stripe_construct_event_async_is_a_trusted_verifier(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/stripe-async/route.ts",
        """
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  const payload = await request.text();
  const signature = request.headers.get("stripe-signature");
  const event = await stripe.webhooks.constructEventAsync(
    payload,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await enqueueStripeEvent(event);
  return new Response("ok");
}
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []


def test_d282_octokit_verify_and_receive_is_a_trusted_verifier(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/github-webhook-verify-and-receive.ts",
        """
import { Webhooks } from "@octokit/webhooks";
import express from "express";

const webhooks = new Webhooks({
  secret: process.env.GITHUB_WEBHOOK_SECRET!,
});

app.post("/github/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  await webhooks.verifyAndReceive({
    id: req.headers["x-github-delivery"],
    name: req.headers["x-github-event"],
    payload: req.body,
    signature: req.headers["x-hub-signature-256"],
  });
  return res.json({ ok: true });
});
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []


def test_d282_signature_from_trusted_next_headers_is_safe(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/stripe-next-headers/route.ts",
        """
import { headers } from "next/headers";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  const payload = await request.text();
  const signature = (await headers()).get("stripe-signature");
  const event = stripe.webhooks.constructEvent(
    payload,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await enqueueStripeEvent(event);
  return new Response("ok");
}
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []


def test_d282_express_router_alias_is_still_a_webhook_route(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/aliased-stripe-router.ts",
        """
import express from "express";

const router = express.Router();
const webhookRouter = router;

webhookRouter.post("/stripe/webhook", async (req, res) => {
  await enqueueStripeEvent(req.body);
  return res.json({ ok: true });
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_request_alias_raw_body_is_still_webhook_input(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/aliased-stripe-request.ts",
        """
import express from "express";

const app = express();

app.post("/stripe/webhook", async (req, res) => {
  const webhookRequest = req;
  const payload = webhookRequest.rawBody;
  await enqueueStripeEvent(payload);
  return res.json({ ok: true });
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


@pytest.mark.parametrize(
    ("case", "handler_export"),
    [
        ("reexport", "export { handler as POST };"),
        ("wrapped", "export const POST = withTracing(handler);"),
    ],
)
def test_d280_next_exported_handler_indirection_remains_a_route(
    tmp_path: Path, case: str, handler_export: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        f"app/api/{case}-handler/route.ts",
        f"""
async function handler(request: Request) {{
  await db.user.create({{ data: await request.json() }});
  return Response.json({{ ok: true }});
}}

{handler_export}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


@pytest.mark.parametrize(
    "mutation,processed_expression",
    [
        (
            'req.body = req.headers["x-unverified-payload"];',
            "req.body",
        ),
        (
            'webhookRequest = { body: req.headers["x-unverified-payload"] };',
            "webhookRequest.body",
        ),
    ],
    ids=["direct_request_body_mutation", "reassigned_request_alias"],
)
def test_d282_request_source_must_remain_stable_after_verification(
    tmp_path: Path, mutation: str, processed_expression: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/stripe-webhook-mutated-request.ts",
        f"""
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);

app.post("/stripe/webhook", async (req, res) => {{
  let webhookRequest = req;
  const signature = req.headers["stripe-signature"];
  stripe.webhooks.constructEvent(
    webhookRequest.body,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  {mutation}
  await enqueueStripeEvent({processed_expression});
  return res.json({{ ok: true }});
}});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


@pytest.mark.parametrize(
    "provider_setup,verification",
    [
        (
            """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_API_KEY!);
""",
            """
  stripe.webhooks.constructEventAsync(
    req.body,
    req.headers["stripe-signature"],
    process.env.STRIPE_WEBHOOK_SECRET,
  );
""",
        ),
        (
            """
import { Webhooks } from "@octokit/webhooks";
const webhooks = new Webhooks({
  secret: process.env.GITHUB_WEBHOOK_SECRET!,
});
""",
            """
  webhooks.verifyAndReceive({
    id: req.headers["x-github-delivery"],
    name: req.headers["x-github-event"],
    payload: req.body,
    signature: req.headers["x-hub-signature-256"],
  });
""",
        ),
    ],
    ids=["stripe_construct_event_async", "octokit_verify_and_receive"],
)
def test_d282_async_verifier_promise_must_be_enforced(
    tmp_path: Path, provider_setup: str, verification: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/ignored-async-webhook-verifier.ts",
        provider_setup
        + """
app.post("/stripe/webhook", async (req, res) => {
"""
        + verification
        + """
  await dispatchWebhook(req.body);
  return res.json({ ok: true });
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


@pytest.mark.parametrize(
    "pre_auth_source",
    [
        "  evil.auth();\n",
        """
  const session = await getServerSession();
  if (!session) return new Response("Unauthorized", { status: 401 });
  function getServerSession() { return { attackerChosen: true }; }
""",
    ],
    ids=["untrusted_auth_shaped_effect", "hoisted_local_auth_shadow"],
)
def test_d280_auth_shape_or_shadow_cannot_prove_a_route_safe(
    tmp_path: Path, pre_auth_source: str
) -> None:
    trailing_auth = (
        ""
        if "function getServerSession" in pre_auth_source
        else """
  const session = await getServerSession();
  if (!session) return new Response("Unauthorized", { status: 401 });
"""
    )
    findings = _scan_typescript(
        tmp_path,
        "app/api/auth-shadow/route.ts",
        """
import { getServerSession } from "next-auth";

export async function POST() {
"""
        + pre_auth_source
        + trailing_auth
        + """
  await db.user.deleteMany();
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


@pytest.mark.parametrize(
    "auth_source",
    [
        """
  const session = getServerSession();
  if (!session) return new Response("Unauthorized", { status: 401 });
""",
        "  auth.protect();\n",
    ],
    ids=["unawaited_session_promise", "unawaited_clerk_protect"],
)
def test_d280_async_authentication_must_complete_before_mutation(
    tmp_path: Path, auth_source: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/unawaited-auth/route.ts",
        """
import { getServerSession } from "next-auth";
import { auth } from "@clerk/nextjs/server";

export async function POST() {
"""
        + auth_source
        + """
  await db.user.deleteMany();
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d280_pages_default_exported_identifier_is_a_route(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "pages/api/accounts.ts",
        """
async function handler(req, res) {
  if (req.method === "POST") {
    await db.accounts.deleteMany();
    return res.json({ ok: true });
  }
  return res.status(405).end();
}

export default handler;
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


@pytest.mark.parametrize(
    "early_effect",
    [
        "  await db.audit.deleteMany();\n",
        "  globalState.lastEvent = raw;\n",
    ],
    ids=["effect_before_body_acquisition", "member_write_before_verification"],
)
def test_d282_any_effect_before_verification_remains_unprotected(
    tmp_path: Path, early_effect: str
) -> None:
    body_setup = "  const raw = await request.text();\n"
    if "db.audit" in early_effect:
        body_setup = early_effect + body_setup
        early_effect = ""
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/stripe/route.ts",
        """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_API_SECRET!);

export async function POST(request: Request) {
"""
        + body_setup
        + early_effect
        + """
  const signature = request.headers.get("stripe-signature");
  stripe.webhooks.constructEvent(
    raw,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await dispatch(raw);
  return new Response("ok");
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_webhook_import_and_generic_path_have_matching_rule_ownership(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/route.ts",
        """
import { Webhooks } from "@octokit/webhooks";

export async function POST(request: Request) {
  const event = await request.json();
  await dispatch(event);
  return new Response("ok");
}
""",
    )

    assert _rule_findings(findings, "SKY-D280") == []
    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_parent_scope_fake_verifier_shadows_trusted_module_instance(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/parent-shadowed-octokit.ts",
        """
import { Webhooks } from "@octokit/webhooks";
const webhooks = new Webhooks({
  secret: process.env.GITHUB_WEBHOOK_SECRET!,
});

export function register(app) {
  const webhooks = { verify: () => true };
  app.post("/github/webhook", async (req, res) => {
    const raw = req.body;
    const signature = req.headers["x-hub-signature-256"];
    const verified = webhooks.verify(raw, signature);
    if (!verified) return res.status(401).end();
    await dispatch(raw);
    return res.json({ ok: true });
  });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d252_reassigned_shorthand_flag_is_not_proven_true(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "cookies/reassigned-shorthand.ts",
        """
let httpOnly = true;
let secure = true;
secure = false;
res.cookie("session", token, { httpOnly, secure });
""",
    )

    finding = _one_rule_finding(findings, "SKY-D252")
    assert _security_evidence(finding)["options"]["secure"] == "unknown"


def test_d282_signature_from_stable_next_headers_alias_is_safe(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/stripe-header-alias/route.ts",
        """
import { headers } from "next/headers";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  const raw = await request.text();
  const headersList = await headers();
  const signature = headersList.get("stripe-signature");
  const event = stripe.webhooks.constructEvent(
    raw,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await dispatch(event);
  return new Response("ok");
}
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []


def test_d282_svix_header_object_from_next_headers_is_safe(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/svix-header-object/route.ts",
        """
import { headers } from "next/headers";
import { Webhook } from "svix";

const webhook = new Webhook(process.env.SVIX_WEBHOOK_SECRET!);

export async function POST(request: Request) {
  const raw = await request.text();
  const headersList = await headers();
  const svixHeaders = {
    "svix-id": headersList.get("svix-id"),
    "svix-timestamp": headersList.get("svix-timestamp"),
    "svix-signature": headersList.get("svix-signature"),
  };
  const event = webhook.verify(raw, svixHeaders);
  await dispatch(event);
  return new Response("ok");
}
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []


def test_d282_named_express_callback_is_still_a_webhook_route(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/named-stripe-webhook.ts",
        """
async function webhookHandler(req, res) {
  await dispatch(req.body);
  return res.json({ ok: true });
}

app.post("/stripe/webhook", webhookHandler);
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d280_pages_default_wrapper_resolves_inline_handler(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "pages/api/wrapped-handler.ts",
        """
export default withLogging(async function handler(req, res) {
  if (req.method === "POST") {
    await db.accounts.deleteMany();
    return res.json({ ok: true });
  }
  return res.status(405).end();
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


@pytest.mark.parametrize(
    "early_effect",
    [
        "  new AuditWriter(body);\n",
        "  globalMutationCount++;\n",
    ],
    ids=["constructor", "update_expression"],
)
def test_d280_unknown_effects_before_auth_are_not_treated_as_protected(
    tmp_path: Path, early_effect: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/accounts/route.ts",
        """
import { getServerSession } from "next-auth";

export async function POST(request: Request) {
  const body = await request.json();
"""
        + early_effect
        + """
  const session = await getServerSession();
  if (!session) return new Response("unauthorized", { status: 401 });
  await db.account.create({ data: body });
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


@pytest.mark.parametrize(
    "early_effect",
    [
        "  new EventRecorder(raw);\n",
        "  globalWebhookCount++;\n",
    ],
    ids=["constructor", "update_expression"],
)
def test_d282_unknown_effects_before_verification_remain_unprotected(
    tmp_path: Path, early_effect: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/stripe/route.ts",
        """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  const raw = await request.text();
"""
        + early_effect
        + """
  const signature = request.headers.get("stripe-signature");
  const event = stripe.webhooks.constructEvent(
    raw,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await dispatch(event);
  return new Response("ok");
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_commonjs_stripe_raw_middleware_pattern_is_safe(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/stripe-webhook-commonjs.js",
        """
const express = require("express");
const stripe = require("stripe")(process.env.STRIPE_API_KEY);

app.post(
  "/stripe/webhook",
  express.raw({ type: "application/json" }),
  (req, res) => {
    const signature = req.headers["stripe-signature"];
    const event = stripe.webhooks.constructEvent(
      req.body,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET,
    );
    dispatch(event);
    return res.json({ ok: true });
  },
);
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []


def test_d282_next_pages_parsed_body_is_not_treated_as_raw(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "pages/api/stripe/webhook.ts",
        """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();
  const signature = req.headers["stripe-signature"];
  const event = stripe.webhooks.constructEvent(
    req.body,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await dispatch(event);
  return res.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


@pytest.mark.parametrize("include_config", [False, True])
def test_d282_next_pages_requires_disabled_parser_for_micro_raw_body(
    tmp_path: Path, include_config: bool
) -> None:
    config = (
        "export const config = { api: { bodyParser: false } };\n"
        if include_config
        else ""
    )
    findings = _scan_typescript(
        tmp_path,
        "pages/api/stripe/micro-webhook.ts",
        """
import { buffer } from "micro";
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_API_KEY!);
"""
        + config
        + """
export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();
  const raw = await buffer(req);
  const signature = req.headers["stripe-signature"];
  const event = stripe.webhooks.constructEvent(
    raw,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await dispatch(event);
  return res.json({ ok: true });
}
""",
    )

    assert _rule_findings(findings, "SKY-D280") == []
    if include_config:
        assert _rule_findings(findings, "SKY-D282") == []
    else:
        finding = _one_rule_finding(findings, "SKY-D282")
        assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_shadowed_commonjs_require_cannot_prove_stripe_verifier(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/stripe-webhook-shadowed-require.js",
        """
function registerRoute(require) {
  const stripe = require("stripe")(process.env.STRIPE_API_KEY);
  app.post("/stripe/webhook", (req, res) => {
    const signature = req.headers["stripe-signature"];
    const event = stripe.webhooks.constructEvent(
      req.body,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET,
    );
    dispatch(event);
    return res.json({ ok: true });
  });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_comment_only_provider_hint_does_not_claim_ordinary_route(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhook/route.ts",
        """
// Stripe migration note: this endpoint is not a provider webhook.
export async function POST(request: Request) {
  const body = await request.json();
  await db.jobs.create({ data: body });
  return Response.json({ ok: true });
}
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []
    assert len(_rule_findings(findings, "SKY-D280")) == 1


def test_d282_later_parent_scope_shadow_cannot_borrow_import_provenance(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/github-webhook-parent-shadow.ts",
        """
import { Webhooks } from "@octokit/webhooks";
const trustedWebhooks = new Webhooks({
  secret: process.env.GITHUB_WEBHOOK_SECRET,
});

function registerRoute() {
  app.post("/github/webhook", async (req, res) => {
    const signature = req.headers["x-hub-signature-256"];
    const verified = await webhooks.verify(req.body, signature);
    if (!verified) return res.status(401).end();
    await dispatch(req.body);
    return res.json({ ok: true });
  });
  const webhooks = { verify: () => true };
  return webhooks;
}

registerRoute(trustedWebhooks);
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d280_external_mutating_route_reexport_fails_closed(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/accounts/route.ts",
        'export { handler as POST } from "./handler";\n',
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    evidence = _security_evidence(finding)
    assert evidence["analysis_complete"] is False
    assert evidence["guards_missing"] == [AUTH_GUARD_PROOF]


@pytest.mark.parametrize(
    "export_source",
    [
        'import { handler } from "./handler";\nexport const POST = handler;\n',
        'import { handler } from "./handler";\nexport { handler as POST };\n',
        (
            'import { handler } from "./handler";\n'
            "export const POST = withLogging(handler);\n"
        ),
    ],
    ids=["imported-binding", "imported-export-clause", "wrapped-import"],
)
def test_d280_unresolved_external_app_handlers_fail_closed(
    tmp_path: Path, export_source: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/accounts/route.ts",
        export_source,
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    evidence = _security_evidence(finding)
    assert evidence["analysis_complete"] is False
    assert evidence["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d282_express_json_body_is_not_treated_as_raw(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/stripe-webhook-json-body.ts",
        """
import express from "express";
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_API_KEY!);

app.post("/stripe/webhook", express.json(), async (req, res) => {
  const signature = req.headers["stripe-signature"];
  const event = stripe.webhooks.constructEvent(
    req.body,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await dispatch(event);
  return res.json({ ok: true });
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_nested_require_cannot_overwrite_outer_import_provenance(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/stripe-webhook-scope-provenance.ts",
        """
import FakeStripe from "evil-stripe";
const stripe = new FakeStripe(process.env.STRIPE_API_KEY!);

function unrelatedFactory() {
  const FakeStripe = require("stripe");
  return FakeStripe;
}

app.post("/stripe/webhook", async (req, res) => {
  const signature = req.headers["stripe-signature"];
  const event = stripe.webhooks.constructEvent(
    req.rawBody,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await dispatch(event);
  return res.json({ ok: true });
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_module_provider_reassignment_after_handler_invalidates_proof(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/stripe-reassigned-module/route.ts",
        """
import Stripe from "stripe";
let stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  const raw = await request.text();
  const signature = request.headers.get("stripe-signature");
  const event = stripe.webhooks.constructEvent(
    raw,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await dispatch(event);
  return new Response("ok");
}

stripe = {
  webhooks: { constructEvent: (raw) => JSON.parse(raw) },
};
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_response_body_write_before_verification_is_a_side_effect(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/stripe-webhook-early-response.ts",
        """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_API_KEY!);

app.post("/stripe/webhook", async (req, res) => {
  const raw = req.rawBody;
  res.write(raw);
  const signature = req.headers["stripe-signature"];
  stripe.webhooks.constructEvent(
    raw,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  return res.end();
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_verifier_finally_side_effect_does_not_reject_failure(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/stripe-finally/route.ts",
        """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  const raw = await request.text();
  const signature = request.headers.get("stripe-signature");
  try {
    stripe.webhooks.constructEvent(
      raw,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET,
    );
  } catch {
    return new Response("invalid", { status: 401 });
  } finally {
    await dispatch(raw);
  }
  return new Response("ok");
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


@pytest.mark.parametrize(
    "export_source",
    [
        "export const POST = handler;\n",
        "export { handler as POST };\n",
    ],
    ids=["const-alias", "export-clause"],
)
def test_d280_hoisted_local_handler_is_analyzed(
    tmp_path: Path, export_source: str
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/hoisted/route.ts",
        export_source
        + """
async function handler(request: Request) {
  await db.account.deleteMany();
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["analysis_complete"] is True


def test_d280_unsafe_wrapper_cannot_borrow_safe_callback_body(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/wrapped/route.ts",
        """
import { getServerSession } from "next-auth";

async function safeHandler(request: Request) {
  const session = await getServerSession();
  if (!session) return new Response("unauthorized", { status: 401 });
  return Response.json({ ok: true });
}

async function unsafeHandler(request: Request) {
  await db.account.deleteMany();
  return Response.json({ ok: true });
}

function discardAndReturnUnsafe(_safe) {
  return unsafeHandler;
}

export const POST = discardAndReturnUnsafe(safeHandler);
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["analysis_complete"] is False


@pytest.mark.parametrize(
    ("relative_path", "route_path"),
    [
        ("src/stripe-events.ts", "/stripe/events"),
        ("src/github-hooks.ts", "/github/hooks"),
    ],
)
def test_d282_provider_event_routes_do_not_require_literal_webhook_name(
    tmp_path: Path, relative_path: str, route_path: str
) -> None:
    provider_setup = (
        'import Stripe from "stripe";\n'
        if "stripe" in route_path
        else 'import { createHmac } from "node:crypto";\n'
    )
    findings = _scan_typescript(
        tmp_path,
        relative_path,
        provider_setup
        + f"""
app.post("{route_path}", async (req, res) => {{
  await dispatch(req.body);
  return res.json({{ ok: true }});
}});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_module_env_secret_overwrite_invalidates_verifier(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/webhooks/stripe-env-overwrite/route.ts",
        """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  const raw = await request.text();
  const signature = request.headers.get("stripe-signature");
  const event = stripe.webhooks.constructEvent(
    raw,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await dispatch(event);
  return new Response("ok");
}

process.env.STRIPE_WEBHOOK_SECRET = "public-fallback";
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_pages_ignores_effects_in_rejected_get_branch(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "pages/api/stripe/webhook.ts",
        """
import { buffer } from "micro";
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_API_KEY!);
export const config = { api: { bodyParser: false } };

export default async function handler(req, res) {
  if (req.method === "GET") {
    await db.health.findMany();
    return res.json({ ok: true });
  }
  if (req.method !== "POST") return res.status(405).end();
  const raw = await buffer(req);
  const signature = req.headers["stripe-signature"];
  const event = stripe.webhooks.constructEvent(
    raw,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await dispatch(event);
  return res.json({ ok: true });
}
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []
    assert _rule_findings(findings, "SKY-D280") == []


def test_d282_provider_import_does_not_claim_unrelated_post_route(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/mixed-routes.ts",
        """
import express from "express";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);

app.post("/health", express.json(), async (req, res) => {
  await recordHealth(req.body);
  return res.json({ ok: true });
});

app.post(
  "/stripe/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const signature = req.headers["stripe-signature"];
    const event = stripe.webhooks.constructEvent(
      req.body,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET,
    );
    await dispatch(event);
    return res.json({ ok: true });
  },
);
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []


def test_d282_route_budget_overflow_fails_closed_for_late_webhook(
    tmp_path: Path,
) -> None:
    registrations = "\n".join(
        f'app.post("/ordinary-{index}", ordinaryHandler);' for index in range(512)
    )
    findings = _scan_typescript(
        tmp_path,
        "src/large-stripe-router.ts",
        f"""
import Stripe from "stripe";

function ordinaryHandler(_req, res) {{
  return res.json({{ ok: true }});
}}

function webhookHandler(req, res) {{
  dispatch(req.rawBody);
  return res.json({{ ok: true }});
}}

{registrations}
app.post("/stripe/webhook", webhookHandler);
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    evidence = _security_evidence(finding)
    assert evidence["analysis_complete"] is False
    assert "route budget exceeded" in evidence["analysis_diagnostics"]
    assert "omitted by route budget" in evidence["sink"]


def test_d280_authjs_v5_local_adapter_is_proven_cross_file(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"name":"authjs-proof-fixture","private":true}\n',
        encoding="utf-8",
    )
    (tmp_path / "tsconfig.json").write_text(
        '{"compilerOptions":{"baseUrl":".","paths":{"@/*":["./*"]}}}\n',
        encoding="utf-8",
    )
    (tmp_path / "auth.ts").write_text(
        """
import NextAuth from "next-auth";

export const { auth, handlers, signIn, signOut } = NextAuth({
  providers: [],
});
""",
        encoding="utf-8",
    )

    findings = _scan_typescript(
        tmp_path,
        "app/api/account/route.ts",
        """
import { auth } from "@/auth";

export async function POST(request: Request) {
  const session = await auth();
  if (!session) return new Response("unauthorized", { status: 401 });
  await db.account.update({
    where: { id: session.user.id },
    data: await request.json(),
  });
  return Response.json({ ok: true });
}
""",
    )

    assert _rule_findings(findings, "SKY-D280") == []


def test_d280_authjs_adapter_read_failure_does_not_prove_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "package.json").write_text(
        '{"name":"authjs-symlink-fixture","private":true}\n',
        encoding="utf-8",
    )
    (tmp_path / "tsconfig.json").write_text(
        '{"compilerOptions":{"baseUrl":".","paths":{"@/*":["./*"]}}}\n',
        encoding="utf-8",
    )
    (tmp_path / "auth.ts").write_text(
        """
import NextAuth from "next-auth";

export const { auth } = NextAuth({ providers: [] });
""",
        encoding="utf-8",
    )

    from skylos.visitors.languages.typescript import security_proofs

    safe_read_calls: list[tuple[tuple, dict]] = []

    def reject_safe_read(*args, **kwargs):
        safe_read_calls.append((args, kwargs))
        return None

    monkeypatch.setattr(
        security_proofs,
        "read_project_text_no_symlink",
        reject_safe_read,
    )
    findings = _scan_typescript(
        tmp_path,
        "app/api/account/route.ts",
        """
import { auth } from "@/auth";

export async function POST() {
  const session = await auth();
  if (!session) return new Response("unauthorized", { status: 401 });
  await db.account.deleteMany();
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert len(safe_read_calls) == 1
    (project_root, target), read_options = safe_read_calls[0]
    assert project_root == str(tmp_path)
    assert target == str(tmp_path / "auth.ts")
    assert read_options == {
        "max_bytes": security_proofs._MAX_LOCAL_AUTH_MODULE_BYTES,
        "errors": "surrogateescape",
        "newline": "",
    }
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d280_authjs_adapter_proof_is_not_reused_after_same_size_rewrite(
    tmp_path: Path,
) -> None:
    (tmp_path / "package.json").write_text(
        '{"name":"authjs-rewrite-fixture","private":true}\n',
        encoding="utf-8",
    )
    (tmp_path / "tsconfig.json").write_text(
        '{"compilerOptions":{"baseUrl":".","paths":{"@/*":["./*"]}}}\n',
        encoding="utf-8",
    )
    auth_module = tmp_path / "auth.ts"
    trusted_source = (
        'import NextAuth from "next-auth";\n'
        "export const { auth } = NextAuth({ providers: [] });\n"
    )
    untrusted_source = (
        'import FakeAuth from "fake-auth";\n'
        "export const { auth } = FakeAuth({ providers: [] });\n"
    )
    assert len(untrusted_source.encode()) == len(trusted_source.encode())
    auth_module.write_text(trusted_source, encoding="utf-8")
    original_stat = auth_module.stat()
    route_source = """
import { auth } from "@/auth";

export async function POST() {
  const session = await auth();
  if (!session) return new Response("unauthorized", { status: 401 });
  await db.account.deleteMany();
  return Response.json({ ok: true });
}
"""

    trusted_findings = _scan_typescript(
        tmp_path,
        "app/api/account/route.ts",
        route_source,
    )
    assert _rule_findings(trusted_findings, "SKY-D280") == []

    auth_module.write_text(untrusted_source, encoding="utf-8")
    os.utime(
        auth_module,
        ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
    )
    rewritten_stat = auth_module.stat()
    assert rewritten_stat.st_size == original_stat.st_size
    assert rewritten_stat.st_mtime_ns == original_stat.st_mtime_ns

    rewritten_findings = _scan_typescript(
        tmp_path,
        "app/api/account/route.ts",
        route_source,
    )
    finding = _one_rule_finding(rewritten_findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d280_spoofed_local_auth_adapter_is_not_trusted(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"name":"authjs-spoof-fixture","private":true}\n',
        encoding="utf-8",
    )
    (tmp_path / "tsconfig.json").write_text(
        '{"compilerOptions":{"baseUrl":".","paths":{"@/*":["./*"]}}}\n',
        encoding="utf-8",
    )
    (tmp_path / "auth.ts").write_text(
        "export const auth = async () => ({ user: { id: 'attacker' } });\n",
        encoding="utf-8",
    )

    findings = _scan_typescript(
        tmp_path,
        "app/api/account/route.ts",
        """
import { auth } from "@/auth";

export async function POST() {
  const session = await auth();
  if (!session) return new Response("unauthorized", { status: 401 });
  await db.account.deleteMany();
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d282_earlier_express_handler_cannot_hide_behind_later_verifier(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/multi-handler-router.ts",
        """
import express from "express";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);
const unsafeFirst = async (req, _res, next) => {
  await dispatch(req.body);
  next();
};
const verifiesLater = async (req, res) => {
  const signature = req.headers["stripe-signature"];
  const event = stripe.webhooks.constructEvent(
    req.body,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  await dispatchVerified(event);
  return res.json({ ok: true });
};

app.post(
  "/stripe/webhook",
  express.raw({ type: "application/json" }),
  unsafeFirst,
  verifiesLater,
);
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_verified_express_middleware_can_protect_later_raw_handler(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/verified-middleware-router.ts",
        """
import express from "express";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);
const verifyFirst = (req, _res, next) => {
  const signature = req.headers["stripe-signature"];
  stripe.webhooks.constructEvent(
    req.body,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  next();
};
const handleVerified = async (req, res) => {
  await dispatch(req.body);
  return res.json({ ok: true });
};

app.post(
  "/stripe/webhook",
  express.raw({ type: "application/json" }),
  verifyFirst,
  handleVerified,
);
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []


def test_d282_prior_middleware_proof_does_not_cover_later_unsigned_rewrite(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/rewritten-middleware-router.ts",
        """
import express from "express";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);
const verifyFirst = (req, _res, next) => {
  const signature = req.headers["stripe-signature"];
  stripe.webhooks.constructEvent(
    req.body,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  next();
};
const rewriteAndHandle = async (req, res) => {
  req.body = Buffer.from(req.headers["x-event"] ?? "");
  await dispatch(req.body);
  return res.json({ ok: true });
};

app.post(
  "/stripe/webhook",
  express.raw({ type: "application/json" }),
  verifyFirst,
  rewriteAndHandle,
);
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_chained_express_route_keeps_its_webhook_path(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/chained-router.ts",
        """
import express from "express";
import Stripe from "stripe";

const router = express.Router();
router.route("/stripe/webhook").post(async (req, res) => {
  await dispatch(req.rawBody);
  return res.json({ ok: true });
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_destructured_request_body_is_still_webhook_input(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/destructured-webhook.ts",
        """
import express from "express";
import Stripe from "stripe";

app.post(
  "/stripe/webhook",
  express.raw({ type: "application/json" }),
  async ({ body, headers }, res) => {
    await dispatch(body);
    return res.json({ ok: true });
  },
);
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d282_destructured_raw_body_and_headers_can_be_proven_safe(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/destructured-webhook-safe.ts",
        """
import express from "express";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_API_KEY!);
app.post(
  "/stripe/webhook",
  express.raw({ type: "application/json" }),
  async ({ body: raw, headers }, res) => {
    const signature = headers["stripe-signature"];
    const event = stripe.webhooks.constructEvent(
      raw,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET,
    );
    await dispatch(event);
    return res.json({ ok: true });
  },
);
""",
    )

    assert _rule_findings(findings, "SKY-D282") == []


def test_d282_node_budget_cannot_hide_late_express_webhook(tmp_path: Path) -> None:
    filler = "".join(f"const filler{index} = {index};\n" for index in range(15_000))
    findings = _scan_typescript(
        tmp_path,
        "src/large-router.ts",
        'import Stripe from "stripe";\n'
        + filler
        + """
app.post("/stripe/webhook", async (req, res) => {
  await dispatch(req.rawBody);
  return res.json({ ok: true });
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    evidence = _security_evidence(finding)
    assert evidence["analysis_complete"] is False
    assert "node budget exceeded" in evidence["analysis_diagnostics"]


def test_d280_delete_before_authentication_is_a_mutation(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/account/route.ts",
        """
import { getServerSession } from "next-auth";
const globalState = { account: 1 };

export async function POST() {
  delete globalState.account;
  const session = await getServerSession();
  if (!session) return new Response("unauthorized", { status: 401 });
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d282_verification_does_not_authorize_unrelated_request_header(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/stripe/webhook/route.ts",
        """
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_API_KEY!);

export async function POST(request: Request) {
  const raw = await request.text();
  const signature = request.headers.get("stripe-signature");
  stripe.webhooks.constructEvent(
    raw,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET,
  );
  const forged = request.headers.get("x-event");
  await dispatch(forged);
  return new Response("ok");
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert "not verified" in " ".join(_security_evidence(finding)["guards_seen"])


def test_d280_member_of_trusted_auth_import_is_not_the_auth_function(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/account/route.ts",
        """
import { getServerSession } from "next-auth";
(getServerSession as any).fake = async () => ({ attacker: true });

export async function POST(request: Request) {
  const session = await (getServerSession as any).fake();
  if (!session) return new Response("unauthorized", { status: 401 });
  await db.account.deleteMany();
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["guards_missing"] == [AUTH_GUARD_PROOF]


def test_d282_mutated_crypto_module_cannot_prove_hmac_guard(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/github-webhook.ts",
        """
const crypto = require("node:crypto");
crypto.timingSafeEqual = () => true;

app.post("/github/webhook", async (req, res) => {
  const provided = Buffer.from(
    req.headers["x-hub-signature-256"] ?? "",
    "hex",
  );
  const expected = crypto
    .createHmac("sha256", process.env.GITHUB_WEBHOOK_SECRET)
    .update(req.rawBody)
    .digest();
  if (!crypto.timingSafeEqual(provided, expected)) {
    return res.status(401).end();
  }
  await dispatch(req.rawBody);
  return res.json({ ok: true });
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D282")
    assert _security_evidence(finding)["guards_missing"] == [WEBHOOK_GUARD_PROOF]


def test_d252_mutated_object_freeze_cannot_prove_cookie_flags(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/cookies.ts",
        """
Object.freeze = () => ({ httpOnly: false, secure: false });
const options = Object.freeze({ httpOnly: true, secure: true });
res.cookie("session", token, options);
""",
    )

    finding = _one_rule_finding(findings, "SKY-D252")
    assert set(_security_evidence(finding)["options"].values()) != {"true"}


def test_d252_later_module_monkeypatch_applies_before_handler_runs(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/cookie-handler.ts",
        """
export function setCookie(res, token) {
  const options = Object.freeze({ httpOnly: true, secure: true });
  res.cookie("session", token, options);
}

Object.freeze = () => ({ httpOnly: false, secure: false });
""",
    )

    finding = _one_rule_finding(findings, "SKY-D252")
    assert set(_security_evidence(finding)["options"].values()) != {"true"}


def test_d280_positive_guard_must_cover_every_mutation(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/partially-guarded/route.ts",
        """
import { getServerSession } from "next-auth";

export async function POST() {
  const session = await getServerSession();
  if (session) {
    await db.audit.create({ data: { action: "attempt" } });
  }
  await db.account.deleteMany();
  return Response.json({ ok: true });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D280")
    assert _security_evidence(finding)["sink"] == "db.account.deleteMany"


def test_d280_positive_guard_can_cover_multiple_mutations(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/fully-guarded/route.ts",
        """
import { getServerSession } from "next-auth";

export async function POST() {
  const session = await getServerSession();
  if (session) {
    await db.audit.create({ data: { action: "attempt" } });
    await db.account.deleteMany();
    return Response.json({ ok: true });
  }
  return new Response("Unauthorized", { status: 401 });
}
""",
    )

    assert _rule_findings(findings, "SKY-D280") == []


def test_d280_positive_guard_with_rejecting_else_covers_following_mutation(
    tmp_path: Path,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/positive-auth-fallthrough/route.ts",
        """
import { getServerSession } from "next-auth";

export async function POST() {
  const session = await getServerSession();
  if (session) {
    await db.audit.create({ data: { action: "attempt" } });
  } else {
    return new Response("Unauthorized", { status: 401 });
  }
  await db.account.deleteMany();
  return Response.json({ ok: true });
}
""",
    )

    assert _rule_findings(findings, "SKY-D280") == []


def test_d282_provider_api_route_keeps_d280_ownership(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/stripe/customers/route.ts",
        """
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(request: Request) {
  const body = await request.json();
  await stripe.customers.create(body);
  return Response.json({ ok: true });
}
""",
    )

    _one_rule_finding(findings, "SKY-D280")
    assert _rule_findings(findings, "SKY-D282") == []


def test_d282_provider_event_route_keeps_webhook_ownership(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "app/api/stripe/events/route.ts",
        """
import Stripe from "stripe";

export async function POST(request: Request) {
  const body = await request.json();
  await dispatch(body);
  return Response.json({ ok: true });
}
""",
    )

    _one_rule_finding(findings, "SKY-D282")
    assert _rule_findings(findings, "SKY-D280") == []


def test_d252_local_cookie_serializer_is_not_an_http_sink(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/local-cookie-serializer.ts",
        """
const serializer = {
  cookie(name: string, value: string, options: object) {
    return JSON.stringify({ name, value, options });
  },
};

serializer.cookie("theme", "dark", {});
const res = serializer;
res.cookie("theme", "dark", {});
""",
    )

    assert _rule_findings(findings, "SKY-D252") == []


def test_d252_http_response_cookie_remains_a_sink(tmp_path: Path) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/http-cookie-response.ts",
        """
export function setSessionCookie(res, token: string) {
  res.cookie("session", token, { httpOnly: false, secure: false });
}
""",
    )

    finding = _one_rule_finding(findings, "SKY-D252")
    assert set(_security_evidence(finding)["options"].values()) == {"false"}


@pytest.mark.parametrize(
    ("initial_value", "replacement", "expect_finding"),
    [
        ("res", "serializer", False),
        ("serializer", "res", True),
    ],
    ids=["response-reassigned-to-local", "local-reassigned-to-response"],
)
def test_d252_response_provenance_follows_reassignment(
    tmp_path: Path,
    initial_value: str,
    replacement: str,
    expect_finding: bool,
) -> None:
    findings = _scan_typescript(
        tmp_path,
        "src/reassigned-cookie-response.ts",
        f"""
const serializer = {{
  cookie(name: string, value: string, options: object) {{
    return JSON.stringify({{ name, value, options }});
  }},
}};

export function setSessionCookie(res, token: string) {{
  let target = {initial_value};
  target = {replacement};
  target.cookie("session", token, {{ httpOnly: false, secure: false }});
}}
""",
    )

    matches = _rule_findings(findings, "SKY-D252")
    assert bool(matches) is expect_finding


def test_d252_event_budget_fails_closed_for_custom_route_response_name(
    tmp_path: Path,
) -> None:
    calls = "".join("  noop();\n" for _ in range(4_100))
    findings = _scan_typescript(
        tmp_path,
        "src/custom-response-cookie-route.ts",
        """
app.post("/session", (request, outgoing) => {
"""
        + calls
        + """
  outgoing.cookie(
    "session",
    token,
    { httpOnly: false, secure: false },
  );
});
""",
    )

    finding = _one_rule_finding(findings, "SKY-D252")
    evidence = _security_evidence(finding)
    assert evidence["analysis_complete"] is False
    assert any(
        "event budget exceeded" in item for item in evidence["analysis_diagnostics"]
    )
