from __future__ import annotations

import ast
import textwrap

from skylos.rules.danger.danger import scan_file_with_tree
from skylos.rules.danger.danger_webhook import webhook_flow
from skylos.visitors.languages.typescript import scan_typescript_file
from skylos.visitors.languages.typescript.security_flow import FlowLimits


def _scan_python(code: str, filename: str = "app.py") -> list[dict]:
    source = textwrap.dedent(code)
    tree = ast.parse(source)
    findings: list[dict] = []
    scan_file_with_tree(tree, filename, findings, source=source)
    return findings


def _scan_ts(tmp_path, code: str, filename: str) -> list[dict]:
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(code), encoding="utf-8")
    results = scan_typescript_file(str(path))
    *_, danger = results[:8]
    return danger


def _rule_ids(findings: list[dict]) -> set[str]:
    return {finding["rule_id"] for finding in findings}


def test_fastapi_stripe_webhook_without_signature_flags():
    findings = _scan_python(
        """
        app = make_app()

        @app.post("/stripe/webhook")
        async def stripe_webhook(request):
            event = await request.json()
            if event["type"] == "checkout.session.completed":
                grant_credits(event["data"]["object"]["customer"])
            return {"ok": True}
        """
    )

    assert "SKY-D282" in _rule_ids(findings)


def test_fastapi_stripe_webhook_with_construct_event_is_safe():
    findings = _scan_python(
        """
        app = make_app()

        @app.post("/stripe/webhook")
        async def stripe_webhook(request):
            body = await request.body()
            sig = request.headers.get("stripe-signature")
            event = stripe.Webhook.construct_event(body, sig, STRIPE_WEBHOOK_SECRET)
            return {"ok": True}
        """
    )

    assert "SKY-D282" not in _rule_ids(findings)


def test_fastapi_stripe_webhook_with_instance_verify_is_safe():
    findings = _scan_python(
        """
        app = make_app()

        @app.post("/stripe/webhook")
        async def stripe_webhook(request):
            body = await request.body()
            sig = request.headers.get("stripe-signature")
            webhook = Webhook(STRIPE_WEBHOOK_SECRET)
            event = webhook.verify(body, sig)
            return {"ok": True, "event": event}
        """
    )

    assert "SKY-D282" not in _rule_ids(findings)


def test_flask_github_webhook_with_hmac_compare_is_safe():
    findings = _scan_python(
        """
        app = make_app()

        @app.route("/github/webhook", methods=["POST"])
        def github_webhook():
            body = request.data
            sig = request.headers.get("x-hub-signature-256")
            expected = sign(body)
            if not hmac.compare_digest(sig, expected):
                return "bad", 401
            return "ok"
        """
    )

    assert "SKY-D282" not in _rule_ids(findings)


def test_non_webhook_callback_route_is_not_flagged():
    findings = _scan_python(
        """
        app = make_app()

        @app.post("/oauth/callback")
        async def oauth_callback(request):
            payload = await request.json()
            return payload
        """
    )

    assert "SKY-D282" not in _rule_ids(findings)


def test_python_many_unverified_webhook_constructors_still_flags():
    constructors = "\n".join(
        f"            candidate_{index} = Webhook('secret-{index}')"
        for index in range(250)
    )
    findings = _scan_python(
        f"""
        app = make_app()

        @app.post("/stripe/webhook")
        async def stripe_webhook(request):
            event = await request.json()
{constructors}
            return event
        """
    )

    assert "SKY-D282" in _rule_ids(findings)


def test_python_test_path_is_not_flagged():
    findings = _scan_python(
        """
        app = make_app()

        @app.post("/stripe/webhook")
        async def stripe_webhook(request):
            event = await request.json()
            return event
        """,
        filename="tests/test_webhook.py",
    )

    assert "SKY-D282" not in _rule_ids(findings)


def test_nextjs_stripe_webhook_without_signature_flags(tmp_path):
    findings = _scan_ts(
        tmp_path,
        """
        import Stripe from "stripe";

        const stripe = new Stripe(process.env.STRIPE_API_KEY!);

        export async function POST(req: Request) {
          const event = await req.json();
          if (event.type === "checkout.session.completed") {
            await grantCredits(event.data.object.customer);
          }
          return Response.json({ received: true });
        }
        """,
        "app/api/stripe/webhook/route.ts",
    )

    ids = _rule_ids(findings)
    assert "SKY-D282" in ids
    assert "SKY-D280" not in ids


def test_nextjs_stripe_webhook_with_construct_event_is_safe(tmp_path):
    findings = _scan_ts(
        tmp_path,
        """
        import Stripe from "stripe";

        const stripe = new Stripe(process.env.STRIPE_API_KEY!);

        export async function POST(req: Request) {
          const body = await req.text();
          const sig = req.headers.get("stripe-signature");
          const event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
          return Response.json({ received: true });
        }
        """,
        "app/api/stripe/webhook/route.ts",
    )

    assert "SKY-D282" not in _rule_ids(findings)


def test_nextjs_stripe_webhook_with_instance_verify_is_safe(tmp_path):
    findings = _scan_ts(
        tmp_path,
        """
        import { Webhook } from "svix";

        export async function POST(req: Request) {
          const body = await req.text();
          const sig = req.headers.get("stripe-signature");
          const webhook = new Webhook(process.env.STRIPE_WEBHOOK_SECRET!);
          const event = webhook.verify(body, sig);
          return Response.json({ received: true, event });
        }
        """,
        "app/api/svix/webhook/route.ts",
    )

    assert "SKY-D282" not in _rule_ids(findings)


def test_express_github_webhook_with_hmac_is_safe(tmp_path):
    findings = _scan_ts(
        tmp_path,
        """
        import { createHmac, timingSafeEqual } from "node:crypto";
        import express from "express";

        app.post("/github/webhook", express.raw({ type: "application/json" }), async (req, res) => {
          const signature = req.headers["x-hub-signature-256"];
          const expected = createHmac("sha256", process.env.GITHUB_WEBHOOK_SECRET!).update(req.body).digest("hex");
          if (!timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
            return res.status(401).send("bad");
          }
          return res.json({ ok: true });
        });
        """,
        "src/server.ts",
    )

    assert "SKY-D282" not in _rule_ids(findings)


def test_non_webhook_post_route_is_not_flagged(tmp_path):
    findings = _scan_ts(
        tmp_path,
        """
        export async function POST(req: Request) {
          const payload = await req.json();
          return Response.json(payload);
        }
        """,
        "app/api/users/route.ts",
    )

    assert "SKY-D282" not in _rule_ids(findings)


def test_typescript_many_unverified_webhook_constructors_still_flags(tmp_path):
    constructors = "\n".join(
        f"          const candidate{index} = new Webhook('secret-{index}');"
        for index in range(250)
    )
    findings = _scan_ts(
        tmp_path,
        f"""
        export async function POST(req: Request) {{
          const event = await req.json();
{constructors}
          return Response.json(event);
        }}
        """,
        "app/api/stripe/webhook/route.ts",
    )

    assert "SKY-D282" in _rule_ids(findings)


def test_typescript_test_file_is_not_flagged(tmp_path):
    findings = _scan_ts(
        tmp_path,
        """
        export async function POST(req: Request) {
          const event = await req.json();
          return Response.json(event);
        }
        """,
        "tests/stripe-webhook.test.ts",
    )

    assert "SKY-D282" not in _rule_ids(findings)


def test_webhook_analysis_uses_bounded_patterns_and_flow_budgets():
    python_patterns = [pattern.pattern for pattern in webhook_flow._VERIFY_PATTERNS]

    assert all(".*?" not in pattern for pattern in python_patterns)
    limits = FlowLimits()
    assert limits.max_nodes > 0
    assert limits.max_work_items > limits.max_nodes
    assert limits.max_expr_depth > 0
