from __future__ import annotations

import ast
import textwrap

from skylos.rules.danger.danger import scan_file_with_tree
from skylos.visitors.languages.typescript import scan_typescript_file


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

    assert "SKY-D282" in _rule_ids(findings)


def test_nextjs_stripe_webhook_with_construct_event_is_safe(tmp_path):
    findings = _scan_ts(
        tmp_path,
        """
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


def test_express_github_webhook_with_hmac_is_safe(tmp_path):
    findings = _scan_ts(
        tmp_path,
        """
        app.post("/github/webhook", async (req, res) => {
          const signature = req.headers["x-hub-signature-256"];
          const expected = createHmac("sha256", secret).update(req.body).digest("hex");
          if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
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
