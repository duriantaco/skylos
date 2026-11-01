"""SKY-D251: library results that do not carry the credential they were given.

An HTTP response holds the server's status, headers and body; the request's
URL, headers and body stay reachable through ``.url``, ``.request``,
``.history`` and the response object itself. A signature check or token
decode returns the verified payload, not the signing key. Project helpers,
wrappers and lookalike modules keep every argument's credential.
"""

import json
import textwrap

import pytest

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture


def _d251_lines(tmp_path, monkeypatch, source, listed_only=False):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    write_fixture(tmp_path, "app.py", source)
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="proof"\n')
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
        )
    )
    assert not result.get("analysis_errors")
    return sorted(
        finding["line"]
        for finding in result.get("danger", [])
        if finding["rule_id"] == "SKY-D251"
        and (not listed_only or finding["listing"]["listed"])
    )


def _source(text):
    return textwrap.dedent(text).strip("\n") + "\n"


SERVER_DATA_ONLY = {
    "requests_response_body_and_status": """
        import logging
        import os

        import requests

        logger = logging.getLogger(__name__)
        payload = {"code": "abc", "client_secret": os.environ["GOOGLE_CLIENT_SECRET"]}
        verified = requests.post("https://oauth2.example.test/token", data=payload)
        if verified.status_code != 200:
            logger.error(f"Token request failed: {verified.text}")
            logger.error("Error JSON: %s", verified.json())
        owner = verified.json().get("owner")
        logger.info(f"Owner: {owner}")
    """,
    "httpx_client_with_credential_headers": """
        import logging
        import os

        import httpx

        token = os.getenv("SERVICE_API_TOKEN")
        client = httpx.Client(headers={"Authorization": f"Bearer {token}"})
        response = client.get("https://api.example.test/items")
        logging.info("status %s", response.status_code)
        logging.info("items %s", response.raise_for_status().json())
    """,
    "aiohttp_session_response": """
        import logging
        import os

        import aiohttp

        async def fetch():
            token = os.getenv("SERVICE_API_TOKEN")
            async with aiohttp.ClientSession(headers={"X-Token": token}) as session:
                async with session.get("https://api.example.test/items") as resp:
                    logging.info("status %s %s", resp.status, resp.headers)
    """,
    "stripe_webhook_event_with_configured_module": """
        import logging
        import os

        enabled = os.getenv("BILLING") == "1"
        if enabled:
            import stripe

            stripe.api_key = os.getenv("STRIPE_API_KEY")
        endpoint_secret = os.getenv("STRIPE_SIGNING_SECRET")
        logger = logging.getLogger(__name__)

        def subscribe(payload, sig_header):
            event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
            logger.warning(f"Unhandled Stripe event type: {event['type']}")
            again = stripe.Webhook.construct_event(payload, sig_header, secret=endpoint_secret)
            logger.info("event %s", again["id"])
    """,
    "jwt_claims_and_signature_check": """
        import hmac
        import logging
        import os

        import jwt
        from jose import jws
        from jose import jwt as jose_jwt

        SECRET_KEY = os.environ["JWT_SECRET_KEY"]

        def handle(token, signature, body):
            claims = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            logging.info("user %s", claims["sub"])
            other = jose_jwt.decode(token, key=SECRET_KEY, algorithms=["HS256"])
            logging.info("user %s", other)
            payload = jws.verify(token, SECRET_KEY, algorithms=["HS256"])
            logging.info("payload %s", payload)
            parts = jwt.decode_complete(token, key=SECRET_KEY, algorithms=["HS256"])
            logging.info("header %s", parts["header"])
            valid = hmac.compare_digest(signature, os.getenv("WEBHOOK_SECRET"))
            logging.info("signature valid: %s", valid)
    """,
}


@pytest.mark.parametrize("name", sorted(SERVER_DATA_ONLY))
def test_results_without_the_credential_are_not_reported(tmp_path, monkeypatch, name):
    source = _source(SERVER_DATA_ONLY[name])
    assert _d251_lines(tmp_path, monkeypatch, source) == []


STILL_REPORTED = {
    "response_url_with_token_in_params": """
        import logging
        import os

        import requests

        token = os.getenv("SERVICE_API_TOKEN")
        resp = requests.get("https://api.example.test/items", params={"token": token})
        if resp.ok:
            logging.info("fetched %s", resp.url)
    """,
    "response_request_headers": """
        import logging
        import os

        import requests

        token = os.getenv("SERVICE_API_TOKEN")
        resp = requests.get("https://api.example.test", headers={"Authorization": token})
        logging.debug("sent %s", resp.request.headers)
    """,
    "response_history": """
        import os

        import httpx

        password = os.getenv("SERVICE_PASSWORD")
        resp = httpx.get("https://api.example.test", auth=("svc", password))
        print(resp.history)
    """,
    "whole_response_object": """
        import logging
        import os

        import requests

        token = os.getenv("SERVICE_API_TOKEN")
        resp = requests.get(f"https://api.example.test/?token={token}")
        logging.info("response %s", resp)
    """,
    "raise_for_status_result_url": """
        import os

        import httpx

        token = os.getenv("SERVICE_API_TOKEN")
        client = httpx.Client(params={"token": token})
        print(client.get("https://api.example.test").raise_for_status().url)
    """,
    "client_headers": """
        import logging
        import os

        import httpx

        token = os.getenv("SERVICE_API_TOKEN")
        client = httpx.Client(headers={"Authorization": f"Bearer {token}"})
        logging.info("client headers %s", client.headers)
    """,
    "settings_object_built_from_secret": """
        import os

        from app.config import Settings

        api_key = os.getenv("SERVICE_API_KEY")
        settings = Settings(api_key=api_key)
        print(f"settings: {settings}")
    """,
    "project_helper_returning_secret": """
        import os

        def passthrough(value):
            return value

        token = os.getenv("SERVICE_API_TOKEN")
        print(passthrough(token))
    """,
    "fstring_of_secret": """
        import os

        token = os.getenv("SERVICE_API_TOKEN")
        print(f"token={token}")
    """,
    "project_wrapper_around_requests": """
        import logging
        import os

        import requests

        def post(url, **options):
            return requests.post(url, **options)

        password = os.getenv("SERVICE_PASSWORD")
        reply = post("https://api.example.test", data={"password": password})
        logging.info("reply %s", reply.text)
    """,
    "aliased_request_function": """
        import os

        import requests

        fetch = requests.get
        token = os.getenv("SERVICE_API_TOKEN")
        reply = fetch("https://api.example.test", params={"token": token})
        print(reply.url)
    """,
    "lookalike_requests_module": """
        import logging
        import os

        from vendor import requests

        token = os.getenv("SERVICE_API_TOKEN")
        reply = requests.post("https://api.example.test", data={"token": token})
        logging.info("reply %s", reply.text)
    """,
    "requests_name_rebound_to_a_project_client": """
        import logging
        import os

        import requests

        from app.http import Client

        requests = Client(token=os.getenv("SERVICE_API_TOKEN"))
        reply = requests.post("https://api.example.test")
        logging.info("reply %s", reply.text)
    """,
    "complete_decode_keeps_the_signed_token": """
        import logging
        import os

        import jwt

        token = os.getenv("SERVICE_API_TOKEN")
        parts = jwt.decode_complete(token, "public", algorithms=["HS256"])
        logging.info("token parts %s", parts)
    """,
    "lookalike_decoder": """
        import logging
        import os

        from vendor.tokens import decode

        SECRET_KEY = os.environ["JWT_SECRET_KEY"]
        claims = decode("token", SECRET_KEY)
        logging.info("claims %s", claims)
    """,
    "stripe_webhook_replaced_in_a_function": """
        import logging
        import os

        import stripe

        from app.fakes import FakeWebhook

        def install_fake():
            stripe.Webhook = FakeWebhook

        endpoint_secret = os.getenv("STRIPE_SIGNING_SECRET")
        event = stripe.Webhook.construct_event("{}", "sig", endpoint_secret)
        logging.info("event %s", event)
    """,
    "stripe_secret_through_starred_arguments": """
        import logging
        import os

        import stripe

        parts = ["{}", "sig", os.getenv("STRIPE_SIGNING_SECRET")]
        event = stripe.Webhook.construct_event(*parts)
        logging.info("event %s", event)
    """,
    "stripe_webhook_replaced_through_a_module_alias": """
        import logging
        import os

        import stripe

        from app.fakes import FakeWebhook

        stripe.api_key = os.getenv("STRIPE_API_KEY")
        billing = stripe
        billing.Webhook = FakeWebhook
        endpoint_secret = os.getenv("STRIPE_SIGNING_SECRET")
        event = stripe.Webhook.construct_event("{}", "sig", endpoint_secret)
        logging.info("event %s", event["id"])
    """,
    "default_url_constant_built_from_secret": """
        import logging
        import os

        import requests

        DEFAULT_URL = f"https://api.example.test/items?token={os.environ['API_TOKEN']}"
        resp = requests.get(DEFAULT_URL)
        logging.info("fetched %s", resp.url)
    """,
    "module_constant_token_in_session_headers": """
        import logging
        import os

        import requests

        TOKEN = os.environ["API_TOKEN"]
        DEFAULT_HEADERS = {"Authorization": f"Bearer {TOKEN}"}
        session = requests.Session()
        resp = session.get("https://api.example.test", headers=DEFAULT_HEADERS)
        logging.info("sent %s", resp.request.headers)
    """,
    "constant_named_payload_is_the_secret": """
        import logging
        import os

        import stripe

        SAMPLE_PAYLOAD = os.environ["WEBHOOK_SECRET"]
        event = stripe.Webhook.construct_event(SAMPLE_PAYLOAD, "sig", "whsec_public")
        logging.info("event %s", event)
    """,
    "configured_module_member_itself": """
        import os

        import stripe

        stripe.api_key = os.getenv("STRIPE_API_KEY")
        print(f"using key {stripe.api_key}")
    """,
    "configured_module_namespace": """
        import logging
        import os

        import stripe

        stripe.api_key = os.getenv("STRIPE_API_KEY")
        logging.info("stripe settings %s", vars(stripe))
    """,
}


@pytest.mark.parametrize("name", sorted(STILL_REPORTED))
def test_credential_reachable_from_the_result_still_reports(
    tmp_path, monkeypatch, name
):
    source = _source(STILL_REPORTED[name])
    last_line = source.count("\n")
    assert _d251_lines(tmp_path, monkeypatch, source, listed_only=True) == [last_line]


@pytest.mark.parametrize(
    "module, reported",
    [("import logging", True), ("from vendor import logging", False)],
)
def test_conditionally_imported_output_module_keeps_its_identity(
    tmp_path, monkeypatch, module, reported
):
    source = _source(
        f"""
        import os

        if os.getenv("VERBOSE"):
            {module}
        token = os.getenv("SERVICE_API_TOKEN")
        logging.info("token %s", token)
        """
    )
    expected = []
    if reported:
        expected = [source.count("\n")]
    assert _d251_lines(tmp_path, monkeypatch, source) == expected
