import pytest


@pytest.fixture
def api_client():
    return {"base_url": "https://api.internal"}


@pytest.fixture(name="order_payload")
def payload_fixture():
    return {"id": "ord_001"}


def test_create_order(api_client, order_payload):
    assert api_client["base_url"]
    assert order_payload["id"]
