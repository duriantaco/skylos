import os

import pytest

os.environ.setdefault("SECRET_KEY", "test-only")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ITEMS_DB", str(tmp_path / "items.db"))
    from app import create_app

    return create_app().test_client()


def test_list_items(client):
    assert len(client.get("/items").get_json()) == 3


def test_owner_can_update(client):
    response = client.put("/items/1", json={"qty": 7}, headers={"X-User": "alice"})
    assert response.get_json()["qty"] == 7


def test_requires_a_user(client):
    assert client.put("/items/1", json={"qty": 7}).status_code == 401
