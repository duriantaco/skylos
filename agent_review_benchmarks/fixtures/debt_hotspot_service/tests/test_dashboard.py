from app import handle_dashboard


def test_dashboard_happy_path():
    result = handle_dashboard({"id": "u1", "balance": 5, "status": "active"})
    assert result["summary"]["status"] == "active"
