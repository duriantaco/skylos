from app import handle_status


def test_status_handler():
    result = handle_status({"X-Request-ID": " abc "})
    assert result["status"] == "ok"
    assert result["headers"]["x-request-id"] == "abc"
