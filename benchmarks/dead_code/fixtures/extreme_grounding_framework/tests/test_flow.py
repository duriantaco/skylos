from api import dispatch_http
from cli import dispatch_job


def test_http_search_reaches_repository():
    result = dispatch_http({"query": {"email": "a@example.com"}})
    assert result == []


def test_registered_hook_is_list_based():
    assert dispatch_job({"source": "cli", "job": "registered", "name": "version"})
