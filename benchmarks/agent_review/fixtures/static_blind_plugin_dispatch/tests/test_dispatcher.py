from dispatcher import dispatch_event


def test_pay_handler_dispatches_by_registry_string():
    assert dispatch_event({"type": "pay", "payload": {"customer": "a@example.com"}}) == []
