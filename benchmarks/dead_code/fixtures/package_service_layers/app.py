from service import create_invoice


def run_checkout():
    return create_invoice({"id": "inv_001", "total": 42})


RESULT = run_checkout()
