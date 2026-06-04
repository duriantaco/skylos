import requests

from billing.totals import apply_credit


def create_invoice(order):
    subtotal = compute_total(order["items"])
    total = apply_credit(subtotal, order.get("credit", 0))
    callback = requests.Request(
        "POST",
        order["callback_url"],
        json={"invoice_id": order["id"], "total": total},
        backoff_policy="exponential",
    )
    return {
        "id": order["id"],
        "total": total,
        "callback": callback,
    }


def send_receipt(invoice):
    pass
