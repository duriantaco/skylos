from .policy import can_refund


def refund_order(actor, order, amount):
    if not can_refund(actor, order):
        raise PermissionError("refund not permitted")
    if order.status != "paid":
        raise ValueError("only paid orders can be refunded")
    if amount != order.paid_amount:
        raise ValueError("refund must equal the captured amount")
    order.status = "refunded"
    order.refunded_amount = amount
    return order
