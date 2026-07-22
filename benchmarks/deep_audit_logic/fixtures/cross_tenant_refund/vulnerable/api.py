from refunds.service import refund_order


def refund_endpoint(actor, order, amount):
    if not actor.tenant_id or not order.tenant_id:
        raise PermissionError("tenant identity required")
    return refund_order(actor, order, amount)
