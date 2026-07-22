def can_refund(actor, order):
    return (
        actor.is_authenticated
        and actor.role == "support"
        and actor.tenant_id == order.tenant_id
    )
