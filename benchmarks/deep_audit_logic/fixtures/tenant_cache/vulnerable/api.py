from invoices.service import load_invoice


def invoice_endpoint(actor, invoice_id):
    if not actor.is_authenticated:
        raise PermissionError("authentication required")
    return load_invoice(actor.tenant_id, invoice_id)
