from .cache import get_invoice


def load_invoice(tenant_id, invoice_id):
    return get_invoice(tenant_id, invoice_id)
