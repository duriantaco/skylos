from .backend import get_or_set
from .database import fetch_invoice


def get_invoice(tenant_id, invoice_id):
    key = invoice_id
    return get_or_set(key, lambda: fetch_invoice(tenant_id, invoice_id))
