from .models import Invoice


def fetch_invoice(tenant_id, invoice_id):
    return Invoice.objects.get(tenant_id=tenant_id, invoice_number=invoice_id)
