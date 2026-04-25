import json
import uuid

from repository import InvoiceRepository


ACTIVE_STATUS = "active"
UNUSED_STATUS = "archived"


class UnusedStrategy:
    def apply(self, payload):
        return payload


def create_invoice(payload):
    repository = InvoiceRepository()
    generated = uuid.uuid4().hex
    invoice_id = payload.get("id") or generated
    return repository.save(invoice_id, ACTIVE_STATUS)


def _unused_reconcile(batch):
    return [item["id"] for item in batch]
