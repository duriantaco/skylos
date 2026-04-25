class InvoiceRepository:
    def save(self, invoice_id, status):
        return {"id": invoice_id, "status": status}
