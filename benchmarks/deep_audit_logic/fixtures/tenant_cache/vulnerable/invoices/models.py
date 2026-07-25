from django.db import models


class Invoice(models.Model):
    tenant_id = models.CharField(max_length=255)
    invoice_number = models.CharField(max_length=255)
    total = models.DecimalField(max_digits=12, decimal_places=2)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tenant_id", "invoice_number"],
                name="unique_invoice_number_per_tenant",
            )
        ]
