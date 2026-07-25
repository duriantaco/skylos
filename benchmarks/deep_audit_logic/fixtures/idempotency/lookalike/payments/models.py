from django.db import models


class EventReceipt(models.Model):
    event_id = models.CharField(max_length=255, unique=True)
    status = models.CharField(max_length=16)
    provider_capture_id = models.CharField(max_length=255, null=True)


class ProviderCapture(models.Model):
    idempotency_key = models.CharField(max_length=255, unique=True)
    payment_id = models.CharField(max_length=255, unique=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
