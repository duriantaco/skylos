from django.db import models


class EventReceipt(models.Model):
    event_id = models.CharField(max_length=255, unique=True)


class ProviderCapture(models.Model):
    payment_id = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
