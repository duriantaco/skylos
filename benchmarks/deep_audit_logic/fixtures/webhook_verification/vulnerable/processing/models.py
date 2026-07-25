from django.db import models


class Account(models.Model):
    provider_subscription_id = models.CharField(max_length=255, unique=True)
    plan = models.CharField(max_length=64)
    plan_version = models.PositiveBigIntegerField(null=True)
