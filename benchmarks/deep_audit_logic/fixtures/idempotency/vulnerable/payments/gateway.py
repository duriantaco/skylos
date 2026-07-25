from .models import ProviderCapture


def capture(payment_id, amount):
    return ProviderCapture.objects.create(payment_id=payment_id, amount=amount)
