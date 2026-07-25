from .models import ProviderCapture


def capture_once(event_id, payment_id, amount):
    capture, created = ProviderCapture.objects.get_or_create(
        payment_id=payment_id,
        defaults={"idempotency_key": event_id, "amount": amount},
    )
    if not created and capture.amount != amount:
        raise ValueError("idempotency key reused with different payment data")
    return capture
