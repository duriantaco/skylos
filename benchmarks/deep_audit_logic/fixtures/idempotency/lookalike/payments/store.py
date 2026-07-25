from .models import EventReceipt


def ensure_pending(event_id):
    EventReceipt.objects.get_or_create(
        event_id=event_id,
        defaults={"status": "pending"},
    )


def mark_completed(event_id, capture_id):
    return (
        EventReceipt.objects.filter(event_id=event_id, status="pending").update(
            status="completed",
            provider_capture_id=capture_id,
        )
        == 1
    )
