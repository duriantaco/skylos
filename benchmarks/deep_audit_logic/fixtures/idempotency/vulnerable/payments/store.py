from .models import EventReceipt


def event_seen(event_id):
    return EventReceipt.objects.filter(event_id=event_id).exists()


def mark_event_seen(event_id):
    EventReceipt.objects.create(event_id=event_id)
