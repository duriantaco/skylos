from .models import EventReceipt


def claim_once(event_id):
    _receipt, created = EventReceipt.objects.get_or_create(event_id=event_id)
    return created
