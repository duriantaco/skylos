from django.db import transaction

from .models import Account


PLAN_BY_PRICE_ID = {"price_basic": "basic", "price_pro": "pro"}


@transaction.atomic
def apply_event(event):
    version = event["version"]
    if type(version) is not int or version < 0:
        raise ValueError("invalid provider version")
    try:
        plan = PLAN_BY_PRICE_ID[event["price_id"]]
    except KeyError as exc:
        raise ValueError("unknown provider price") from exc
    account = Account.objects.select_for_update().get(
        provider_subscription_id=event["subscription_id"]
    )
    if account.plan_version is not None and version <= account.plan_version:
        return "already_applied"
    account.plan = plan
    account.plan_version = version
    account.save(update_fields=["plan", "plan_version"])
    return "applied"
