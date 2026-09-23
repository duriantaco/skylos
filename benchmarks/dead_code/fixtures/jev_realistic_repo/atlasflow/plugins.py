def receipt_adapter(context):
    context["trace"].append("receipt")


def event_adapter(context):
    context["trace"].append("event")


def catalog_adapter(context):
    context["trace"].append("catalog")


def ledger_adapter(context):
    context["trace"].append("ledger")


def storage_adapter(context):
    context["trace"].append("storage")


def audit_adapter(context):
    context["trace"].append("audit")


def invoice_adapter(context):
    context["trace"].append("invoice")


def search_adapter(context):
    context["trace"].append("search")
