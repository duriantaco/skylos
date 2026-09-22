def validate_records(context):
    context["trace"].append("validate")


def rotate_indexes(context):
    context["trace"].append("rotate")


def publish_snapshot(context):
    context["trace"].append("publish")


def fetch_batches(context):
    context["trace"].append("fetch")


def collect_invoices(context):
    context["trace"].append("invoices")


def normalize_rows(context):
    context["trace"].append("normalize")


def prune_sessions(context):
    context["trace"].append("prune")


def merge_catalog(context):
    context["trace"].append("merge")


def reshape_events(context):
    context["trace"].append("reshape")


def compress_payloads(context):
    context["trace"].append("compress")


def render_receipts(context):
    context["trace"].append("render")


def flush_metrics(context):
    context["trace"].append("metrics")
