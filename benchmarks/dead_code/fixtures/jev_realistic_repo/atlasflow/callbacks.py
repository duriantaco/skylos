def record_latency(context):
    context["trace"].append("latency")


def emit_signal(context):
    context["trace"].append("signal")


def record_start(context):
    context["trace"].append("start")


def trace_finish(context):
    context["trace"].append("finish")


def audit_before(context):
    context["trace"].append("audit")


def stamp_batch(context):
    context["trace"].append("batch")


def mark_queue(context):
    context["trace"].append("queue")


def mark_success(context):
    context["trace"].append("success")


def note_accept(context):
    context["trace"].append("accept")


def trace_step(context):
    context["trace"].append("step")


def stamp_result(context):
    context["trace"].append("result")


def send_notice(context):
    context["trace"].append("notice")
