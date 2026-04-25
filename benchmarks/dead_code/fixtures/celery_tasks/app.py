from celery import Celery, shared_task


celery_app = Celery("billing")


@celery_app.task(name="billing.send_receipt")
def send_receipt(invoice_id):
    return {"sent": invoice_id}


@shared_task
def rebuild_rollups():
    return "rebuilt"


def unused_task_helper():
    return "not scheduled"


class UnusedTaskPayload:
    def serialize(self):
        return {}
