from celery import Task


class DemoTask(Task):
    def run(self, value):
        return value


class TaskDraft:
    pass


def queue_payload():
    return None
