from celery import Task


class DemoTask(Task):
    def run(self, value):
        return value
