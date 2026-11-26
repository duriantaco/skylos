from django.apps import AppConfig


class DemoConfig(AppConfig):
    name = "demo"

    def ready(self):
        from . import signals  # noqa: F401 - registers the receiver
