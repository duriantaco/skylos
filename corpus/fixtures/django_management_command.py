from django.core.management.base import BaseCommand


class Command(BaseCommand):
    def handle(self, *args, **options):
        return None


class CommandPreview:
    pass


def parse_command():
    return "preview"
