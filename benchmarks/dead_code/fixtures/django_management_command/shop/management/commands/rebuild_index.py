from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Rebuild the search index."

    def add_arguments(self, parser):
        parser.add_argument("--tenant", default="default")

    def handle(self, *args, **options):
        return rebuild_index(options["tenant"])


def rebuild_index(tenant):
    return f"indexed:{tenant}"


def unused_export_job():
    return "stale"


class UnusedCommandHelper:
    def build(self):
        return "unused"
