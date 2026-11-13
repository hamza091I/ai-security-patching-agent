from django.core.management.base import BaseCommand

from scanner.services.publish import publish_pending_events


class Command(BaseCommand):
    help = "Publish SARIF, comments and commit statuses for finished repository scans."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=20)
        parser.add_argument("--max-attempts", type=int, default=None)

    def handle(self, *args, **options):
        result = publish_pending_events(limit=options["limit"], max_attempts=options["max_attempts"])
        self.stdout.write(
            f"published={result['published']} waiting={result['waiting']} retry={result['retry']}"
        )
        if not any(result.values()):
            self.stdout.write("No repository results waiting to be published.")
