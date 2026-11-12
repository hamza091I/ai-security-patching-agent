from django.core.management.base import BaseCommand
from django.db import transaction

from scanner.models import RepositoryEvent
from scanner.services.token_crypto import decrypt_token
from scanner.views import enqueue_remote_scan
from scanner.services.provider_clients import ProviderError


class Command(BaseCommand):
    help = "Fetch queued repository webhook commits and create durable ScanJobs."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=20)

    def handle(self, *args, **options):
        events = RepositoryEvent.objects.filter(status="QUEUED").select_related("integration", "integration__project").order_by("created_at")[:options["limit"]]
        processed = failed = 0
        for event in events:
            integration = event.integration
            try:
                if not decrypt_token(integration.access_token_encrypted):
                    raise ProviderError("Integration has no provider access token.")
                with transaction.atomic():
                    jobs = enqueue_remote_scan(integration, event.ref or integration.default_branch)
                    event.status = "PROCESSED"
                    event.save(update_fields=["status"])
                processed += 1
                self.stdout.write(f"event={event.id} jobs={len(jobs)} status=PROCESSED")
            except (ProviderError, OSError, ValueError) as exc:
                event.status = "INVALID"
                event.payload = {"error": str(exc), "original": event.payload}
                event.save(update_fields=["status", "payload"])
                failed += 1
                self.stderr.write(f"event={event.id} status=INVALID error={type(exc).__name__}")
        self.stdout.write(f"Processed repository events: {processed}; failed: {failed}")
