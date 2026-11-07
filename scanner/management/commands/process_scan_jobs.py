from django.core.management.base import BaseCommand

from scanner.models import ScanJob
from scanner.services.scan_jobs import execute_scan_job


class Command(BaseCommand):
    help = "Process pending security scan jobs once and exit."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=10)

    def handle(self, *args, **options):
        limit = max(1, min(options["limit"], 100))
        job_ids = list(
            ScanJob.objects.filter(status="PENDING")
            .order_by("created_at")
            .values_list("id", flat=True)[:limit]
        )
        if not job_ids:
            self.stdout.write("No pending scan jobs.")
            return
        for job_id in job_ids:
            job = execute_scan_job(job_id)
            self.stdout.write(f"job={job.id} status={job.status} progress={job.progress}%")
        self.stdout.write(self.style.SUCCESS(f"Processed {len(job_ids)} scan job(s)."))
