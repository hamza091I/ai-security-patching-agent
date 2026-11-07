from django.conf import settings
from django.core.management.base import BaseCommand

from scanner.models import ScanJob
from scanner.services.scan_jobs import execute_scan_job, recover_stale_jobs, requeue_failed_jobs


class Command(BaseCommand):
    help = "Recover stale jobs, optionally retry failures, then process pending scan jobs once."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=10)
        parser.add_argument("--retry-failed", action="store_true", help="Requeue failed jobs with remaining retry budget.")
        parser.add_argument("--recover-stale", action="store_true", help="Recover RUNNING jobs with an expired heartbeat.")
        parser.add_argument("--stale-after", type=int, default=None, help="Override stale heartbeat age in seconds.")

    def handle(self, *args, **options):
        limit = max(1, min(options["limit"], 100))
        recovered = recover_stale_jobs(options["stale_after"]) if options["recover_stale"] else 0
        retried = requeue_failed_jobs(limit) if options["retry_failed"] else 0
        job_ids = list(
            ScanJob.objects.filter(status="PENDING")
            .order_by("created_at")
            .values_list("id", flat=True)[:limit]
        )
        self.stdout.write(
            f"recovered={recovered} retried={retried} timeout={settings.SCAN_JOB_TIMEOUT_SECONDS}s"
        )
        if not job_ids:
            self.stdout.write("No pending scan jobs.")
            return
        for job_id in job_ids:
            job = execute_scan_job(job_id)
            self.stdout.write(f"job={job.id} status={job.status} progress={job.progress}% retries={job.retry_count}")
        self.stdout.write(self.style.SUCCESS(f"Processed {len(job_ids)} scan job(s)."))
