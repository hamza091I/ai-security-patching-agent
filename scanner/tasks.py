"""Optional Celery adapter; local management commands remain the zero-dependency fallback."""
try:
    from celery import shared_task
except ImportError:  # pragma: no cover
    def shared_task(function=None, **kwargs):
        return function if function else (lambda fn: fn)

from scanner.services.publish import publish_pending_events
from scanner.services.scan_jobs import execute_scan_job, recover_stale_jobs
from scanner.models import ScanJob


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def process_scan_job_task(self, job_id):
    return execute_scan_job(job_id).status


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def publish_repository_results_task(self):
    return publish_pending_events()


@shared_task
def recover_stale_scan_jobs_task():
    return recover_stale_jobs()
