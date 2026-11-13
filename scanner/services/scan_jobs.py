import logging
import time

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from scanner.analysis.security_scanner import full_security_scan
from scanner.core.patcher import propose_patch
from scanner.models import AuditLog, CodeScan, ScanJob, VulnerabilityReport
from scanner.services.publish import publish_event


ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
logger = logging.getLogger("security_platform")


def _persist_scan(job, patched_code, findings):
    scan = CodeScan.objects.create(
        user=job.requested_by,
        organization=job.organization,
        project=job.project,
        original_code=job.source_code,
        patched_code=patched_code,
        status="SUCCESS",
        is_vulnerable=bool(findings),
    )
    VulnerabilityReport.objects.bulk_create([
        VulnerabilityReport(
            scan=scan,
            cwe_id=finding.get("cwe_id", "UNKNOWN"),
            vulnerability_type=finding.get("type", "Security Issue"),
            severity=(str(finding.get("severity", "medium")).upper()
                      if str(finding.get("severity", "medium")).upper() in ALLOWED_SEVERITIES else "LOW"),
            line_number=finding.get("line_start", 0),
            description=finding.get("message", ""),
            recommendation=finding.get("recommendation", ""),
        )
        for finding in findings
    ])
    return scan


def _audit(job, action, metadata=None):
    AuditLog.objects.create(
        organization=job.organization,
        actor=job.requested_by,
        action=action,
        metadata={"job_id": job.id, **(metadata or {})},
    )


def recover_stale_jobs(stale_after_seconds=None):
    """Move abandoned RUNNING jobs back to PENDING or FAILED.

    A job is only requeued while it still has retry budget. This makes worker
    crashes recoverable without allowing an infinite retry loop.
    """
    stale_after = stale_after_seconds or settings.SCAN_JOB_STALE_SECONDS
    cutoff = timezone.now() - timezone.timedelta(seconds=stale_after)
    recovered = 0
    for job in ScanJob.objects.select_related("organization", "requested_by").filter(
        status="RUNNING", heartbeat_at__lt=cutoff
    ):
        if job.retry_count < job.max_retries:
            job.retry_count += 1
            job.status = "PENDING"
            job.progress = 0
            job.error_message = "Worker heartbeat expired; job returned to the queue."
            job.started_at = None
            job.heartbeat_at = None
            job.save(update_fields=["retry_count", "status", "progress", "error_message", "started_at", "heartbeat_at"])
            _audit(job, "scan_job.recovered", {"retry_count": job.retry_count})
        else:
            job.status = "FAILED"
            job.error_message = "Worker heartbeat expired and retry budget was exhausted."
            job.completed_at = timezone.now()
            job.save(update_fields=["status", "error_message", "completed_at"])
            _audit(job, "scan_job.failed", {"reason": "stale_job_retry_exhausted"})
        recovered += 1
    return recovered


def requeue_failed_jobs(limit=10):
    """Requeue failed jobs that still have retry budget."""
    jobs = ScanJob.objects.filter(status="FAILED", retry_count__lt=settings.SCAN_JOB_MAX_RETRIES).order_by("created_at")[:max(1, min(limit, 100))]
    count = 0
    for job in jobs:
        job.status = "PENDING"
        job.progress = 0
        job.error_message = "Queued for retry by worker policy."
        job.completed_at = None
        job.heartbeat_at = None
        job.max_retries = settings.SCAN_JOB_MAX_RETRIES
        job.save(update_fields=["status", "progress", "error_message", "completed_at", "heartbeat_at", "max_retries"])
        _audit(job, "scan_job.retry_queued", {"retry_count": job.retry_count})
        count += 1
    return count


def execute_scan_job(job_id):
    """Run one durable job and enforce a post-execution timeout guard."""
    with transaction.atomic():
        job = ScanJob.objects.select_for_update().select_related("organization", "project", "requested_by").get(pk=job_id)
        if job.status != "PENDING":
            return job
        now = timezone.now()
        job.status = "RUNNING"
        job.progress = 10
        job.started_at = now
        job.heartbeat_at = now
        job.timeout_seconds = job.timeout_seconds or settings.SCAN_JOB_TIMEOUT_SECONDS
        job.save(update_fields=["status", "progress", "started_at", "heartbeat_at", "timeout_seconds"])

    started = time.monotonic()
    try:
        result = full_security_scan(code=job.source_code, filename=job.filename, engines=job.engines or None)
        elapsed = time.monotonic() - started
        if elapsed > job.timeout_seconds:
            raise TimeoutError(f"Scan exceeded the {job.timeout_seconds}s execution limit.")
        findings = result.get("all_findings", [])
        syntax_findings = [finding for finding in findings if finding.get("cwe_id") == "SYNTAX"]
        if syntax_findings:
            raise ValueError(syntax_findings[0].get("message", "The submitted code contains a syntax error."))

        ScanJob.objects.filter(pk=job_id).update(progress=60, heartbeat_at=timezone.now())
        patch = propose_patch(job.source_code, job.filename)
        elapsed = time.monotonic() - started
        if elapsed > job.timeout_seconds:
            raise TimeoutError(f"Scan exceeded the {job.timeout_seconds}s execution limit.")
        scan = _persist_scan(job, patch["patched_code"], findings)
        payload = {
            "scan_id": scan.id,
            "language": result.get("language"),
            "is_vulnerable": bool(findings),
            "findings_count": len(findings),
            "vulnerabilities": findings,
            "engines": {
                "ast": result.get("ast_findings", []),
                "bandit": result.get("bandit_findings", []),
                "javascript": result.get("javascript_findings", []),
            },
            "patched_code": patch["patched_code"],
            "patch": patch,
            "duration_seconds": round(elapsed, 3),
        }
        ScanJob.objects.filter(pk=job_id).update(status="SUCCEEDED", progress=100, result=payload, completed_at=timezone.now(), heartbeat_at=timezone.now())
        _audit(job, "scan_job.succeeded", {"scan_id": scan.id, "finding_count": len(findings), "duration_seconds": round(elapsed, 3)})
    except Exception as exc:
        ScanJob.objects.filter(pk=job_id).update(status="FAILED", progress=100, error_message=f"{type(exc).__name__}: {exc}", completed_at=timezone.now(), heartbeat_at=timezone.now())
        _audit(job, "scan_job.failed", {"error_type": type(exc).__name__})

    job = ScanJob.objects.get(pk=job_id)
    if job.repository_event_id:
        # Best effort: a provider outage must never lose a finished scan. The
        # publish worker retries events whose feedback could not be delivered.
        try:
            publish_event(job.repository_event)
        except Exception:  # pragma: no cover - defensive, provider network boundary
            logger.exception("repository_event_publish_failed", extra={"job_id": job.id})
    return job
