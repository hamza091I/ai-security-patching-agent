from django.db import transaction
from django.utils import timezone

from scanner.analysis.security_scanner import full_security_scan
from scanner.core.patcher import propose_patch
from scanner.models import AuditLog, CodeScan, ScanJob, VulnerabilityReport


ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


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
    for finding in findings:
        severity = str(finding.get("severity", "medium")).upper()
        if severity not in ALLOWED_SEVERITIES:
            severity = "LOW"
        VulnerabilityReport.objects.create(
            scan=scan,
            cwe_id=finding.get("cwe_id", "UNKNOWN"),
            vulnerability_type=finding.get("type", "Security Issue"),
            severity=severity,
            line_number=finding.get("line_start", 0),
            description=finding.get("message", ""),
            recommendation=finding.get("recommendation", ""),
        )
    return scan


def execute_scan_job(job_id):
    """Run one durable job. Returns the fresh job and never runs a terminal job twice."""
    with transaction.atomic():
        job = ScanJob.objects.select_for_update().select_related("organization", "project", "requested_by").get(pk=job_id)
        if job.status != "PENDING":
            return job
        job.status = "RUNNING"
        job.progress = 10
        job.started_at = timezone.now()
        job.save(update_fields=["status", "progress", "started_at"])

    try:
        result = full_security_scan(code=job.source_code, filename=job.filename, engines=job.engines or None)
        findings = result.get("all_findings", [])
        syntax_findings = [finding for finding in findings if finding.get("cwe_id") == "SYNTAX"]
        if syntax_findings:
            raise ValueError(syntax_findings[0].get("message", "The submitted code contains a syntax error."))

        ScanJob.objects.filter(pk=job_id).update(progress=60)
        patch = propose_patch(job.source_code, job.filename)
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
        }
        ScanJob.objects.filter(pk=job_id).update(
            status="SUCCEEDED",
            progress=100,
            result=payload,
            completed_at=timezone.now(),
        )
        AuditLog.objects.create(
            organization=job.organization,
            actor=job.requested_by,
            action="scan_job.succeeded",
            metadata={"job_id": job.id, "scan_id": scan.id, "finding_count": len(findings)},
        )
    except Exception as exc:
        ScanJob.objects.filter(pk=job_id).update(
            status="FAILED",
            progress=100,
            error_message=f"{type(exc).__name__}: {exc}",
            completed_at=timezone.now(),
        )
        AuditLog.objects.create(
            organization=job.organization,
            actor=job.requested_by,
            action="scan_job.failed",
            metadata={"job_id": job.id, "error_type": type(exc).__name__},
        )

    return ScanJob.objects.get(pk=job_id)
