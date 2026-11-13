"""Publish completed repository scans back to GitHub or GitLab.

The worker scans every supported source file as its own durable ``ScanJob``.
Once all jobs for a repository event are terminal this module aggregates the
findings, builds a SARIF 2.1.0 document, comments on the pull/merge request
(or the commit for a plain push), and posts a commit status. The commit status
is the merge gate: when a CRITICAL/HIGH finding exists the status is
``failure`` and branch protection can require that check before merging.
"""

from django.conf import settings
from django.utils import timezone

from scanner.models import AuditLog, RepositoryEvent
from scanner.services.provider_actions import ProviderActions
from scanner.services.provider_clients import ProviderClient, ProviderError, normalize_ref
from scanner.services.token_crypto import decrypt_token

SEVERITY_LEVELS = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
STATUS_CONTEXT = "ai-security-patching-agent/security"
TERMINAL_STATUSES = {"SUCCEEDED", "FAILED", "CANCELLED"}


def client_for(integration):
    from scanner.services.provider_oauth import OAuthError, refresh_integration_token

    try:
        refresh_integration_token(integration)
    except OAuthError as exc:
        raise ProviderError(str(exc)) from exc
    return ProviderClient(
        integration.provider,
        decrypt_token(integration.access_token_encrypted),
        timeout=settings.PROVIDER_HTTP_TIMEOUT_SECONDS,
    )


def repository_path(name):
    """Make an archive path repository-relative.

    GitHub zipballs and GitLab archives wrap every file in a top-level folder
    such as ``owner-repo-sha123/src/app.py``. SARIF consumers expect the path
    that exists in the repository, so the wrapper is removed.
    """
    parts = (name or "").replace("\\", "/").split("/")
    if len(parts) > 1:
        return "/".join(parts[1:])
    return name or "unknown"


def collect_findings(jobs):
    findings = []
    for job in jobs:
        result = job.result or {}
        for finding in result.get("vulnerabilities", []) or []:
            item = dict(finding)
            item["file"] = repository_path(job.filename)
            item["severity"] = str(item.get("severity", "LOW")).upper()
            if item["severity"] not in SEVERITY_RANK:
                item["severity"] = "LOW"
            item["line_start"] = item.get("line_start") or 1
            findings.append(item)
    findings.sort(key=lambda item: (-SEVERITY_RANK.get(item["severity"], 0), item["file"], item.get("line_start", 1)))
    return findings


def summarize_findings(findings, jobs=None, failed_jobs=0):
    counts = {severity: 0 for severity in SEVERITY_RANK}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    blocking = [finding for finding in findings if finding["severity"] in settings.MERGE_BLOCK_SEVERITIES]
    return {
        "total": len(findings),
        "severity_counts": counts,
        "blocking": len(blocking),
        "files_scanned": len(jobs) if jobs is not None else 0,
        "failed_jobs": failed_jobs,
        "passed": not blocking and not failed_jobs,
    }


def build_sarif(findings, tool_name="AI Security Patching Agent"):
    rules = {}
    results = []
    for finding in findings:
        rule_id = str(finding.get("rule_id") or finding.get("cwe_id") or "security-rule")
        cwe_id = str(finding.get("cwe_id") or "")
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": str(finding.get("type") or rule_id),
            "shortDescription": {"text": str(finding.get("type") or rule_id)},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[-1]}.html" if cwe_id.startswith("CWE-") else "",
            "properties": {"tags": [tag for tag in ("security", cwe_id) if tag]},
        })
        region = {"startLine": int(finding.get("line_start") or 1)}
        if finding.get("line_end"):
            region["endLine"] = int(finding["line_end"])
        results.append({
            "ruleId": rule_id,
            "level": SEVERITY_LEVELS.get(finding["severity"], "warning"),
            "message": {"text": str(finding.get("message") or "Security issue detected.")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding["file"]},
                    "region": region,
                }
            }],
            "properties": {
                "severity": finding["severity"],
                "confidence": finding.get("confidence"),
                "engine": finding.get("engine"),
                "cwe": cwe_id,
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "informationUri": "https://github.com/hamza091I/ai-security-patching-agent",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def build_comment(event, summary, findings, dashboard_url=""):
    icon = "✅" if summary["passed"] else "❌"
    verdict = "passed — no blocking findings" if summary["passed"] else "blocked — critical or high severity findings detected"
    if summary["failed_jobs"]:
        verdict = "incomplete — one or more files could not be scanned"
    lines = [
        f"## {icon} AI Security Patching Agent — {verdict}",
        "",
        f"**Event:** {event.event_type} · **Ref:** `{normalize_ref(event.ref) or 'unknown'}`"
        + (f" · **Commit:** `{event.commit_sha[:12]}`" if event.commit_sha else ""),
        f"**Files scanned:** {summary['files_scanned']} · **Findings:** {summary['total']}"
        f" · **Blocking:** {summary['blocking']}",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"| {severity.title()} | {summary['severity_counts'].get(severity, 0)} |")
    if findings:
        lines += ["", "<details><summary>Top findings</summary>", "", "| File | Line | Rule | Severity |", "| --- | --- | --- | --- |"]
        for finding in findings[:10]:
            lines.append(
                f"| `{finding['file']}` | {finding['line_start']} | {finding.get('cwe_id') or finding.get('rule_id') or 'security'} | {finding['severity']} |"
            )
        if len(findings) > 10:
            lines.append(f"| … | | {len(findings) - 10} more finding(s) | |")
        lines += ["", "</details>"]
    if not summary["passed"]:
        lines += [
            "",
            f"The `{STATUS_CONTEXT}` commit status is failing. Add it as a required status check "
            "in branch protection to block merging until the findings are fixed.",
        ]
    if dashboard_url:
        lines += ["", f"[Open the Sentinel AI dashboard]({dashboard_url})"]
    lines += ["", "_This comment is generated automatically. Patches are proposals that require human review._"]
    return "\n".join(lines)


def _pull_request_number(event):
    payload = event.payload or {}
    if event.integration.provider == "GITHUB":
        pull_request = payload.get("pull_request") or {}
        number = pull_request.get("number") or payload.get("number")
    else:
        attributes = payload.get("object_attributes") or {}
        number = attributes.get("iid")
    try:
        return int(number) if number else None
    except (TypeError, ValueError):
        return None


def _dashboard_url(integration):
    if not settings.PUBLIC_BASE_URL:
        return ""
    return f"{settings.PUBLIC_BASE_URL}/"


def publish_event(event, force=False):
    """Publish one repository event. Safe to call repeatedly."""
    if event.published_at and not force:
        return {"status": "already_published", "published_at": event.published_at.isoformat()}
    if not settings.PROVIDER_PUBLISH_ENABLED and not force:
        return {"status": "disabled"}
    jobs = list(event.scan_jobs.all())
    pending = [job for job in jobs if job.status not in TERMINAL_STATUSES]
    if pending:
        return {"status": "waiting", "pending": len(pending)}
    integration = event.integration
    if integration.status != "ACTIVE":
        return {"status": "skipped", "reason": "integration_not_active"}
    failed_jobs = [job for job in jobs if job.status == "FAILED"]
    findings = collect_findings(jobs)
    summary = summarize_findings(findings, jobs, len(failed_jobs))
    result = {
        "status": "published",
        "verdict": "passed" if summary["passed"] else "blocked",
        "summary": summary,
        "sarif": None,
        "comment": None,
        "status_check": None,
        "errors": [],
    }
    ref = normalize_ref(event.ref) or integration.default_branch
    commit_sha = event.commit_sha or next((job.commit_sha for job in jobs if job.commit_sha), "")
    body = build_comment(event, summary, findings, _dashboard_url(integration))

    try:
        actions = ProviderActions(client_for(integration))
    except ProviderError as exc:
        result["errors"].append(f"client: {exc}")
        actions = None

    if actions is not None:
        if commit_sha and settings.PROVIDER_SARIF_UPLOAD:
            try:
                result["sarif"] = actions.upload_sarif(
                    integration.repository_url, commit_sha, ref, build_sarif(findings)
                )
            except (ProviderError, ValueError) as exc:
                result["errors"].append(f"sarif: {exc}")
        try:
            number = _pull_request_number(event)
            if not number and event.event_type in {"PUSH", "SYNC"}:
                found = actions.client.find_open_pull_request(integration.repository_url, ref)
                number = found.get("number") if found else None
            if number:
                actions.comment(integration.repository_url, number, body)
                result["comment"] = {"target": "pull_request", "number": number}
            elif commit_sha:
                actions.comment_on_commit(integration.repository_url, commit_sha, body)
                result["comment"] = {"target": "commit", "sha": commit_sha}
            else:
                result["comment"] = {"target": "none", "reason": "no pull request or commit to comment on"}
        except (ProviderError, ValueError) as exc:
            result["errors"].append(f"comment: {exc}")
        if commit_sha:
            try:
                description = (
                    f"{summary['blocking']} blocking finding(s) in {summary['files_scanned']} file(s)"
                    if not summary["passed"]
                    else f"No blocking findings in {summary['files_scanned']} file(s)"
                )
                result["status_check"] = actions.set_security_status(
                    integration.repository_url, commit_sha, ref, summary["passed"], description, _dashboard_url(integration)
                )
            except (ProviderError, ValueError) as exc:
                result["errors"].append(f"status: {exc}")

    event.publish_attempts += 1
    event.publish_result = result
    if result["errors"]:
        result["status"] = "retry"
        event.save(update_fields=["publish_attempts", "publish_result"])
    else:
        event.status = "PUBLISHED"
        event.published_at = timezone.now()
        event.save(update_fields=["publish_attempts", "publish_result", "status", "published_at"])
    AuditLog.objects.create(
        organization=integration.organization,
        action="repository_event.published",
        metadata={
            "integration_id": integration.id,
            "event_id": event.id,
            "verdict": result["verdict"],
            "findings": summary["total"],
            "blocking": summary["blocking"],
            "errors": len(result["errors"]),
        },
    )
    return result


def publish_pending_events(limit=20, max_attempts=None):
    """Publish processed events whose scan jobs are finished."""
    max_attempts = max_attempts or settings.PROVIDER_MAX_PUBLISH_ATTEMPTS
    events = (
        RepositoryEvent.objects.filter(status="PROCESSED", publish_attempts__lt=max_attempts)
        .select_related("integration")
        .order_by("created_at")[: max(1, min(limit, 100))]
    )
    published = waiting = retry = 0
    for event in events:
        result = publish_event(event)
        if result.get("status") == "published":
            published += 1
        elif result.get("status") == "waiting":
            waiting += 1
        elif result.get("status") == "retry":
            retry += 1
    return {"published": published, "waiting": waiting, "retry": retry}
