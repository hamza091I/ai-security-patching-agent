import time
import json
import csv
import hashlib
import os
import io
from pathlib import Path

from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.utils.text import slugify
from django.core import signing

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated

from scanner.analysis.security_scanner import full_security_scan
from scanner.core.patcher import propose_patch
from .models import APIKey, AuditLog, CodeScan, Membership, Organization, Project, RepositoryIntegration, ScanJob, VulnerabilityReport
from scanner.services.integrations import create_integration_project, hash_secret, ingest_webhook
from scanner.services.provider_clients import ProviderClient, ProviderError, extract_source_files
from scanner.services.provider_oauth import build_authorization_url, exchange_code, new_state
from scanner.services.token_crypto import decrypt_token


def health_view(request):
    return JsonResponse({"status": "ok", "service": "ai-security-patching-agent"})


def readiness_view(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        return JsonResponse({"status": "ready", "database": "ok"})
    except Exception as exc:
        return JsonResponse({"status": "not_ready", "database": "error", "detail": type(exc).__name__}, status=503)


def metrics_view(request):
    if not request.user.is_authenticated:
        return JsonResponse({"detail": "Authentication required."}, status=401)
    return JsonResponse({
        "status": "ok",
        "scans_total": CodeScan.objects.filter(user=request.user).count(),
        "open_findings": VulnerabilityReport.objects.filter(scan__user=request.user, status="OPEN").count(),
    })


@login_required(login_url="/login/")
def home_view(request):
    return render(request, "scanner/index.html")


def _save_scan(user, code, patched, findings, project=None):
    membership = Membership.objects.filter(user=user).select_related("organization").first()
    scan = CodeScan.objects.create(
        user=user,
        organization=membership.organization if membership else None,
        project=project,
        original_code=code,
        patched_code=patched,
        status="SUCCESS",
        is_vulnerable=bool(findings),
    )

    for finding in findings:
        severity = finding.get("severity", "medium").upper()

        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
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

    if membership:
        AuditLog.objects.create(
            organization=membership.organization,
            actor=user,
            action="scan.completed",
            metadata={"scan_id": scan.id, "finding_count": len(findings), "project_id": project.id if project else None},
        )

    return scan


def summarize_findings(findings, duration_ms=None):
    """Build a stable summary for the dashboard and API clients."""
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    languages = set()
    engines = set()

    for finding in findings:
        severity = str(finding.get("severity", "low")).lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
        if finding.get("language"):
            languages.add(str(finding["language"]))
        if finding.get("engine"):
            engines.add(str(finding["engine"]))

    summary = {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "languages": sorted(languages),
        "engines": sorted(engines),
    }
    if duration_ms is not None:
        summary["duration_ms"] = duration_ms
    return summary


class ScanCodeAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        started_at = time.perf_counter()
        try:
            code = request.data.get("code", "") or request.POST.get("code", "")
            filename = request.data.get("filename", "sample.py")
            engines = request.data.get("engines")
            project = None
            project_id = request.data.get("project_id")
            if project_id:
                membership = Membership.objects.filter(user=request.user).select_related("organization").first()
                if not membership:
                    return Response({"status": "error", "message": "Create or join a workspace first."}, status=403)
                project = Project.objects.filter(id=project_id, organization=membership.organization).first()
                if not project:
                    return Response({"status": "error", "message": "Project not found in your workspace."}, status=404)

            if not isinstance(code, str) or not code.strip():
                return Response(
                    {
                        "status": "error",
                        "message": "Please provide code to scan.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            result = full_security_scan(
                code=code,
                filename=filename,
                engines=engines,
            )

            findings = result["all_findings"]
            summary = summarize_findings(
                findings,
                duration_ms=round((time.perf_counter() - started_at) * 1000, 2),
            )

            syntax_findings = [
                finding
                for finding in findings
                if finding.get("cwe_id") == "SYNTAX"
            ]

            if syntax_findings:
                return Response(
                    {
                        "status": "error",
                        "message": syntax_findings[0].get(
                            "message",
                            "The submitted code contains a syntax error.",
                        ),
                        "findings": findings,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            patch = propose_patch(code, filename)

            scan = _save_scan(
                user=request.user,
                code=code,
                patched=patch["patched_code"],
                findings=findings,
                project=project,
            )

            return Response(
                {
                    "status": "success",
                    "scan_id": scan.id,
                    "project": {"id": project.id, "slug": project.slug} if project else None,
                    "language": result["language"],
                    "is_vulnerable": bool(findings),
                    "original_code": code,
                    "patched_code": patch["patched_code"],
                    "patch": patch,
                    "vulnerabilities": findings,
                    "engines": {
                        "ast": result["ast_findings"],
                        "bandit": result["bandit_findings"],
                        "javascript": result["javascript_findings"],
                    },
                    "result": {
                        "vulnerabilities_count": len(findings),
                        "summary": summary,
                    },
                    "summary": summary,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as exc:
            return Response(
                {
                    "status": "error",
                    "message": f"Scan failed: {type(exc).__name__}: {exc}",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class CompareAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            code = request.data.get("code", "")
            filename = request.data.get("filename", "sample.py")

            if not isinstance(code, str) or not code.strip():
                return Response(
                    {
                        "status": "error",
                        "message": "Please provide code to compare.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            result = full_security_scan(
                code=code,
                filename=filename,
                engines=request.data.get("engines"),
            )

            counts = {
                key: len(result[key])
                for key in (
                    "ast_findings",
                    "bandit_findings",
                    "javascript_findings",
                )
            }

            return Response(
                {
                    "status": "success",
                    "language": result["language"],
                    "counts": counts,
                    "findings": result["all_findings"],
                },
                status=status.HTTP_200_OK,
            )

        except Exception as exc:
            return Response(
                {
                    "status": "error",
                    "message": f"Compare failed: {type(exc).__name__}: {exc}",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class HistoryAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        scans = CodeScan.objects.filter(
            user=request.user
        ).order_by("-created_at")[:50]

        rows = [
            {
                "id": scan.id,
                "status": scan.status,
                "is_vulnerable": scan.is_vulnerable,
                "created_at": scan.created_at.isoformat(),
                "finding_count": scan.vulnerabilities.count(),
            }
            for scan in scans
        ]

        return Response(
            {
                "status": "success",
                "scans": rows,
            },
            status=status.HTTP_200_OK,
        )


class EvaluationSummaryAPIView(APIView):
    """Expose the latest checked benchmark result to the dashboard."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        report_path = Path(__file__).resolve().parent.parent / "reports" / "hamzeh-week1-merged-evaluation.json"
        if not report_path.exists():
            report_path = Path(__file__).resolve().parent.parent / "reports" / "hamzeh-week1-evaluation.json"

        try:
            report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
        except (OSError, ValueError):
            report = {}

        return Response(
            {
                "status": "success",
                "available": bool(report),
                "source": report_path.name if report else None,
                "counts": report.get("counts", {}),
                "metrics": report.get("metrics", {}),
                "total_cases": report.get("total_cases", report.get("metrics", {}).get("total", 0)),
                "passed_cases": report.get("passed_cases", 0),
                "failed_cases": report.get("failed_cases", 0),
            },
            status=status.HTTP_200_OK,
        )


def _workspace_for_user(user):
    membership = Membership.objects.filter(user=user).select_related("organization").first()
    return membership.organization if membership else None


class ProjectListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        organization = _workspace_for_user(request.user)
        if not organization:
            return Response({"status": "success", "projects": []})
        projects = organization.projects.order_by("name")
        return Response({"status": "success", "projects": [
            {"id": project.id, "name": project.name, "slug": project.slug,
             "repository_url": project.repository_url, "default_branch": project.default_branch,
             "scan_count": project.scans.count()}
            for project in projects
        ]})

    def post(self, request):
        organization = _workspace_for_user(request.user)
        name = str(request.data.get("name", "")).strip()
        if not organization:
            return Response({"status": "error", "message": "Create or join a workspace first."}, status=403)
        if not name:
            return Response({"status": "error", "message": "Project name is required."}, status=400)
        slug = slugify(name)
        if Project.objects.filter(organization=organization, slug=slug).exists():
            return Response({"status": "error", "message": "A project with this name already exists."}, status=409)
        project = Project.objects.create(
            organization=organization,
            name=name,
            slug=slug,
            repository_url=str(request.data.get("repository_url", "")).strip(),
            default_branch=str(request.data.get("default_branch", "main")).strip() or "main",
        )
        AuditLog.objects.create(organization=organization, actor=request.user, action="project.created", metadata={"project_id": project.id})
        return Response({"status": "success", "project": {"id": project.id, "name": project.name, "slug": project.slug}}, status=201)


class IntegrationListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        organization = _workspace_for_user(request.user)
        integrations = RepositoryIntegration.objects.filter(organization=organization).select_related("project").order_by("provider", "repository_url")
        return Response({"status": "success", "integrations": [{
            "id": item.id, "provider": item.provider, "status": item.status,
            "repository_url": item.repository_url, "default_branch": item.default_branch,
            "project_id": item.project_id, "oauth_status": "NOT_CONNECTED",
            "webhook_ready": bool(item.webhook_secret_hash or (item.provider == "GITHUB" and os.getenv("GITHUB_WEBHOOK_SECRET"))),
        } for item in integrations]})

    def post(self, request):
        organization = _workspace_for_user(request.user)
        if not organization:
            return Response({"status": "error", "message": "Create or join a workspace first."}, status=403)
        provider = str(request.data.get("provider", "")).upper()
        repository_url = str(request.data.get("repository_url", "")).strip()
        if provider not in {"GITHUB", "GITLAB"} or not repository_url:
            return Response({"status": "error", "message": "provider must be GITHUB or GITLAB and repository_url is required."}, status=400)
        secret = str(request.data.get("webhook_secret", "")).strip()
        integration, created = RepositoryIntegration.objects.get_or_create(
            organization=organization, provider=provider, repository_url=repository_url,
            defaults={"default_branch": str(request.data.get("default_branch", "main"))[:120], "webhook_secret_hash": hash_secret(secret) if secret else "", "connected_by": request.user},
        )
        if not created:
            if secret:
                integration.webhook_secret_hash = hash_secret(secret)
            integration.default_branch = str(request.data.get("default_branch", integration.default_branch))[:120]
            integration.save(update_fields=["webhook_secret_hash", "default_branch", "updated_at"])
        project = create_integration_project(integration, request.user)
        AuditLog.objects.create(organization=organization, actor=request.user, action="integration.created", metadata={"integration_id": integration.id, "provider": provider, "project_id": project.id})
        return Response({"status": "success", "integration": {"id": integration.id, "provider": provider, "repository_url": repository_url, "project_id": project.id, "oauth_status": "NOT_CONNECTED", "webhook_ready": bool(integration.webhook_secret_hash or (provider == "GITHUB" and os.getenv("GITHUB_WEBHOOK_SECRET"))), "note": "OAuth connection and repository API fetch require provider App credentials."}}, status=201 if created else 200)


class IntegrationOAuthStartAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, integration_id):
        organization = _workspace_for_user(request.user)
        integration = RepositoryIntegration.objects.filter(id=integration_id, organization=organization).first()
        if not integration:
            return Response({"status": "error", "message": "Integration not found."}, status=404)
        state = new_state()
        integration.oauth_state = state
        integration.save(update_fields=["oauth_state", "updated_at"])
        try:
            url = build_authorization_url(integration.provider, state)
        except (RuntimeError, ValueError) as exc:
            return Response({"status": "error", "message": str(exc)}, status=503)
        return Response({"status": "success", "provider": integration.provider, "authorization_url": url})


class IntegrationOAuthCallbackAPIView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request, provider):
        state = request.query_params.get("state", "")
        code = request.query_params.get("code", "")
        integration = RepositoryIntegration.objects.filter(provider=provider.upper(), oauth_state=state).first()
        if not integration or not state or not code:
            return Response({"status": "error", "message": "Invalid or expired OAuth state."}, status=400)
        try:
            values = exchange_code(provider, code, state)
        except (RuntimeError, ValueError) as exc:
            return Response({"status": "error", "message": str(exc)}, status=502)
        for field, value in values.items():
            setattr(integration, field, value)
        integration.status = "ACTIVE"
        integration.save(update_fields=[*values.keys(), "status", "updated_at"])
        AuditLog.objects.create(organization=integration.organization, action="integration.oauth_connected", metadata={"integration_id": integration.id, "provider": integration.provider})
        return Response({"status": "success", "integration_id": integration.id, "provider": integration.provider, "connected": True})


def _provider_client_for(integration):
    return ProviderClient(integration.provider, decrypt_token(integration.access_token_encrypted), timeout=settings.PROVIDER_HTTP_TIMEOUT_SECONDS)


class IntegrationRepositoriesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, integration_id):
        organization = _workspace_for_user(request.user)
        integration = RepositoryIntegration.objects.filter(id=integration_id, organization=organization).first()
        if not integration:
            return Response({"status": "error", "message": "Integration not found."}, status=404)
        try:
            repos = _provider_client_for(integration).list_repositories()
        except ProviderError as exc:
            return Response({"status": "error", "message": str(exc)}, status=502)
        return Response({"status": "success", "repositories": [r.__dict__ for r in repos]})


class IntegrationBranchesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, integration_id):
        organization = _workspace_for_user(request.user)
        integration = RepositoryIntegration.objects.filter(id=integration_id, organization=organization).first()
        if not integration:
            return Response({"status": "error", "message": "Integration not found."}, status=404)
        repository_url = request.query_params.get("repository_url", integration.repository_url)
        try:
            branches = _provider_client_for(integration).list_branches(repository_url)
        except ProviderError as exc:
            return Response({"status": "error", "message": str(exc)}, status=502)
        return Response({"status": "success", "branches": branches})


def enqueue_remote_scan(integration, ref=None):
    client = _provider_client_for(integration)
    ref = ref or integration.default_branch
    archive = client.download_repository(integration.repository_url, ref)
    files = extract_source_files(archive, settings.REMOTE_SCAN_MAX_FILES, settings.REMOTE_SCAN_MAX_FILE_BYTES)
    if not integration.project_id:
        create_integration_project(integration, integration.connected_by)
    jobs = []
    for filename, source_code in files:
        jobs.append(ScanJob.objects.create(
            organization=integration.organization,
            project=integration.project,
            requested_by=integration.connected_by,
            filename=filename,
            engines=["ast", "bandit", "javascript"],
            source_code=source_code,
        ))
    return jobs


class IntegrationSyncAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, integration_id):
        organization = _workspace_for_user(request.user)
        integration = RepositoryIntegration.objects.filter(id=integration_id, organization=organization, status="ACTIVE").first()
        if not integration:
            return Response({"status": "error", "message": "An active integration is required."}, status=404)
        try:
            jobs = enqueue_remote_scan(integration, str(request.data.get("ref", "")).strip() or integration.default_branch)
        except ProviderError as exc:
            return Response({"status": "error", "message": str(exc)}, status=502)
        AuditLog.objects.create(organization=organization, actor=request.user, action="integration.sync_queued", metadata={"integration_id": integration.id, "job_count": len(jobs)})
        return Response({"status": "accepted", "integration_id": integration.id, "job_ids": [job.id for job in jobs], "file_count": len(jobs)}, status=202)


class RepositoryWebhookAPIView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request, provider, integration_id):
        integration = RepositoryIntegration.objects.filter(id=integration_id, provider=provider.upper(), status__in=["PENDING", "ACTIVE"]).first()
        if not integration:
            return Response({"status": "error", "message": "Integration not found."}, status=404)
        try:
            event = ingest_webhook(integration, request.headers, request.body)
        except PermissionError as exc:
            return Response({"status": "error", "message": str(exc)}, status=401)
        except (ValueError, UnicodeDecodeError):
            return Response({"status": "error", "message": "Invalid webhook JSON."}, status=400)
        return Response({"status": "accepted", "event_id": event.id, "event_type": event.event_type, "status": event.status, "next_step": "Run process_repository_events worker to fetch the commit and create ScanJobs."}, status=202)


class FindingListUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        organization = _workspace_for_user(request.user)
        findings = VulnerabilityReport.objects.filter(scan__user=request.user)
        if organization:
            findings = VulnerabilityReport.objects.filter(scan__organization=organization)
        status_filter = request.query_params.get("status")
        severity_filter = request.query_params.get("severity")
        if status_filter:
            findings = findings.filter(status=status_filter.upper())
        if severity_filter:
            findings = findings.filter(severity=severity_filter.upper())
        findings = findings.select_related("scan", "assigned_to").order_by("-updated_at")[:100]
        return Response({"status": "success", "findings": [
            {"id": item.id, "scan_id": item.scan_id, "cwe_id": item.cwe_id,
             "type": item.vulnerability_type, "severity": item.severity,
             "status": item.status, "line_number": item.line_number,
             "description": item.description, "recommendation": item.recommendation,
             "assigned_to": item.assigned_to.username if item.assigned_to else None,
             "updated_at": item.updated_at.isoformat()}
            for item in findings
        ]})

    def patch(self, request, finding_id):
        organization = _workspace_for_user(request.user)
        finding = VulnerabilityReport.objects.filter(id=finding_id, scan__organization=organization).select_related("scan").first()
        if not finding:
            return Response({"status": "error", "message": "Finding not found in your workspace."}, status=404)
        if "status" in request.data:
            new_status = str(request.data["status"]).upper()
            if new_status not in {"OPEN", "IN_PROGRESS", "FALSE_POSITIVE", "RESOLVED", "REOPENED"}:
                return Response({"status": "error", "message": "Invalid finding status."}, status=400)
            finding.status = new_status
        if "assigned_to" in request.data:
            username = str(request.data["assigned_to"]).strip()
            member = Membership.objects.filter(organization=organization, user__username=username).select_related("user").first()
            if username and not member:
                return Response({"status": "error", "message": "Assignee is not a member of this workspace."}, status=400)
            finding.assigned_to = member.user if member else None
        finding.save()
        AuditLog.objects.create(organization=organization, actor=request.user, action="finding.updated", metadata={"finding_id": finding.id, "status": finding.status})
        return Response({"status": "success", "finding_id": finding.id, "finding_status": finding.status})


class APIKeyListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        organization = _workspace_for_user(request.user)
        keys = organization.api_keys.order_by("-created_at") if organization else APIKey.objects.none()
        return Response({"status": "success", "api_keys": [{"prefix": key.prefix, "name": key.name, "revoked": bool(key.revoked_at), "created_at": key.created_at.isoformat(), "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None} for key in keys]})

    def post(self, request):
        organization = _workspace_for_user(request.user)
        name = str(request.data.get("name", "")).strip() or "Default CI key"
        if not organization:
            return Response({"status": "error", "message": "Create or join a workspace first."}, status=403)
        raw_key = APIKey.generate_raw_key()
        key = APIKey.objects.create(organization=organization, name=name, prefix=raw_key[:11], key_hash=hashlib.sha256(raw_key.encode()).hexdigest())
        AuditLog.objects.create(organization=organization, actor=request.user, action="api_key.created", metadata={"prefix": key.prefix})
        return Response({"status": "success", "api_key": {"name": key.name, "prefix": key.prefix, "token": raw_key, "warning": "Save this token now. It will not be shown again."}}, status=201)


class APIKeyRevokeAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, prefix):
        organization = _workspace_for_user(request.user)
        key = APIKey.objects.filter(organization=organization, prefix=prefix, revoked_at__isnull=True).first()
        if not key:
            return Response({"status": "error", "message": "API key not found."}, status=404)
        key.revoke()
        AuditLog.objects.create(organization=organization, actor=request.user, action="api_key.revoked", metadata={"prefix": prefix})
        return Response({"status": "success", "prefix": prefix, "revoked": True})


class ReportExportAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        organization = _workspace_for_user(request.user)
        findings = VulnerabilityReport.objects.filter(scan__organization=organization).select_related("scan", "assigned_to") if organization else VulnerabilityReport.objects.filter(scan__user=request.user).select_related("scan", "assigned_to")
        rows = [{"id": item.id, "scan_id": item.scan_id, "cwe_id": item.cwe_id, "severity": item.severity, "status": item.status, "line": item.line_number, "description": item.description, "recommendation": item.recommendation} for item in findings.order_by("id")]
        # `format` is reserved by DRF content negotiation; use `type` for exports.
        output_format = request.query_params.get("type", "json").lower()
        if output_format == "csv":
            buffer = io.StringIO(); writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()) if rows else ["id", "scan_id", "cwe_id", "severity", "status", "line", "description", "recommendation"]); writer.writeheader(); writer.writerows(rows)
            response = HttpResponse(buffer.getvalue(), content_type="text/csv"); response["Content-Disposition"] = "attachment; filename=security-findings.csv"; return response
        if output_format == "sarif":
            sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "AI Security Patching Agent"}}, "results": [{"ruleId": row["cwe_id"], "level": row["severity"].lower(), "message": {"text": row["description"]}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"scan/{row['scan_id']}"}, "region": {"startLine": row["line"] or 1}}}]} for row in rows]}]}
            response = HttpResponse(json.dumps(sarif, indent=2), content_type="application/sarif+json"); response["Content-Disposition"] = "attachment; filename=security-findings.sarif"; return response
        return Response({"status": "success", "generated_at": time.time(), "findings": rows})


def _serialize_scan_job(job, include_source=False):
    payload = {
        "id": job.id,
        "status": job.status,
        "progress": job.progress,
        "filename": job.filename,
        "engines": job.engines,
        "project_id": job.project_id,
        "result": job.result,
        "error": job.error_message or None,
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }
    if include_source:
        payload["source_code"] = job.source_code
    return payload


class ScanJobListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        organization = _workspace_for_user(request.user)
        if not organization:
            return Response({"status": "success", "jobs": []})
        jobs = organization.scan_jobs.select_related("project").order_by("-created_at")[:50]
        return Response({"status": "success", "jobs": [_serialize_scan_job(job) for job in jobs]})

    def post(self, request):
        organization = _workspace_for_user(request.user)
        if not organization:
            return Response({"status": "error", "message": "Create or join a workspace first."}, status=403)
        source_code = request.data.get("code", "")
        if not isinstance(source_code, str) or not source_code.strip():
            return Response({"status": "error", "message": "Please provide code to scan."}, status=400)
        max_bytes = settings.MAX_SCAN_BYTES
        if len(source_code.encode("utf-8")) > max_bytes:
            return Response({"status": "error", "message": "Source code exceeds the 1 MB plan limit."}, status=413)
        project = None
        project_id = request.data.get("project_id")
        if project_id:
            project = Project.objects.filter(id=project_id, organization=organization).first()
            if not project:
                return Response({"status": "error", "message": "Project not found in your workspace."}, status=404)
        idempotency_key = request.headers.get("Idempotency-Key") or request.data.get("idempotency_key")
        if idempotency_key:
            idempotency_key = str(idempotency_key).strip()[:120]
            existing = ScanJob.objects.filter(organization=organization, idempotency_key=idempotency_key).first()
            if existing:
                return Response({"status": "accepted", "replayed": True, "job": _serialize_scan_job(existing)}, status=200)
        job = ScanJob.objects.create(
            organization=organization,
            project=project,
            requested_by=request.user,
            filename=str(request.data.get("filename", "sample.py"))[:255],
            engines=request.data.get("engines") or ["ast", "bandit", "javascript"],
            source_code=source_code,
            idempotency_key=idempotency_key,
        )
        AuditLog.objects.create(organization=organization, actor=request.user, action="scan_job.created", metadata={"job_id": job.id, "project_id": project.id if project else None})
        return Response({"status": "accepted", "replayed": False, "job": _serialize_scan_job(job)}, status=202)


class ScanJobDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def _job(self, request, job_id):
        organization = _workspace_for_user(request.user)
        return ScanJob.objects.filter(id=job_id, organization=organization).select_related("project").first(), organization

    def get(self, request, job_id):
        job, _ = self._job(request, job_id)
        if not job:
            return Response({"status": "error", "message": "Scan job not found."}, status=404)
        return Response({"status": "success", "job": _serialize_scan_job(job, include_source=False)})

    def post(self, request, job_id):
        job, organization = self._job(request, job_id)
        if not job:
            return Response({"status": "error", "message": "Scan job not found."}, status=404)
        if job.status != "PENDING":
            return Response({"status": "error", "message": "Only pending jobs can be cancelled."}, status=409)
        job.status = "CANCELLED"
        job.progress = 100
        job.completed_at = timezone.now()
        job.save(update_fields=["status", "progress", "completed_at"])
        AuditLog.objects.create(organization=organization, actor=request.user, action="scan_job.cancelled", metadata={"job_id": job.id})
        return Response({"status": "success", "job": _serialize_scan_job(job)})


def login_view(request):
    if request.user.is_authenticated:
        return redirect("/")

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        user = authenticate(
            request,
            username=username,
            password=password,
        )

        if user is not None:
            login(request, user)
            return redirect("/")

        return render(
            request,
            "scanner/login.html",
            {
                "error": "Invalid username or password.",
            },
        )

    return render(request, "scanner/login.html")


def register_view(request):
    if request.user.is_authenticated:
        return redirect("/")

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "")

        if not username or len(password) < 8:
            return render(
                request,
                "scanner/login.html",
                {
                    "error": (
                        "Username is required and password must contain "
                        "at least 8 characters."
                    ),
                    "register_mode": True,
                },
            )

        if User.objects.filter(username=username).exists():
            return render(
                request,
                "scanner/login.html",
                {
                    "error": "Username already exists.",
                    "register_mode": True,
                },
            )

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
        )

        organization = Organization.objects.create(
            name=f"{username}'s Workspace",
            slug=f"{slugify(username)}-{user.id}",
            owner=user,
        )
        Membership.objects.create(organization=organization, user=user, role="OWNER")
        AuditLog.objects.create(organization=organization, actor=user, action="workspace.created")

        login(request, user)
        return redirect("/")

    return render(
        request,
        "scanner/login.html",
        {
            "register_mode": True,
        },
    )


def logout_view(request):
    logout(request)
    return redirect("/login/")
