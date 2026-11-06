import time

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated

from scanner.analysis.security_scanner import full_security_scan
from scanner.core.patcher import propose_patch
from .models import CodeScan, VulnerabilityReport


@login_required(login_url="/login/")
def home_view(request):
    return render(request, "scanner/index.html")


def _save_scan(user, code, patched, findings):
    scan = CodeScan.objects.create(
        user=user,
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
            )

            return Response(
                {
                    "status": "success",
                    "scan_id": scan.id,
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
