import hashlib
import secrets
from datetime import timedelta

from django.contrib.auth import authenticate, login, get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.core.cache import cache
from django.db.models import Sum
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from scanner.models import APIKey, AssistantRequest, AuditLog, EmailVerification, Membership, TeamInvite, UsageRecord
from scanner.core.patcher import propose_patch
from scanner.views import _workspace_for_user


def page(queryset, request, serializer, default=25, maximum=100):
    try:
        number = max(1, int(request.query_params.get("page", 1)))
        size = max(1, min(maximum, int(request.query_params.get("page_size", default))))
    except ValueError:
        number, size = 1, default
    total = queryset.count()
    rows = queryset[(number - 1) * size:number * size]
    return {"page": number, "page_size": size, "total": total, "has_next": number * size < total, "items": [serializer(x) for x in rows]}


class OpenAPISchemaAPIView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        return Response({"openapi": "3.0.3", "info": {"title": "Sentinel AI Security API", "version": "1.0.0"}, "servers": [{"url": "/"}], "paths": {
            "/api/v1/scan-jobs/": {"post": {"summary": "Create a durable security scan job"}},
            "/api/v1/findings/": {"get": {"summary": "List paginated findings"}},
            "/api/v1/api-keys/": {"get": {"summary": "List workspace keys"}, "post": {"summary": "Create a workspace key"}},
            "/api/v1/team/": {"get": {"summary": "List workspace members"}, "post": {"summary": "Invite a member"}},
            "/api/v1/assistant/": {"post": {"summary": "Propose a patch requiring human approval"}},
        }, "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}}})


class TeamAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        org = _workspace_for_user(request.user)
        if not org: return Response({"status": "success", "members": []})
        members = org.memberships.select_related("user").order_by("user__username")
        return Response({"status": "success", **page(members, request, lambda m: {"username": m.user.username, "email": m.user.email, "role": m.role, "joined_at": m.joined_at.isoformat()}, default=50)})
    def post(self, request):
        org = _workspace_for_user(request.user)
        email = str(request.data.get("email", "")).strip().lower()
        role = str(request.data.get("role", "DEVELOPER")).upper()
        if not org or not email or role not in {"ADMIN", "DEVELOPER", "VIEWER"}: return Response({"status": "error", "message": "Valid workspace, email and role are required."}, status=400)
        raw = secrets.token_urlsafe(32)
        invite = TeamInvite.objects.create(organization=org, email=email, role=role, token_hash=hashlib.sha256(raw.encode()).hexdigest(), invited_by=request.user, expires_at=timezone.now() + timedelta(days=7))
        send_mail("You are invited to Sentinel AI", f"Invite token: {raw}", None, [email], fail_silently=True)
        AuditLog.objects.create(organization=org, actor=request.user, action="team.invite_created", metadata={"email": email, "role": role, "invite_id": invite.id})
        return Response({"status": "success", "invite_id": invite.id, "email": email, "token": "sent_by_email"}, status=201)


class APIKeyRotateAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, prefix):
        org = _workspace_for_user(request.user)
        old = APIKey.objects.filter(organization=org, prefix=prefix, revoked_at__isnull=True).first()
        if not old: return Response({"status": "error", "message": "API key not found."}, status=404)
        raw = APIKey.generate_raw_key()
        old.revoked_at = timezone.now(); old.save(update_fields=["revoked_at"])
        new = APIKey.objects.create(organization=org, name=old.name, prefix=raw[:11], key_hash=hashlib.sha256(raw.encode()).hexdigest())
        AuditLog.objects.create(organization=org, actor=request.user, action="api_key.rotated", metadata={"old_prefix": prefix, "new_prefix": new.prefix})
        return Response({"status": "success", "api_key": {"prefix": new.prefix, "token": raw, "name": new.name}}, status=201)


class UsageAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        org = _workspace_for_user(request.user)
        today = timezone.localdate()
        rows = UsageRecord.objects.filter(organization=org, period=today).values("metric").annotate(total_sum=Sum("quantity"))
        return Response({"status": "success", "plan": getattr(org, "plan", "FREE"), "period": str(today), "usage": {row["metric"]: row["total_sum"] for row in rows}})


class AssistantAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        org = _workspace_for_user(request.user)
        code = request.data.get("code", "")
        filename = request.data.get("filename", "sample.py")
        if not org or not isinstance(code, str) or not code.strip(): return Response({"status": "error", "message": "Workspace and code are required."}, status=400)
        patch = propose_patch(code, filename)
        assistant = AssistantRequest.objects.create(organization=org, requested_by=request.user, prompt=str(request.data.get("prompt", "Generate a safe patch")), evidence={"filename": filename}, proposed_diff=patch.get("patched_code", ""))
        return Response({"status": "draft", "request_id": assistant.id, "proposed_patch": assistant.proposed_diff, "requires_human_approval": True}, status=201)
    def patch(self, request, request_id):
        org = _workspace_for_user(request.user)
        item = AssistantRequest.objects.filter(id=request_id, organization=org).first()
        if not item: return Response({"status": "error", "message": "Assistant request not found."}, status=404)
        decision = str(request.data.get("decision", "")).upper()
        if decision not in {"APPROVE", "REJECT"}: return Response({"status": "error", "message": "decision must be APPROVE or REJECT."}, status=400)
        item.status = "APPROVED" if decision == "APPROVE" else "REJECTED"; item.approved_by = request.user; item.regression_passed = decision == "APPROVE"; item.save(update_fields=["status", "approved_by", "regression_passed", "updated_at"])
        AuditLog.objects.create(organization=org, actor=request.user, action="assistant.decision", metadata={"request_id": item.id, "decision": decision})
        return Response({"status": "success", "request_id": item.id, "decision": item.status, "patch": item.proposed_diff})


class VerifyEmailAPIView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        raw = str(request.data.get("token", ""))
        item = EmailVerification.objects.filter(token_hash=hashlib.sha256(raw.encode()).hexdigest(), verified_at__isnull=True).select_related("user").first()
        if not item or item.expired(): return Response({"status": "error", "message": "Invalid or expired verification token."}, status=400)
        item.verified_at = timezone.now(); item.user.is_active = True; item.user.save(update_fields=["is_active"]); item.save(update_fields=["verified_at"])
        return Response({"status": "success", "verified": True})


class PasswordResetRequestAPIView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        email = str(request.data.get("email", "")).strip().lower()
        user = get_user_model().objects.filter(email__iexact=email, is_active=True).first()
        if user:
            token = default_token_generator.make_token(user)
            send_mail("Reset your Sentinel AI password", f"Use token {user.pk}:{token} with the reset endpoint.", None, [email], fail_silently=True)
        return Response({"status": "accepted", "message": "If that email exists, reset instructions were sent."})


class PasswordResetConfirmAPIView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        try:
            user = get_user_model().objects.get(pk=int(request.data.get("user_id")))
        except (TypeError, ValueError, get_user_model().DoesNotExist):
            return Response({"status": "error", "message": "Invalid reset request."}, status=400)
        token = str(request.data.get("token", ""))
        password = str(request.data.get("password", ""))
        if not default_token_generator.check_token(user, token) or len(password) < 10:
            return Response({"status": "error", "message": "Invalid token or password."}, status=400)
        user.set_password(password); user.save(update_fields=["password"])
        return Response({"status": "success", "reset": True})
