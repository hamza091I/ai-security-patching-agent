import logging
import time
import uuid

from django.conf import settings

logger = logging.getLogger("security_platform")


class RequestIDMiddleware:
    """Attach a request ID to logs and every HTTP response."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = request.headers.get(settings.REQUEST_ID_HEADER) or str(uuid.uuid4())
        request.request_id = request_id
        response = self.get_response(request)
        response[settings.REQUEST_ID_HEADER] = request_id
        return response


class TenantContextMiddleware:
    """Attach the user's first workspace to the request context.

    Views still scope querysets explicitly; this provides one canonical context
    for tenant-aware services and observability.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.organization = None
        if getattr(request, "user", None) is not None and request.user.is_authenticated:
            from scanner.models import Membership

            membership = Membership.objects.filter(user=request.user).select_related("organization").order_by("joined_at").first()
            request.organization = membership.organization if membership else None
        return self.get_response(request)


class StructuredRequestLoggingMiddleware:
    """Emit a compact structured log record for every HTTP request."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        started = time.perf_counter()
        response = self.get_response(request)
        logger.info("http.request", extra={
            "request_id": getattr(request, "request_id", ""),
            "method": request.method,
            "path": request.path,
            "status": response.status_code,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "user_id": getattr(getattr(request, "user", None), "id", None),
            "organization_id": getattr(getattr(request, "organization", None), "id", None),
        })
        return response
