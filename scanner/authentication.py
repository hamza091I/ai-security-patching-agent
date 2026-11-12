import hashlib
import hmac

from django.utils import timezone
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .models import APIKey


class WorkspaceAPIKeyAuthentication(BaseAuthentication):
    """Authenticate ``Authorization: Bearer sa_...`` without storing raw keys."""

    keyword = "Bearer"

    def authenticate(self, request):
        header = request.headers.get("Authorization", "")
        if not header:
            return None
        try:
            keyword, raw_key = header.split(" ", 1)
        except ValueError as exc:
            raise AuthenticationFailed("Invalid Authorization header.") from exc
        if keyword.lower() != self.keyword.lower() or not raw_key.startswith("sa_"):
            raise AuthenticationFailed("Use a Bearer workspace API key.")

        prefix = raw_key[:11]
        key = APIKey.objects.select_related("organization__owner").filter(
            prefix=prefix,
            revoked_at__isnull=True,
        ).first()
        digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        if not key or not hmac.compare_digest(key.key_hash, digest):
            raise AuthenticationFailed("Invalid or revoked API key.")

        APIKey.objects.filter(pk=key.pk).update(last_used_at=timezone.now())
        return key.organization.owner, key
