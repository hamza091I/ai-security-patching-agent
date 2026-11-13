import secrets
from datetime import datetime, timedelta, timezone

import requests
from django.conf import settings
from django.utils import timezone as django_timezone

from .token_crypto import decrypt_token, encrypt_token


class OAuthError(RuntimeError):
    """A safe, user-facing OAuth configuration or exchange error."""


def oauth_config(provider):
    provider = provider.upper()
    if provider == "GITHUB":
        return {
            "authorize": "https://github.com/login/oauth/authorize",
            "token": "https://github.com/login/oauth/access_token",
            "client_id": settings.GITHUB_CLIENT_ID,
            "client_secret": settings.GITHUB_CLIENT_SECRET,
            "callback": settings.GITHUB_CALLBACK_URL,
            "scope": "repo read:user",
        }
    if provider == "GITLAB":
        return {
            "authorize": "https://gitlab.com/oauth/authorize",
            "token": "https://gitlab.com/oauth/token",
            "client_id": settings.GITLAB_CLIENT_ID,
            "client_secret": settings.GITLAB_CLIENT_SECRET,
            "callback": settings.GITLAB_CALLBACK_URL,
            "scope": "api read_user",
        }
    raise ValueError("Unsupported provider.")


def build_authorization_url(provider, state):
    config = oauth_config(provider)
    if not config["client_id"]:
        raise OAuthError(f"{provider} OAuth client is not configured.")
    params = {
        "client_id": config["client_id"],
        "redirect_uri": config["callback"],
        "state": state,
        "scope": config["scope"],
        "response_type": "code",
    }
    return requests.Request("GET", config["authorize"], params=params).prepare().url


def _expiry_from_payload(data):
    """Compute the absolute token expiry.

    GitHub user-to-server tokens send ``expires_in`` and sometimes
    ``created_at`` as an ISO timestamp; GitLab sends ``created_at`` as a Unix
    timestamp. A missing ``created_at`` must fall back to "now" instead of the
    Unix epoch, which previously made freshly issued tokens look expired.
    """
    expires_in = data.get("expires_in")
    if not expires_in:
        return None
    try:
        expires_in = int(expires_in)
    except (TypeError, ValueError):
        return None
    created_at = data.get("created_at")
    base = django_timezone.now()
    if isinstance(created_at, str) and created_at:
        try:
            base = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except ValueError:
            base = django_timezone.now()
    elif isinstance(created_at, (int, float)) and created_at:
        try:
            base = datetime.fromtimestamp(int(created_at), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            base = django_timezone.now()
    if django_timezone.is_naive(base):
        base = django_timezone.make_aware(base, timezone.utc)
    return base + timedelta(seconds=expires_in)


def _credentials_from_payload(data):
    if not data.get("access_token"):
        raise OAuthError("Provider did not return an access token.")
    return {
        "access_token_encrypted": encrypt_token(data["access_token"]),
        "refresh_token_encrypted": encrypt_token(data.get("refresh_token", "")),
        "token_expires_at": _expiry_from_payload(data),
        "oauth_state": "",
    }


def exchange_code(provider, code, state):
    config = oauth_config(provider)
    if not config["client_id"] or not config["client_secret"]:
        raise OAuthError(f"{provider} OAuth credentials are not configured.")
    response = requests.post(config["token"], data={
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "code": code,
        "redirect_uri": config["callback"],
        "grant_type": "authorization_code",
    }, headers={"Accept": "application/json"}, timeout=settings.PROVIDER_HTTP_TIMEOUT_SECONDS)
    if response.status_code >= 400:
        raise OAuthError("Provider token exchange failed.")
    return _credentials_from_payload(response.json())


def refresh_access_token(provider, refresh_token):
    """Exchange a stored refresh token for a new access token."""
    config = oauth_config(provider)
    if not refresh_token:
        raise OAuthError("No refresh token is stored for this integration.")
    if not config["client_id"] or not config["client_secret"]:
        raise OAuthError(f"{provider} OAuth credentials are not configured.")
    response = requests.post(config["token"], data={
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }, headers={"Accept": "application/json"}, timeout=settings.PROVIDER_HTTP_TIMEOUT_SECONDS)
    if response.status_code >= 400:
        raise OAuthError("Provider token refresh failed. Reconnect the integration.")
    return _credentials_from_payload(response.json())


def token_needs_refresh(integration, leeway_seconds=120):
    expires_at = integration.token_expires_at
    if not expires_at:
        return False
    return expires_at <= django_timezone.now() + timedelta(seconds=leeway_seconds)


def refresh_integration_token(integration, force=False):
    """Refresh an expiring provider token in place.

    Returns True when the stored credentials were updated. GitHub OAuth Apps
    never expire (no expiry stored), so nothing happens for them.
    """
    if not force and not token_needs_refresh(integration):
        return False
    refresh_token = decrypt_token(integration.refresh_token_encrypted)
    values = refresh_access_token(integration.provider, refresh_token)
    for field, value in values.items():
        setattr(integration, field, value)
    integration.save(update_fields=[*values.keys(), "updated_at"])
    return True


def new_state():
    return secrets.token_urlsafe(32)
