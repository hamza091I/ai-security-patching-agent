import secrets
from datetime import datetime, timezone

import requests
from django.conf import settings

from .token_crypto import encrypt_token


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
        raise RuntimeError(f"{provider} OAuth client is not configured.")
    params = {
        "client_id": config["client_id"],
        "redirect_uri": config["callback"],
        "state": state,
        "scope": config["scope"],
        "response_type": "code",
    }
    return requests.Request("GET", config["authorize"], params=params).prepare().url


def exchange_code(provider, code, state):
    config = oauth_config(provider)
    if not config["client_id"] or not config["client_secret"]:
        raise RuntimeError(f"{provider} OAuth credentials are not configured.")
    response = requests.post(config["token"], data={
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "code": code,
        "redirect_uri": config["callback"],
        "grant_type": "authorization_code",
    }, headers={"Accept": "application/json"}, timeout=settings.PROVIDER_HTTP_TIMEOUT_SECONDS)
    if response.status_code >= 400:
        raise RuntimeError("Provider token exchange failed.")
    data = response.json()
    if not data.get("access_token"):
        raise RuntimeError("Provider did not return an access token.")
    expires = data.get("created_at", 0) + data.get("expires_in", 0) if data.get("expires_in") else None
    expires_at = datetime.fromtimestamp(expires, tz=timezone.utc) if expires else None
    return {
        "access_token_encrypted": encrypt_token(data["access_token"]),
        "refresh_token_encrypted": encrypt_token(data.get("refresh_token", "")),
        "token_expires_at": expires_at,
        "oauth_state": "",
    }


def new_state():
    return secrets.token_urlsafe(32)
