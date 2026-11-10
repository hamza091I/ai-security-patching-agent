import hashlib
import hmac
import json
import os

from django.conf import settings
from django.utils.text import slugify

from scanner.models import AuditLog, Project, RepositoryEvent, RepositoryIntegration


def hash_secret(secret):
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_webhook(integration, headers, raw_body):
    """Verify provider signatures without storing a raw webhook secret.

    GitHub uses a process-level GITHUB_WEBHOOK_SECRET because its signature is
    HMAC-based. GitLab sends a token and can be verified against the digest
    stored on the integration.
    """
    if integration.provider == "GITHUB":
        secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
        signature = headers.get("X-Hub-Signature-256", "")
        expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
        return bool(secret) and hmac.compare_digest(signature, expected)
    token = headers.get("X-Gitlab-Token", "")
    return bool(token and integration.webhook_secret_hash and hmac.compare_digest(hash_secret(token), integration.webhook_secret_hash))


def event_from_payload(provider, headers, payload):
    if provider == "GITHUB":
        event = headers.get("X-GitHub-Event", "")
        event_type = "PULL_REQUEST" if event == "pull_request" else "PUSH" if event == "push" else "UNKNOWN"
        ref = payload.get("ref", "") or payload.get("pull_request", {}).get("head", {}).get("ref", "")
        sha = payload.get("after", "") or payload.get("pull_request", {}).get("head", {}).get("sha", "")
        delivery = headers.get("X-GitHub-Delivery", "")
    else:
        event = headers.get("X-Gitlab-Event", "")
        event_type = "MERGE_REQUEST" if event == "Merge Request Hook" else "PUSH" if event == "Push Hook" else "UNKNOWN"
        ref = payload.get("ref", "") or payload.get("object_attributes", {}).get("source_branch", "")
        sha = payload.get("after", "") or payload.get("checkout_sha", "")
        delivery = headers.get("X-Gitlab-Event-UUID", "")
    return event_type, ref, sha, delivery


def ingest_webhook(integration, headers, raw_body):
    if not verify_webhook(integration, headers, raw_body):
        raise PermissionError("Invalid webhook signature.")
    payload = json.loads(raw_body.decode("utf-8"))
    event_type, ref, sha, delivery = event_from_payload(integration.provider, headers, payload)
    if event_type == "UNKNOWN":
        status = "IGNORED"
    else:
        status = "RECEIVED"
    event = RepositoryEvent.objects.create(
        integration=integration,
        event_type=event_type,
        delivery_id=delivery,
        ref=ref,
        commit_sha=sha,
        payload=payload,
        status=status,
    )
    AuditLog.objects.create(
        organization=integration.organization,
        action="repository_event.received",
        metadata={"integration_id": integration.id, "event_id": event.id, "event_type": event_type, "commit_sha": sha},
    )
    return event


def create_integration_project(integration, user):
    if integration.project_id:
        return integration.project
    name = integration.repository_url.rstrip("/").rsplit("/", 1)[-1] or f"{integration.provider.lower()}-repository"
    slug = slugify(name)
    base = slug or "repository"
    counter = 2
    while Project.objects.filter(organization=integration.organization, slug=slug).exists():
        slug = f"{base}-{counter}"
        counter += 1
    project = Project.objects.create(organization=integration.organization, name=name, slug=slug, repository_url=integration.repository_url, default_branch=integration.default_branch)
    integration.project = project
    integration.save(update_fields=["project", "updated_at"])
    AuditLog.objects.create(organization=integration.organization, actor=user, action="integration.project_created", metadata={"integration_id": integration.id, "project_id": project.id})
    return project
