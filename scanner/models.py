import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone


class Organization(models.Model):
    name = models.CharField(max_length=150)
    slug = models.SlugField(max_length=170, unique=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="owned_organizations")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class Membership(models.Model):
    ROLE_CHOICES = [("OWNER", "Owner"), ("ADMIN", "Admin"), ("DEVELOPER", "Developer"), ("VIEWER", "Viewer")]
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="memberships")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="organization_memberships")
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="DEVELOPER")
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["organization", "user"], name="unique_organization_member")]


class Project(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="projects")
    name = models.CharField(max_length=150)
    slug = models.SlugField(max_length=170)
    repository_url = models.URLField(blank=True)
    default_branch = models.CharField(max_length=120, default="main")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["organization", "slug"], name="unique_project_slug_per_org")]

    def __str__(self):
        return f"{self.organization.slug}/{self.slug}"


class APIKey(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="api_keys")
    name = models.CharField(max_length=100)
    prefix = models.CharField(max_length=12, unique=True)
    key_hash = models.CharField(max_length=128)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    @staticmethod
    def generate_raw_key():
        return "sa_" + secrets.token_urlsafe(32)

    def revoke(self):
        self.revoked_at = timezone.now()
        self.save(update_fields=["revoked_at"])


class AuditLog(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="audit_logs")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=120)
    request_id = models.CharField(max_length=80, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class RepositoryIntegration(models.Model):
    PROVIDER_CHOICES = [("GITHUB", "GitHub"), ("GITLAB", "GitLab")]
    STATUS_CHOICES = [("PENDING", "Pending OAuth"), ("ACTIVE", "Active"), ("DISABLED", "Disabled")]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="repository_integrations")
    project = models.OneToOneField("Project", on_delete=models.CASCADE, related_name="integration", null=True, blank=True)
    provider = models.CharField(max_length=10, choices=PROVIDER_CHOICES)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="PENDING")
    repository_url = models.URLField()
    external_account_id = models.CharField(max_length=150, blank=True)
    default_branch = models.CharField(max_length=120, default="main")
    webhook_secret_hash = models.CharField(max_length=64, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    connected_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["organization", "provider", "repository_url"], name="unique_repo_integration")]


class RepositoryEvent(models.Model):
    EVENT_CHOICES = [("PUSH", "Push"), ("PULL_REQUEST", "Pull Request"), ("MERGE_REQUEST", "Merge Request"), ("UNKNOWN", "Unknown")]
    STATUS_CHOICES = [("RECEIVED", "Received"), ("QUEUED", "Queued"), ("IGNORED", "Ignored"), ("INVALID", "Invalid")]

    integration = models.ForeignKey(RepositoryIntegration, on_delete=models.CASCADE, related_name="events")
    event_type = models.CharField(max_length=20, choices=EVENT_CHOICES)
    delivery_id = models.CharField(max_length=200, blank=True)
    ref = models.CharField(max_length=255, blank=True)
    commit_sha = models.CharField(max_length=100, blank=True)
    payload = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="RECEIVED")
    created_at = models.DateTimeField(auto_now_add=True)


class CodeScan(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="code_scans", null=True, blank=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="scans", null=True, blank=True)
    project = models.ForeignKey(Project, on_delete=models.SET_NULL, related_name="scans", null=True, blank=True)

    STATUS_CHOICES = [("PENDING", "Pending Scan"), ("SUCCESS", "Scanned and Patched"), ("FAILED", "Scan Failed")]
    original_code = models.TextField(help_text="The original code entered by the user")
    patched_code = models.TextField(blank=True, null=True, help_text="The code after scanning and patch proposal")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="PENDING")
    is_vulnerable = models.BooleanField(default=False, help_text="Does the code contain vulnerabilities?")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Scan #{self.id} - {self.status} - {self.created_at:%Y-%m-%d %H:%M}"


class ScanJob(models.Model):
    STATUS_CHOICES = [
        ("PENDING", "Pending"),
        ("RUNNING", "Running"),
        ("SUCCEEDED", "Succeeded"),
        ("FAILED", "Failed"),
        ("CANCELLED", "Cancelled"),
    ]
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="scan_jobs")
    project = models.ForeignKey(Project, on_delete=models.SET_NULL, related_name="scan_jobs", null=True, blank=True)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, related_name="requested_scan_jobs", null=True, blank=True)
    filename = models.CharField(max_length=255, default="sample.py")
    engines = models.JSONField(default=list, blank=True)
    source_code = models.TextField()
    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default="PENDING", db_index=True)
    progress = models.PositiveSmallIntegerField(default=0)
    idempotency_key = models.CharField(max_length=120, null=True, blank=True)
    result = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)
    retry_count = models.PositiveSmallIntegerField(default=0)
    max_retries = models.PositiveSmallIntegerField(default=2)
    timeout_seconds = models.PositiveIntegerField(default=300)
    heartbeat_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "idempotency_key"],
                name="unique_scan_job_idempotency",
            )
        ]
        indexes = [
            models.Index(fields=["organization", "status", "-created_at"], name="scanjob_org_status_created"),
            models.Index(fields=["status", "heartbeat_at"], name="scanjob_status_heartbeat"),
        ]


class VulnerabilityReport(models.Model):
    SEVERITY_CHOICES = [("CRITICAL", "Critical"), ("HIGH", "High"), ("MEDIUM", "Medium"), ("LOW", "Low")]
    scan = models.ForeignKey(CodeScan, on_delete=models.CASCADE, related_name="vulnerabilities")
    cwe_id = models.CharField(max_length=20, help_text="Standard vulnerability ID like CWE-95")
    vulnerability_type = models.CharField(max_length=100, help_text="Vulnerability type")
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default="HIGH")
    line_number = models.IntegerField(null=True, blank=True)
    description = models.TextField()
    recommendation = models.TextField()
    status = models.CharField(max_length=20, default="OPEN")
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_findings")
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.cwe_id} ({self.severity}) in Scan #{self.scan.id}"


class SecurityKnowledgeBase(models.Model):
    cwe_id = models.CharField(max_length=20, unique=True)
    title = models.CharField(max_length=200)
    vulnerable_example = models.TextField()
    secure_example = models.TextField()
    explanation = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
