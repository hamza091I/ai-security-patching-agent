from django.conf import settings
from django.db import models
from django.utils import timezone


class EmailVerification(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="email_verification")
    token_hash = models.CharField(max_length=128)
    expires_at = models.DateTimeField()
    verified_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def is_verified(self):
        return bool(self.verified_at)

    def expired(self):
        return timezone.now() >= self.expires_at


class TeamInvite(models.Model):
    organization = models.ForeignKey("Organization", on_delete=models.CASCADE, related_name="team_invites")
    email = models.EmailField()
    role = models.CharField(max_length=20, default="DEVELOPER")
    token_hash = models.CharField(max_length=128)
    invited_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    accepted_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)


class UsageRecord(models.Model):
    organization = models.ForeignKey("Organization", on_delete=models.CASCADE, related_name="usage_records")
    metric = models.CharField(max_length=50)
    quantity = models.PositiveIntegerField(default=1)
    period = models.DateField()
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["organization", "metric", "period"])]


class AssistantRequest(models.Model):
    STATUS_CHOICES = [("DRAFT", "Draft"), ("APPROVED", "Approved"), ("REJECTED", "Rejected"), ("APPLIED", "Applied")]
    organization = models.ForeignKey("Organization", on_delete=models.CASCADE, related_name="assistant_requests")
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    scan = models.ForeignKey("CodeScan", on_delete=models.CASCADE, null=True, blank=True)
    vulnerability_id = models.CharField(max_length=80, blank=True)
    prompt = models.TextField()
    evidence = models.JSONField(default=dict, blank=True)
    proposed_diff = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="DRAFT")
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="approved_assistant_requests")
    regression_passed = models.BooleanField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
