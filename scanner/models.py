from django.db import models

class CodeScan(models.Model):
    """
    Table to store code scanning operations performed by the user
    """
    STATUS_CHOICES = [
        ('PENDING', 'Pending Scan'),
        ('SUCCESS', 'Scanned and Patched'),
        ('FAILED', 'Scan Failed'),
    ]

    original_code = models.TextField(help_text="The original code entered by the user")
    patched_code = models.TextField(blank=True, null=True, help_text="The code after patching and fixing")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    is_vulnerable = models.BooleanField(default=False, help_text="Does the code contain vulnerabilities?")
    created_at = models.DateTimeField(auto_now_add=True, help_text="Scan date and time")

    def __str__(self):
        return f"Scan #{self.id} - {self.status} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"


class VulnerabilityReport(models.Model):
    """
    Table to store details of each vulnerability detected in a specific scan
    """
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]

    scan = models.ForeignKey(CodeScan, on_delete=models.CASCADE, related_name='vulnerabilities')
    cwe_id = models.CharField(max_length=20, help_text="Standard vulnerability ID like CWE-95")
    vulnerability_type = models.CharField(max_length=100, help_text="Type of vulnerability (e.g., Code Injection)")
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='HIGH')
    line_number = models.IntegerField(null=True, blank=True, help_text="Line number containing the vulnerability")
    description = models.TextField(help_text="Detailed description and risks of the vulnerability")
    recommendation = models.TextField(help_text="Safe recommendation for remediation")

    def __str__(self):
        return f"{self.cwe_id} ({self.severity}) in Scan #{self.scan.id}"


class SecurityKnowledgeBase(models.Model):
    """
    Table for security knowledge base to be used in the future with RAG and ChromaDB
    """
    cwe_id = models.CharField(max_length=20, unique=True, help_text="Standard vulnerability ID")
    title = models.CharField(max_length=200, help_text="Vulnerability title")
    vulnerable_example = models.TextField(help_text="Example of insecure code")
    secure_example = models.TextField(help_text="Example of secure and patched code")
    explanation = models.TextField(help_text="Explanation of patching and prevention mechanism")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.cwe_id} - {self.title}"