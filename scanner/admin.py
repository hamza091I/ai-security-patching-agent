from django.contrib import admin
from .models import CodeScan, VulnerabilityReport, SecurityKnowledgeBase

@admin.register(CodeScan)
class CodeScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'status', 'is_vulnerable', 'created_at')
    list_filter = ('status', 'is_vulnerable', 'created_at')
    search_fields = ('original_code', 'patched_code')

@admin.register(VulnerabilityReport)
class VulnerabilityReportAdmin(admin.ModelAdmin):
    list_display = ('scan', 'cwe_id', 'vulnerability_type', 'severity', 'line_number')
    list_filter = ('severity', 'cwe_id')
    search_fields = ('cwe_id', 'vulnerability_type', 'description')

@admin.register(SecurityKnowledgeBase)
class SecurityKnowledgeBaseAdmin(admin.ModelAdmin):
    list_display = ('cwe_id', 'title', 'created_at')
    search_fields = ('cwe_id', 'title', 'vulnerable_example', 'secure_example')