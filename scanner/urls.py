from django.urls import path
from .views import (APIKeyListCreateAPIView, APIKeyRevokeAPIView, CompareAPIView, EvaluationSummaryAPIView,
                    FindingListUpdateAPIView, HistoryAPIView, ProjectListCreateAPIView, ReportExportAPIView,
                    ScanCodeAPIView, health_view, home_view, login_view, logout_view, metrics_view,
                    readiness_view, register_view)

urlpatterns = [
    path('', home_view, name='index'),
    path('login/', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('logout/', logout_view, name='logout'),
    path('health/', health_view, name='health'),
    path('ready/', readiness_view, name='ready'),
    path('metrics/', metrics_view, name='metrics'),
    path('api/scan/', ScanCodeAPIView.as_view(), name='api_scan'),
    path('api/compare/', CompareAPIView.as_view(), name='api_compare'),
    path('api/history/', HistoryAPIView.as_view(), name='api_history'),
    path('api/evaluation/summary/', EvaluationSummaryAPIView.as_view(), name='api_evaluation_summary'),
    path('api/v1/scan/', ScanCodeAPIView.as_view(), name='api_v1_scan'),
    path('api/v1/compare/', CompareAPIView.as_view(), name='api_v1_compare'),
    path('api/v1/history/', HistoryAPIView.as_view(), name='api_v1_history'),
    path('api/v1/evaluation/summary/', EvaluationSummaryAPIView.as_view(), name='api_v1_evaluation_summary'),
    path('api/v1/projects/', ProjectListCreateAPIView.as_view(), name='api_v1_projects'),
    path('api/v1/findings/', FindingListUpdateAPIView.as_view(), name='api_v1_findings'),
    path('api/v1/findings/<int:finding_id>/', FindingListUpdateAPIView.as_view(), name='api_v1_finding'),
    path('api/v1/api-keys/', APIKeyListCreateAPIView.as_view(), name='api_v1_api_keys'),
    path('api/v1/api-keys/<str:prefix>/revoke/', APIKeyRevokeAPIView.as_view(), name='api_v1_revoke_api_key'),
    path('api/v1/reports/export/', ReportExportAPIView.as_view(), name='api_v1_report_export'),
]
