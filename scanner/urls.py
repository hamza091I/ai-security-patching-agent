from django.urls import path
from scanner.views import scan_and_patch_api

urlpatterns = [
    path('scan-code/', scan_and_patch_api, name='scan_code_api'),
]