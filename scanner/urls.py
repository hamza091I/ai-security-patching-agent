from django.urls import path
from . import views

urlpatterns = [
    path('', views.home_view, name='index'),
    path('api/scan-code/', views.ScanCodeAPIView.as_view(), name='scan_and_patch_api'),
]