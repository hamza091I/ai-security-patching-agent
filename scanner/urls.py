from django.urls import path
from scanner.views import ScanCodeAPIView
from . import views

urlpatterns = [
    path('', views.home_view, name='index'),
    path('api/scan/', ScanCodeAPIView.as_view(), name='api_scan'),
]