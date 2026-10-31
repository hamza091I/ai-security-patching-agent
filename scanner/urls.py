from django.urls import path
from .views import home_view,ScanCodeAPIView,CompareAPIView,HistoryAPIView,login_view,register_view,logout_view
urlpatterns=[path('',home_view,name='index'),path('login/',login_view,name='login'),path('register/',register_view,name='register'),path('logout/',logout_view,name='logout'),path('api/scan/',ScanCodeAPIView.as_view(),name='api_scan'),path('api/compare/',CompareAPIView.as_view(),name='api_compare'),path('api/history/',HistoryAPIView.as_view(),name='api_history')]
