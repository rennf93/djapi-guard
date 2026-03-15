"""
URL configuration for the simple example project.
"""

from django.urls import path
from example_app import views

urlpatterns = [
    path("", views.root, name="root"),
    path("health", views.health, name="health"),
    path("api/info", views.api_info, name="api-info"),
    path("api/data", views.api_data, name="api-data"),
    path("api/test/xss", views.test_xss, name="test-xss"),
    path("api/test/sqli", views.test_sqli, name="test-sqli"),
]
