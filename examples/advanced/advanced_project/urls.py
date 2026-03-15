"""
URL configuration for the advanced example project.
"""

from advanced_app import views
from django.urls import path

urlpatterns = [
    path("", views.root, name="root"),
    path("health", views.health, name="health"),
    path("api/info", views.api_info, name="api-info"),
    # Rate limited routes
    path("api/limited", views.rate_limited, name="api-limited"),
    # Authentication routes
    path("api/protected", views.protected, name="api-protected"),
    path("api/api-key", views.api_key_protected, name="api-key"),
    # Content filtering routes
    path("api/json-only", views.json_only, name="json-only"),
    path("api/small-payload", views.small_payload, name="small-payload"),
    # Access control routes
    path("api/local-only", views.local_only, name="local-only"),
    # Advanced routes
    path("api/business-hours", views.business_hours, name="business-hours"),
    path("api/honeypot", views.honeypot_endpoint, name="honeypot"),
    # Behavioral analysis routes
    path("api/monitored", views.monitored, name="monitored"),
    # Admin routes
    path("api/admin/ban/<str:ip>", views.ban_ip, name="ban-ip"),
    path("api/admin/unban/<str:ip>", views.unban_ip, name="unban-ip"),
    # Security test routes
    path("api/test/xss", views.test_xss, name="test-xss"),
    path("api/test/sqli", views.test_sqli, name="test-sqli"),
    # Bypass route
    path("api/unprotected", views.unprotected, name="unprotected"),
]
