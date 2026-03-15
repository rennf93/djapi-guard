"""
DjangoAPI Guard Advanced Example
=================================

This example demonstrates the full feature set of the DjangoAPI Guard
security middleware, including decorator-based per-view security controls.

Features demonstrated:
- IP whitelisting/blacklisting with CIDR support
- Rate limiting (global and per-endpoint)
- Automatic IP banning
- Penetration attempt detection
- User agent filtering
- Content type filtering
- Request size limiting
- Time-based access control
- Behavioral analysis and monitoring
- Custom authentication schemes
- Honeypot detection
- Redis integration for distributed environments
- Security headers
- CORS configuration

Run with: gunicorn advanced_project.wsgi:application --bind 0.0.0.0:8000 --reload
Or: python manage.py runserver 0.0.0.0:8000
"""

import json
import logging
from datetime import datetime, timezone

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from djangoapi_guard import SecurityConfig, SecurityDecorator, ip_ban_manager

# Configure logging
logger = logging.getLogger(__name__)

# Initialize security decorator with config from settings
config: SecurityConfig = settings.GUARD_SECURITY_CONFIG
security = SecurityDecorator(config)


# ============================================================================
# Basic Routes
# ============================================================================


@require_GET
def root(request: HttpRequest) -> JsonResponse:
    """Root endpoint."""
    return JsonResponse(
        {
            "message": "DjangoAPI Guard Advanced Example",
            "docs": "/api/info",
            "health": "/health",
        }
    )


@require_GET
def health(request: HttpRequest) -> JsonResponse:
    """Health check endpoint (excluded from security checks)."""
    timestamp = datetime.now(timezone.utc).isoformat()
    return JsonResponse({"status": "healthy", "timestamp": timestamp})


@require_GET
def api_info(request: HttpRequest) -> JsonResponse:
    """API information endpoint."""
    return JsonResponse(
        {
            "name": "DjangoAPI Guard Advanced Example",
            "version": "1.0.0",
            "security": "enabled",
            "features": [
                "rate_limiting",
                "ip_filtering",
                "penetration_detection",
                "behavioral_analysis",
                "security_headers",
                "redis_integration",
                "decorators",
            ],
        }
    )


# ============================================================================
# Rate Limited Routes
# ============================================================================


@require_GET
@security.rate_limit(requests=5, window=60)
def rate_limited(request: HttpRequest) -> JsonResponse:
    """Rate-limited endpoint: 5 requests per minute."""
    return JsonResponse(
        {"message": "This endpoint is rate limited", "limit": "5/minute"}
    )


# ============================================================================
# Authentication Routes
# ============================================================================


@require_GET
@security.require_auth(type="bearer")
def protected(request: HttpRequest) -> JsonResponse:
    """Protected endpoint requiring Bearer token."""
    return JsonResponse({"message": "Authenticated!", "user": "authenticated_user"})


@require_GET
@security.api_key_auth("X-API-Key")
def api_key_protected(request: HttpRequest) -> JsonResponse:
    """Endpoint requiring API key."""
    return JsonResponse({"message": "API key validated!"})


# ============================================================================
# Content Filtering Routes
# ============================================================================


@csrf_exempt
@require_POST
@security.content_type_filter(["application/json"])
def json_only(request: HttpRequest) -> JsonResponse:
    """Endpoint that only accepts JSON content."""
    try:
        data = json.loads(request.body) if request.body else {}
    except (json.JSONDecodeError, ValueError):
        data = {}
    return JsonResponse({"received": data})


@csrf_exempt
@require_POST
@security.max_request_size(1024)
def small_payload(request: HttpRequest) -> JsonResponse:
    """Endpoint with 1KB request size limit."""
    return JsonResponse({"message": "Payload accepted"})


# ============================================================================
# Access Control Routes
# ============================================================================


@require_GET
@security.require_ip(whitelist=["127.0.0.1", "::1", "10.0.0.0/8"])
def local_only(request: HttpRequest) -> JsonResponse:
    """Endpoint restricted to local/private IPs."""
    return JsonResponse({"message": "Local access granted"})


# ============================================================================
# Advanced Routes
# ============================================================================


@require_GET
@security.time_window("09:00", "17:00", "UTC")
def business_hours(request: HttpRequest) -> JsonResponse:
    """Endpoint available only during business hours (UTC)."""
    return JsonResponse(
        {
            "message": "Business hours endpoint",
            "current_time": datetime.now(timezone.utc).strftime("%H:%M"),
        }
    )


@csrf_exempt
@require_POST
@security.honeypot_detection(["bot_trap", "hidden_field"])
def honeypot_endpoint(request: HttpRequest) -> JsonResponse:
    """Endpoint with honeypot bot detection."""
    try:
        data = json.loads(request.body) if request.body else {}
    except (json.JSONDecodeError, ValueError):
        data = {}
    return JsonResponse({"message": "Human verified!", "data": data})


# ============================================================================
# Behavioral Analysis Routes
# ============================================================================


@require_GET
@security.usage_monitor(max_calls=10, window=3600, action="log")
def monitored(request: HttpRequest) -> JsonResponse:
    """Endpoint with behavioral usage monitoring."""
    return JsonResponse({"message": "Usage is being monitored"})


# ============================================================================
# Admin Routes
# ============================================================================


@csrf_exempt
@require_POST
@security.require_auth(type="bearer")
def ban_ip(request: HttpRequest, ip: str) -> JsonResponse:
    """Ban an IP address."""
    ip_ban_manager.ban_ip(ip, duration=3600, reason="admin_ban")
    return JsonResponse({"message": f"IP {ip} banned for 1 hour"})


@csrf_exempt
@require_POST
@security.require_auth(type="bearer")
def unban_ip(request: HttpRequest, ip: str) -> JsonResponse:
    """Unban an IP address."""
    ip_ban_manager.unban_ip(ip)
    return JsonResponse({"message": f"IP {ip} unbanned"})


# ============================================================================
# Security Test Routes
# ============================================================================


@require_GET
def test_xss(request: HttpRequest) -> JsonResponse:
    """Route to test XSS detection (try adding script tags in query params)."""
    query = request.GET.get("q", "")
    return JsonResponse({"query": query, "message": "XSS detection is active"})


@require_GET
def test_sqli(request: HttpRequest) -> JsonResponse:
    """Route to test SQL injection detection."""
    query = request.GET.get("q", "")
    return JsonResponse(
        {"query": query, "message": "SQL injection detection is active"}
    )


# ============================================================================
# Bypass Route
# ============================================================================


@require_GET
@security.bypass(["all"])
def unprotected(request: HttpRequest) -> JsonResponse:
    """Endpoint that bypasses all security checks."""
    return JsonResponse({"message": "This endpoint has no security checks"})
