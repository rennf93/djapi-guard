"""
Simple example views demonstrating DjangoAPI Guard.

These views are protected by the DjangoAPIGuard middleware
configured in settings.py. Security features like rate limiting,
IP filtering, penetration detection, and security headers are
applied automatically to all requests.
"""

from datetime import datetime, timezone

from django.http import HttpRequest, JsonResponse


def root(request: HttpRequest) -> JsonResponse:
    """Root endpoint."""
    return JsonResponse(
        {
            "message": "DjangoAPI Guard Simple Example",
            "docs": "/api/info",
            "health": "/health",
        }
    )


def health(request: HttpRequest) -> JsonResponse:
    """Health check endpoint (excluded from security checks via exclude_paths)."""
    timestamp = datetime.now(timezone.utc).isoformat()
    return JsonResponse({"status": "healthy", "timestamp": timestamp})


def api_info(request: HttpRequest) -> JsonResponse:
    """API information endpoint."""
    return JsonResponse(
        {
            "name": "DjangoAPI Guard Simple Example",
            "version": "1.0.0",
            "security": "enabled",
            "features": [
                "rate_limiting",
                "ip_filtering",
                "penetration_detection",
                "security_headers",
            ],
        }
    )


def api_data(request: HttpRequest) -> JsonResponse:
    """Sample data endpoint protected by rate limiting and security checks."""
    return JsonResponse(
        {
            "data": [
                {"id": 1, "name": "Item 1"},
                {"id": 2, "name": "Item 2"},
                {"id": 3, "name": "Item 3"},
            ],
            "count": 3,
        }
    )


def test_xss(request: HttpRequest) -> JsonResponse:
    """Route to test XSS detection (try adding script tags in query params)."""
    query = request.GET.get("q", "")
    return JsonResponse({"query": query, "message": "XSS detection is active"})


def test_sqli(request: HttpRequest) -> JsonResponse:
    """Route to test SQL injection detection."""
    query = request.GET.get("q", "")
    return JsonResponse(
        {"query": query, "message": "SQL injection detection is active"}
    )
