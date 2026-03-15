"""
Django settings for the simple example project.

Demonstrates basic DjangoAPI Guard configuration with:
- Rate limiting
- IP blacklisting
- Security headers
- Penetration detection
"""

from djangoapi_guard import SecurityConfig

# ============================================================================
# Django Core Settings
# ============================================================================

SECRET_KEY = "example-secret-key-do-not-use-in-production"

DEBUG = True

ALLOWED_HOSTS = ["*"]

ROOT_URLCONF = "example_project.urls"

WSGI_APPLICATION = "example_project.wsgi.application"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ============================================================================
# Installed Apps
# ============================================================================

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
]

# ============================================================================
# Middleware
# ============================================================================

MIDDLEWARE = [
    "djangoapi_guard.DjangoAPIGuard",
    "django.middleware.common.CommonMiddleware",
]

# ============================================================================
# DjangoAPI Guard Configuration
# ============================================================================

GUARD_SECURITY_CONFIG = SecurityConfig(
    # Rate limiting
    rate_limit=100,
    rate_limit_window=60,
    # IP management
    whitelist=["127.0.0.1", "::1"],
    blacklist=[],
    # Auto-banning
    auto_ban_threshold=10,
    auto_ban_duration=3600,
    enable_ip_banning=True,
    # Penetration detection
    enable_penetration_detection=True,
    # Logging
    log_suspicious_level="WARNING",
    log_request_level="INFO",
    # Security headers
    security_headers={
        "enabled": True,
        "csp": "default-src 'self'; script-src 'self'",
        "hsts": {
            "max_age": 31536000,
            "include_subdomains": True,
            "preload": False,
        },
        "frame_options": "DENY",
        "content_type_options": "nosniff",
        "xss_protection": "1; mode=block",
        "referrer_policy": "strict-origin-when-cross-origin",
    },
    # Path exclusions
    exclude_paths=["/health", "/static", "/favicon.ico"],
    # HTTPS (disabled for local development)
    enforce_https=False,
)
