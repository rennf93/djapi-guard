"""
Django settings for the advanced example project.

Demonstrates DjangoAPI Guard with:
- Redis integration for distributed rate limiting
- CORS configuration
- Behavioral analysis
- Custom authentication schemes
- Cloud provider IP blocking
- Time-based access control
"""

import os

from djangoapi_guard import SecurityConfig

# ============================================================================
# Django Core Settings
# ============================================================================

SECRET_KEY = "example-secret-key-do-not-use-in-production"

DEBUG = True

ALLOWED_HOSTS = ["*"]

ROOT_URLCONF = "advanced_project.urls"

WSGI_APPLICATION = "advanced_project.wsgi.application"

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
# DjangoAPI Guard Configuration (Advanced)
# ============================================================================

GUARD_SECURITY_CONFIG = SecurityConfig(
    # Redis configuration for distributed environments
    enable_redis=True,
    redis_url=os.getenv("REDIS_URL", "redis://localhost:6379"),
    redis_prefix=os.getenv("REDIS_PREFIX", "djangoapi_guard:"),
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
    # CORS
    enable_cors=True,
    cors_allow_origins=["*"],
    cors_allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    cors_allow_headers=["*"],
    cors_allow_credentials=False,
    # Path exclusions
    exclude_paths=["/health", "/static", "/favicon.ico"],
    # HTTPS (disabled for local development)
    enforce_https=False,
)
