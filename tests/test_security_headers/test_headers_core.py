import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from collections.abc import Generator
from typing import Any

import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from djangoapi_guard.handlers.ratelimit_handler import RateLimitManager
from djangoapi_guard.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)
from djangoapi_guard.middleware import DjangoAPIGuard
from djangoapi_guard.models import SecurityConfig


@pytest.fixture
def reset_headers_manager() -> Generator[None, None, None]:
    """Reset security headers manager state before each test."""
    security_headers_manager.reset()
    RateLimitManager._instance = None
    yield
    security_headers_manager.reset()
    RateLimitManager._instance = None


def _create_middleware_and_request(
    config: SecurityConfig,
    view: Any = None,
) -> HttpResponse:
    if view is None:

        def view(request: Any) -> HttpResponse:
            return HttpResponse('{"message": "test"}', content_type="application/json")

    from django.conf import settings

    original_config = getattr(settings, "GUARD_SECURITY_CONFIG", None)
    settings.GUARD_SECURITY_CONFIG = config

    try:
        middleware = DjangoAPIGuard(view)
        factory = RequestFactory()
        request = factory.get("/test")
        response = middleware(request)
    finally:
        if original_config is None:
            if hasattr(settings, "GUARD_SECURITY_CONFIG"):
                delattr(settings, "GUARD_SECURITY_CONFIG")
        else:
            settings.GUARD_SECURITY_CONFIG = original_config

    return response


def test_default_security_headers(reset_headers_manager: None) -> None:
    """Test that default security headers are applied."""
    config = SecurityConfig(
        security_headers={"enabled": True},
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )

    response = _create_middleware_and_request(config)

    assert response.status_code == 200
    assert response["X-Content-Type-Options"] == "nosniff"
    assert response["X-Frame-Options"] == "SAMEORIGIN"
    assert response["X-XSS-Protection"] == "1; mode=block"
    assert response["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert response.has_header("Permissions-Policy")


def test_custom_csp_header(reset_headers_manager: None) -> None:
    """Test Content Security Policy header configuration."""
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "csp": {
                "default-src": ["'self'"],
                "script-src": ["'self'", "https://trusted.cdn.com"],
                "style-src": ["'self'", "'unsafe-inline'"],
            },
        },
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )

    response = _create_middleware_and_request(config)

    assert response.status_code == 200
    csp = response["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self' https://trusted.cdn.com" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp


def test_hsts_header(reset_headers_manager: None) -> None:
    """Test HTTP Strict Transport Security header."""
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "hsts": {
                "max_age": 31536000,
                "include_subdomains": True,
                "preload": True,
            },
        },
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )

    response = _create_middleware_and_request(config)

    assert response.status_code == 200
    hsts = response["Strict-Transport-Security"]
    assert "max-age=31536000" in hsts
    assert "includeSubDomains" in hsts
    assert "preload" in hsts


def test_custom_headers(reset_headers_manager: None) -> None:
    """Test custom security headers."""
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "custom": {
                "X-Custom-Header": "custom-value",
                "X-Another-Header": "another-value",
            },
        },
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )

    response = _create_middleware_and_request(config)

    assert response.status_code == 200
    assert response["X-Custom-Header"] == "custom-value"
    assert response["X-Another-Header"] == "another-value"


def test_frame_options_deny(reset_headers_manager: None) -> None:
    """Test X-Frame-Options with DENY value."""
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "frame_options": "DENY",
        },
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )

    response = _create_middleware_and_request(config)

    assert response.status_code == 200
    assert response["X-Frame-Options"] == "DENY"


def test_custom_referrer_policy(reset_headers_manager: None) -> None:
    """Test custom Referrer-Policy header."""
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "referrer_policy": "no-referrer",
        },
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )

    response = _create_middleware_and_request(config)

    assert response.status_code == 200
    assert response["Referrer-Policy"] == "no-referrer"


def test_permissions_policy_disabled(reset_headers_manager: None) -> None:
    """Test disabling Permissions-Policy header."""
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "permissions_policy": None,
        },
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )

    response = _create_middleware_and_request(config)

    assert response.status_code == 200
    assert not response.has_header("Permissions-Policy")


def test_security_headers_disabled(reset_headers_manager: None) -> None:
    """Test that security headers are not added when disabled."""
    config = SecurityConfig(
        security_headers={"enabled": False},
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )

    response = _create_middleware_and_request(config)

    assert response.status_code == 200
    assert not response.has_header("X-Content-Type-Options")
    assert not response.has_header("X-Frame-Options")


def test_security_headers_on_error_response(reset_headers_manager: None) -> None:
    """Test that security headers are added to error responses."""
    config = SecurityConfig(
        security_headers={"enabled": True},
        custom_request_check=lambda request: HttpResponse(
            "Forbidden by custom check", status=403
        ),
        enable_redis=False,
        enable_agent=False,
        passive_mode=False,
        rate_limit=1000,
    )

    response = _create_middleware_and_request(config)

    assert response.status_code == 403
    assert response.content.decode() == "Forbidden by custom check"
    # Note: In Django Guard, blocked responses from the security pipeline
    # are returned before post-processing (which applies security headers),
    # so security headers are NOT applied to blocked responses.


def test_security_headers_manager_singleton() -> None:
    """Test that SecurityHeadersManager is a singleton."""
    manager1 = SecurityHeadersManager()
    manager2 = SecurityHeadersManager()

    assert manager1 is manager2
    assert manager1 is security_headers_manager


def test_headers_caching() -> None:
    """Test that headers are cached properly."""
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        csp={"default-src": ["'self'"]},
    )

    headers1 = manager.get_headers("/test")
    assert "Content-Security-Policy" in headers1

    headers2 = manager.get_headers("/test")
    assert headers1 == headers2

    headers3 = manager.get_headers("/different")
    assert "Content-Security-Policy" in headers3


def test_new_default_security_headers() -> None:
    """Test that new security headers are in defaults."""
    manager = SecurityHeadersManager()

    headers = manager.get_headers()

    assert "X-Permitted-Cross-Domain-Policies" in headers
    assert headers["X-Permitted-Cross-Domain-Policies"] == "none"

    assert "X-Download-Options" in headers
    assert headers["X-Download-Options"] == "noopen"

    assert "Cross-Origin-Embedder-Policy" in headers
    assert headers["Cross-Origin-Embedder-Policy"] == "require-corp"

    assert "Cross-Origin-Opener-Policy" in headers
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"

    assert "Cross-Origin-Resource-Policy" in headers
    assert headers["Cross-Origin-Resource-Policy"] == "same-origin"


def test_original_headers_still_present() -> None:
    """Test that original security headers are still included."""
    manager = SecurityHeadersManager()

    headers = manager.get_headers()

    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "SAMEORIGIN"
    assert headers["X-XSS-Protection"] == "1; mode=block"
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert headers["Permissions-Policy"] == "geolocation=(), microphone=(), camera=()"


def test_configure_with_all_params() -> None:
    """Test configure method with all parameters."""
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        csp={"default-src": ["'self'"]},
        hsts_max_age=31536000,
        hsts_include_subdomains=True,
        hsts_preload=True,
        frame_options="DENY",
        content_type_options="nosniff",
        xss_protection="0",
        referrer_policy="no-referrer",
        permissions_policy="camera=()",
        custom_headers={"X-Test": "value"},
        cors_origins=["https://example.com"],
        cors_allow_credentials=False,
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["Content-Type"],
    )

    headers = manager.get_headers("/test")
    assert "Content-Security-Policy" in headers
    assert "Strict-Transport-Security" in headers
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-XSS-Protection"] == "0"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Permissions-Policy"] == "camera=()"
    assert headers["X-Test"] == "value"


def test_configure_disabled() -> None:
    """Test configure with enabled=False."""
    manager = SecurityHeadersManager()
    manager.configure(enabled=False)

    headers = manager.get_headers("/test")
    assert headers == {}


def test_get_headers_without_path() -> None:
    """Test get_headers without specifying a path."""
    manager = SecurityHeadersManager()
    manager.configure(enabled=True)

    headers = manager.get_headers()
    assert "X-Content-Type-Options" in headers


def test_get_headers_with_path() -> None:
    """Test get_headers with a specific path."""
    manager = SecurityHeadersManager()
    manager.configure(enabled=True)

    headers = manager.get_headers("/api/users")
    assert "X-Content-Type-Options" in headers


def test_build_hsts_basic() -> None:
    """Test basic HSTS header building."""
    manager = SecurityHeadersManager()

    hsts_config = {"max_age": 31536000}
    result = manager._build_hsts(hsts_config)
    assert result == "max-age=31536000"


def test_build_hsts_with_all_options() -> None:
    """Test HSTS header building with all options."""
    manager = SecurityHeadersManager()

    hsts_config = {
        "max_age": 31536000,
        "include_subdomains": True,
        "preload": True,
    }
    result = manager._build_hsts(hsts_config)
    assert "max-age=31536000" in result
    assert "includeSubDomains" in result
    assert "preload" in result


def test_reset_clears_all_state() -> None:
    """Test that reset clears all configuration state."""
    manager = SecurityHeadersManager()
    manager.configure(
        csp={"default-src": ["'self'"]},
        hsts_max_age=31536000,
        custom_headers={"X-Custom": "value"},
        cors_origins=["https://example.com"],
    )

    manager.reset()

    assert manager.csp_config is None
    assert manager.hsts_config is None
    assert manager.cors_config is None
    assert len(manager.custom_headers) == 0
    assert manager.enabled is True


def test_add_custom_headers_none() -> None:
    """Test _add_custom_headers with None input."""
    manager = SecurityHeadersManager()
    original_custom = dict(manager.custom_headers)

    manager._add_custom_headers(None)

    assert manager.custom_headers == original_custom


def test_configure_cors_empty_origins() -> None:
    """Test _configure_cors with empty origins list."""
    manager = SecurityHeadersManager()

    manager._configure_cors([], False, None, None)

    assert manager.cors_config is None
