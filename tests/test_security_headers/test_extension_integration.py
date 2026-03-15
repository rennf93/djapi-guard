import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from collections.abc import Generator

import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory

from djangoapi_guard.handlers.security_headers_handler import security_headers_manager
from djangoapi_guard.middleware import DjangoAPIGuard
from djangoapi_guard.models import SecurityConfig


@pytest.fixture
def reset_headers_manager() -> Generator[None, None, None]:
    """Reset security headers manager state before each test."""
    security_headers_manager.reset()
    yield
    security_headers_manager.reset()


def test_security_headers_none_config(reset_headers_manager: None) -> None:
    """Test when config.security_headers is None."""
    config = SecurityConfig(
        security_headers=None,
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )

    def dummy_view(request: HttpRequest) -> HttpResponse:
        return HttpResponse('{"message": "test"}', content_type="application/json")

    from django.conf import settings

    original_config = getattr(settings, "GUARD_SECURITY_CONFIG", None)
    settings.GUARD_SECURITY_CONFIG = config

    try:
        middleware = DjangoAPIGuard(dummy_view)
        factory = RequestFactory()
        request = factory.get("/test")
        response = middleware(request)

        assert security_headers_manager.enabled is False
        assert response.status_code == 200

        assert not response.has_header("X-Content-Type-Options")
        assert not response.has_header("X-Frame-Options")
        assert not response.has_header("X-XSS-Protection")
    finally:
        if original_config is None:
            if hasattr(settings, "GUARD_SECURITY_CONFIG"):
                delattr(settings, "GUARD_SECURITY_CONFIG")
        else:
            settings.GUARD_SECURITY_CONFIG = original_config


def test_security_headers_disabled_config(reset_headers_manager: None) -> None:
    """Test when security headers are explicitly disabled."""
    config = SecurityConfig(
        security_headers={"enabled": False},
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )

    def dummy_view(request: HttpRequest) -> HttpResponse:
        return HttpResponse('{"message": "test"}', content_type="application/json")

    from django.conf import settings

    original_config = getattr(settings, "GUARD_SECURITY_CONFIG", None)
    settings.GUARD_SECURITY_CONFIG = config

    try:
        middleware = DjangoAPIGuard(dummy_view)
        factory = RequestFactory()
        request = factory.get("/test")
        response = middleware(request)

        assert response.status_code == 200
        assert not response.has_header("X-Content-Type-Options")
        assert not response.has_header("X-Frame-Options")
    finally:
        if original_config is None:
            if hasattr(settings, "GUARD_SECURITY_CONFIG"):
                delattr(settings, "GUARD_SECURITY_CONFIG")
        else:
            settings.GUARD_SECURITY_CONFIG = original_config
