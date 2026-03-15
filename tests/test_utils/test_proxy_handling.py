"""Tests for proxy handling - adapted from Flask Guard."""

import logging
import os
from unittest.mock import patch

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

import pytest
from django.test import RequestFactory

from djangoapi_guard.models import SecurityConfig
from djangoapi_guard.utils import extract_client_ip


def test_extract_client_ip_without_trusted_proxies() -> None:
    """Test extracting client IP without trusted proxies."""
    config = SecurityConfig(enable_redis=False, enable_agent=False)

    factory = RequestFactory()
    request = factory.get("/", HTTP_X_FORWARDED_FOR="1.2.3.4")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    ip = extract_client_ip(request, config)
    assert ip == "127.0.0.1"


def test_extract_client_ip_with_trusted_proxies() -> None:
    """Test extracting client IP with trusted proxies."""
    config = SecurityConfig(
        enable_redis=False, enable_agent=False, trusted_proxies=["127.0.0.1"]
    )

    factory = RequestFactory()
    request = factory.get("/", HTTP_X_FORWARDED_FOR="1.2.3.4")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    ip = extract_client_ip(request, config)
    assert ip == "1.2.3.4"


def test_extract_client_ip_with_cidr_trusted_proxies() -> None:
    """Test extracting client IP with CIDR notation in trusted proxies."""
    config = SecurityConfig(
        enable_redis=False, enable_agent=False, trusted_proxies=["127.0.0.0/8"]
    )

    factory = RequestFactory()
    request = factory.get("/", HTTP_X_FORWARDED_FOR="1.2.3.4")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    ip = extract_client_ip(request, config)
    assert ip == "1.2.3.4"


def test_extract_client_ip_with_proxy_depth() -> None:
    """Test extracting client IP with proxy depth."""
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        trusted_proxies=["127.0.0.1"],
        trusted_proxy_depth=2,
    )

    factory = RequestFactory()
    request = factory.get("/", HTTP_X_FORWARDED_FOR="5.6.7.8, 1.2.3.4")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    ip = extract_client_ip(request, config)
    assert ip == "5.6.7.8"


def test_extract_client_ip_without_xforwarded() -> None:
    """Test extracting client IP from trusted proxy but without X-Forwarded-For."""
    config = SecurityConfig(
        enable_redis=False, enable_agent=False, trusted_proxies=["127.0.0.1"]
    )

    factory = RequestFactory()
    request = factory.get("/")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    request.META.pop("HTTP_X_FORWARDED_FOR", None)

    ip = extract_client_ip(request, config)
    assert ip == "127.0.0.1"


def test_extract_client_ip_with_untrusted_proxy() -> None:
    """Test extracting client IP from untrusted proxy."""
    config = SecurityConfig(
        enable_redis=False, enable_agent=False, trusted_proxies=["10.0.0.1"]
    )

    factory = RequestFactory()
    request = factory.get("/", HTTP_X_FORWARDED_FOR="1.2.3.4")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    ip = extract_client_ip(request, config)
    assert ip == "127.0.0.1"


def test_extract_client_ip_error_handling(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test error handling in extract_client_ip when ip_address validation fails."""
    config = SecurityConfig(
        enable_redis=False, enable_agent=False, trusted_proxies=["127.0.0.1"]
    )

    factory = RequestFactory()
    request = factory.get("/", HTTP_X_FORWARDED_FOR="invalid-ip")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    with caplog.at_level(logging.WARNING):
        with patch(
            "djangoapi_guard.utils.ip_address", side_effect=ValueError("Invalid IP")
        ):
            ip = extract_client_ip(request, config)
            assert ip == "127.0.0.1"
            assert "Potential IP spoof attempt" in caplog.text


def test_extract_client_ip_fallback_to_connecting_ip() -> None:
    """Test falling back to connecting IP when forwarded chain is too short."""
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        trusted_proxies=["127.0.0.1"],
        trusted_proxy_depth=3,
    )

    factory = RequestFactory()
    request = factory.get("/", HTTP_X_FORWARDED_FOR="1.2.3.4")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    ip = extract_client_ip(request, config)
    assert ip == "127.0.0.1"


def test_extract_client_ip_untrusted_without_forwarded() -> None:
    """Test extracting client IP from untrusted proxy without X-Forwarded-For."""
    config = SecurityConfig(
        enable_redis=False, enable_agent=False, trusted_proxies=["10.0.0.1"]
    )

    factory = RequestFactory()
    request = factory.get("/")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    request.META.pop("HTTP_X_FORWARDED_FOR", None)

    ip = extract_client_ip(request, config)
    assert ip == "127.0.0.1"
