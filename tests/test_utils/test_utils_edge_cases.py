import os
from typing import cast
from unittest.mock import MagicMock, Mock, patch

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from django.test import RequestFactory

from djangoapi_guard.core.checks.helpers import is_referrer_domain_allowed
from djangoapi_guard.models import SecurityConfig
from djangoapi_guard.utils import (
    _extract_from_forwarded_header,
    _sanitize_for_log,
    detect_penetration_attempt,
    extract_client_ip,
)


class TestSanitizeForLog:
    """Test _sanitize_for_log edge cases."""

    def test_sanitize_empty_string(self) -> None:
        """Test sanitize with empty string returns empty string."""
        result = _sanitize_for_log("")
        assert result == ""

    def test_sanitize_none(self) -> None:
        result = _sanitize_for_log(cast(str, None))
        assert result is None

    def test_sanitize_with_content(self) -> None:
        """Test sanitize with actual content works."""
        result = _sanitize_for_log("test\nvalue")
        assert result == "test\\nvalue"


class TestExtractFromForwardedHeader:
    """Test _extract_from_forwarded_header edge cases."""

    def test_extract_empty_header(self) -> None:
        """Test extract with empty header returns None."""
        result = _extract_from_forwarded_header("", 1)
        assert result is None

    def test_extract_with_valid_header(self) -> None:
        """Test extract with valid header."""
        result = _extract_from_forwarded_header("1.2.3.4, 5.6.7.8", 2)
        assert result == "1.2.3.4"


class TestExtractClientIPExceptionHandling:
    """Test extract_client_ip exception handling."""

    def test_extract_client_ip_with_invalid_forwarded_for(self) -> None:
        """Test extract_client_ip handles ValueError/IndexError gracefully."""
        factory = RequestFactory()
        request = factory.get("/", HTTP_X_FORWARDED_FOR="invalid-ip-format")
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        config = SecurityConfig(enable_redis=False, enable_agent=False)
        config.trusted_proxies = ["127.0.0.1"]
        config.trusted_proxy_depth = 999

        with patch(
            "djangoapi_guard.utils._extract_from_forwarded_header",
            side_effect=ValueError("Invalid IP"),
        ):
            result = extract_client_ip(request, config, None)
            assert result == "127.0.0.1"

    def test_extract_client_ip_logs_warning_on_error(self) -> None:
        """Test that extract_client_ip logs warning when exception occurs."""
        factory = RequestFactory()
        request = factory.get("/", HTTP_X_FORWARDED_FOR="1.2.3.4")
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        config = SecurityConfig(enable_redis=False, enable_agent=False)
        config.trusted_proxies = ["127.0.0.1"]
        config.trusted_proxy_depth = 1

        with (
            patch(
                "djangoapi_guard.utils._extract_from_forwarded_header",
                side_effect=IndexError("Test error"),
            ),
            patch("djangoapi_guard.utils.logging") as mock_logging,
        ):
            result = extract_client_ip(request, config, None)

            assert result == "127.0.0.1"
            mock_logging.warning.assert_any_call(
                "Error processing client IP: Test error"
            )


class TestDetectPenetrationAttemptURLPath:
    """Test detect_penetration_attempt URL path checking."""

    def test_detect_penetration_url_path_with_real_threat(self) -> None:
        """Test penetration detection in URL path with REAL threat."""
        factory = RequestFactory()
        request = factory.get("/../../etc/passwd")
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        detected, trigger = detect_penetration_attempt(request)

        assert detected is True
        assert "URL path" in trigger


class TestSendAgentEvent:
    """Test send_agent_event helper from utils."""

    def test_send_agent_event_with_request(self) -> None:
        """Test send_agent_event sends event with request info."""
        import sys
        import types

        from djangoapi_guard.utils import send_agent_event

        mock_agent = Mock()
        mock_agent.send_event = MagicMock()

        mock_module = types.ModuleType("guard_agent")

        class MockSecurityEvent:
            def __init__(self, **kwargs: object) -> None:
                for k, v in kwargs.items():
                    setattr(self, k, v)

        mock_module.SecurityEvent = MockSecurityEvent  # type: ignore[attr-defined]
        original = sys.modules.get("guard_agent")
        sys.modules["guard_agent"] = mock_module

        try:
            factory = RequestFactory()
            request = factory.post("/test", HTTP_USER_AGENT="TestAgent")

            send_agent_event(
                mock_agent,
                "test_event",
                "1.2.3.4",
                "blocked",
                "test reason",
                request=request,
            )
            mock_agent.send_event.assert_called_once()
        finally:
            if original:
                sys.modules["guard_agent"] = original
            else:
                sys.modules.pop("guard_agent", None)

    def test_send_agent_event_no_agent(self) -> None:
        """Test send_agent_event returns early when no agent."""
        from djangoapi_guard.utils import send_agent_event

        send_agent_event(None, "test_event", "1.2.3.4", "blocked", "test reason")

    def test_send_agent_event_exception(self) -> None:
        """Test send_agent_event handles exceptions gracefully."""
        import sys
        import types

        from djangoapi_guard.utils import send_agent_event

        mock_agent = Mock()
        mock_agent.send_event = Mock(side_effect=Exception("Agent error"))

        mock_module = types.ModuleType("guard_agent")
        mock_module.SecurityEvent = Mock(side_effect=Exception("Import error"))  # type: ignore[attr-defined]
        original = sys.modules.get("guard_agent")
        sys.modules["guard_agent"] = mock_module

        try:
            send_agent_event(
                mock_agent, "test_event", "1.2.3.4", "blocked", "test reason"
            )
        finally:
            if original:
                sys.modules["guard_agent"] = original
            else:
                sys.modules.pop("guard_agent", None)


class TestExtractClientIPWithTrustedProxies:
    """Test extract_client_ip with trusted proxy configuration."""

    def test_extract_client_ip_with_trusted_proxy_success(self) -> None:
        """Test extract_client_ip extracts from X-Forwarded-For via trusted proxy."""
        factory = RequestFactory()
        request = factory.get("/", HTTP_X_FORWARDED_FOR="203.0.113.50, 192.168.1.1")
        request.META["REMOTE_ADDR"] = "192.168.1.1"

        config = SecurityConfig(enable_redis=False, enable_agent=False)
        config.trusted_proxies = ["192.168.1.1"]
        config.trusted_proxy_depth = 1

        result = extract_client_ip(request, config, None)
        assert result == "203.0.113.50"

    def test_extract_client_ip_no_remote_addr(self) -> None:
        """Test extract_client_ip returns 'unknown' when remote_addr is empty."""
        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = ""

        config = SecurityConfig(enable_redis=False, enable_agent=False)

        result = extract_client_ip(request, config, None)
        assert result == "unknown"


class TestJsonFieldSemanticThreat:
    """Test _check_json_field_threats with non-regex threat type (e.g., semantic)."""

    def test_non_regex_threat_type(self) -> None:
        """JSON field threat with type != 'regex' returns threat_type description."""
        from djangoapi_guard.utils import _check_json_fields

        mock_result = {
            "is_threat": True,
            "threats": [
                {
                    "type": "semantic",
                    "attack_type": "sql_injection",
                    "probability": 0.95,
                }
            ],
        }

        with patch("djangoapi_guard.utils.sus_patterns_handler") as mock_handler:
            mock_handler.detect.return_value = mock_result

            detected, trigger = _check_json_fields(
                {"username": "malicious_value"},
                "request_body",
                "1.2.3.4",
                "test-correlation-id",
            )

        assert detected is True
        assert "semantic" in trigger
        assert "username" in trigger


class TestReferrerDomainAllowedExceptionHandling:
    """Test is_referrer_domain_allowed exception handling."""

    def test_is_referrer_domain_allowed_with_none(self) -> None:
        result = is_referrer_domain_allowed(cast(str, None), ["example.com"])
        assert result is False

    def test_is_referrer_domain_allowed_with_invalid_type(self) -> None:
        result = is_referrer_domain_allowed(cast(str, 12345), ["example.com"])
        assert result is False

    def test_is_referrer_domain_allowed_with_malformed_url(self) -> None:
        """Test exception handling when URL parsing fails."""
        result = is_referrer_domain_allowed("://no-scheme", ["example.com"])
        assert result is False
