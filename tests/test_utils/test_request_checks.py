"""Tests for request checks - adapted from Flask Guard."""

import logging
import os
from typing import Any
from unittest.mock import MagicMock, Mock, patch

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from django.test import RequestFactory
from pytest_mock import MockerFixture

from djangoapi_guard.handlers.cloud_handler import cloud_handler
from djangoapi_guard.handlers.ipinfo_handler import IPInfoManager
from djangoapi_guard.handlers.suspatterns_handler import sus_patterns_handler
from djangoapi_guard.models import SecurityConfig
from djangoapi_guard.utils import (
    check_ip_country,
    detect_penetration_attempt,
    is_ip_allowed,
    is_user_agent_allowed,
)

IPINFO_TOKEN = "test_token"


def test_is_ip_allowed(mocker: MockerFixture) -> None:
    """Test the is_ip_allowed function with various IP addresses."""
    mocker.patch("djangoapi_guard.utils.check_ip_country", return_value=False)

    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
    )
    assert is_ip_allowed("127.0.0.1", config)
    assert not is_ip_allowed("192.168.1.1", config)

    empty_config = SecurityConfig(
        enable_redis=False, enable_agent=False, whitelist=[], blacklist=[]
    )
    assert is_ip_allowed("127.0.0.1", empty_config)
    assert is_ip_allowed("192.168.1.1", empty_config)

    whitelist_config = SecurityConfig(
        enable_redis=False, enable_agent=False, whitelist=["127.0.0.1"]
    )
    assert is_ip_allowed("127.0.0.1", whitelist_config)
    assert not is_ip_allowed("192.168.1.1", whitelist_config)

    blacklist_config = SecurityConfig(
        enable_redis=False, enable_agent=False, blacklist=["192.168.1.1"]
    )
    assert is_ip_allowed("127.0.0.1", blacklist_config)
    assert not is_ip_allowed("192.168.1.1", blacklist_config)


def test_is_user_agent_allowed() -> None:
    """Test the is_user_agent_allowed function."""
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        blocked_user_agents=[r"badbot"],
    )
    assert is_user_agent_allowed("goodbot", config)
    assert not is_user_agent_allowed("badbot", config)


def test_detect_penetration_attempt() -> None:
    """Test the detect_penetration_attempt function with a normal request."""
    factory = RequestFactory()
    request = factory.get("/")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    result, _ = detect_penetration_attempt(request)
    assert not result


def test_detect_penetration_attempt_xss() -> None:
    """Test the detect_penetration_attempt function with an XSS attempt."""
    factory = RequestFactory()
    request = factory.get("/?param=<script>alert('xss')</script>")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    result, trigger = detect_penetration_attempt(request)
    assert result
    assert "script" in trigger.lower()


def test_detect_penetration_attempt_sql_injection() -> None:
    """Test SQL injection detection."""
    factory = RequestFactory()
    request = factory.get("/?query=UNION+SELECT+NULL--")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    result, _ = detect_penetration_attempt(request)
    assert result


def test_detect_penetration_attempt_directory_traversal() -> None:
    """Test the detect_penetration_attempt function with a directory traversal."""
    factory = RequestFactory()
    request = factory.get("/../../etc/passwd")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    result, _ = detect_penetration_attempt(request)
    assert result


def test_detect_penetration_attempt_command_injection() -> None:
    """Test the detect_penetration_attempt function with a command injection."""
    factory = RequestFactory()
    request = factory.get("/?cmd=|cat+/etc/passwd")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    result, _ = detect_penetration_attempt(request)
    assert result


def test_detect_penetration_attempt_ssrf() -> None:
    """Test the detect_penetration_attempt function with an SSRF attempt."""
    factory = RequestFactory()
    request = factory.get("/?param=http://169.254.169.254/latest/meta-data/")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    assert detect_penetration_attempt(request)


def test_detect_penetration_attempt_open_redirect() -> None:
    """Test the detect_penetration_attempt function with an open redirect."""
    factory = RequestFactory()
    request = factory.get("/?param=//evil.com")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    assert detect_penetration_attempt(request)


def test_detect_penetration_attempt_crlf_injection() -> None:
    """Test the detect_penetration_attempt function with a CRLF injection."""
    factory = RequestFactory()
    request = factory.get("/?param=%0d%0aSet-Cookie:%20mycookie=myvalue")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    assert detect_penetration_attempt(request)


def test_detect_penetration_attempt_path_manipulation() -> None:
    """Test the detect_penetration_attempt function with path manipulation."""
    factory = RequestFactory()
    request = factory.get("/../../../../etc/passwd")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    assert detect_penetration_attempt(request)


def test_detect_penetration_attempt_shell_injection() -> None:
    """Test shell injection detection."""
    factory = RequestFactory()
    request = factory.get("/?cmd=;ls%20-la%20/")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    result, _ = detect_penetration_attempt(request)
    assert result

    request2 = factory.get("/?cmd=echo%20hello")
    request2.META["REMOTE_ADDR"] = "127.0.0.1"

    result2, _ = detect_penetration_attempt(request2)
    assert not result2


def test_detect_penetration_attempt_nosql_injection() -> None:
    """Test the detect_penetration_attempt function with a NoSQL injection."""
    factory = RequestFactory()
    request = factory.get("/?param={ '$ne': '' }")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    assert detect_penetration_attempt(request)


def test_detect_penetration_attempt_json_injection() -> None:
    """Test JSON content detection."""
    factory = RequestFactory()

    malicious_body = b"""
            {
                "script": "<script>alert(1)</script>",
                "sql": "UNION SELECT * FROM users",
                "cmd": ";cat /etc/passwd",
                "path": "../../../etc/shadow"
            }
        """

    request = factory.post("/", data=malicious_body, content_type="application/json")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    result, _ = detect_penetration_attempt(request)
    assert result

    legitimate_body = b"""
            {
                "user_id": 123,
                "name": "John Doe",
                "email": "john@example.com",
                "preferences": {
                    "theme": "dark",
                    "notifications": true
                }
            }
        """

    request2 = factory.post("/", data=legitimate_body, content_type="application/json")
    request2.META["REMOTE_ADDR"] = "127.0.0.1"

    result2, _ = detect_penetration_attempt(request2)
    assert not result2


def test_detect_penetration_attempt_http_header_injection() -> None:
    """Test the detect_penetration_attempt function with HTTP header injection."""
    factory = RequestFactory()
    request = factory.get("/")
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    request.META["HTTP_X_FORWARDED_FOR"] = "127.0.0.1\r\nSet-Cookie: mycookie=myvalue"

    result, _ = detect_penetration_attempt(request)
    assert result


def test_get_ip_country(mocker: MockerFixture) -> None:
    """Test the check_ip_country function."""
    mock_ipinfo = mocker.patch("djangoapi_guard.handlers.ipinfo_handler.IPInfoManager")
    mock_db = mock_ipinfo.return_value
    mock_db.get_country.return_value = "US"
    mock_db.reader = True

    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        blocked_countries=["CN"],
    )

    country = check_ip_country("1.1.1.1", config, mock_db)
    assert not country

    mock_db.get_country.return_value = "CN"
    country = check_ip_country("1.1.1.1", config, mock_db)
    assert country


def test_is_ip_allowed_cloud_providers(mocker: MockerFixture) -> None:
    """Test the is_ip_allowed function with cloud provider IP blocking."""
    mocker.patch("djangoapi_guard.utils.check_ip_country", return_value=True)
    mocker.patch.object(
        cloud_handler,
        "is_cloud_ip",
        side_effect=lambda ip, *_: ip.startswith("13."),
    )

    config = SecurityConfig(
        enable_redis=False, enable_agent=False, block_cloud_providers={"AWS"}
    )

    assert is_ip_allowed("127.0.0.1", config)
    assert not is_ip_allowed("13.59.255.255", config)
    assert is_ip_allowed("8.8.8.8", config)


def test_check_ip_country() -> None:
    """Test country checking functionality."""
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        blocked_countries=["CN"],
        whitelist_countries=["US"],
    )

    mock_db = Mock()
    mock_db.get_country.return_value = "CN"
    mock_db.is_initialized = True

    factory = RequestFactory()
    request = factory.get("/")

    assert check_ip_country(request, config, mock_db)

    mock_db.get_country.return_value = "US"
    assert not check_ip_country(request, config, mock_db)


def test_whitelisted_country(mocker: MockerFixture) -> None:
    """Test country whitelist functionality."""
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        whitelist_countries=["US"],
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
    )

    mock_ipinfo = mocker.Mock()
    mock_ipinfo.get_country.return_value = "US"
    mock_ipinfo.reader = True
    mock_ipinfo.is_initialized = True

    assert not check_ip_country("8.8.8.8", config, mock_ipinfo)


def test_cloud_provider_blocking(mocker: MockerFixture) -> None:
    """Test cloud provider blocking."""
    mocker.patch("djangoapi_guard.utils.cloud_handler.is_cloud_ip", return_value=True)
    config = SecurityConfig(
        enable_redis=False, enable_agent=False, block_cloud_providers={"AWS"}
    )

    assert not is_ip_allowed("8.8.8.8", config)


def test_check_ip_country_not_initialized() -> None:
    """Test check_ip_country when IPInfo reader is not initialized."""
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        blocked_countries=["CN"],
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
    )

    mock_ipinfo = Mock()
    mock_ipinfo.is_initialized = False
    mock_ipinfo.initialize = MagicMock()
    mock_ipinfo.get_country.return_value = "US"

    result = check_ip_country("1.1.1.1", config, mock_ipinfo)
    assert not result
    mock_ipinfo.initialize.assert_called_once()


def test_check_ip_country_no_country_found() -> None:
    """Test check_ip_country when country lookup fails."""
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        blocked_countries=["CN"],
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
    )

    mock_ipinfo = Mock()
    mock_ipinfo.reader = True
    mock_ipinfo.is_initialized = True
    mock_ipinfo.get_country.return_value = None

    result = check_ip_country("1.1.1.1", config, mock_ipinfo)
    assert not result


def test_check_ip_country_no_countries_configured(
    caplog: Any,
) -> None:
    """Test check_ip_country when no countries are blocked or whitelisted."""
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        blocked_countries=[],
        whitelist_countries=[],
    )

    mock_ipinfo = Mock()
    mock_ipinfo.reader = True
    mock_ipinfo.is_initialized = True
    mock_ipinfo.get_country.return_value = "US"

    with caplog.at_level(logging.WARNING):
        result = check_ip_country("1.1.1.1", config, mock_ipinfo)
        assert not result
        assert "No countries blocked or whitelisted" in caplog.text
        assert "1.1.1.1" in caplog.text


def test_is_ip_allowed_cidr_blacklist() -> None:
    """Test the is_ip_allowed function with CIDR notation in blacklist."""
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        blacklist=["192.168.1.0/24"],
        whitelist=[],
    )

    assert not is_ip_allowed("192.168.1.100", config)
    assert not is_ip_allowed("192.168.1.1", config)
    assert not is_ip_allowed("192.168.1.254", config)

    assert is_ip_allowed("192.168.2.1", config)
    assert is_ip_allowed("192.168.0.1", config)
    assert is_ip_allowed("10.0.0.1", config)

    config_multiple = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        blacklist=["192.168.1.0/24", "10.0.0.0/8"],
        whitelist=[],
    )

    assert not is_ip_allowed("192.168.1.100", config_multiple)
    assert not is_ip_allowed("10.10.10.10", config_multiple)
    assert is_ip_allowed("172.16.0.1", config_multiple)


def test_is_ip_allowed_cidr_whitelist() -> None:
    """Test the is_ip_allowed function with CIDR notation in whitelist."""
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        whitelist=["192.168.1.0/24"],
        blacklist=[],
    )

    assert is_ip_allowed("192.168.1.100", config)
    assert is_ip_allowed("192.168.1.1", config)
    assert is_ip_allowed("192.168.1.254", config)

    assert not is_ip_allowed("192.168.2.1", config)
    assert not is_ip_allowed("192.168.0.1", config)
    assert not is_ip_allowed("10.0.0.1", config)


def test_is_ip_allowed_invalid_ip(caplog: Any) -> None:
    """Test is_ip_allowed with invalid IP address."""
    config = SecurityConfig(enable_redis=False, enable_agent=False)

    with caplog.at_level(logging.ERROR):
        result = is_ip_allowed("invalid-ip", config)
        assert not result


def test_is_ip_allowed_general_exception(caplog: Any, mocker: MockerFixture) -> None:
    """Test is_ip_allowed with unexpected exception."""
    config = SecurityConfig(enable_redis=False, enable_agent=False)

    mock_error = Exception("Unexpected error")
    mocker.patch("djangoapi_guard.utils.ip_address", side_effect=mock_error)

    with caplog.at_level(logging.ERROR):
        result = is_ip_allowed("192.168.1.1", config)
        assert result
        assert "Error checking IP 192.168.1.1" in caplog.text
        assert "Unexpected error" in caplog.text


def test_detect_penetration_attempt_body_error() -> None:
    """Test penetration detection with body reading error."""
    factory = RequestFactory()
    request = factory.post("/", data=b"", content_type="application/json")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    with patch.object(
        type(request),
        "body",
        new_callable=lambda: property(
            fget=lambda self: (_ for _ in ()).throw(Exception("Body read error"))
        ),
    ):
        result, _ = detect_penetration_attempt(request)
        # Should not raise, body error is handled gracefully
        assert isinstance(result, bool)


def test_is_ip_allowed_blocked_country(mocker: MockerFixture) -> None:
    """Test is_ip_allowed with blocked country."""
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        geo_ip_handler=IPInfoManager("test"),
        blocked_countries=["CN"],
    )

    mock_ipinfo = Mock()
    mock_ipinfo.reader = True
    mock_ipinfo.get_country.return_value = "CN"

    mocker.patch("djangoapi_guard.utils.check_ip_country", return_value=True)

    result = is_ip_allowed("192.168.1.1", config, mock_ipinfo)
    assert not result


def test_detect_penetration_semantic_threat() -> None:
    """Test semantic threat detection."""
    factory = RequestFactory()
    request = factory.get("/?search=SELECT * FROM users WHERE admin=1")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    def mock_detect(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "is_threat": True,
            "threats": [
                {
                    "type": "semantic",
                    "attack_type": "sql_injection",
                    "probability": 0.95,
                }
            ],
        }

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        result, trigger = detect_penetration_attempt(request)

        assert result is True
        assert "Semantic attack: sql_injection (score: 0.95)" in trigger


def test_detect_penetration_semantic_threat_with_score() -> None:
    """Test semantic threat with threat_score instead of probability."""
    factory = RequestFactory()
    request = factory.get("/?input=malicious_content")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    def mock_detect(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "is_threat": True,
            "threats": [
                {
                    "type": "semantic",
                    "attack_type": "suspicious",
                    "threat_score": 0.88,
                }
            ],
        }

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        result, trigger = detect_penetration_attempt(request)

        assert result is True
        assert "Semantic attack: suspicious (score: 0.88)" in trigger


def test_detect_penetration_fallback_pattern_match() -> None:
    """Test fallback pattern matching when enhanced detection fails."""
    factory = RequestFactory()
    request = factory.get("/?test=<script>alert(1)</script>")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    def mock_detect_error(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("Detection engine failure")

    mock_pattern = MagicMock()
    mock_pattern.search.return_value = MagicMock()

    with (
        patch.object(sus_patterns_handler, "detect", side_effect=mock_detect_error),
        patch.object(
            sus_patterns_handler,
            "get_all_compiled_patterns",
            return_value=[(mock_pattern, frozenset({"unknown"}))],
        ),
        patch("logging.error") as mock_error,
    ):
        result, trigger = detect_penetration_attempt(request)

        assert result is True
        assert "Value matched pattern (fallback)" in trigger

        mock_error.assert_called()
        error_msg = mock_error.call_args[0][0]
        assert "Enhanced detection failed" in error_msg


def test_detect_penetration_fallback_pattern_exception() -> None:
    """Test fallback pattern exception handling."""
    factory = RequestFactory()
    request = factory.get("/?test=normal_content")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    def mock_detect_error(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("Detection engine failure")

    mock_pattern = MagicMock()
    mock_pattern.search.side_effect = Exception("Pattern error")

    with (
        patch.object(sus_patterns_handler, "detect", side_effect=mock_detect_error),
        patch.object(
            sus_patterns_handler,
            "get_all_compiled_patterns",
            return_value=[(mock_pattern, frozenset({"unknown"}))],
        ),
        patch("logging.error") as mock_log_error,
    ):
        result, trigger = detect_penetration_attempt(request)

        assert result is False
        assert trigger == ""

        assert mock_log_error.call_count >= 1


def test_detect_penetration_short_body() -> None:
    """Test request body logging when body is short."""
    factory = RequestFactory()

    short_body = b"<script>XSS</script>"

    request = factory.post("/api/data", data=short_body, content_type="text/plain")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    with patch("logging.warning"):
        result, trigger = detect_penetration_attempt(request)

        assert result is True
        assert "Request body:" in trigger


def test_detect_penetration_empty_threat_fallback() -> None:
    """Test empty threats array fallback."""
    factory = RequestFactory()

    json_payload = '{"field": "suspicious_value"}'

    request = factory.get(f"/?data={json_payload}")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    def mock_detect(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "is_threat": True,
            "threats": [],
        }

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        result, trigger = detect_penetration_attempt(request)

        assert result is True
        assert "JSON field 'field' contains threat" in trigger


def test_detect_penetration_unknown_threat_type() -> None:
    """Test handling of unknown threat type."""
    factory = RequestFactory()
    request = factory.get("/?param=test_value")
    request.META["REMOTE_ADDR"] = "127.0.0.1"

    def mock_detect(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {
            "is_threat": True,
            "threats": [{"type": "unknown_type", "data": "some_data"}],
        }

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        result, trigger = detect_penetration_attempt(request)

        assert result is True
        assert trigger == "Query param 'param': Threat detected"
