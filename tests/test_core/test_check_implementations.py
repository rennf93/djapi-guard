"""Tests for all missing check implementations"""

import os
from collections import defaultdict
from datetime import datetime
from unittest.mock import Mock, patch

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from djangoapi_guard.core.checks.implementations.authentication import (
    AuthenticationCheck,
)
from djangoapi_guard.core.checks.implementations.cloud_provider import (
    CloudProviderCheck,
)
from djangoapi_guard.core.checks.implementations.custom_request import (
    CustomRequestCheck,
)
from djangoapi_guard.core.checks.implementations.custom_validators import (
    CustomValidatorsCheck,
)
from djangoapi_guard.core.checks.implementations.https_enforcement import (
    HttpsEnforcementCheck,
)
from djangoapi_guard.core.checks.implementations.ip_security import IpSecurityCheck
from djangoapi_guard.core.checks.implementations.rate_limit import RateLimitCheck
from djangoapi_guard.core.checks.implementations.referrer import ReferrerCheck
from djangoapi_guard.core.checks.implementations.request_size_content import (
    RequestSizeContentCheck,
)
from djangoapi_guard.core.checks.implementations.required_headers import (
    RequiredHeadersCheck,
    _classify_header_violation,
)
from djangoapi_guard.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from djangoapi_guard.core.checks.implementations.time_window import TimeWindowCheck
from djangoapi_guard.core.checks.implementations.user_agent import UserAgentCheck
from djangoapi_guard.core.events import MetricsCollector
from djangoapi_guard.core.responses.context import ResponseContext
from djangoapi_guard.core.responses.factory import ErrorResponseFactory
from djangoapi_guard.decorators.base import RouteConfig
from djangoapi_guard.models import SecurityConfig


@pytest.fixture
def rf() -> RequestFactory:
    return RequestFactory()


@pytest.fixture
def mock_guard() -> Mock:
    guard = Mock()
    guard.config = SecurityConfig(enable_redis=False, enable_agent=False)
    guard.logger = Mock()
    guard.event_bus = Mock()
    guard.create_error_response = Mock(
        side_effect=lambda status_code, default_message: HttpResponse(
            default_message, status=status_code
        )
    )
    guard.route_resolver = Mock()
    guard.rate_limit_handler = Mock()
    guard.response_factory = Mock()
    guard.redis_handler = None
    guard.geo_ip_handler = None
    guard.suspicious_request_counts = defaultdict(int)
    return guard


# ── AuthenticationCheck ──────────────────────────────────────────────


class TestAuthenticationCheck:
    def test_auth_failure_active_mode_returns_401(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """active mode returns 401."""
        mock_guard.config.passive_mode = False
        check = AuthenticationCheck(mock_guard)
        request = rf.get("/test")
        request._guard_route_config = RouteConfig()
        request._guard_route_config.auth_required = "bearer"
        result = check.check(request)
        assert result is not None
        assert result.status_code == 401

    def test_auth_valid_bearer_returns_none(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """valid auth returns None."""
        check = AuthenticationCheck(mock_guard)
        request = rf.get("/test", HTTP_AUTHORIZATION="Bearer valid_token")
        request._guard_route_config = RouteConfig()
        request._guard_route_config.auth_required = "bearer"
        result = check.check(request)
        assert result is None


# ── CloudProviderCheck ───────────────────────────────────────────────


class TestCloudProviderCheck:
    def test_cloud_skip_no_resolver(self, mock_guard: Mock) -> None:
        """route_resolver=None returns False."""
        mock_guard.route_resolver = None
        check = CloudProviderCheck(mock_guard)
        result = check._should_skip_check(None)
        assert result is False

    def test_cloud_providers_no_resolver(self, mock_guard: Mock) -> None:
        """route_resolver=None returns None."""
        mock_guard.route_resolver = None
        check = CloudProviderCheck(mock_guard)
        result = check._get_cloud_providers(None)
        assert result is None


# ── CustomRequestCheck ───────────────────────────────────────────────


class TestCustomRequestCheck:
    def test_custom_req_unknown_status(self, mock_guard: Mock) -> None:
        """no status_code attr returns 'unknown'."""
        check = CustomRequestCheck(mock_guard)
        obj = object()
        assert check._get_response_status(obj) == "unknown"

    def test_custom_req_anonymous_name(self, mock_guard: Mock) -> None:
        """no __name__ attr returns 'anonymous'."""
        mock_guard.config.custom_request_check = object()
        check = CustomRequestCheck(mock_guard)
        assert check._get_check_function_name() == "anonymous"

    def test_custom_req_event_no_bus(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """event_bus=None returns early."""
        mock_guard.event_bus = None
        check = CustomRequestCheck(mock_guard)
        request = rf.get("/test")
        check._send_custom_check_event(request, Mock())

    def test_custom_req_modifier_no_factory(self, mock_guard: Mock) -> None:
        """response_factory=None returns response as-is."""
        mock_guard.response_factory = None
        check = CustomRequestCheck(mock_guard)
        response = HttpResponse("test", status=200)
        result = check._apply_response_modifier(response)
        assert result is response

    def test_custom_req_check_returns_none(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """custom_check returns None."""
        mock_guard.config.custom_request_check = lambda r: None
        check = CustomRequestCheck(mock_guard)
        request = rf.get("/test")
        result = check.check(request)
        assert result is None

    def test_custom_req_passive_mode(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """passive_mode + custom response returns None."""
        mock_guard.config.passive_mode = True
        mock_guard.config.custom_request_check = lambda r: HttpResponse(
            "blocked", status=403
        )
        check = CustomRequestCheck(mock_guard)
        request = rf.get("/test")
        result = check.check(request)
        assert result is None


# ── CustomValidatorsCheck ────────────────────────────────────────────


class TestCustomValidatorsCheck:
    def test_validators_log_failure(self, mock_guard: Mock, rf: RequestFactory) -> None:
        """_log_validation_failure calls log_activity."""
        check = CustomValidatorsCheck(mock_guard)
        request = rf.get("/test")
        with patch(
            "djangoapi_guard.core.checks.implementations.custom_validators.log_activity"
        ) as mock_log:
            check._log_validation_failure(request)
            mock_log.assert_called_once()

    def test_validators_event_no_bus(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """event_bus=None returns early."""
        mock_guard.event_bus = None
        check = CustomValidatorsCheck(mock_guard)
        request = rf.get("/test")
        check._send_violation_event(request, lambda: None)

    def test_validators_active_returns_response(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """validator returns HttpResponse, active mode."""
        mock_guard.config.passive_mode = False
        blocked = HttpResponse("Validation failed", status=422)
        validator = Mock(return_value=blocked)
        check = CustomValidatorsCheck(mock_guard)
        request = rf.get("/test")
        route_config = RouteConfig()
        route_config.custom_validators = [validator]
        request._guard_route_config = route_config
        result = check.check(request)
        assert result is blocked

    def test_validators_non_http_response(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """validator returns truthy non-HttpResponse."""
        mock_guard.config.passive_mode = False
        validator = Mock(return_value="error string")
        check = CustomValidatorsCheck(mock_guard)
        request = rf.get("/test")
        route_config = RouteConfig()
        route_config.custom_validators = [validator]
        request._guard_route_config = route_config
        result = check.check(request)
        assert result is None

    def test_validators_passive_returns_none(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """validator returns HttpResponse, passive."""
        mock_guard.config.passive_mode = True
        blocked = HttpResponse("Validation failed", status=422)
        validator = Mock(return_value=blocked)
        check = CustomValidatorsCheck(mock_guard)
        request = rf.get("/test")
        route_config = RouteConfig()
        route_config.custom_validators = [validator]
        request._guard_route_config = route_config
        result = check.check(request)
        assert result is None


# ── HttpsEnforcementCheck ────────────────────────────────────────────


class TestHttpsEnforcementCheck:
    def test_https_redirect_no_factory(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """response_factory=None creates redirect."""
        mock_guard.response_factory = None
        check = HttpsEnforcementCheck(mock_guard)
        request = rf.get("/test")
        result = check._create_https_redirect(request)
        assert result.status_code == 301
        assert "https://" in result["Location"]


# ── IpSecurityCheck ──────────────────────────────────────────────────


class TestIpSecurityCheck:
    def test_ip_blocked_active_returns_403(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """route IP restriction blocked, active mode."""
        mock_guard.config.passive_mode = False
        check = IpSecurityCheck(mock_guard)
        request = rf.get("/test")
        route_config = RouteConfig()
        route_config.ip_blacklist = ["10.0.0.1"]
        with patch(
            "djangoapi_guard.core.checks.implementations"
            ".ip_security.check_route_ip_access",
            return_value=False,
        ):
            result = check._check_route_ip_restrictions(
                request, "10.0.0.1", route_config
            )
        assert result is not None
        assert result.status_code == 403


# ── RateLimitCheck ───────────────────────────────────────────────────


class TestRateLimitCheck:
    def test_rate_create_handler(self, mock_guard: Mock) -> None:
        """creates temp handler."""
        mock_guard.redis_handler = None
        check = RateLimitCheck(mock_guard)
        handler = check._create_rate_handler(100, 60)
        assert handler is not None
        assert handler.config.rate_limit == 100

    def test_rate_create_handler_with_redis(self, mock_guard: Mock) -> None:
        """initializes redis on temp handler."""
        mock_guard.redis_handler = Mock()
        check = RateLimitCheck(mock_guard)
        handler = check._create_rate_handler(100, 60)
        assert handler is not None

    def test_rate_event_no_bus(self, mock_guard: Mock, rf: RequestFactory) -> None:
        """event_bus=None returns early."""
        mock_guard.event_bus = None
        check = RateLimitCheck(mock_guard)
        request = rf.get("/test")
        check._send_rate_limit_event(request, "test", {})

    def test_rate_endpoint_limit_hit(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """endpoint in config, limit applied."""
        mock_guard.config.endpoint_rate_limits = {"/api/test": (1, 60)}
        mock_guard.redis_handler = None
        check = RateLimitCheck(mock_guard)
        request = rf.get("/api/test")
        request._guard_client_ip = "1.2.3.4"
        with patch.object(
            check,
            "_apply_rate_limit_check",
            return_value=HttpResponse("Rate limited", status=429),
        ):
            result = check._check_endpoint_rate_limit(request, "1.2.3.4", "/api/test")
        assert result is not None
        assert result.status_code == 429

    def test_rate_route_limit_hit(self, mock_guard: Mock, rf: RequestFactory) -> None:
        """route with rate_limit, no window."""
        check = RateLimitCheck(mock_guard)
        request = rf.get("/test")
        route_config = RouteConfig()
        route_config.rate_limit = 10
        route_config.rate_limit_window = None
        with patch.object(
            check,
            "_apply_rate_limit_check",
            return_value=HttpResponse("Rate limited", status=429),
        ):
            result = check._check_route_rate_limit(request, "1.2.3.4", route_config)
        assert result is not None

    def test_rate_global_no_handler(self, mock_guard: Mock, rf: RequestFactory) -> None:
        """rate_limit_handler=None returns None."""
        mock_guard.rate_limit_handler = None
        check = RateLimitCheck(mock_guard)
        request = rf.get("/test")
        result = check._check_global_rate_limit(request, "1.2.3.4")
        assert result is None

    def test_rate_check_bypassed(self, mock_guard: Mock, rf: RequestFactory) -> None:
        """bypassed returns None."""
        mock_guard.route_resolver.should_bypass_check.return_value = True
        check = RateLimitCheck(mock_guard)
        request = rf.get("/test")
        request._guard_client_ip = "1.2.3.4"
        request._guard_is_whitelisted = False
        route_config = RouteConfig()
        request._guard_route_config = route_config
        result = check.check(request)
        assert result is None

    def test_rate_check_endpoint_exceeded(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """endpoint limit exceeded returns response."""
        mock_guard.config.endpoint_rate_limits = {"/test": (1, 60)}
        mock_guard.route_resolver.should_bypass_check.return_value = False
        check = RateLimitCheck(mock_guard)
        request = rf.get("/test")
        request._guard_client_ip = "1.2.3.4"
        request._guard_is_whitelisted = False
        route_config = RouteConfig()
        request._guard_route_config = route_config
        response_429 = HttpResponse("Rate limited", status=429)
        with patch.object(
            check, "_check_endpoint_rate_limit", return_value=response_429
        ):
            result = check.check(request)
        assert result is not None
        assert result.status_code == 429

    def test_rate_check_route_exceeded(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """route limit exceeded returns response."""
        mock_guard.config.endpoint_rate_limits = {}
        mock_guard.route_resolver.should_bypass_check.return_value = False
        check = RateLimitCheck(mock_guard)
        request = rf.get("/test")
        request._guard_client_ip = "1.2.3.4"
        request._guard_is_whitelisted = False
        route_config = RouteConfig()
        route_config.rate_limit = 5
        request._guard_route_config = route_config
        response_429 = HttpResponse("Rate limited", status=429)
        with patch.object(check, "_check_endpoint_rate_limit", return_value=None):
            with patch.object(
                check,
                "_check_route_rate_limit",
                return_value=response_429,
            ):
                result = check.check(request)
        assert result is not None
        assert result.status_code == 429


# ── ReferrerCheck ────────────────────────────────────────────────────


class TestReferrerCheck:
    def test_referrer_missing_active_403(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """active mode, missing referrer returns 403."""
        mock_guard.config.passive_mode = False
        check = ReferrerCheck(mock_guard)
        request = rf.get("/test")
        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]
        result = check._handle_missing_referrer(request, route_config)
        assert result is not None
        assert result.status_code == 403

    def test_referrer_invalid_active_403(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """active mode, invalid referrer returns 403."""
        mock_guard.config.passive_mode = False
        check = ReferrerCheck(mock_guard)
        request = rf.get("/test")
        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]
        result = check._handle_invalid_referrer(
            request, "https://evil.com/page", route_config
        )
        assert result is not None
        assert result.status_code == 403

    def test_referrer_check_missing(self, mock_guard: Mock, rf: RequestFactory) -> None:
        """check() with missing referrer."""
        mock_guard.config.passive_mode = False
        check = ReferrerCheck(mock_guard)
        request = rf.get("/test")
        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]
        request._guard_route_config = route_config
        result = check.check(request)
        assert result is not None
        assert result.status_code == 403

    def test_referrer_check_invalid(self, mock_guard: Mock, rf: RequestFactory) -> None:
        """check() with invalid referrer domain."""
        mock_guard.config.passive_mode = False
        check = ReferrerCheck(mock_guard)
        request = rf.get("/test", HTTP_REFERER="https://evil.com/page")
        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]
        request._guard_route_config = route_config
        result = check.check(request)
        assert result is not None
        assert result.status_code == 403

    def test_referrer_check_valid(self, mock_guard: Mock, rf: RequestFactory) -> None:
        """check() with valid referrer returns None."""
        check = ReferrerCheck(mock_guard)
        request = rf.get("/test", HTTP_REFERER="https://example.com/page")
        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]
        request._guard_route_config = route_config
        result = check.check(request)
        assert result is None


# ── RequestSizeContentCheck ──────────────────────────────────────────


class TestRequestSizeContentCheck:
    def test_size_no_limit(self, mock_guard: Mock, rf: RequestFactory) -> None:
        """no max_request_size returns None."""
        check = RequestSizeContentCheck(mock_guard)
        request = rf.get("/test")
        route_config = RouteConfig()
        route_config.max_request_size = None
        result = check._check_request_size_limit(request, route_config)
        assert result is None

    def test_size_within_limit(self, mock_guard: Mock, rf: RequestFactory) -> None:
        """within limit returns None."""
        check = RequestSizeContentCheck(mock_guard)
        request = rf.get("/test", CONTENT_LENGTH="100")
        route_config = RouteConfig()
        route_config.max_request_size = 1000
        result = check._check_request_size_limit(request, route_config)
        assert result is None

    def test_size_exceeded_active_413(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """exceeded, active returns 413."""
        mock_guard.config.passive_mode = False
        check = RequestSizeContentCheck(mock_guard)
        request = rf.get("/test", CONTENT_LENGTH="5000")
        route_config = RouteConfig()
        route_config.max_request_size = 1000
        result = check._check_request_size_limit(request, route_config)
        assert result is not None
        assert result.status_code == 413

    def test_content_no_types(self, mock_guard: Mock, rf: RequestFactory) -> None:
        """no allowed_content_types returns None."""
        check = RequestSizeContentCheck(mock_guard)
        request = rf.get("/test")
        route_config = RouteConfig()
        route_config.allowed_content_types = None
        result = check._check_content_type_allowed(request, route_config)
        assert result is None

    def test_content_type_allowed(self, mock_guard: Mock, rf: RequestFactory) -> None:
        """content type in allowed returns None."""
        check = RequestSizeContentCheck(mock_guard)
        request = rf.post("/test", data=b"test", content_type="application/json")
        route_config = RouteConfig()
        route_config.allowed_content_types = ["application/json"]
        result = check._check_content_type_allowed(request, route_config)
        assert result is None

    def test_content_type_blocked_415(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """disallowed, active returns 415."""
        mock_guard.config.passive_mode = False
        check = RequestSizeContentCheck(mock_guard)
        request = rf.post("/test", data=b"test", content_type="text/xml")
        route_config = RouteConfig()
        route_config.allowed_content_types = ["application/json"]
        result = check._check_content_type_allowed(request, route_config)
        assert result is not None
        assert result.status_code == 415

    def test_check_delegates_size_then_content(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """check() delegates to both sub-checks."""
        check = RequestSizeContentCheck(mock_guard)
        request = rf.post("/test", data=b"test", content_type="application/json")
        route_config = RouteConfig()
        route_config.max_request_size = 10000
        route_config.allowed_content_types = ["application/json"]
        request._guard_route_config = route_config
        result = check.check(request)
        assert result is None

    def test_check_size_exceeded_returns_early(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """size check fails, returns size_response."""
        mock_guard.config.passive_mode = False
        check = RequestSizeContentCheck(mock_guard)
        request = rf.post(
            "/test",
            data=b"x" * 100,
            content_type="application/json",
            CONTENT_LENGTH="5000",
        )
        route_config = RouteConfig()
        route_config.max_request_size = 100
        route_config.allowed_content_types = ["application/json"]
        request._guard_route_config = route_config
        result = check.check(request)
        assert result is not None
        assert result.status_code == 413


# ── RequiredHeadersCheck ─────────────────────────────────────────────


class TestRequiredHeadersCheck:
    def test_classify_api_key(self) -> None:
        """x-api-key classification."""
        dtype, vtype = _classify_header_violation("X-Api-Key")
        assert dtype == "authentication"
        assert vtype == "api_key_required"

    def test_classify_authorization(self) -> None:
        """authorization classification."""
        dtype, vtype = _classify_header_violation("Authorization")
        assert dtype == "authentication"
        assert vtype == "required_header"

    def test_classify_other(self) -> None:
        """other header classification."""
        dtype, vtype = _classify_header_violation("X-Custom")
        assert dtype == "advanced"
        assert vtype == "required_header"

    def test_missing_header_active_400(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """active mode, missing header returns 400."""
        mock_guard.config.passive_mode = False
        check = RequiredHeadersCheck(mock_guard)
        request = rf.get("/test")
        result = check._handle_missing_header(request, "X-Api-Key")
        assert result is not None
        assert result.status_code == 400

    def test_all_headers_present(self, mock_guard: Mock, rf: RequestFactory) -> None:
        """all required headers present returns None."""
        check = RequiredHeadersCheck(mock_guard)
        request = rf.get("/test", HTTP_X_API_KEY="my-key")
        route_config = RouteConfig()
        route_config.required_headers = {"X-Api-Key": "required"}
        request._guard_route_config = route_config
        result = check.check(request)
        assert result is None


# ── SuspiciousActivityCheck ──────────────────────────────────────────


class TestSuspiciousActivityCheck:
    def test_suspicious_disabled_by_decorator(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """disabled by decorator, sends event."""
        check = SuspiciousActivityCheck(mock_guard)
        request = rf.get("/test")
        request._guard_client_ip = "1.2.3.4"
        request._guard_is_whitelisted = False
        route_config = RouteConfig()
        route_config.enable_suspicious_detection = False
        request._guard_route_config = route_config
        mock_guard.config.enable_penetration_detection = True

        with patch(
            "djangoapi_guard.core.checks.implementations"
            ".suspicious_activity.detect_penetration_patterns",
            return_value=(False, "disabled_by_decorator"),
        ):
            result = check.check(request)
        assert result is None
        mock_guard.event_bus.send_middleware_event.assert_called_once()
        call_kwargs = mock_guard.event_bus.send_middleware_event.call_args
        assert call_kwargs[1]["event_type"] == "decorator_violation"
        assert call_kwargs[1]["action_taken"] == "detection_disabled"

    def test_suspicious_disabled_no_event_bus(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """disabled by decorator, event_bus=None."""
        mock_guard.event_bus = None
        check = SuspiciousActivityCheck(mock_guard)
        request = rf.get("/test")
        request._guard_client_ip = "1.2.3.4"
        request._guard_is_whitelisted = False
        request._guard_route_config = RouteConfig()
        mock_guard.config.enable_penetration_detection = True

        with patch(
            "djangoapi_guard.core.checks.implementations"
            ".suspicious_activity.detect_penetration_patterns",
            return_value=(False, "disabled_by_decorator"),
        ):
            result = check.check(request)
        assert result is None


# ── TimeWindowCheck ──────────────────────────────────────────────────


class TestTimeWindowCheck:
    def test_time_window_wrap_around(self, mock_guard: Mock) -> None:
        """wrap-around (start > end)."""
        check = TimeWindowCheck(mock_guard)
        restrictions = {
            "start": "22:00",
            "end": "06:00",
            "timezone": "UTC",
        }
        with patch(
            "djangoapi_guard.core.checks.implementations.time_window.datetime"
        ) as mock_dt:
            mock_now = Mock()
            mock_now.strftime.return_value = "23:00"
            mock_dt.now.return_value = mock_now
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            result = check._check_time_window(restrictions)
        assert result is True

    def test_time_window_wrap_around_outside(self, mock_guard: Mock) -> None:
        """wrap-around, current time outside."""
        check = TimeWindowCheck(mock_guard)
        restrictions = {
            "start": "22:00",
            "end": "06:00",
            "timezone": "UTC",
        }
        with patch(
            "djangoapi_guard.core.checks.implementations.time_window.datetime"
        ) as mock_dt:
            mock_now = Mock()
            mock_now.strftime.return_value = "12:00"
            mock_dt.now.return_value = mock_now
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            result = check._check_time_window(restrictions)
        assert result is False

    def test_time_window_blocked_active(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """outside window, active returns 403."""
        mock_guard.config.passive_mode = False
        check = TimeWindowCheck(mock_guard)
        request = rf.get("/test")
        route_config = RouteConfig()
        route_config.time_restrictions = {
            "start": "22:00",
            "end": "06:00",
            "timezone": "UTC",
        }
        request._guard_route_config = route_config

        with patch.object(check, "_check_time_window", return_value=False):
            result = check.check(request)
        assert result is not None
        assert result.status_code == 403
        mock_guard.event_bus.send_middleware_event.assert_called_once()

    def test_time_window_blocked_passive_returns_none(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """outside window, passive returns None."""
        mock_guard.config.passive_mode = True
        check = TimeWindowCheck(mock_guard)
        request = rf.get("/test")
        route_config = RouteConfig()
        route_config.time_restrictions = {
            "start": "22:00",
            "end": "06:00",
            "timezone": "UTC",
        }
        request._guard_route_config = route_config

        with patch.object(check, "_check_time_window", return_value=False):
            result = check.check(request)
        assert result is None


# ── UserAgentCheck ───────────────────────────────────────────────────


class TestUserAgentCheck:
    def test_ua_action_passive(self, mock_guard: Mock) -> None:
        """passive returns 'logged_only'."""
        mock_guard.config.passive_mode = True
        check = UserAgentCheck(mock_guard)
        assert check._get_action_taken() == "logged_only"

    def test_ua_route_event_no_bus(self, mock_guard: Mock, rf: RequestFactory) -> None:
        """event_bus=None returns early."""
        mock_guard.event_bus = None
        check = UserAgentCheck(mock_guard)
        request = rf.get("/test")
        check._send_route_violation_event(request, "BadBot")

    def test_ua_global_event_no_bus(self, mock_guard: Mock, rf: RequestFactory) -> None:
        """event_bus=None returns early."""
        mock_guard.event_bus = None
        check = UserAgentCheck(mock_guard)
        request = rf.get("/test")
        check._send_global_block_event(request, "BadBot")

    def test_ua_blocked_passive_returns_none(
        self, mock_guard: Mock, rf: RequestFactory
    ) -> None:
        """blocked UA, passive returns None."""
        mock_guard.config.passive_mode = True
        mock_guard.config.blocked_user_agents = ["BadBot"]
        check = UserAgentCheck(mock_guard)
        request = rf.get("/test", HTTP_USER_AGENT="BadBot/1.0")
        request._guard_is_whitelisted = False
        request._guard_route_config = None

        with patch(
            "djangoapi_guard.core.checks.implementations"
            ".user_agent.check_user_agent_allowed",
            return_value=False,
        ):
            result = check.check(request)
        assert result is None


# ── ErrorResponseFactory ─────────────────────────────────────────────


class TestFactoryProcessResponse:
    def test_factory_process_response_with_behavioral_rules(
        self, rf: RequestFactory
    ) -> None:
        """process_response with behavioral rules."""
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        metrics = Mock(spec=MetricsCollector)
        context = ResponseContext(
            config=config,
            logger=Mock(),
            metrics_collector=metrics,
            agent_handler=None,
        )
        factory = ErrorResponseFactory(context)

        request = rf.get("/test", REMOTE_ADDR="1.2.3.4")
        response = HttpResponse("OK", status=200)
        route_config = RouteConfig()
        route_config.behavior_rules = [Mock()]

        callback = Mock()

        result = factory.process_response(
            request=request,
            response=response,
            response_time=0.1,
            route_config=route_config,
            process_behavioral_rules=callback,
        )

        callback.assert_called_once()
        assert result is not None
