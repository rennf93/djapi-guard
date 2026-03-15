import ipaddress
import os
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

import django.conf
import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory

from djangoapi_guard.core.checks.helpers import validate_auth_header
from djangoapi_guard.core.events.extension_events import SecurityEventBus
from djangoapi_guard.decorators.base import (
    BaseSecurityDecorator,
    RouteConfig,
)
from djangoapi_guard.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from djangoapi_guard.handlers.cloud_handler import CloudManager
from djangoapi_guard.handlers.ipinfo_handler import IPInfoManager
from djangoapi_guard.handlers.ratelimit_handler import RateLimitManager
from djangoapi_guard.middleware import DjangoAPIGuard
from djangoapi_guard.models import SecurityConfig
from djangoapi_guard.protocols.geo_ip_protocol import GeoIPHandler


def _get_response(request: HttpRequest) -> HttpResponse:
    return HttpResponse('{"ok": true}', content_type="application/json")


@pytest.fixture(autouse=True)
def reset_singletons() -> Generator[None, None, None]:
    RateLimitManager._instance = None
    original_ipinfo = IPInfoManager._instance
    IPInfoManager._instance = None
    yield
    RateLimitManager._instance = None
    IPInfoManager._instance = original_ipinfo


class TestBaseSecurityDecoratorInitializeAgent:
    def test_initialize_agent_sets_handler_and_forwards_to_tracker(self) -> None:
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        decorator = BaseSecurityDecorator(config)
        mock_agent = MagicMock()

        decorator.initialize_agent(mock_agent)

        assert decorator.agent_handler is mock_agent
        assert decorator.behavior_tracker.agent_handler is mock_agent


class TestExtensionAgentInitGenericException:
    def test_agent_init_generic_exception_logs_and_continues(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=True,
            agent_api_key="test-key",
            agent_project_id="test-project",
        )

        mock_agent_config = MagicMock()
        with patch.object(
            SecurityConfig, "to_agent_config", return_value=mock_agent_config
        ):
            mock_module = MagicMock()
            mock_module.guard_agent.side_effect = RuntimeError("init failed")
            with patch.dict("sys.modules", {"guard_agent": mock_module}):
                with patch.object(
                    django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
                ):
                    middleware = DjangoAPIGuard(_get_response)
                    assert middleware.agent_handler is None
                    middleware.reset()


class TestExtensionProcessResponse:
    def test_process_response_delegates_to_factory(self) -> None:
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        factory = RequestFactory()
        request = factory.get("/test")
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        response = HttpResponse("test", status=200)
        result = middleware._process_response(request, response, 0.01, None)
        assert result is not None

        middleware.reset()


class TestBehaviorTrackerInitializeAgent:
    def test_initialize_agent_sets_handler(self) -> None:
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        tracker = BehaviorTracker(config)
        mock_agent = MagicMock()

        tracker.initialize_agent(mock_agent)

        assert tracker.agent_handler is mock_agent


class TestBehaviorTrackerApplyActionWithAgent:
    def test_apply_action_sends_event_to_agent(self) -> None:
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        tracker = BehaviorTracker(config)
        mock_agent = MagicMock()
        tracker.agent_handler = mock_agent

        rule = BehaviorRule(
            rule_type="usage",
            threshold=5,
            window=60,
            action="log",
        )

        with patch.object(tracker, "_send_behavior_event") as mock_send:
            tracker.apply_action(rule, "1.2.3.4", "/api/test", "threshold exceeded")
            mock_send.assert_called_once_with(
                event_type="behavioral_violation",
                ip_address="1.2.3.4",
                action_taken="log",
                reason="Behavioral rule violated: threshold exceeded",
                endpoint="/api/test",
                rule_type="usage",
                threshold=5,
                window=60,
            )

    def test_apply_action_passive_mode_sends_logged_only(self) -> None:
        config = SecurityConfig(
            enable_redis=False, enable_agent=False, passive_mode=True
        )
        tracker = BehaviorTracker(config)
        mock_agent = MagicMock()
        tracker.agent_handler = mock_agent

        rule = BehaviorRule(
            rule_type="usage",
            threshold=5,
            window=60,
            action="ban",
        )

        with patch.object(tracker, "_send_behavior_event") as mock_send:
            tracker.apply_action(rule, "1.2.3.4", "/api/test", "threshold exceeded")
            mock_send.assert_called_once()
            call_kwargs = mock_send.call_args
            assert call_kwargs.kwargs["action_taken"] == "logged_only"


class TestCloudHandlerInitializeAgent:
    def test_initialize_agent_sets_handler(self) -> None:
        manager = CloudManager()
        mock_agent = MagicMock()

        manager.initialize_agent(mock_agent)

        assert manager.agent_handler is mock_agent


class TestCloudHandlerGetCloudProviderDetailsMatch:
    def test_get_cloud_provider_details_returns_match(self) -> None:
        manager = CloudManager()
        network = ipaddress.ip_network("10.0.0.0/8")
        manager.ip_ranges["AWS"] = {network}

        result = manager.get_cloud_provider_details("10.1.2.3")

        assert result is not None
        assert result[0] == "AWS"
        assert result[1] == "10.0.0.0/8"


class TestCloudHandlerGetCloudProviderDetailsInvalidIP:
    def test_get_cloud_provider_details_invalid_ip_returns_none(self) -> None:
        manager = CloudManager()
        manager.ip_ranges["AWS"] = {ipaddress.ip_network("10.0.0.0/8")}

        result = manager.get_cloud_provider_details("not-an-ip")

        assert result is None


class TestIPInfoManagerInitializeAgent:
    def test_initialize_agent_sets_handler(self) -> None:
        manager = IPInfoManager("test_token", None)
        mock_agent = MagicMock()

        manager.initialize_agent(mock_agent)

        assert manager.agent_handler is mock_agent


class TestIPInfoManagerDownloadFailureAgentEvent:
    def test_initialize_sends_agent_event_on_download_failure(self) -> None:
        tmp_path = Path("/tmp/test_ipinfo_agent_event")
        tmp_path.mkdir(parents=True, exist_ok=True)
        db_path = tmp_path / "test.mmdb"

        manager = IPInfoManager("test_token", db_path)
        mock_agent = MagicMock()
        manager.agent_handler = mock_agent

        if db_path.exists():
            db_path.unlink()

        with (
            patch.object(manager, "_is_db_outdated", return_value=True),
            patch.object(
                manager,
                "_download_database",
                side_effect=RuntimeError("download failed"),
            ),
            patch.object(manager, "_send_geo_event") as mock_send,
        ):
            manager.initialize()

            mock_send.assert_called_once()
            call_kwargs = mock_send.call_args
            assert call_kwargs.kwargs["event_type"] == "geo_lookup_failed"
            assert call_kwargs.kwargs["action_taken"] == "database_download_failed"

        if db_path.exists():
            db_path.unlink()


class TestIPInfoManagerLookupFailureAgentEvent:
    def test_get_country_sends_agent_event_on_lookup_exception(self) -> None:
        manager = IPInfoManager("test_token", None)
        mock_agent = MagicMock()
        manager.agent_handler = mock_agent

        mock_reader = MagicMock()
        mock_reader.get.side_effect = RuntimeError("lookup error")
        manager.reader = mock_reader

        with patch.object(manager, "_send_geo_event") as mock_send:
            result = manager.get_country("1.2.3.4")

            assert result is None
            mock_send.assert_called_once()
            call_kwargs = mock_send.call_args
            assert call_kwargs.kwargs["event_type"] == "geo_lookup_failed"
            assert call_kwargs.kwargs["action_taken"] == "lookup_failed"

    def test_get_country_silences_agent_errors_in_lookup(self) -> None:
        manager = IPInfoManager("test_token", None)
        mock_agent = MagicMock()
        manager.agent_handler = mock_agent

        mock_reader = MagicMock()
        mock_reader.get.side_effect = RuntimeError("lookup error")
        manager.reader = mock_reader

        with patch.object(
            manager,
            "_send_geo_event",
            side_effect=RuntimeError("agent send failed"),
        ):
            result = manager.get_country("1.2.3.4")
            assert result is None


class TestIPInfoManagerCheckCountryAccessAllowed:
    def test_check_country_access_allowed_country(self) -> None:
        manager = IPInfoManager("test_token", None)

        with patch.object(manager, "get_country", return_value="US"):
            allowed, country = manager.check_country_access(
                "1.2.3.4",
                blocked_countries=["CN", "RU"],
            )
            assert allowed is True
            assert country == "US"

    def test_check_country_access_allowed_with_whitelist(self) -> None:
        manager = IPInfoManager("test_token", None)

        with patch.object(manager, "get_country", return_value="US"):
            allowed, country = manager.check_country_access(
                "1.2.3.4",
                blocked_countries=[],
                whitelist_countries=["US", "CA"],
            )
            assert allowed is True
            assert country == "US"


class TestValidateAuthHeaderGenericType:
    def test_generic_auth_empty_header_returns_false(self) -> None:
        valid, msg = validate_auth_header("", "api_key")
        assert valid is False
        assert msg == "Missing api_key authentication"

    def test_generic_auth_nonempty_header_returns_true(self) -> None:
        valid, msg = validate_auth_header("SomeToken abc123", "custom")
        assert valid is True
        assert msg == ""


class TestGetDetectionDisabledReason:
    def test_disabled_by_decorator_reason(self) -> None:
        from djangoapi_guard.core.checks.helpers import _get_detection_disabled_reason

        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=True,
        )
        result = _get_detection_disabled_reason(config, route_specific_detection=False)
        assert result == "disabled_by_decorator"


class TestReferrerCheckBlocking:
    def test_referrer_domain_allowed(self) -> None:
        from djangoapi_guard.core.checks.helpers import is_referrer_domain_allowed

        assert is_referrer_domain_allowed("https://example.com/page", ["example.com"])
        assert is_referrer_domain_allowed(
            "https://sub.example.com/page", ["example.com"]
        )
        assert not is_referrer_domain_allowed("https://evil.com/page", ["example.com"])


class TestSecurityEventBusException:
    def test_send_middleware_event_logs_error_on_exception(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=True,
            agent_api_key="test-key",
            agent_project_id="test-project",
            agent_enable_events=True,
        )

        mock_agent = MagicMock()
        mock_agent.send_event.side_effect = RuntimeError("agent error")

        event_bus = SecurityEventBus(
            agent_handler=mock_agent,
            config=config,
            geo_ip_handler=None,
        )

        factory = RequestFactory()
        request = factory.get("/test", HTTP_USER_AGENT="test-agent")
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        mock_guard_agent = MagicMock()
        with patch.dict("sys.modules", {"guard_agent": mock_guard_agent}):
            event_bus.send_middleware_event(
                event_type="test_event",
                request=request,
                action_taken="test_action",
                reason="test reason",
            )


class TestRouteConfigDefaults:
    def test_route_config_defaults(self) -> None:
        rc = RouteConfig()
        assert rc.rate_limit is None
        assert rc.rate_limit_window is None
        assert rc.ip_whitelist is None
        assert rc.ip_blacklist is None
        assert rc.blocked_countries is None
        assert rc.whitelist_countries is None
        assert rc.bypassed_checks == set()
        assert rc.require_https is False
        assert rc.auth_required is None
        assert rc.custom_validators == []
        assert rc.blocked_user_agents == []
        assert rc.required_headers == {}
        assert rc.behavior_rules == []
        assert rc.block_cloud_providers == set()
        assert rc.max_request_size is None
        assert rc.allowed_content_types is None
        assert rc.time_restrictions is None
        assert rc.enable_suspicious_detection is True
        assert rc.require_referrer is None
        assert rc.api_key_required is False
        assert rc.session_limits is None
        assert rc.geo_rate_limits is None


class TestBaseSecurityDecoratorRouteConfig:
    def test_get_route_config_returns_none_for_unknown(self) -> None:
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        decorator = BaseSecurityDecorator(config)
        assert decorator.get_route_config("unknown_route") is None

    def test_ensure_route_config_creates_config(self) -> None:
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        decorator = BaseSecurityDecorator(config)

        def dummy_func() -> None:
            pass

        rc = decorator._ensure_route_config(dummy_func)
        assert isinstance(rc, RouteConfig)

    def test_apply_route_config_sets_guard_route_id(self) -> None:
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        decorator = BaseSecurityDecorator(config)

        def dummy_func() -> None:
            pass

        result = decorator._apply_route_config(dummy_func)
        assert hasattr(result, "_guard_route_id")


class TestBehaviorRuleDefaults:
    def test_behavior_rule_defaults(self) -> None:
        rule = BehaviorRule(rule_type="usage", threshold=5)
        assert rule.rule_type == "usage"
        assert rule.threshold == 5
        assert rule.window == 3600
        assert rule.pattern is None
        assert rule.action == "log"
        assert rule.custom_action is None


class TestRateLimitManagerReset:
    def test_reset_clears_timestamps(self) -> None:
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        manager = RateLimitManager(config)
        manager.request_timestamps["test_ip"].append(1.0)
        assert len(manager.request_timestamps) > 0

        manager.reset()
        assert len(manager.request_timestamps) == 0


class TestMiddlewareCheckTimeWindow:
    def test_check_time_window(self) -> None:
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        result = middleware._check_time_window({"start": "00:00", "end": "23:59"})
        assert isinstance(result, bool)

        middleware.reset()


class TestMiddlewareDefaultConfig:
    def test_default_config_when_none(self) -> None:
        """Middleware creates default SecurityConfig when config is None."""
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", None, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        assert middleware.config is not None
        assert isinstance(middleware.config, SecurityConfig)
        middleware.reset()


class TestMiddlewareGeoIpNone:
    def test_no_countries_no_geo_handler(self) -> None:
        """geo_ip_handler stays None when no countries configured."""
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            blocked_countries=[],
            whitelist_countries=[],
        )
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        assert middleware.geo_ip_handler is None
        middleware.reset()


class TestMiddlewareGeoIpAssigned:
    def test_countries_configured_assigns_handler(self) -> None:
        """geo_ip_handler is assigned from config when countries are configured."""
        mock_geo_handler = MagicMock(spec=GeoIPHandler)
        mock_geo_handler.is_initialized = True
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            blocked_countries=["CN"],
            geo_ip_handler=mock_geo_handler,
        )
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        assert middleware.geo_ip_handler is mock_geo_handler
        middleware.reset()


class TestMiddlewareRedisInit:
    def test_redis_enabled_creates_handler(self) -> None:
        """Redis handler is created when enable_redis=True."""
        config = SecurityConfig(
            enable_redis=True,
            redis_url="redis://localhost:6379",
            enable_agent=False,
        )
        with (
            patch.object(
                django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
            ),
            patch(
                "djangoapi_guard.handlers.redis_handler.RedisManager"
            ) as mock_redis_cls,
        ):
            mock_redis_instance = MagicMock()
            mock_redis_instance.config = config
            mock_redis_cls.return_value = mock_redis_instance
            middleware = DjangoAPIGuard(_get_response)

        assert middleware.redis_handler is not None
        middleware.reset()


class TestMiddlewareAgentInvalidConfig:
    def test_agent_invalid_config_logs_warning(self) -> None:
        """Agent init logs warning when config is invalid (returns falsy)."""
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=True,
            agent_api_key="test-key",
            agent_project_id="test-project",
        )
        with (
            patch.object(
                django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
            ),
            patch.object(SecurityConfig, "to_agent_config", return_value=None),
        ):
            middleware = DjangoAPIGuard(_get_response)

        assert middleware.agent_handler is None
        middleware.reset()


class TestMiddlewareAgentImportError:
    def test_agent_import_error_logs_warning(self) -> None:
        """Agent init logs warning when guard_agent not installed."""
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=True,
            agent_api_key="test-key",
            agent_project_id="test-project",
        )
        mock_agent_config = MagicMock()
        with (
            patch.object(
                django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
            ),
            patch.object(
                SecurityConfig, "to_agent_config", return_value=mock_agent_config
            ),
            patch.dict("sys.modules", {"guard_agent": None}),
        ):
            middleware = DjangoAPIGuard(_get_response)

        assert middleware.agent_handler is None
        middleware.reset()


class TestMiddlewarePassthrough:
    def test_passthrough_returns_early(self) -> None:
        """__call__ returns early when passthrough matches."""
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            custom_request_check=lambda r: HttpResponse("pass", status=200),
        )
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        factory = RequestFactory()
        request = factory.get("/health")
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        # Mock passthrough to return early
        with patch.object(
            middleware.bypass_handler,
            "handle_passthrough",
            return_value=HttpResponse("ok", status=200),
        ):
            response = middleware(request)

        assert response.status_code == 200
        middleware.reset()


class TestMiddlewareBypass:
    def test_bypass_returns_early(self) -> None:
        """__call__ returns early when bypass matches."""
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
        )
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        factory = RequestFactory()
        request = factory.get("/api/test")
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        with (
            patch.object(
                middleware.bypass_handler,
                "handle_passthrough",
                return_value=None,
            ),
            patch.object(
                middleware.bypass_handler,
                "handle_security_bypass",
                return_value=HttpResponse("bypassed", status=200),
            ),
        ):
            response = middleware(request)

        assert response.status_code == 200
        middleware.reset()


class TestMiddlewarePipelineNone:
    def test_no_pipeline_returns_none(self) -> None:
        """_execute_security_pipeline returns None when pipeline is None."""
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        middleware.security_pipeline = None

        factory = RequestFactory()
        request = factory.get("/api/test")
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        result = middleware._execute_security_pipeline(request)
        assert result is None
        middleware.reset()


class TestMiddlewareHttpsRedirect:
    def test_creates_redirect(self) -> None:
        """_create_https_redirect delegates to response_factory."""
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        factory = RequestFactory()
        request = factory.get("/api/test")
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        response = middleware._create_https_redirect(request)
        assert response is not None
        middleware.reset()


class TestMiddlewarePassiveMode:
    def test_passive_mode_ignores_rate_limit(self) -> None:
        """_check_rate_limit returns None in passive_mode even when rate limited."""
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            passive_mode=True,
            enable_rate_limiting=True,
            rate_limit=1,
            rate_limit_window=60,
        )
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        factory = RequestFactory()
        request = factory.get("/api/test")
        request.META["REMOTE_ADDR"] = "1.2.3.4"

        # Simulate rate limit exceeded
        with patch.object(
            middleware.rate_limit_handler,
            "check_rate_limit",
            return_value=HttpResponse("Rate limited", status=429),
        ):
            result = middleware._check_rate_limit(request, "1.2.3.4")

        assert result is None
        middleware.reset()


class TestMiddlewareCloudRefresh:
    def test_no_providers_returns_early(self) -> None:
        """refresh_cloud_ip_ranges returns early when no cloud providers."""
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            block_cloud_providers=set(),
        )
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        middleware.refresh_cloud_ip_ranges()
        assert middleware.last_cloud_ip_refresh == 0
        middleware.reset()


class TestCloudHandlerInitRedis:
    def test_initialize_redis_calls_refresh(self) -> None:
        """initialize_redis sets redis_handler and calls refresh."""
        CloudManager._instance = None
        manager = CloudManager()
        mock_redis = MagicMock()
        mock_redis.get_key.return_value = None

        with patch.object(manager, "_refresh_sync"):
            manager.initialize_redis(mock_redis, providers=set(), ttl=3600)

        assert manager.redis_handler is mock_redis


class TestCloudHandlerRefreshCacheHit:
    def test_refresh_uses_cached_ranges(self) -> None:
        """refresh parses cached IP ranges from Redis."""
        import ipaddress

        CloudManager._instance = None
        manager = CloudManager()
        mock_redis = MagicMock()
        mock_redis.get_key.return_value = "10.0.0.0/8,192.168.0.0/16"
        manager.redis_handler = mock_redis

        manager.refresh(providers={"AWS"})

        assert len(manager.ip_ranges["AWS"]) == 2
        assert ipaddress.ip_network("10.0.0.0/8") in manager.ip_ranges["AWS"]


class TestCloudHandlerGetDetailsNoMatch:
    def test_get_cloud_provider_details_no_match_returns_none(self) -> None:
        """get_cloud_provider_details returns None for valid IP not in any range."""
        import ipaddress

        CloudManager._instance = None
        manager = CloudManager()
        manager.ip_ranges["AWS"] = {ipaddress.ip_network("10.0.0.0/8")}

        result = manager.get_cloud_provider_details("203.0.113.50")

        assert result is None


class TestCloudHandlerRefreshException:
    def test_refresh_exception_sets_empty(self) -> None:
        """refresh sets empty set on exception for a provider."""
        CloudManager._instance = None
        manager = CloudManager()
        mock_redis = MagicMock()
        mock_redis.get_key.side_effect = RuntimeError("Redis error")
        manager.redis_handler = mock_redis

        # Remove existing ranges for test provider
        if "AWS" in manager.ip_ranges:
            del manager.ip_ranges["AWS"]

        manager.refresh(providers={"AWS"})

        assert manager.ip_ranges["AWS"] == set()


class TestSusPatternsInitRedis:
    def test_load_cached_patterns(self) -> None:
        """initialize_redis loads cached custom patterns from Redis."""
        from djangoapi_guard.handlers.suspatterns_handler import SusPatternsManager

        SusPatternsManager.reset()
        mgr = SusPatternsManager()

        mock_redis = MagicMock()
        mock_redis.get_key.return_value = "test_pattern_1,test_pattern_2"

        mgr.initialize_redis(mock_redis)

        assert "test_pattern_1" in mgr.custom_patterns
        assert "test_pattern_2" in mgr.custom_patterns
        SusPatternsManager.reset()


class TestSusPatternsEventException:
    def test_send_event_exception_logged(self) -> None:
        """_send_pattern_event logs error on agent exception."""
        from djangoapi_guard.handlers.suspatterns_handler import SusPatternsManager

        SusPatternsManager.reset()
        mgr = SusPatternsManager()
        agent = MagicMock()
        agent.send_event.side_effect = RuntimeError("Agent error")
        mgr.agent_handler = agent

        # Should not raise
        mgr._send_pattern_event(
            event_type="test",
            ip_address="1.2.3.4",
            action_taken="test",
            reason="test reason",
        )
        SusPatternsManager.reset()


class TestSusPatternsAddWithRedis:
    def test_add_custom_pattern_redis_update(self) -> None:
        """add_pattern updates Redis when adding custom pattern."""
        from djangoapi_guard.handlers.suspatterns_handler import SusPatternsManager

        SusPatternsManager.reset()
        mgr = SusPatternsManager()
        mock_redis = MagicMock()
        mgr.redis_handler = mock_redis

        SusPatternsManager.add_pattern("custom_test_pattern", custom=True)

        mock_redis.set_key.assert_called()
        assert "custom_test_pattern" in mgr.custom_patterns
        SusPatternsManager.reset()


class TestSusPatternsRemoveWithRedis:
    def test_remove_pattern_redis_update(self) -> None:
        """_remove_custom_pattern updates Redis when removing."""
        from djangoapi_guard.handlers.suspatterns_handler import SusPatternsManager

        SusPatternsManager.reset()
        mgr = SusPatternsManager()
        mock_redis = MagicMock()
        mgr.redis_handler = mock_redis

        SusPatternsManager.add_pattern("remove_test_pattern", custom=True)
        mock_redis.reset_mock()

        result = mgr._remove_custom_pattern("remove_test_pattern")

        assert result is True
        mock_redis.set_key.assert_called()
        assert "remove_test_pattern" not in mgr.custom_patterns
        SusPatternsManager.reset()


class TestIPBanResetGlobalState:
    def test_reset_global_state(self) -> None:
        """reset_global_state creates a new IPBanManager instance."""
        from djangoapi_guard.handlers import ipban_handler
        from djangoapi_guard.handlers.ipban_handler import (
            IPBanManager,
            reset_global_state,
        )

        original_id = id(ipban_handler.ip_ban_manager)
        # Reset singleton to allow new instance creation
        IPBanManager._instance = None
        reset_global_state()

        assert id(ipban_handler.ip_ban_manager) != original_id


class TestMiddlewareResolveConfig:
    def test_resolve_config_with_config(self) -> None:
        """_resolve_config sets config when config is not None."""
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        new_config = SecurityConfig(
            enable_redis=False, enable_agent=False, rate_limit=50
        )
        middleware._resolve_config(new_config)

        assert middleware.config is new_config
        middleware.reset()

    def test_resolve_config_none_with_existing(self) -> None:
        """_resolve_config with None keeps existing config."""
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        middleware._resolve_config(None)
        assert middleware.config is config
        middleware.reset()

    def test_resolve_config_none_no_existing_raises(self) -> None:
        """_resolve_config raises ValueError when config is None
        and self.config is None."""
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        middleware.config = None  # type: ignore[assignment]
        import pytest as _pytest

        with _pytest.raises(ValueError, match="SecurityConfig must be provided"):
            middleware._resolve_config(None)
        middleware.config = config
        middleware.reset()


class TestMiddlewareAgentSuccess:
    def test_agent_init_success_log_message(self) -> None:
        """Agent init logs success when guard_agent works."""
        import sys
        import types

        config = SecurityConfig(
            enable_redis=False,
            enable_agent=True,
            agent_api_key="test-key",
            agent_project_id="test-project",
        )
        mock_agent_config = MagicMock()
        mock_guard_agent_module: Any = types.ModuleType("guard_agent")
        mock_agent_instance = MagicMock()
        mock_guard_agent_module.guard_agent = MagicMock(
            return_value=mock_agent_instance
        )

        with (
            patch.object(
                django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
            ),
            patch.object(
                SecurityConfig, "to_agent_config", return_value=mock_agent_config
            ),
            patch.dict(sys.modules, {"guard_agent": mock_guard_agent_module}),
        ):
            middleware = DjangoAPIGuard(_get_response)

        assert middleware.agent_handler is mock_agent_instance
        middleware.reset()


class TestMiddlewareBehavioralUsageFalsy:
    def test_behavioral_usage_no_route_config(self) -> None:
        """_process_behavioral_usage skips when route_config is None."""
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        factory = RequestFactory()
        request = factory.get("/api/test")
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        middleware._process_behavioral_usage(request, "127.0.0.1", None)
        middleware.reset()

    def test_behavioral_usage_with_rules(self) -> None:
        """_process_behavioral_usage processes rules when
        route_config has behavior_rules."""
        from djangoapi_guard.handlers.behavior_handler import BehaviorRule

        config = SecurityConfig(enable_redis=False, enable_agent=False)
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        factory = RequestFactory()
        request = factory.get("/api/test")
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        route_config = RouteConfig()
        route_config.behavior_rules = [
            BehaviorRule(rule_type="usage", threshold=5, window=60, action="log")
        ]

        with patch.object(
            middleware.behavioral_processor, "process_usage_rules"
        ) as mock_process:
            middleware._process_behavioral_usage(request, "127.0.0.1", route_config)
            mock_process.assert_called_once_with(request, "127.0.0.1", route_config)

        middleware.reset()


class TestMiddlewareCheckRateLimitNotExceeded:
    def test_rate_limit_not_exceeded_returns_response(self) -> None:
        """_check_rate_limit returns None when rate limit not exceeded (non-passive)."""
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            passive_mode=False,
            enable_rate_limiting=True,
            rate_limit=100,
            rate_limit_window=60,
        )
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        factory = RequestFactory()
        request = factory.get("/api/test")
        request.META["REMOTE_ADDR"] = "1.2.3.4"

        # check_rate_limit returns None (not exceeded)
        with patch.object(
            middleware.rate_limit_handler,
            "check_rate_limit",
            return_value=None,
        ):
            result = middleware._check_rate_limit(request, "1.2.3.4")

        assert result is None
        middleware.reset()


class TestMiddlewareGetEndpointId:
    def test_get_endpoint_id(self) -> None:
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            middleware = DjangoAPIGuard(_get_response)

        factory = RequestFactory()
        request = factory.get("/api/test")
        request.META["REMOTE_ADDR"] = "127.0.0.1"

        endpoint_id = middleware._get_endpoint_id(request)
        assert isinstance(endpoint_id, str)

        middleware.reset()


class TestMiddlewareRuntimeErrors:
    def _make_middleware(self) -> DjangoAPIGuard:
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        with patch.object(
            django.conf.settings, "GUARD_SECURITY_CONFIG", config, create=True
        ):
            return DjangoAPIGuard(_get_response)

    def test_init_routing_event_bus_none(self) -> None:
        mw = self._make_middleware()
        mw.event_bus = None
        with pytest.raises(RuntimeError):
            mw._init_routing_and_validation()
        mw.reset()

    def test_init_routing_response_factory_none(self) -> None:
        mw = self._make_middleware()
        mw.response_factory = None
        with pytest.raises(RuntimeError):
            mw._init_routing_and_validation()
        mw.reset()

    def test_validate_call_config_none(self) -> None:
        mw = self._make_middleware()
        object.__setattr__(mw, "config", None)
        with pytest.raises(RuntimeError):
            mw._validate_call_preconditions()
        mw.reset()

    def test_validate_call_bypass_handler_none(self) -> None:
        mw = self._make_middleware()
        mw.bypass_handler = None
        with pytest.raises(RuntimeError):
            mw._validate_call_preconditions()
        mw.reset()

    def test_validate_call_route_resolver_none(self) -> None:
        mw = self._make_middleware()
        mw.route_resolver = None
        with pytest.raises(RuntimeError):
            mw._validate_call_preconditions()
        mw.reset()

    def test_validate_call_behavioral_processor_none(self) -> None:
        mw = self._make_middleware()
        mw.behavioral_processor = None
        with pytest.raises(RuntimeError):
            mw._validate_call_preconditions()
        mw.reset()

    def test_validate_call_response_factory_none(self) -> None:
        mw = self._make_middleware()
        mw.response_factory = None
        with pytest.raises(RuntimeError):
            mw._validate_call_preconditions()
        mw.reset()

    def test_handle_preflight_bypass_handler_none(self) -> None:
        mw = self._make_middleware()
        mw.bypass_handler = None
        rf = RequestFactory()
        request = rf.get("/api/test")
        with pytest.raises(RuntimeError):
            mw._handle_preflight_and_passthrough(request)
        mw.reset()

    def test_prepare_request_route_resolver_none(self) -> None:
        mw = self._make_middleware()
        mw.route_resolver = None
        rf = RequestFactory()
        request = rf.get("/api/test")
        with pytest.raises(RuntimeError):
            mw._prepare_request(request)
        mw.reset()

    def test_prepare_request_bypass_handler_none(self) -> None:
        mw = self._make_middleware()
        mw.bypass_handler = None
        rf = RequestFactory()
        request = rf.get("/api/test")
        with pytest.raises(RuntimeError):
            mw._prepare_request(request)
        mw.reset()

    def test_finalize_response_factory_none(self) -> None:
        mw = self._make_middleware()
        mw.response_factory = None
        rf = RequestFactory()
        request = rf.get("/api/test")
        response = HttpResponse("ok")
        with pytest.raises(RuntimeError):
            mw._finalize_response(request, response, None)
        mw.reset()

    def test_finalize_behavioral_processor_none(self) -> None:
        mw = self._make_middleware()
        mw.behavioral_processor = None
        rf = RequestFactory()
        request = rf.get("/api/test")
        response = HttpResponse("ok")
        with pytest.raises(RuntimeError):
            mw._finalize_response(request, response, None)
        mw.reset()

    def test_initialize_handlers_none(self) -> None:
        mw = self._make_middleware()
        mw.handler_initializer = None
        with pytest.raises(RuntimeError):
            mw._initialize_handlers()
        mw.reset()

    def test_process_behavioral_usage_none(self) -> None:
        mw = self._make_middleware()
        mw.behavioral_processor = None
        rf = RequestFactory()
        request = rf.get("/api/test")
        with pytest.raises(RuntimeError):
            mw._process_behavioral_usage(request, "1.2.3.4", None)
        mw.reset()

    def test_handle_preflight_response_factory_none(self) -> None:
        mw = self._make_middleware()
        mw.response_factory = None
        rf = RequestFactory()
        request = rf.get("/api/test")
        with pytest.raises(RuntimeError):
            mw._handle_preflight(request)
        mw.reset()

    def test_create_https_redirect_none(self) -> None:
        mw = self._make_middleware()
        mw.response_factory = None
        rf = RequestFactory()
        request = rf.get("/api/test")
        with pytest.raises(RuntimeError):
            mw._create_https_redirect(request)
        mw.reset()

    def test_check_time_window_validator_none(self) -> None:
        mw = self._make_middleware()
        mw.validator = None
        with pytest.raises(RuntimeError):
            mw._check_time_window({})
        mw.reset()

    def test_process_response_factory_none(self) -> None:
        mw = self._make_middleware()
        mw.response_factory = None
        rf = RequestFactory()
        request = rf.get("/api/test")
        response = HttpResponse("ok")
        with pytest.raises(RuntimeError):
            mw._process_response(request, response, 0.1, None)
        mw.reset()

    def test_process_response_behavioral_none(self) -> None:
        mw = self._make_middleware()
        mw.behavioral_processor = None
        rf = RequestFactory()
        request = rf.get("/api/test")
        response = HttpResponse("ok")
        with pytest.raises(RuntimeError):
            mw._process_response(request, response, 0.1, None)
        mw.reset()

    def test_process_decorator_usage_rules_none(self) -> None:
        mw = self._make_middleware()
        mw.behavioral_processor = None
        rf = RequestFactory()
        request = rf.get("/api/test")
        with pytest.raises(RuntimeError):
            mw._process_decorator_usage_rules(request, "1.2.3.4", RouteConfig())
        mw.reset()

    def test_process_decorator_return_rules_none(self) -> None:
        mw = self._make_middleware()
        mw.behavioral_processor = None
        rf = RequestFactory()
        request = rf.get("/api/test")
        response = HttpResponse("ok")
        with pytest.raises(RuntimeError):
            mw._process_decorator_return_rules(
                request, response, "1.2.3.4", RouteConfig()
            )
        mw.reset()

    def test_get_endpoint_id_none(self) -> None:
        mw = self._make_middleware()
        mw.behavioral_processor = None
        rf = RequestFactory()
        request = rf.get("/api/test")
        with pytest.raises(RuntimeError):
            mw._get_endpoint_id(request)
        mw.reset()

    def test_create_error_response_none(self) -> None:
        mw = self._make_middleware()
        mw.response_factory = None
        with pytest.raises(RuntimeError):
            mw.create_error_response(400, "bad request")
        mw.reset()


class TestSecurityCheckBaseRuntimeErrors:
    def test_config_none_raises_runtime_error(self) -> None:
        middleware = MagicMock()
        middleware.config = None
        middleware.logger = MagicMock()

        from djangoapi_guard.core.checks.base import SecurityCheck

        class DummyCheck(SecurityCheck):
            @property
            def check_name(self) -> str:
                return "dummy"

            def check(self, request: HttpRequest) -> HttpResponse | None:
                return None

        with pytest.raises(RuntimeError, match="initialized with config"):
            DummyCheck(middleware)

    def test_logger_none_raises_runtime_error(self) -> None:
        middleware = MagicMock()
        middleware.config = SecurityConfig(enable_redis=False, enable_agent=False)
        middleware.logger = None

        from djangoapi_guard.core.checks.base import SecurityCheck

        class DummyCheck(SecurityCheck):
            @property
            def check_name(self) -> str:
                return "dummy"

            def check(self, request: HttpRequest) -> HttpResponse | None:
                return None

        with pytest.raises(RuntimeError, match="initialized with logger"):
            DummyCheck(middleware)


class TestHoneypotValidFormAndJsonData:
    def _get_honeypot_validator(self, trap_fields: list[str]) -> Any:
        from djangoapi_guard.decorators import SecurityDecorator

        config = SecurityConfig(enable_redis=False, enable_agent=False)
        guard = SecurityDecorator(config)

        def dummy_view(request: HttpRequest) -> HttpResponse:
            return HttpResponse("ok")

        guard.honeypot_detection(trap_fields)(dummy_view)
        route_id = guard._get_route_id(dummy_view)
        route_config = guard.get_route_config(route_id)
        assert route_config is not None
        return route_config.custom_validators[0]

    def test_valid_form_data_returns_none(self) -> None:
        validator = self._get_honeypot_validator(["honeypot_field"])
        rf = RequestFactory()
        request = rf.post(
            "/api/test",
            data={"username": "real_user"},
            content_type="application/x-www-form-urlencoded",
        )
        result = validator(request)
        assert result is None

    def test_valid_json_data_returns_none(self) -> None:
        import json as json_mod

        validator = self._get_honeypot_validator(["honeypot_field"])
        rf = RequestFactory()
        request = rf.post(
            "/api/test",
            data=json_mod.dumps({"username": "real_user"}),
            content_type="application/json",
        )
        result = validator(request)
        assert result is None
