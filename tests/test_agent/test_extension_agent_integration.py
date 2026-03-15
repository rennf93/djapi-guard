import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, override_settings

from djangoapi_guard.decorators.base import RouteConfig
from djangoapi_guard.middleware import DjangoAPIGuard
from djangoapi_guard.models import SecurityConfig


def _make_middleware(config: SecurityConfig) -> DjangoAPIGuard:
    """Helper to create middleware with a given config."""

    def get_response(request: HttpRequest) -> HttpResponse:
        return HttpResponse("ok", status=200)

    with (
        override_settings(GUARD_SECURITY_CONFIG=config),
        patch(
            "djangoapi_guard.handlers.redis_handler.RedisManager.initialize",
        ),
        patch(
            "djangoapi_guard.handlers.ratelimit_handler.RateLimitManager.initialize_redis",
        ),
        patch(
            "djangoapi_guard.core.initialization.handler_initializer.HandlerInitializer.initialize_redis_handlers",
        ),
        patch(
            "djangoapi_guard.core.initialization.handler_initializer.HandlerInitializer.initialize_dynamic_rule_manager",
        ),
    ):
        middleware = DjangoAPIGuard(get_response)

    return middleware


class TestExtensionAgentIntegration:
    def test_agent_initialization_success(self, config: SecurityConfig) -> None:
        middleware = _make_middleware(config)

        assert middleware.agent_handler is not None

    def test_agent_initialization_import_error(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        caplog.set_level("INFO", logger="djangoapi_guard")

        import sys

        guard_agent_backup = sys.modules.pop("guard_agent", None)
        guard_models_backup = sys.modules.pop("guard_agent.models", None)

        try:
            import builtins

            original_import = builtins.__import__

            def mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
                if name == "guard_agent":
                    raise ImportError("No module named 'guard_agent'")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=mock_import):
                middleware = _make_middleware(config)

                assert middleware.agent_handler is None
                assert "Agent enabled but configuration is invalid" in caplog.text
        finally:
            if guard_agent_backup:
                sys.modules["guard_agent"] = guard_agent_backup
            if guard_models_backup:
                sys.modules["guard_agent.models"] = guard_models_backup

    def test_extension_import_error_handler(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        caplog.set_level("INFO", logger="djangoapi_guard")

        mock_agent_config = MagicMock()

        with patch.object(
            SecurityConfig, "to_agent_config", return_value=mock_agent_config
        ):
            import builtins

            original_import = builtins.__import__

            def mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
                if name == "guard_agent":
                    raise ImportError("No module named 'guard_agent'")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=mock_import):
                middleware = _make_middleware(config)

                assert middleware.agent_handler is None
                warning_msg = "Agent enabled but guard_agent package not installed"
                assert warning_msg in caplog.text
                assert "Install with: pip install fastapi-guard-agent" in caplog.text

    def test_agent_initialization_exception(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        caplog.set_level("INFO", logger="djangoapi_guard")

        mock_guard_agent = MagicMock(side_effect=Exception("Connection failed"))

        with patch.dict(
            "sys.modules",
            {"guard_agent": MagicMock(guard_agent=mock_guard_agent)},
        ):
            middleware = _make_middleware(config)

            assert middleware.agent_handler is None
            assert "Failed to initialize Guard Agent" in caplog.text

    def test_agent_initialization_invalid_config(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        invalid_config = SecurityConfig(enable_agent=False)

        middleware = _make_middleware(invalid_config)

        assert middleware.agent_handler is None

    def test_agent_disabled(self, config: SecurityConfig) -> None:
        config = SecurityConfig(enable_agent=False)

        middleware = _make_middleware(config)

        assert middleware.agent_handler is None

    def test_send_middleware_event_success(self, config: SecurityConfig) -> None:
        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler

        request = MagicMock(spec=HttpRequest)
        request.path = "/api/test"
        request.method = "GET"
        request.META = {"HTTP_USER_AGENT": "test-agent", "REMOTE_ADDR": "192.168.1.100"}

        with patch(
            "djangoapi_guard.middleware.extract_client_ip",
            MagicMock(return_value="192.168.1.100"),
        ):
            middleware.event_bus.send_middleware_event(
                "decorator_violation", request, "blocked", "test reason", extra="data"
            )

            middleware.agent_handler.send_event.assert_called_once()

    def test_send_middleware_event_disabled(self) -> None:
        config = SecurityConfig(
            enable_agent=True, agent_api_key="test-api-key", agent_enable_events=False
        )

        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()

        request = MagicMock(spec=HttpRequest)

        assert middleware.event_bus is not None
        middleware.event_bus.send_middleware_event(
            "decorator_violation", request, "blocked", "test reason"
        )

        middleware.agent_handler.send_event.assert_not_called()

    def test_send_middleware_event_no_agent(self, config: SecurityConfig) -> None:
        middleware = _make_middleware(config)
        middleware.agent_handler = None

        request = MagicMock(spec=HttpRequest)

        assert middleware.event_bus is not None
        middleware.event_bus.send_middleware_event(
            "decorator_violation", request, "blocked", "test reason"
        )

    def test_send_middleware_event_with_geo_handler(
        self, config: SecurityConfig
    ) -> None:
        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler

        mock_geo_handler = MagicMock()
        mock_geo_handler.get_country.return_value = "US"
        middleware.geo_ip_handler = mock_geo_handler
        middleware.event_bus.geo_ip_handler = mock_geo_handler

        request = MagicMock(spec=HttpRequest)
        request.path = "/api/test"
        request.method = "POST"
        request.META = {"HTTP_USER_AGENT": "test-agent", "REMOTE_ADDR": "192.168.1.100"}

        with patch(
            "djangoapi_guard.middleware.extract_client_ip",
            MagicMock(return_value="192.168.1.100"),
        ):
            middleware.event_bus.send_middleware_event(
                "country_blocked", request, "allowed", "from US"
            )

            middleware.agent_handler.send_event.assert_called_once()

            sent_event = middleware.agent_handler.send_event.call_args[0][0]
            assert sent_event.country == "US"
            assert sent_event.ip_address == "192.168.1.100"

    def test_send_middleware_event_geo_handler_failure(
        self, config: SecurityConfig
    ) -> None:
        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler

        mock_geo_handler = MagicMock()
        mock_geo_handler.get_country.side_effect = Exception("Geo lookup failed")
        middleware.geo_ip_handler = mock_geo_handler

        request = MagicMock(spec=HttpRequest)
        request.path = "/api/test"
        request.method = "GET"
        request.META = {"HTTP_USER_AGENT": "test-agent", "REMOTE_ADDR": "192.168.1.100"}

        with patch(
            "djangoapi_guard.middleware.extract_client_ip",
            MagicMock(return_value="192.168.1.100"),
        ):
            middleware.event_bus.send_middleware_event(
                "decorator_violation", request, "blocked", "test reason"
            )

            middleware.agent_handler.send_event.assert_called_once()

            sent_event = middleware.agent_handler.send_event.call_args[0][0]
            assert sent_event.country is None
            assert sent_event.ip_address == "192.168.1.100"

    def test_send_middleware_event_agent_failure(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        middleware.agent_handler.send_event.side_effect = Exception("Network error")
        assert middleware.event_bus is not None
        middleware.event_bus.agent_handler = middleware.agent_handler

        request = MagicMock(spec=HttpRequest)
        request.path = "/api/test"
        request.method = "GET"
        request.META = {"HTTP_USER_AGENT": "test-agent"}

        with patch(
            "djangoapi_guard.middleware.extract_client_ip",
            MagicMock(return_value="192.168.1.100"),
        ):
            with caplog.at_level(logging.ERROR):
                middleware.event_bus.send_middleware_event(
                    "decorator_violation", request, "blocked", "test reason"
                )

            assert "Failed to send security event to agent" in caplog.text

    def test_send_security_metric_success(self, config: SecurityConfig) -> None:
        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler

        middleware.metrics_collector.send_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

        middleware.agent_handler.send_metric.assert_called_once()

        sent_metric = middleware.agent_handler.send_metric.call_args[0][0]
        assert sent_metric.metric_type == "response_time"
        assert sent_metric.value == 123.45
        assert sent_metric.tags == {"endpoint": "/api/test"}

    def test_send_security_metric_disabled(self) -> None:
        config = SecurityConfig(
            enable_agent=True, agent_api_key="test-api-key", agent_enable_metrics=False
        )

        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()

        assert middleware.metrics_collector is not None
        middleware.metrics_collector.send_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

        middleware.agent_handler.send_metric.assert_not_called()

    def test_send_security_metric_no_agent(self, config: SecurityConfig) -> None:
        middleware = _make_middleware(config)
        middleware.agent_handler = None

        assert middleware.metrics_collector is not None
        middleware.metrics_collector.send_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

    def test_send_security_metric_agent_failure(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler
        middleware.agent_handler.send_metric.side_effect = Exception("Network error")

        middleware.metrics_collector.send_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

        assert "Failed to send metric to agent" in caplog.text

    def test_send_security_metric_no_tags(self, config: SecurityConfig) -> None:
        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler

        middleware.metrics_collector.send_metric("request_count", 1.0)

        middleware.agent_handler.send_metric.assert_called_once()

        sent_metric = middleware.agent_handler.send_metric.call_args[0][0]
        assert sent_metric.tags == {}

    def test_collect_request_metrics(self, config: SecurityConfig) -> None:
        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()

        request = MagicMock(spec=HttpRequest)
        request.path = "/api/test"
        request.method = "GET"

        assert middleware.metrics_collector is not None
        with patch.object(
            middleware.metrics_collector, "send_metric", MagicMock()
        ) as mock_send:
            middleware.metrics_collector.collect_request_metrics(request, 50.5, 200)

            assert mock_send.call_count == 2

            mock_send.assert_any_call(
                "response_time",
                50.5,
                {"endpoint": "/api/test", "method": "GET", "status": "200"},
            )

            mock_send.assert_any_call(
                "request_count", 1.0, {"endpoint": "/api/test", "method": "GET"}
            )

    def test_collect_request_metrics_disabled(self) -> None:
        config = SecurityConfig(
            enable_agent=True, agent_api_key="test-api-key", agent_enable_metrics=False
        )

        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()

        request = MagicMock(spec=HttpRequest)
        request.path = "/api/test"
        request.method = "GET"

        assert middleware.metrics_collector is not None
        middleware.metrics_collector.collect_request_metrics(request, 50.5, 200)

        middleware.agent_handler.send_metric.assert_not_called()

    def test_collect_request_metrics_no_agent(self, config: SecurityConfig) -> None:
        middleware = _make_middleware(config)
        middleware.agent_handler = None

        request = MagicMock(spec=HttpRequest)
        request.path = "/api/test"
        request.method = "GET"

        assert middleware.metrics_collector is not None
        middleware.metrics_collector.collect_request_metrics(request, 50.5, 200)

    def test_collect_request_metrics_different_status_codes(
        self, config: SecurityConfig
    ) -> None:
        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()

        request = MagicMock(spec=HttpRequest)
        request.path = "/api/secure"
        request.method = "POST"

        assert middleware.metrics_collector is not None
        with patch.object(
            middleware.metrics_collector, "send_metric", MagicMock()
        ) as mock_send:
            middleware.metrics_collector.collect_request_metrics(request, 25.3, 403)

            mock_send.assert_any_call(
                "response_time",
                25.3,
                {"endpoint": "/api/secure", "method": "POST", "status": "403"},
            )

            middleware.metrics_collector.collect_request_metrics(request, 100.2, 500)

            mock_send.assert_any_call(
                "response_time",
                100.2,
                {"endpoint": "/api/secure", "method": "POST", "status": "500"},
            )

    def test_agent_init_invalid_config_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level("INFO", logger="djangoapi_guard")

        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
        )

        with patch.object(SecurityConfig, "to_agent_config", return_value=None):
            middleware = _make_middleware(config)

        assert "Agent enabled but configuration is invalid" in caplog.text
        assert middleware.agent_handler is None

    def test_emergency_mode_block_with_event(self, config: SecurityConfig) -> None:
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            emergency_mode=True,
            emergency_whitelist=["192.168.1.1"],
        )

        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler

        factory = RequestFactory()
        request = factory.get("/test", REMOTE_ADDR="10.0.0.1")

        response = middleware(request)

        assert response.status_code == 503
        middleware.agent_handler.send_event.assert_called_once()
        event = middleware.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "emergency_mode_block"
        assert event.action_taken == "request_blocked"

    def test_emergency_mode_allow_whitelist_with_logging(
        self,
    ) -> None:
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            emergency_mode=True,
            emergency_whitelist=["192.168.1.1"],
        )

        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()

        factory = RequestFactory()

        with (
            patch("djangoapi_guard.utils.log_activity", MagicMock()),
            patch(
                "djangoapi_guard.core.checks.helpers.detect_penetration_attempt",
                MagicMock(return_value=(False, "")),
            ),
        ):
            request = factory.get("/test", REMOTE_ADDR="192.168.1.1")
            response = middleware(request)

        assert response.status_code == 200

    def test_generic_auth_requirement_failure(self) -> None:
        route_config = RouteConfig()
        route_config.auth_required = "custom"

        config = SecurityConfig(enable_agent=True, agent_api_key="test-key")

        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler

        factory = RequestFactory()

        with patch.object(
            middleware.route_resolver, "get_route_config", return_value=route_config
        ):
            request = factory.get("/test")
            response = middleware(request)

        assert response.status_code == 401
        middleware.agent_handler.send_event.assert_called_once()
        event = middleware.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert "Missing custom authentication" in event.reason

    def test_missing_referrer_with_event(self) -> None:
        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        config = SecurityConfig(enable_agent=True, agent_api_key="test-key")

        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler

        factory = RequestFactory()

        with patch.object(
            middleware.route_resolver, "get_route_config", return_value=route_config
        ):
            request = factory.get("/test")
            response = middleware(request)

        assert response.status_code == 403
        middleware.agent_handler.send_event.assert_called_once()
        event = middleware.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert event.metadata["violation_type"] == "require_referrer"

    def test_referrer_parsing_exception(self) -> None:
        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        config = SecurityConfig(enable_agent=True, agent_api_key="test-key")

        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()

        factory = RequestFactory()

        with patch.object(
            middleware.route_resolver, "get_route_config", return_value=route_config
        ):
            with patch("urllib.parse.urlparse", side_effect=Exception("Parse error")):
                request = factory.get("/test", HTTP_REFERER="invalid://url")
                response = middleware(request)

        assert response.status_code == 403

    def test_invalid_referrer_domain_with_event(self) -> None:
        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        config = SecurityConfig(enable_agent=True, agent_api_key="test-key")

        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler

        factory = RequestFactory()

        with patch.object(
            middleware.route_resolver, "get_route_config", return_value=route_config
        ):
            request = factory.get("/test", HTTP_REFERER="https://evil.com/page")
            response = middleware(request)

        assert response.status_code == 403
        middleware.agent_handler.send_event.assert_called_once()
        event = middleware.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert "not in allowed domains" in event.reason

    def test_route_specific_user_agent_block_event(self) -> None:
        route_config = RouteConfig()
        route_config.blocked_user_agents = ["BadBot"]

        config = SecurityConfig(enable_agent=True, agent_api_key="test-key")

        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler

        factory = RequestFactory()

        with patch.object(
            middleware.route_resolver, "get_route_config", return_value=route_config
        ):
            request = factory.get("/test", HTTP_USER_AGENT="BadBot/1.0")
            response = middleware(request)

        assert response.status_code == 403
        calls = middleware.agent_handler.send_event.call_args_list
        assert len(calls) >= 1
        event = calls[0][0][0]
        assert event.event_type == "decorator_violation"
        assert event.metadata["violation_type"] == "user_agent"

    def test_suspicious_detection_disabled_by_decorator(
        self, config: SecurityConfig
    ) -> None:
        route_config = RouteConfig()
        route_config.enable_suspicious_detection = False

        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_penetration_detection=True,
        )

        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler

        factory = RequestFactory()

        with patch.object(
            middleware.route_resolver, "get_route_config", return_value=route_config
        ):
            request = factory.get("/test?cmd=rm%20-rf")
            middleware(request)

        middleware.agent_handler.send_event.assert_called_once()
        event = middleware.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert event.metadata["violation_type"] == "suspicious_detection_disabled"

    def test_dynamic_endpoint_rate_limiting(self) -> None:
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_redis=True,
            redis_url="redis://localhost:6379",
            endpoint_rate_limits={"/api/sensitive": (10, 60)},
        )

        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler

        mock_redis_handler = MagicMock()
        middleware.redis_handler = mock_redis_handler

        mock_rate_handler = MagicMock()
        mock_rate_handler.check_rate_limit = MagicMock(
            return_value=HttpResponse("Rate limit exceeded", status=429)
        )
        mock_rate_handler.initialize_redis = MagicMock()

        factory = RequestFactory()

        with (
            patch(
                "djangoapi_guard.core.checks.implementations.rate_limit.RateLimitManager",
                return_value=mock_rate_handler,
            ),
            patch(
                "djangoapi_guard.utils.extract_client_ip",
                MagicMock(return_value="127.0.0.1"),
            ),
            patch("djangoapi_guard.utils.log_activity", MagicMock()),
            patch(
                "djangoapi_guard.core.checks.helpers.detect_penetration_attempt",
                MagicMock(return_value=(False, "")),
            ),
        ):
            request = factory.get("/api/sensitive")
            response = middleware(request)

        assert response.status_code == 429
        middleware.agent_handler.send_event.assert_called_once()
        event = middleware.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "dynamic_rule_violation"
        assert event.metadata["rule_type"] == "endpoint_rate_limit"
        assert event.metadata["endpoint"] == "/api/sensitive"
        assert event.metadata["rate_limit"] == 10
        assert event.metadata["window"] == 60

    def test_route_specific_rate_limit_exceeded_event(self) -> None:
        route_config = RouteConfig()
        route_config.rate_limit = 5
        route_config.rate_limit_window = 30

        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_redis=True,
            redis_url="redis://localhost:6379",
        )

        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler

        mock_redis_handler = MagicMock()
        middleware.redis_handler = mock_redis_handler

        mock_rate_handler = MagicMock()
        mock_rate_handler.check_rate_limit = MagicMock(
            return_value=HttpResponse("Rate limit exceeded", status=429)
        )
        mock_rate_handler.initialize_redis = MagicMock()

        factory = RequestFactory()

        with (
            patch.object(
                middleware.route_resolver, "get_route_config", return_value=route_config
            ),
            patch(
                "djangoapi_guard.core.checks.implementations.rate_limit.RateLimitManager",
                return_value=mock_rate_handler,
            ),
            patch(
                "djangoapi_guard.utils.extract_client_ip",
                MagicMock(return_value="127.0.0.1"),
            ),
            patch("djangoapi_guard.utils.log_activity", MagicMock()),
            patch(
                "djangoapi_guard.core.checks.helpers.detect_penetration_attempt",
                MagicMock(return_value=(False, "")),
            ),
        ):
            request = factory.get("/test")
            response = middleware(request)

        assert response.status_code == 429
        middleware.agent_handler.send_event.assert_called_once()
        event = middleware.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert event.metadata["decorator_type"] == "rate_limiting"
        assert event.metadata["violation_type"] == "rate_limit"
        assert event.metadata["rate_limit"] == 5
        assert event.metadata["window"] == 30

    def test_cloud_provider_detection_with_agent_event(
        self, config: SecurityConfig
    ) -> None:
        config.block_cloud_providers = {"AWS", "GCP"}

        middleware = _make_middleware(config)
        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler

        mock_cloud_handler = MagicMock()
        mock_cloud_handler.is_cloud_ip.return_value = True
        mock_cloud_handler.get_cloud_provider_details.return_value = (
            "aws",
            "3.0.0.0/8",
        )
        mock_cloud_handler.agent_handler = middleware.agent_handler
        mock_cloud_handler.send_cloud_detection_event = MagicMock()
        mock_cloud_handler.refresh = MagicMock()

        mock_time = MagicMock()
        mock_time.time.return_value = 9999999999

        factory = RequestFactory()

        with (
            patch(
                "djangoapi_guard.core.checks.implementations.cloud_provider.cloud_handler",
                mock_cloud_handler,
            ),
            patch(
                "djangoapi_guard.core.checks.implementations.cloud_ip_refresh.time",
                mock_time,
            ),
            patch(
                "djangoapi_guard.utils.extract_client_ip",
                MagicMock(return_value="3.3.3.3"),
            ),
            patch("djangoapi_guard.utils.log_activity", MagicMock()),
            patch(
                "djangoapi_guard.core.checks.helpers.detect_penetration_attempt",
                MagicMock(return_value=(False, "")),
            ),
        ):
            request = factory.get(
                "/test",
                HTTP_USER_AGENT="Mozilla/5.0",
                REMOTE_ADDR="3.3.3.3",
            )
            response = middleware(request)

        assert response.status_code == 403
        mock_cloud_handler.send_cloud_detection_event.assert_called_once_with(
            "3.3.3.3", "aws", "3.0.0.0/8", "request_blocked"
        )

    def test_initialize_with_agent_handler(self) -> None:
        mock_geo_ip_handler = MagicMock()
        mock_geo_ip_handler.initialize_agent = MagicMock()
        mock_geo_ip_handler.initialize_redis = MagicMock()

        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_redis=True,
            redis_url="redis://localhost:6379",
            enable_dynamic_rules=True,
            block_cloud_providers={"AWS"},
            whitelist_countries=["US"],
            geo_ip_handler=mock_geo_ip_handler,
        )

        middleware = _make_middleware(config)

        middleware.agent_handler = MagicMock()
        assert middleware.event_bus is not None
        assert middleware.metrics_collector is not None
        middleware.event_bus.agent_handler = middleware.agent_handler
        middleware.metrics_collector.agent_handler = middleware.agent_handler
        middleware.redis_handler = MagicMock()
        middleware.guard_decorator = MagicMock()
        middleware.guard_decorator.initialize_agent = MagicMock()

        mock_redis_init = MagicMock()
        mock_agent_init = MagicMock()

        with (
            patch.object(
                middleware.handler_initializer,
                "initialize_redis_handlers",
                mock_redis_init,
            ),
            patch.object(
                middleware.handler_initializer,
                "initialize_agent_integrations",
                mock_agent_init,
            ),
        ):
            middleware._initialize_handlers()

        mock_redis_init.assert_called_once()

        mock_agent_init.assert_called_once()

        assert middleware.geo_ip_handler is not None
