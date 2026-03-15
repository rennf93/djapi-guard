import logging
import sys
import time
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory

from djangoapi_guard.decorators.base import BaseSecurityDecorator
from djangoapi_guard.handlers.cloud_handler import cloud_handler
from djangoapi_guard.handlers.ratelimit_handler import (
    RateLimitManager,
    rate_limit_handler,
)
from djangoapi_guard.middleware import DjangoAPIGuard
from djangoapi_guard.models import SecurityConfig


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> Iterator[None]:
    yield
    config = SecurityConfig(enable_redis=False, enable_agent=False)
    handler = rate_limit_handler(config)
    handler.reset()


class TestDjangoAPIGuard:
    def _make_middleware(self, config: SecurityConfig | None = None) -> DjangoAPIGuard:
        if config is None:
            config = SecurityConfig(enable_redis=False, enable_agent=False)

        import django.conf

        django.conf.settings.GUARD_SECURITY_CONFIG = config

        def get_response(request: HttpRequest) -> HttpResponse:
            return HttpResponse("OK", status=200)

        return DjangoAPIGuard(get_response)

    def test_middleware_creation(self) -> None:
        middleware = self._make_middleware()
        assert middleware is not None
        assert middleware.config is not None

    def test_passthrough_request(self) -> None:
        middleware = self._make_middleware()
        factory = RequestFactory()
        request = factory.get("/")
        response = middleware(request)
        assert response.status_code == 200

    def test_excluded_path(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            exclude_paths=["/health"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.get("/health")
        response = middleware(request)
        assert response.status_code == 200

    def test_ip_blacklist(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            blacklist=["192.168.1.100"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.get("/api/test/")
        request.META["REMOTE_ADDR"] = "192.168.1.100"
        response = middleware(request)
        assert response.status_code == 403

    def test_ip_whitelist_allows(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            whitelist=["10.0.0.1"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "10.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

    def test_ip_whitelist_blacklist_combined(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            whitelist=["127.0.0.1"],
            blacklist=["192.168.1.1"],
            enable_penetration_detection=False,
            trusted_proxies=["127.0.0.1"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "192.168.1.1"
        response = middleware(request)
        assert response.status_code == 403

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "10.0.0.1"
        response = middleware(request)
        assert response.status_code == 403

    def test_rate_limiting(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            rate_limit=2,
            rate_limit_window=60,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        for _ in range(3):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "10.0.0.50"
            response = middleware(request)

        assert response.status_code == 429

    def test_rate_limiting_with_reset(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            rate_limit=2,
            rate_limit_window=1,
            enable_rate_limiting=True,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 429

        middleware.reset()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

    def test_rate_limiting_multiple_ips(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            rate_limit=2,
            rate_limit_window=60,
            enable_rate_limiting=True,
            whitelist=[],
            blacklist=[],
            enable_penetration_detection=False,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        for i in range(1, 4):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "192.168.1.1"
            response = middleware(request)
            assert response.status_code == (200 if i <= 2 else 429)

        for i in range(1, 4):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "192.168.1.5"
            response = middleware(request)
            assert response.status_code == (200 if i <= 2 else 429)

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.1"
        response = middleware(request)
        assert response.status_code == 429

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.5"
        response = middleware(request)
        assert response.status_code == 429

    def test_rate_limiting_disabled(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_rate_limiting=False,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        for _ in range(20):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "10.0.0.1"
            response = middleware(request)
            assert response.status_code == 200

    def test_sliding_window_rate_limiting(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            rate_limit=3,
            rate_limit_window=1,
            enable_rate_limiting=True,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        handler = rate_limit_handler(config)
        handler.reset()

        for _ in range(3):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "127.0.0.1"
            response = middleware(request)
            assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 429

        time.sleep(1.5)

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

    def test_cleanup_expired_request_times(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            rate_limit=2,
            rate_limit_window=1,
        )
        middleware = self._make_middleware(config)
        handler = middleware.rate_limit_handler
        handler.reset()

        assert len(handler.request_timestamps) == 0

        current_time = time.time()
        handler.request_timestamps["ip1"].append(current_time)
        handler.request_timestamps["ip1"].append(current_time)
        handler.request_timestamps["ip2"].append(current_time)

        assert len(handler.request_timestamps["ip1"]) == 2
        assert len(handler.request_timestamps["ip2"]) == 1
        assert len(handler.request_timestamps) == 2

        handler.reset()
        assert len(handler.request_timestamps) == 0

    def test_rate_limiter_deque_cleanup(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            rate_limit=10,
            rate_limit_window=60,
        )
        handler = rate_limit_handler(config)
        handler.reset()

        current_time = time.time()
        window_start = current_time - config.rate_limit_window
        client_ip = "192.168.1.1"

        old_queue = handler.request_timestamps[client_ip]
        old_queue.append(window_start - 0.5)
        old_queue.append(window_start - 0.7)
        old_queue.append(window_start - 0.2)

        assert len(old_queue) == 3
        assert all(ts < window_start for ts in old_queue)

        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = client_ip

        def create_error_response(status_code: int, message: str) -> HttpResponse:
            return HttpResponse(message, status=status_code)

        result = handler.check_rate_limit(request, client_ip, create_error_response)
        assert result is None
        assert len(handler.request_timestamps[client_ip]) == 1

    def test_passive_mode(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            passive_mode=True,
            blacklist=["192.168.1.100"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.100"
        response = middleware(request)
        assert response.status_code == 200

    def test_passive_mode_rate_limiting(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            passive_mode=True,
            rate_limit=1,
            rate_limit_window=60,
            enable_rate_limiting=True,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

        result = middleware._check_rate_limit(request, "127.0.0.1")
        assert result is None

    def test_passive_mode_penetration_detection(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            passive_mode=True,
            whitelist=[],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        with (
            patch(
                "djangoapi_guard.core.checks.implementations.suspicious_activity.detect_penetration_patterns",
                return_value=(True, "SQL injection attempt"),
            ),
            patch(
                "djangoapi_guard.core.checks.implementations.suspicious_activity.log_activity"
            ),
            patch(
                "djangoapi_guard.utils.detect_penetration_attempt",
                return_value=(True, "SQL injection attempt"),
            ),
        ):
            request = factory.get("/login")
            request.META["REMOTE_ADDR"] = "10.0.0.1"
            response = middleware(request)
            assert response.status_code == 200

    def test_user_agent_blocking(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            blocked_user_agents=["BadBot"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.get("/")
        request.META["HTTP_USER_AGENT"] = "BadBot/1.0"
        response = middleware(request)
        assert response.status_code == 403

    def test_user_agent_filtering_allowed(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            blocked_user_agents=[r"badbot"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["HTTP_USER_AGENT"] = "badbot"
        response = middleware(request)
        assert response.status_code == 403

        request = factory.get("/")
        request.META["HTTP_USER_AGENT"] = "goodbot"
        response = middleware(request)
        assert response.status_code == 200

    def test_custom_request_check(self) -> None:
        def custom_check(request: HttpRequest) -> HttpResponse | None:
            if request.META.get("HTTP_X_CUSTOM_HEADER") == "block":
                return HttpResponse("Custom block", status=403)
            return None

        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            custom_request_check=custom_check,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["HTTP_X_CUSTOM_HEADER"] = "block"
        response = middleware(request)
        assert response.status_code == 403
        assert response.content == b"Custom block"

        request = factory.get("/")
        request.META["HTTP_X_CUSTOM_HEADER"] = "allow"
        response = middleware(request)
        assert response.status_code == 200

    def test_custom_response_modifier(self) -> None:
        def custom_modifier(response: HttpResponse) -> HttpResponse:
            response["X-Modified"] = "True"
            return response

        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            custom_response_modifier=custom_modifier,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response["X-Modified"] == "True"
        assert response.status_code == 200

    def test_custom_response_modifier_with_blacklist(self) -> None:
        def custom_modifier(response: HttpResponse) -> HttpResponse:
            response["X-Modified"] = "True"
            return response

        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            blacklist=["192.168.1.5"],
            custom_response_modifier=custom_modifier,
            trusted_proxies=["127.0.0.1"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response["X-Modified"] == "True"
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "192.168.1.5"
        response = middleware(request)
        assert response.status_code == 403

    def test_custom_response_modifier_with_custom_check(self) -> None:
        def custom_modifier(response: HttpResponse) -> HttpResponse:
            response["X-Modified"] = "True"
            return response

        def custom_check(request: HttpRequest) -> HttpResponse | None:
            if request.META.get("HTTP_X_CUSTOM_CHECK"):
                return HttpResponse("I'm a teapot", status=418)
            return None

        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            custom_response_modifier=custom_modifier,
            custom_request_check=custom_check,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["HTTP_X_CUSTOM_CHECK"] = "true"
        response = middleware(request)
        assert response.status_code == 418

        request = factory.get("/")
        response = middleware(request)
        assert response["X-Modified"] == "True"
        assert response.status_code == 200

    def test_custom_error_responses(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            custom_error_responses={403: "Custom Forbidden"},
        )
        middleware = self._make_middleware(config)
        response = middleware.create_error_response(403, "Default")
        assert b"Custom Forbidden" in response.content

    def test_custom_error_responses_with_rate_limit(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            blacklist=["192.168.1.3"],
            custom_error_responses={
                403: "Custom Forbidden",
                429: "Custom Too Many Requests",
            },
            rate_limit=5,
            rate_limit_window=60,
            auto_ban_threshold=10,
            enable_penetration_detection=False,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.3"
        response = middleware(request)
        assert response.status_code == 403
        assert b"Custom Forbidden" in response.content

        for _ in range(5):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "192.168.1.4"
            response = middleware(request)
            assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.4"
        response = middleware(request)
        assert response.status_code == 429
        assert b"Custom Too Many Requests" in response.content

    def test_cors_preflight(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_cors=True,
            cors_allow_origins=["http://example.com"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.options("/")
        request.META["HTTP_ORIGIN"] = "http://example.com"
        response = middleware(request)
        assert response.status_code == 204

    def test_cors_preflight_with_methods_and_headers(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_cors=True,
            cors_allow_origins=["https://example.com"],
            cors_allow_methods=["GET", "POST"],
            cors_allow_headers=["Content-Type"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.options("/")
        request.META["HTTP_ORIGIN"] = "https://example.com"
        response = middleware(request)
        assert response.status_code == 204

    def test_cors_disabled(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_cors=False,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()
        request = factory.get("/")
        request.META["HTTP_ORIGIN"] = "https://example.com"
        response = middleware(request)
        assert response.status_code == 200
        assert "Access-Control-Allow-Origin" not in response

    def test_cloud_ip_blocking(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            block_cloud_providers={"AWS", "GCP", "Azure"},
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        with patch.object(cloud_handler, "is_cloud_ip", return_value=True):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "13.59.255.255"
            response = middleware(request)
            assert response.status_code == 403

        with patch.object(cloud_handler, "is_cloud_ip", return_value=False):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "8.8.8.8"
            response = middleware(request)
            assert response.status_code == 200

    def test_cloud_ip_refresh_no_providers(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            block_cloud_providers=None,
        )
        middleware = self._make_middleware(config)

        initial_refresh_time = middleware.last_cloud_ip_refresh
        middleware.refresh_cloud_ip_ranges()
        assert middleware.last_cloud_ip_refresh == initial_refresh_time

    def test_penetration_detection_disabled(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enable_penetration_detection=False,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "10.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/wp-admin")
        request.META["REMOTE_ADDR"] = "10.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

    def test_emergency_mode_passive(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            emergency_mode=True,
            passive_mode=True,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/test")
        request.META["REMOTE_ADDR"] = "8.8.8.8"
        response = middleware(request)
        assert response.status_code == 200

    def test_create_error_response(self) -> None:
        middleware = self._make_middleware()
        response = middleware.create_error_response(403, "Forbidden")
        assert response.status_code == 403

    def test_reset(self) -> None:
        middleware = self._make_middleware()
        middleware.reset()

    def test_reset_clears_rate_limits(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            rate_limit=2,
            rate_limit_window=60,
            enable_rate_limiting=True,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        for _ in range(2):
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "127.0.0.1"
            middleware(request)

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 429

        middleware.reset()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

    def test_redis_disabled(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
        )
        middleware = self._make_middleware(config)
        assert middleware.redis_handler is None
        assert middleware.rate_limit_handler is not None
        middleware.rate_limit_handler.reset()

    def test_redis_initialization(self) -> None:
        config = SecurityConfig(
            enable_redis=True,
            enable_agent=False,
            redis_url="redis://localhost:6379",
            block_cloud_providers={"AWS"},
        )
        with (
            patch(
                "djangoapi_guard.handlers.redis_handler.RedisManager.initialize"
            ) as redis_init,
            patch(
                "djangoapi_guard.handlers.cloud_handler.cloud_handler.initialize_redis"
            ) as cloud_init,
            patch(
                "djangoapi_guard.handlers.ipban_handler.ip_ban_manager.initialize_redis"
            ) as ipban_init,
            patch(
                "djangoapi_guard.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis"
            ) as sus_init,
            patch(
                "djangoapi_guard.handlers.ratelimit_handler.RateLimitManager.initialize_redis"
            ) as rate_init,
        ):
            self._make_middleware(config)

            redis_init.assert_called_once()
            cloud_init.assert_called_once()
            ipban_init.assert_called_once()
            sus_init.assert_called_once()
            rate_init.assert_called_once()

    def test_redis_initialization_without_cloud(self) -> None:
        config = SecurityConfig(
            enable_redis=True,
            enable_agent=False,
            redis_url="redis://localhost:6379",
        )
        with (
            patch(
                "djangoapi_guard.handlers.redis_handler.RedisManager.initialize"
            ) as redis_init,
            patch(
                "djangoapi_guard.handlers.cloud_handler.cloud_handler.initialize_redis"
            ) as cloud_init,
            patch(
                "djangoapi_guard.handlers.ipban_handler.ip_ban_manager.initialize_redis"
            ) as ipban_init,
            patch(
                "djangoapi_guard.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis"
            ) as sus_init,
            patch(
                "djangoapi_guard.handlers.ratelimit_handler.RateLimitManager.initialize_redis"
            ) as rate_init,
        ):
            self._make_middleware(config)

            redis_init.assert_called_once()
            cloud_init.assert_not_called()
            ipban_init.assert_called_once()
            sus_init.assert_called_once()
            rate_init.assert_called_once()

    def test_agent_initialization_import_error(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=True,
            agent_api_key="test-key",
        )
        with patch.object(
            SecurityConfig,
            "to_agent_config",
            return_value=MagicMock(),
        ):
            middleware = self._make_middleware(config)
            assert middleware.agent_handler is None

    def test_agent_initialization_success(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=True,
            agent_api_key="test-key",
        )
        mock_agent_instance = MagicMock()
        mock_guard_agent_fn = MagicMock(return_value=mock_agent_instance)
        mock_agent_module: Any = MagicMock()
        mock_agent_module.guard_agent = mock_guard_agent_fn

        mock_agent_config = MagicMock()

        with patch.object(
            SecurityConfig,
            "to_agent_config",
            return_value=mock_agent_config,
        ):
            with patch.dict(sys.modules, {"guard_agent": mock_agent_module}):
                middleware = self._make_middleware(config)
                assert middleware.agent_handler is mock_agent_instance
                mock_guard_agent_fn.assert_called_once_with(mock_agent_config)

    def test_agent_initialization_invalid_config(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=True,
            agent_api_key="test-key",
        )
        with patch(
            "djangoapi_guard.models.SecurityConfig.to_agent_config",
            return_value=None,
        ):
            middleware = self._make_middleware(config)
            assert middleware.agent_handler is None

    def test_request_with_unknown_client_ip(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        with patch(
            "djangoapi_guard.middleware.extract_client_ip",
            return_value="unknown",
        ):
            request = factory.get("/")
            response = middleware(request)
            assert response.status_code == 200

    def test_set_decorator_handler(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
        )
        middleware = self._make_middleware(config)

        mock_decorator = MagicMock(spec=BaseSecurityDecorator)
        middleware.set_decorator_handler(mock_decorator)

        assert middleware.guard_decorator is mock_decorator
        assert middleware.route_resolver is not None
        assert middleware.route_resolver.context.guard_decorator is mock_decorator
        assert middleware.behavioral_processor is not None
        assert middleware.behavioral_processor.context.guard_decorator is mock_decorator
        assert middleware.response_factory is not None
        assert middleware.response_factory.context.guard_decorator is mock_decorator
        assert middleware.handler_initializer is not None
        assert middleware.handler_initializer.guard_decorator is mock_decorator

    def test_security_headers_disabled(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            security_headers={"enabled": False},
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200
        assert "X-Content-Type-Options" not in response

    def test_security_headers_none(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            security_headers=None,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

    def test_ipv6_blacklist(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            whitelist=["::1", "2001:db8::1"],
            blacklist=["2001:db8::dead:beef"],
            enable_penetration_detection=False,
            trusted_proxies=["127.0.0.1", "::1"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::dead:beef"
        response = middleware(request)
        assert response.status_code == 403

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::2"
        response = middleware(request)
        assert response.status_code == 403

    def test_ipv6_cidr_whitelist_blacklist(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            whitelist=["2001:db8::/32"],
            blacklist=["2001:db8:dead::/48"],
            enable_penetration_detection=False,
            trusted_proxies=["127.0.0.1", "::1"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8:1::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8:dead::beef"
        response = middleware(request)
        assert response.status_code == 403

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db9::1"
        response = middleware(request)
        assert response.status_code == 403

    def test_mixed_ipv4_ipv6_handling(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            whitelist=["127.0.0.1", "::1", "192.168.1.0/24", "2001:db8::/32"],
            blacklist=["192.168.1.100", "2001:db8:dead::beef"],
            enable_penetration_detection=False,
            trusted_proxies=["127.0.0.1", "::1"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "192.168.1.50"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "192.168.1.100"
        response = middleware(request)
        assert response.status_code == 403

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8:dead::beef"
        response = middleware(request)
        assert response.status_code == 403

    def test_ipv6_rate_limiting(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            rate_limit=2,
            rate_limit_window=60,
            enable_rate_limiting=True,
            whitelist=[],
            enable_penetration_detection=False,
            trusted_proxies=["127.0.0.1"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        handler = rate_limit_handler(config)
        handler.reset()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::1"
        response = middleware(request)
        assert response.status_code == 200

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::1"
        response = middleware(request)
        assert response.status_code == 429

        handler = rate_limit_handler(config)
        handler.reset()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "2001:db8::1"
        response = middleware(request)
        assert response.status_code == 200

    def _make_redis_middleware(self, config: SecurityConfig) -> DjangoAPIGuard:
        with patch(
            "djangoapi_guard.core.initialization.handler_initializer.HandlerInitializer.initialize_redis_handlers"
        ):
            return self._make_middleware(config)

    def test_lua_script_execution(self) -> None:
        config = SecurityConfig(
            enable_redis=True,
            enable_agent=False,
            redis_url="redis://localhost:6379",
            rate_limit=2,
            rate_limit_window=1,
            enable_rate_limiting=True,
        )
        middleware = self._make_redis_middleware(config)
        handler = middleware.rate_limit_handler

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        handler.redis_handler = mock_redis_handler

        mock_conn = MagicMock()
        mock_conn.evalsha = MagicMock(return_value=1)

        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_conn)
        mock_context.__exit__ = MagicMock(return_value=False)
        mock_redis_handler.get_connection.return_value = mock_context

        handler.rate_limit_script_sha = "test_script_sha"

        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.1"

        def create_error_response(status_code: int, message: str) -> HttpResponse:
            return HttpResponse(message, status=status_code)

        result = handler.check_rate_limit(request, "192.168.1.1", create_error_response)
        assert result is None

        mock_conn.evalsha.assert_called_once()

        mock_conn.evalsha.reset_mock()
        mock_conn.evalsha.return_value = 3

        result = handler.check_rate_limit(request, "192.168.1.1", create_error_response)
        assert result is not None
        assert result.status_code == 429

    def test_fallback_to_pipeline(self) -> None:
        config = SecurityConfig(
            enable_redis=True,
            enable_agent=False,
            redis_url="redis://localhost:6379",
            rate_limit=2,
            rate_limit_window=1,
            enable_rate_limiting=True,
        )
        middleware = self._make_redis_middleware(config)
        handler = middleware.rate_limit_handler

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        handler.redis_handler = mock_redis_handler

        mock_conn = MagicMock()
        mock_pipeline = Mock()
        mock_pipeline.zadd = Mock()
        mock_pipeline.zremrangebyscore = Mock()
        mock_pipeline.zcard = Mock()
        mock_pipeline.expire = Mock()
        mock_pipeline.execute = Mock(
            side_effect=[
                [0, 0, 1, True],
                [0, 0, 3, True],
            ]
        )
        mock_conn.pipeline = Mock(return_value=mock_pipeline)

        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_conn)
        mock_context.__exit__ = MagicMock(return_value=False)
        mock_redis_handler.get_connection.return_value = mock_context

        handler.rate_limit_script_sha = None

        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.1"

        def create_error_response(status_code: int, message: str) -> HttpResponse:
            return HttpResponse(message, status=status_code)

        result = handler.check_rate_limit(request, "192.168.1.1", create_error_response)
        assert result is None

        mock_conn.pipeline.assert_called_once()
        mock_pipeline.zadd.assert_called_once()
        mock_pipeline.zremrangebyscore.assert_called_once()
        mock_pipeline.zcard.assert_called_once()
        mock_pipeline.expire.assert_called_once()
        mock_pipeline.execute.assert_called_once()

        mock_conn.pipeline.reset_mock()
        mock_pipeline.zadd.reset_mock()
        mock_pipeline.zremrangebyscore.reset_mock()
        mock_pipeline.zcard.reset_mock()
        mock_pipeline.expire.reset_mock()
        mock_pipeline.execute.reset_mock()

        result = handler.check_rate_limit(request, "192.168.1.1", create_error_response)
        assert result is not None
        assert result.status_code == 429
        assert result.content == b"Too many requests"

        mock_conn.pipeline.assert_called_once()
        mock_pipeline.zadd.assert_called_once()
        mock_pipeline.zremrangebyscore.assert_called_once()
        mock_pipeline.zcard.assert_called_once()
        mock_pipeline.expire.assert_called_once()
        mock_pipeline.execute.assert_called_once()

    def test_rate_limiter_redis_errors(self) -> None:
        from redis.exceptions import RedisError

        config = SecurityConfig(
            enable_redis=True,
            enable_agent=False,
            redis_url="redis://localhost:6379",
            rate_limit=2,
            rate_limit_window=1,
            enable_rate_limiting=True,
        )
        handler = rate_limit_handler(config)

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        handler.redis_handler = mock_redis_handler

        def create_error_response(status_code: int, message: str) -> HttpResponse:
            return HttpResponse(message, status=status_code)

        with (
            patch.object(mock_redis_handler, "get_connection") as mock_get_connection,
            patch.object(logging.Logger, "error") as mock_error,
            patch.object(logging.Logger, "info") as mock_info,
        ):
            mock_conn = MagicMock()
            mock_conn.__enter__ = MagicMock(
                side_effect=RedisError("Redis connection error")
            )
            mock_get_connection.return_value = mock_conn

            handler.rate_limit_script_sha = "test_script_sha"

            factory = RequestFactory()
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "192.168.1.1"

            result = handler.check_rate_limit(
                request, "192.168.1.1", create_error_response
            )
            assert result is None

            mock_error.assert_called_once()
            assert "Redis rate limiting error" in mock_error.call_args[0][0]
            mock_info.assert_called_once_with("Falling back to in-memory rate limiting")

        with (
            patch.object(mock_redis_handler, "get_connection") as mock_get_connection,
            patch.object(logging.Logger, "error") as mock_error,
        ):
            mock_conn = MagicMock()
            mock_conn.__enter__ = MagicMock(side_effect=Exception("Unexpected error"))
            mock_get_connection.return_value = mock_conn

            factory = RequestFactory()
            request = factory.get("/")
            request.META["REMOTE_ADDR"] = "192.168.1.1"

            result = handler.check_rate_limit(
                request, "192.168.1.1", create_error_response
            )
            assert result is None

            mock_error.assert_called_once()
            assert "Unexpected error in rate limiting" in mock_error.call_args[0][0]

    def test_rate_limiter_init_redis_exception(self) -> None:
        config = SecurityConfig(
            enable_redis=True,
            enable_agent=False,
            redis_url="redis://localhost:6379",
        )
        handler = rate_limit_handler(config)

        mock_redis: Any = Mock()
        mock_cm = MagicMock()
        mock_conn = MagicMock()
        mock_conn.script_load = MagicMock(side_effect=Exception("Script load failed"))
        mock_cm.__enter__.return_value = mock_conn
        mock_cm.__exit__ = MagicMock(return_value=False)
        mock_redis.get_connection.return_value = mock_cm
        mock_redis.config = config

        mock_logger = Mock()
        handler.logger = mock_logger

        handler.initialize_redis(mock_redis)

        mock_logger.error.assert_called_once()
        error_msg = mock_logger.error.call_args[0][0]
        assert (
            "Failed to load rate limiting Lua script: Script load failed" == error_msg
        )

    def test_rate_limit_reset_with_redis_errors(self) -> None:
        config = SecurityConfig(
            enable_redis=True,
            enable_agent=False,
            redis_url="redis://localhost:6379",
            rate_limit=2,
            enable_rate_limiting=True,
        )

        RateLimitManager._instance = None
        handler = rate_limit_handler(config)

        mock_redis: Any = Mock()
        mock_redis.config = config

        def mock_keys(*args: Any) -> None:
            raise Exception("Redis keys error")

        mock_redis.keys = mock_keys

        handler.redis_handler = mock_redis

        with patch.object(logging.Logger, "error") as mock_logger:
            handler.reset()

            mock_logger.assert_called_once()
            args = mock_logger.call_args[0]
            assert "Failed to reset Redis rate limits" in args[0]

    def test_https_enforcement(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            enforce_https=True,
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        response = middleware(request)
        assert response.status_code == 301

    def test_excluded_paths_multiple(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            exclude_paths=["/health", "/status", "/metrics"],
        )
        middleware = self._make_middleware(config)
        factory = RequestFactory()

        for path in ["/health", "/status", "/metrics"]:
            request = factory.get(path)
            response = middleware(request)
            assert response.status_code == 200
