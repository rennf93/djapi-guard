import os
import sys
import time
import types
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from django.http import HttpResponse

from djangoapi_guard.handlers.ipban_handler import IPBanManager
from djangoapi_guard.handlers.ratelimit_handler import RateLimitManager
from djangoapi_guard.handlers.redis_handler import RedisManager
from djangoapi_guard.models import SecurityConfig


def _install_mock_guard_agent() -> Any:
    mock_module: Any = types.ModuleType("guard_agent")

    class MockSecurityEvent:
        def __init__(self, **kwargs: object) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    mock_module.SecurityEvent = MockSecurityEvent
    sys.modules["guard_agent"] = mock_module
    return mock_module


def _uninstall_mock_guard_agent() -> None:
    sys.modules.pop("guard_agent", None)


@pytest.fixture(autouse=True)
def _mock_guard_agent() -> Generator[None, None, None]:
    _install_mock_guard_agent()
    yield
    _uninstall_mock_guard_agent()


@pytest.fixture()
def fresh_ipban() -> IPBanManager:
    """Return a fresh IPBanManager singleton."""
    IPBanManager._instance = None
    mgr = IPBanManager()
    return mgr


@pytest.fixture()
def mock_redis_handler() -> MagicMock:
    """Return a MagicMock that behaves like RedisManager."""
    handler = MagicMock()
    handler.config = MagicMock()
    handler.config.redis_prefix = "djangoapi_guard_test:"
    handler.config.enable_redis = True
    return handler


@pytest.fixture()
def redis_config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url="redis://localhost:6379",
        redis_prefix="djangoapi_guard_test:",
    )


class TestIPBanManagerRedis:
    """Tests for Redis-specific paths in IPBanManager."""

    def test_initialize_agent(self, fresh_ipban: IPBanManager) -> None:
        """initialize_agent stores the agent handler."""
        agent = Mock()
        fresh_ipban.initialize_agent(agent)
        assert fresh_ipban.agent_handler is agent

    def test_ban_ip_with_redis(
        self, fresh_ipban: IPBanManager, mock_redis_handler: MagicMock
    ) -> None:
        """ban_ip calls redis_handler.set_key."""
        fresh_ipban.initialize_redis(mock_redis_handler)
        fresh_ipban.ban_ip("10.0.0.1", duration=600, reason="test")

        mock_redis_handler.set_key.assert_called_once()
        args = mock_redis_handler.set_key.call_args
        assert args[0][0] == "banned_ips"
        assert args[0][1] == "10.0.0.1"
        assert args[1]["ttl"] == 600 or args[0][3] == 600

    def test_ban_ip_with_agent(self, fresh_ipban: IPBanManager) -> None:
        """ban_ip sends ban event via agent."""
        agent = Mock()
        fresh_ipban.initialize_agent(agent)
        fresh_ipban.ban_ip("10.0.0.2", duration=300, reason="abuse")

        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "ip_banned"
        assert event.ip_address == "10.0.0.2"

    def test_unban_ip_full_path(
        self, fresh_ipban: IPBanManager, mock_redis_handler: MagicMock
    ) -> None:
        """unban_ip removes from cache, Redis, and sends agent event."""
        agent = Mock()
        fresh_ipban.initialize_redis(mock_redis_handler)
        fresh_ipban.initialize_agent(agent)

        fresh_ipban.ban_ip("10.0.0.3", duration=600)
        agent.reset_mock()

        fresh_ipban.unban_ip("10.0.0.3")

        assert "10.0.0.3" not in fresh_ipban.banned_ips
        mock_redis_handler.delete.assert_called_with("banned_ips", "10.0.0.3")
        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "ip_unbanned"

    def test_is_ip_banned_redis_fallback_hit(
        self, fresh_ipban: IPBanManager, mock_redis_handler: MagicMock
    ) -> None:
        """Cache miss -> Redis hit -> populates cache."""
        future_expiry = str(time.time() + 3600)
        mock_redis_handler.get_key.return_value = future_expiry
        fresh_ipban.initialize_redis(mock_redis_handler)

        result = fresh_ipban.is_ip_banned("10.0.0.4")

        assert result is True
        assert "10.0.0.4" in fresh_ipban.banned_ips
        mock_redis_handler.get_key.assert_called_with("banned_ips", "10.0.0.4")

    def test_is_ip_banned_redis_expired_cleanup(
        self, fresh_ipban: IPBanManager, mock_redis_handler: MagicMock
    ) -> None:
        """Cache miss -> Redis hit but expired -> deletes from Redis."""
        past_expiry = str(time.time() - 100)
        mock_redis_handler.get_key.return_value = past_expiry
        fresh_ipban.initialize_redis(mock_redis_handler)

        result = fresh_ipban.is_ip_banned("10.0.0.5")

        assert result is False
        mock_redis_handler.delete.assert_called_with("banned_ips", "10.0.0.5")

    def test_reset_with_redis(
        self, fresh_ipban: IPBanManager, mock_redis_handler: MagicMock
    ) -> None:
        """reset clears local cache and Redis keys."""
        fresh_ipban.initialize_redis(mock_redis_handler)
        fresh_ipban.ban_ip("10.0.0.6", duration=600)

        mock_conn = MagicMock()
        mock_conn.keys.return_value = [
            "djangoapi_guard_test:banned_ips:10.0.0.6",
        ]
        mock_redis_handler.get_connection.return_value.__enter__ = Mock(
            return_value=mock_conn
        )
        mock_redis_handler.get_connection.return_value.__exit__ = Mock(
            return_value=False
        )

        fresh_ipban.reset()

        assert len(fresh_ipban.banned_ips) == 0
        mock_conn.keys.assert_called_once()
        mock_conn.delete.assert_called_once()

    def test_reset_with_redis_no_keys(
        self, fresh_ipban: IPBanManager, mock_redis_handler: MagicMock
    ) -> None:
        """reset with Redis but no matching keys does not call delete."""
        fresh_ipban.initialize_redis(mock_redis_handler)

        mock_conn = MagicMock()
        mock_conn.keys.return_value = []
        mock_redis_handler.get_connection.return_value.__enter__ = Mock(
            return_value=mock_conn
        )
        mock_redis_handler.get_connection.return_value.__exit__ = Mock(
            return_value=False
        )

        fresh_ipban.reset()
        mock_conn.delete.assert_not_called()


class TestRedisManagerPaths:
    """Tests for uncovered RedisManager code paths."""

    def test_initialize_agent(self, redis_config: SecurityConfig) -> None:
        """initialize_agent stores the agent handler."""
        RedisManager._instance = None
        mgr = RedisManager(redis_config)
        agent = Mock()
        mgr.initialize_agent(agent)
        assert mgr.agent_handler is agent

    def test_send_redis_event_full_flow(self, redis_config: SecurityConfig) -> None:
        """_send_redis_event constructs and sends SecurityEvent."""
        RedisManager._instance = None
        mgr = RedisManager(redis_config)
        agent = Mock()
        mgr.initialize_agent(agent)

        mgr._send_redis_event(
            event_type="redis_connection",
            action_taken="connection_established",
            reason="test reason",
            extra_key="extra_val",
        )

        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "redis_connection"
        assert event.ip_address == "system"
        assert event.metadata["extra_key"] == "extra_val"

    def test_send_redis_event_no_agent(self, redis_config: SecurityConfig) -> None:
        """_send_redis_event returns early when no agent."""
        RedisManager._instance = None
        mgr = RedisManager(redis_config)
        mgr.agent_handler = None
        mgr._send_redis_event("test", "test", "test")

    def test_send_redis_event_exception(self, redis_config: SecurityConfig) -> None:
        """_send_redis_event logs error on exception."""
        RedisManager._instance = None
        mgr = RedisManager(redis_config)
        agent = Mock()
        agent.send_event.side_effect = RuntimeError("agent down")
        mgr.initialize_agent(agent)

        mgr._send_redis_event("test", "test", "test")

    def test_close_with_connection(self, redis_config: SecurityConfig) -> None:
        """close() closes Redis connection and sends event."""
        RedisManager._instance = None
        mgr = RedisManager(redis_config)
        agent = Mock()
        mgr.initialize_agent(agent)

        mock_redis = MagicMock()
        mgr._redis = mock_redis

        mgr.close()

        mock_redis.close.assert_called_once()
        assert not mgr._redis
        assert mgr._closed
        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.action_taken == "connection_closed"

    def test_delete_pattern_no_keys(self, redis_config: SecurityConfig) -> None:
        """delete_pattern returns 0 when no keys match."""
        RedisManager._instance = None
        mgr = RedisManager(redis_config)
        mgr._closed = False

        mock_redis = MagicMock()
        mock_redis.keys.return_value = []
        mgr._redis = mock_redis

        result = mgr.delete_pattern("nonexistent:*")

        assert result == 0
        mock_redis.delete.assert_not_called()

    def test_get_connection_closed_raises(self, redis_config: SecurityConfig) -> None:
        """get_connection raises when _closed=True and sends event."""
        from djangoapi_guard.handlers.redis_handler import RedisConnectionError

        RedisManager._instance = None
        mgr = RedisManager(redis_config)
        agent = Mock()
        mgr.initialize_agent(agent)
        mgr._closed = True

        with pytest.raises(RedisConnectionError):
            with mgr.get_connection():
                pass  # pragma: no cover

        agent.send_event.assert_called()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "redis_error"

    def test_get_connection_reinitializes(self, redis_config: SecurityConfig) -> None:
        """get_connection calls initialize() when _redis is None."""
        RedisManager._instance = None
        mgr = RedisManager(redis_config)
        mgr._closed = False
        mgr._redis = None

        mock_redis = MagicMock()

        def fake_initialize() -> None:
            mgr._redis = mock_redis

        mgr.initialize = fake_initialize  # type: ignore[method-assign]

        with mgr.get_connection() as conn:
            assert conn is mock_redis

    def test_get_connection_none_after_init_raises(
        self, redis_config: SecurityConfig
    ) -> None:
        from djangoapi_guard.handlers.redis_handler import RedisConnectionError

        RedisManager._instance = None
        mgr = RedisManager(redis_config)
        agent = Mock()
        mgr.initialize_agent(agent)
        mgr._closed = False
        mgr._redis = None

        def fake_initialize() -> None:
            mgr._redis = None

        mgr.initialize = fake_initialize  # type: ignore[method-assign]

        with pytest.raises(RedisConnectionError):
            with mgr.get_connection():
                pass  # pragma: no cover

        agent.send_event.assert_called()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "redis_error"

    def test_delete_pattern_safe_operation_none(
        self, redis_config: SecurityConfig
    ) -> None:
        """delete_pattern returns 0 when safe_operation returns None."""
        from unittest.mock import patch

        RedisManager._instance = None
        mgr = RedisManager(redis_config)

        with patch.object(mgr, "safe_operation", return_value=None):
            result = mgr.delete_pattern("some:*")

        assert result == 0

    def test_delete_pattern_with_matching_keys(
        self, redis_config: SecurityConfig
    ) -> None:
        """delete_pattern deletes matching keys and returns count."""
        RedisManager._instance = None
        mgr = RedisManager(redis_config)
        mgr._closed = False

        mock_redis = MagicMock()
        mock_redis.keys.return_value = ["prefix:key1", "prefix:key2"]
        mock_redis.delete.return_value = 2
        mgr._redis = mock_redis

        result = mgr.delete_pattern("some:*")

        assert result == 2
        mock_redis.delete.assert_called_once()


class TestRateLimitManagerRedis:
    """Tests for Redis-specific paths in RateLimitManager."""

    @pytest.fixture(autouse=True)
    def _clean_rate_limiter(self) -> None:
        RateLimitManager._instance = None

    def test_initialize_agent(self) -> None:
        """initialize_agent stores the agent handler."""
        config = SecurityConfig(enable_redis=False)
        mgr = RateLimitManager(config)
        agent = Mock()
        mgr.initialize_agent(agent)
        assert mgr.agent_handler is agent

    def test_non_lua_fallback_path(self) -> None:
        """Pipeline fallback when no Lua script SHA."""
        config = SecurityConfig(
            enable_redis=True,
            redis_url="redis://localhost:6379",
            redis_prefix="djangoapi_guard_test:",
            rate_limit=10,
            rate_limit_window=60,
        )
        mgr = RateLimitManager(config)

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        mgr.redis_handler = mock_redis_handler
        mgr.rate_limit_script_sha = None

        mock_conn = MagicMock()
        mock_pipeline = MagicMock()
        mock_pipeline.execute.return_value = [True, 0, 5, True]
        mock_conn.pipeline.return_value = mock_pipeline
        mock_conn.__enter__ = Mock(return_value=mock_conn)
        mock_conn.__exit__ = Mock(return_value=False)
        mock_redis_handler.get_connection.return_value = mock_conn

        result = mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)

        assert result == 5
        mock_pipeline.zadd.assert_called_once()
        mock_pipeline.zremrangebyscore.assert_called_once()
        mock_pipeline.zcard.assert_called_once()
        mock_pipeline.expire.assert_called_once()

    def test_redis_error_fallback_to_none(self) -> None:
        """Redis error returns None so caller falls back to in-memory."""
        from redis.exceptions import RedisError

        config = SecurityConfig(
            enable_redis=True,
            redis_url="redis://localhost:6379",
            redis_prefix="djangoapi_guard_test:",
            rate_limit=10,
            rate_limit_window=60,
        )
        mgr = RateLimitManager(config)

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        mgr.redis_handler = mock_redis_handler
        mgr.rate_limit_script_sha = "fake_sha"

        mock_conn = MagicMock()
        mock_conn.evalsha.side_effect = RedisError("Connection lost")
        mock_redis_handler.get_connection.return_value.__enter__ = Mock(
            return_value=mock_conn
        )
        mock_redis_handler.get_connection.return_value.__exit__ = Mock(
            return_value=False
        )

        result = mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)

        assert result is None

    def test_initialize_redis_lua_success(self) -> None:
        """initialize_redis loads Lua script SHA successfully."""
        config = SecurityConfig(
            enable_redis=True,
            redis_url="redis://localhost:6379",
            redis_prefix="djangoapi_guard_test:",
            rate_limit=10,
            rate_limit_window=60,
        )
        mgr = RateLimitManager(config)

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        mock_conn = MagicMock()
        mock_conn.script_load.return_value = "abc123sha"
        mock_redis_handler.get_connection.return_value.__enter__ = Mock(
            return_value=mock_conn
        )
        mock_redis_handler.get_connection.return_value.__exit__ = Mock(
            return_value=False
        )

        mgr.initialize_redis(mock_redis_handler)

        assert mgr.rate_limit_script_sha == "abc123sha"
        mock_conn.script_load.assert_called_once()

    def test_initialize_redis_lua_failure(self) -> None:
        """initialize_redis handles Lua script load failure gracefully."""
        config = SecurityConfig(
            enable_redis=True,
            redis_url="redis://localhost:6379",
            redis_prefix="djangoapi_guard_test:",
            rate_limit=10,
            rate_limit_window=60,
        )
        mgr = RateLimitManager(config)

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        mock_conn = MagicMock()
        mock_conn.script_load.side_effect = RuntimeError("Script load failed")
        mock_redis_handler.get_connection.return_value.__enter__ = Mock(
            return_value=mock_conn
        )
        mock_redis_handler.get_connection.return_value.__exit__ = Mock(
            return_value=False
        )

        mgr.initialize_redis(mock_redis_handler)

        assert mgr.rate_limit_script_sha is None

    def test_redis_evalsha_success_returns_count(self) -> None:
        """evalsha success returns count cast to int."""
        config = SecurityConfig(
            enable_redis=True,
            redis_url="redis://localhost:6379",
            redis_prefix="djangoapi_guard_test:",
            rate_limit=10,
            rate_limit_window=60,
        )
        mgr = RateLimitManager(config)

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        mgr.redis_handler = mock_redis_handler
        mgr.rate_limit_script_sha = "fake_sha"

        mock_conn = MagicMock()
        mock_conn.evalsha.return_value = 7
        mock_redis_handler.get_connection.return_value.__enter__ = Mock(
            return_value=mock_conn
        )
        mock_redis_handler.get_connection.return_value.__exit__ = Mock(
            return_value=False
        )

        result = mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)

        assert result == 7

    def test_redis_generic_exception_fallback(self) -> None:
        """Non-RedisError exception returns None."""
        config = SecurityConfig(
            enable_redis=True,
            redis_url="redis://localhost:6379",
            redis_prefix="djangoapi_guard_test:",
            rate_limit=10,
            rate_limit_window=60,
        )
        mgr = RateLimitManager(config)

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        mgr.redis_handler = mock_redis_handler
        mgr.rate_limit_script_sha = "fake_sha"

        mock_conn = MagicMock()
        mock_conn.evalsha.side_effect = TypeError("Unexpected error")
        mock_redis_handler.get_connection.return_value.__enter__ = Mock(
            return_value=mock_conn
        )
        mock_redis_handler.get_connection.return_value.__exit__ = Mock(
            return_value=False
        )

        result = mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)

        assert result is None

    def test_rate_limit_exceeded_with_agent(self) -> None:
        """_handle_rate_limit_exceeded sends event via agent_handler."""
        from django.test import RequestFactory

        config = SecurityConfig(
            enable_redis=False,
            rate_limit=10,
            rate_limit_window=60,
        )
        mgr = RateLimitManager(config)
        agent = Mock()
        mgr.initialize_agent(agent)

        factory = RequestFactory()
        request = factory.get("/api/test")
        request.META["REMOTE_ADDR"] = "1.2.3.4"

        def create_error_response(status_code: int, message: str) -> HttpResponse:
            return HttpResponse(message, status=status_code)

        response = mgr._handle_rate_limit_exceeded(
            request, "1.2.3.4", 15, create_error_response
        )

        assert response.status_code == 429
        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "rate_limited"

    def test_in_memory_sliding_window_cleanup(self) -> None:
        """_get_in_memory_request_count removes expired timestamps via popleft."""
        config = SecurityConfig(
            enable_redis=False,
            rate_limit=100,
            rate_limit_window=60,
        )
        mgr = RateLimitManager(config)

        current_time = time.time()
        # Add old timestamps that should be cleaned up
        mgr.request_timestamps["1.2.3.4"].append(current_time - 120)
        mgr.request_timestamps["1.2.3.4"].append(current_time - 90)
        mgr.request_timestamps["1.2.3.4"].append(current_time - 10)

        window_start = current_time - 60
        count = mgr._get_in_memory_request_count("1.2.3.4", window_start, current_time)

        # Only the non-expired timestamp + the new one should remain
        assert count == 1  # 1 non-expired before adding current
        assert len(mgr.request_timestamps["1.2.3.4"]) == 2  # 1 kept + 1 added

    def test_check_rate_limit_disabled(self) -> None:
        """check_rate_limit returns None when enable_rate_limiting=False."""
        from django.test import RequestFactory

        config = SecurityConfig(
            enable_redis=False,
            enable_rate_limiting=False,
        )
        mgr = RateLimitManager(config)

        factory = RequestFactory()
        request = factory.get("/api/test")
        request.META["REMOTE_ADDR"] = "1.2.3.4"

        result = mgr.check_rate_limit(request, "1.2.3.4", lambda s, m: None)

        assert result is None

    def test_check_rate_limit_redis_path_not_exceeded(self) -> None:
        """check_rate_limit with Redis: count not None, not exceeded returns None."""
        from django.test import RequestFactory

        config = SecurityConfig(
            enable_redis=True,
            redis_url="redis://localhost:6379",
            redis_prefix="djangoapi_guard_test:",
            rate_limit=10,
            rate_limit_window=60,
            enable_rate_limiting=True,
        )
        mgr = RateLimitManager(config)

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        mgr.redis_handler = mock_redis_handler
        mgr.rate_limit_script_sha = "fake_sha"

        mock_conn = MagicMock()
        mock_conn.evalsha.return_value = 3  # Under limit
        mock_redis_handler.get_connection.return_value.__enter__ = Mock(
            return_value=mock_conn
        )
        mock_redis_handler.get_connection.return_value.__exit__ = Mock(
            return_value=False
        )

        factory = RequestFactory()
        request = factory.get("/api/test")
        request.META["REMOTE_ADDR"] = "1.2.3.4"

        result = mgr.check_rate_limit(request, "1.2.3.4", lambda s, m: None)

        assert result is None

    def test_check_rate_limit_redis_path_exceeded(self) -> None:
        """check_rate_limit with Redis: count exceeds limit returns 429."""
        from django.http import HttpResponse
        from django.test import RequestFactory

        config = SecurityConfig(
            enable_redis=True,
            redis_url="redis://localhost:6379",
            redis_prefix="djangoapi_guard_test:",
            rate_limit=10,
            rate_limit_window=60,
            enable_rate_limiting=True,
        )
        mgr = RateLimitManager(config)

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        mgr.redis_handler = mock_redis_handler
        mgr.rate_limit_script_sha = "fake_sha"

        mock_conn = MagicMock()
        mock_conn.evalsha.return_value = 15  # Over limit
        mock_redis_handler.get_connection.return_value.__enter__ = Mock(
            return_value=mock_conn
        )
        mock_redis_handler.get_connection.return_value.__exit__ = Mock(
            return_value=False
        )

        factory = RequestFactory()
        request = factory.get("/api/test")
        request.META["REMOTE_ADDR"] = "1.2.3.4"

        def create_error(status_code: int, message: str) -> HttpResponse:
            return HttpResponse(message, status=status_code)

        result = mgr.check_rate_limit(request, "1.2.3.4", create_error)

        assert result is not None
        assert result.status_code == 429

    def test_reset_with_redis(self) -> None:
        """reset clears timestamps and Redis keys."""
        config = SecurityConfig(
            enable_redis=True,
            redis_url="redis://localhost:6379",
            redis_prefix="djangoapi_guard_test:",
            rate_limit=10,
            rate_limit_window=60,
        )
        mgr = RateLimitManager(config)

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        mock_redis_handler.keys.return_value = ["rate_limit:rate:1.2.3.4"]
        mgr.redis_handler = mock_redis_handler

        mgr.request_timestamps["1.2.3.4"].append(time.time())
        mgr.reset()

        assert len(mgr.request_timestamps) == 0
        mock_redis_handler.keys.assert_called_once()
        mock_redis_handler.delete_pattern.assert_called_once()

    def test_reset_with_redis_exception(self) -> None:
        """reset handles Redis exception gracefully."""
        config = SecurityConfig(
            enable_redis=True,
            redis_url="redis://localhost:6379",
            redis_prefix="djangoapi_guard_test:",
            rate_limit=10,
            rate_limit_window=60,
        )
        mgr = RateLimitManager(config)

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        mock_redis_handler.keys.side_effect = RuntimeError("Redis down")
        mgr.redis_handler = mock_redis_handler

        mgr.request_timestamps["1.2.3.4"].append(time.time())
        mgr.reset()

        assert len(mgr.request_timestamps) == 0
