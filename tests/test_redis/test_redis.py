"""Tests for Redis handler - adapted from Flask Guard."""

import os
import time
from typing import Any
from unittest.mock import MagicMock, patch

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

import pytest
from pytest_mock import MockerFixture

from djangoapi_guard.handlers.redis_handler import RedisConnectionError, RedisManager
from djangoapi_guard.models import SecurityConfig

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
REDIS_PREFIX = os.getenv("REDIS_PREFIX", "test_djangoapi_guard:")


def _make_redis_config(**kwargs: Any) -> SecurityConfig:
    defaults: dict[str, Any] = {
        "enable_redis": True,
        "enable_agent": False,
        "redis_url": REDIS_URL,
        "redis_prefix": REDIS_PREFIX,
    }
    defaults.update(kwargs)
    return SecurityConfig(**defaults)


def _try_redis_connection() -> bool:
    """Check if Redis is available."""
    try:
        config = _make_redis_config()
        handler = RedisManager(config)
        handler.initialize()
        handler.close()
        return True
    except Exception:
        return False


REDIS_AVAILABLE = _try_redis_connection()
skip_no_redis = pytest.mark.skipif(not REDIS_AVAILABLE, reason="Redis not available")


@skip_no_redis
def test_redis_basic_operations() -> None:
    """Test basic Redis operations."""
    config = _make_redis_config()
    handler = RedisManager(config)
    handler.initialize()

    handler.set_key("test", "key1", "value1")
    value = handler.get_key("test", "key1")
    assert value == "value1"

    exists = handler.exists("test", "key1")
    assert exists is True

    handler.delete("test", "key1")
    exists = handler.exists("test", "key1")
    assert exists is False

    handler.close()


def test_redis_disabled() -> None:
    """Test Redis operations when disabled."""
    config = SecurityConfig(enable_redis=False, enable_agent=False)
    handler = RedisManager(config)
    handler.initialize()

    assert not config.enable_redis
    assert handler._redis is None
    result = handler.set_key("test", "key1", "value1")
    assert result is None
    value = handler.get_key("test", "key1")
    assert value is None


@skip_no_redis
def test_redis_error_handling() -> None:
    """Test Redis error handling."""
    from redis.exceptions import ConnectionError

    config = _make_redis_config()
    handler = RedisManager(config)
    handler.initialize()

    def _fail_operation(conn: Any) -> None:
        raise ConnectionError("Test connection error")

    with pytest.raises(RedisConnectionError):
        handler.safe_operation(_fail_operation)

    handler.close()


@skip_no_redis
def test_redis_connection_retry(mocker: MockerFixture) -> None:
    """Test Redis connection retry mechanism."""
    from redis.exceptions import ConnectionError

    config = _make_redis_config()
    handler = RedisManager(config)
    handler.initialize()

    mock_get = MagicMock(side_effect=ConnectionError("Test connection error"))
    if handler._redis:
        mocker.patch.object(handler._redis, "get", mock_get)

    with pytest.raises(RedisConnectionError):
        handler.get_key("test", "retry")


@skip_no_redis
def test_redis_ttl_operations() -> None:
    """Test Redis TTL operations."""
    config = _make_redis_config()
    handler = RedisManager(config)
    handler.initialize()

    handler.set_key("test", "ttl_key", "value", ttl=1)
    value = handler.get_key("test", "ttl_key")
    assert value == "value"

    time.sleep(1.1)
    value = handler.get_key("test", "ttl_key")
    assert value is None

    handler.close()


@skip_no_redis
def test_redis_increment_operations() -> None:
    """Test Redis increment operations."""
    config = _make_redis_config()
    handler = RedisManager(config)
    handler.initialize()

    with handler.get_connection() as conn:
        prefix = config.redis_prefix
        conn.delete(f"{prefix}test:counter")
        conn.delete(f"{prefix}test:ttl_counter")

    value = handler.incr("test", "counter")
    assert value == 1
    value = handler.incr("test", "counter")
    assert value == 2

    value = handler.incr("test", "ttl_counter", ttl=1)
    assert value == 1
    time.sleep(1.1)
    exists = handler.exists("test", "ttl_counter")
    assert not exists

    handler.close()


def test_redis_connection_failures() -> None:
    """Test Redis connection failure scenarios."""
    bad_config = _make_redis_config(redis_url="redis://nonexistent:6379")
    handler = RedisManager(bad_config)
    with pytest.raises(RedisConnectionError):
        handler.initialize()
    assert handler._redis is None


def test_redis_disabled_operations() -> None:
    """Test Redis operations when Redis is disabled."""
    config = SecurityConfig(enable_redis=False, enable_agent=False, redis_url=REDIS_URL)
    handler = RedisManager(config)

    assert handler.get_key("test", "key") is None
    assert handler.set_key("test", "key", "value") is None
    assert handler.incr("test", "counter") is None
    assert handler.exists("test", "key") is None
    assert handler.delete("test", "key") is None


def test_redis_url_none() -> None:
    """Test Redis initialization when redis_url is None."""
    config = SecurityConfig(enable_redis=True, enable_agent=False, redis_url=None)
    handler = RedisManager(config)

    with patch("logging.Logger.warning"):
        handler.initialize()
        assert handler._redis is None


def test_safe_operation_redis_disabled() -> None:
    """Test safe_operation when Redis is disabled."""
    config = SecurityConfig(enable_redis=False, enable_agent=False)
    handler = RedisManager(config)

    mock_func = MagicMock()
    result = handler.safe_operation(mock_func)

    assert result is None
    mock_func.assert_not_called()


def test_redis_keys_and_delete_pattern_with_redis_disabled() -> None:
    """Test keys and delete_pattern functions when Redis is disabled."""
    config = SecurityConfig(enable_redis=False, enable_agent=False)
    handler = RedisManager(config)

    keys_result = handler.keys("*")
    assert keys_result is None

    delete_result = handler.delete_pattern("*")
    assert delete_result is None


@skip_no_redis
def test_redis_connection_context_get_error(monkeypatch: Any) -> None:
    """Test Redis connection get operation with error."""
    from redis.exceptions import ConnectionError

    config = _make_redis_config()
    handler = RedisManager(config)
    handler.initialize()

    def mock_get(*args: Any, **kwargs: Any) -> None:
        raise ConnectionError("Test connection error on get")

    with pytest.raises(RedisConnectionError):
        with handler.get_connection() as conn:
            monkeypatch.setattr(conn, "get", mock_get)
            conn.get("test:key")

    handler.close()
