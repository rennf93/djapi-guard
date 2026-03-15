"""Test configuration for djangoapi-guard-agent integration tests."""

from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

try:
    from guard_agent.models import AgentConfig, SecurityEvent, SecurityMetric
except ModuleNotFoundError:

    class AgentConfig:  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    class SecurityEvent:  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)
            for attr in (
                "timestamp",
                "event_type",
                "ip_address",
                "country",
                "user_agent",
                "action_taken",
                "reason",
                "endpoint",
                "method",
                "metadata",
                "decorator_type",
            ):
                if not hasattr(self, attr):
                    setattr(self, attr, None)

    class SecurityMetric:  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)
            for attr in ("timestamp", "metric_type", "value", "tags"):
                if not hasattr(self, attr):
                    setattr(self, attr, None)


from djangoapi_guard.models import SecurityConfig


@pytest.fixture
def mock_guard_agent() -> Generator[Any, Any, Any]:
    """Mock the guard_agent module for tests that need it."""
    import sys
    import types

    mock_guard_agent_module: Any = types.ModuleType("guard_agent")
    mock_guard_agent_module.SecurityEvent = SecurityEvent
    mock_guard_agent_module.SecurityMetric = SecurityMetric
    mock_guard_agent_module.AgentConfig = AgentConfig

    mock_models_module: Any = types.ModuleType("guard_agent.models")
    mock_models_module.SecurityEvent = SecurityEvent
    mock_models_module.SecurityMetric = SecurityMetric
    mock_models_module.AgentConfig = AgentConfig
    mock_guard_agent_module.models = mock_models_module

    mock_agent_handler = MagicMock()
    mock_guard_agent_func = MagicMock(return_value=mock_agent_handler)
    mock_guard_agent_module.guard_agent = mock_guard_agent_func

    original_modules = {}
    modules_to_mock = [
        "guard_agent",
        "guard_agent.models",
    ]

    for module_name in modules_to_mock:
        if module_name in sys.modules:
            original_modules[module_name] = sys.modules[module_name]

    sys.modules["guard_agent"] = mock_guard_agent_module
    sys.modules["guard_agent.models"] = mock_models_module

    with (
        patch(
            "djangoapi_guard.handlers.behavior_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "djangoapi_guard.handlers.cloud_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "djangoapi_guard.handlers.dynamic_rule_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "djangoapi_guard.decorators.base.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "djangoapi_guard.handlers.ipban_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "djangoapi_guard.handlers.ipinfo_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "djangoapi_guard.handlers.ratelimit_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "djangoapi_guard.handlers.redis_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "djangoapi_guard.handlers.suspatterns_handler.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "djangoapi_guard.utils.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "djangoapi_guard.models.AgentConfig",
            AgentConfig,
            create=True,
        ),
        patch(
            "djangoapi_guard.middleware.guard_agent",
            mock_guard_agent_func,
            create=True,
        ),
        patch(
            "djangoapi_guard.middleware.SecurityEvent",
            SecurityEvent,
            create=True,
        ),
        patch(
            "djangoapi_guard.middleware.SecurityMetric",
            SecurityMetric,
            create=True,
        ),
    ):
        try:
            yield mock_guard_agent_module
        finally:
            for module_name in modules_to_mock:
                if module_name in original_modules:
                    sys.modules[module_name] = original_modules[module_name]
                elif module_name in sys.modules:  # pragma: no cover
                    del sys.modules[module_name]


@pytest.fixture(autouse=True)
def mock_dependencies(mock_guard_agent: MagicMock) -> Generator[Any, Any, Any]:
    """Mock external dependencies to prevent connection attempts."""
    with (
        patch(
            "djangoapi_guard.handlers.redis_handler.RedisManager.initialize",
        ),
        patch(
            "djangoapi_guard.handlers.ipinfo_handler.IPInfoManager.__new__"
        ) as mock_ipinfo,
        patch(
            "djangoapi_guard.handlers.cloud_handler.CloudManager.__new__"
        ) as mock_cloud,
    ):
        mock_ipinfo_instance = MagicMock()
        mock_ipinfo.return_value = mock_ipinfo_instance

        mock_cloud_instance = MagicMock()
        mock_cloud.return_value = mock_cloud_instance
        yield


@pytest.fixture(autouse=True)
def cleanup_singletons() -> Generator[Any, Any, Any]:
    """Reset all singleton handler state between agent tests."""
    from djangoapi_guard.handlers.ipban_handler import ip_ban_manager
    from djangoapi_guard.handlers.ratelimit_handler import RateLimitManager
    from djangoapi_guard.handlers.security_headers_handler import (
        security_headers_manager,
    )
    from djangoapi_guard.handlers.suspatterns_handler import sus_patterns_handler

    # Save original state
    original_patterns_len = len(sus_patterns_handler.patterns)
    original_compiled_len = len(sus_patterns_handler.compiled_patterns)

    yield

    # Reset RateLimitManager singleton
    RateLimitManager._instance = None

    # Reset IPBanManager
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.redis_handler = None
    ip_ban_manager.agent_handler = None

    # Reset SusPatternsManager - restore patterns to original length
    sus_patterns_handler.redis_handler = None
    sus_patterns_handler.agent_handler = None
    sus_patterns_handler.custom_patterns.clear()
    sus_patterns_handler.compiled_custom_patterns.clear()
    while len(sus_patterns_handler.patterns) > original_patterns_len:
        sus_patterns_handler.patterns.pop()
    while len(sus_patterns_handler.compiled_patterns) > original_compiled_len:
        sus_patterns_handler.compiled_patterns.pop()

    # Reset security headers
    security_headers_manager.enabled = False
    security_headers_manager.headers_cache.clear()

    # Reset DynamicRuleManager
    from djangoapi_guard.handlers.dynamic_rule_handler import DynamicRuleManager

    drm_instance = DynamicRuleManager._instance
    if drm_instance is not None:
        if drm_instance._stop_event:
            drm_instance._stop_event.set()
        if drm_instance._update_thread:
            drm_instance._update_thread.join(timeout=1)
        DynamicRuleManager._instance = None


@pytest.fixture
def config() -> SecurityConfig:
    return SecurityConfig(
        enable_agent=True,
        agent_api_key="test-api-key",
        agent_endpoint="http://test.example.com",
        enable_dynamic_rules=True,
        dynamic_rule_interval=5,
        enable_penetration_detection=True,
        enable_ip_banning=True,
        enable_rate_limiting=True,
        rate_limit=100,
        rate_limit_window=60,
        auto_ban_threshold=5,
    )


@pytest.fixture
def mock_agent_handler() -> MagicMock:
    handler = MagicMock()
    handler.get_dynamic_rules = MagicMock()
    handler.send_event = MagicMock()
    return handler


@pytest.fixture
def mock_redis_handler() -> MagicMock:
    return MagicMock()
