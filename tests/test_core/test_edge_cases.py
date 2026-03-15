import os
import re
import sys
from unittest.mock import MagicMock, Mock, patch

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from django.http import HttpRequest, HttpResponse

from djangoapi_guard.core.events.extension_events import SecurityEventBus
from djangoapi_guard.decorators.base import RouteConfig
from djangoapi_guard.handlers.dynamic_rule_handler import DynamicRuleManager
from djangoapi_guard.handlers.ratelimit_handler import RateLimitManager
from djangoapi_guard.handlers.security_headers_handler import SecurityHeadersManager
from djangoapi_guard.handlers.suspatterns_handler import SusPatternsManager
from djangoapi_guard.models import SecurityConfig


class TestDynamicRuleHandler:
    """Test DynamicRuleHandler edge cases."""

    def test_send_rule_received_event_no_agent(self) -> None:
        """Test _send_rule_received_event when no agent handler exists."""
        from datetime import datetime, timezone

        config = SecurityConfig()
        config.enable_dynamic_rules = False
        manager = DynamicRuleManager(config)
        manager.agent_handler = None

        from djangoapi_guard.models import DynamicRules

        rules = DynamicRules(
            rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
        )

        manager._send_rule_received_event(rules)

        assert True


class TestRateLimitHandler:
    """Test RateLimitHandler edge cases."""

    def test_get_redis_request_count_no_redis_handler(self) -> None:
        """Test _get_redis_request_count when no redis handler exists."""
        config = SecurityConfig()
        config.enable_redis = False
        manager = RateLimitManager(config)
        manager.redis_handler = None

        result = manager._get_redis_request_count(
            client_ip="127.0.0.1", current_time=1000.0, window_start=900.0
        )

        assert result is None


class TestSecurityHeadersHandler:
    """Test SecurityHeadersHandler edge cases."""

    def test_get_validated_cors_config_no_cors_config(self) -> None:
        """Test _get_validated_cors_config when cors_config is None."""
        manager = SecurityHeadersManager()
        manager.cors_config = None

        allow_methods, allow_headers = manager._get_validated_cors_config()

        assert allow_methods == ["GET", "POST"]
        assert allow_headers == ["*"]


class TestSusPatternsHandler:
    """Test SusPatternsHandler edge cases."""

    def test_remove_default_pattern_not_found(self) -> None:
        """Test _remove_default_pattern when pattern doesn't exist."""
        handler = SusPatternsManager()

        original_patterns = handler.patterns.copy()
        original_compiled = handler.compiled_patterns.copy()

        try:
            result = handler._remove_default_pattern("nonexistent_pattern_xyz")

            assert result is False
        finally:
            handler.patterns = original_patterns
            handler.compiled_patterns = original_compiled

    def test_remove_default_pattern_invalid_index(self) -> None:
        """Test _remove_default_pattern with index out of range."""
        handler = SusPatternsManager()

        original_patterns = handler.patterns.copy()
        original_compiled = handler.compiled_patterns.copy()

        try:
            test_pattern = "test_pattern_xyz_123_unique_edge"
            handler.patterns.append(test_pattern)
            compiled = re.compile(test_pattern)
            handler.compiled_patterns.append((compiled, frozenset()))

            handler.compiled_patterns = []

            result = handler._remove_default_pattern(test_pattern)

            assert result is False
        finally:
            handler.patterns = original_patterns
            handler.compiled_patterns = original_compiled


class TestUtilsEdgeCases:
    """Test utils.py edge cases."""

    def test_fallback_pattern_check_with_exception(self) -> None:
        """Test _fallback_pattern_check when pattern.search raises exception."""
        from djangoapi_guard.utils import _fallback_pattern_check

        with patch(
            "djangoapi_guard.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_handler:
            mock_pattern = Mock()
            mock_pattern.search = Mock(side_effect=Exception("Pattern error"))
            mock_handler.get_all_compiled_patterns = MagicMock(
                return_value=[mock_pattern]
            )

            result = _fallback_pattern_check("test_value")

            assert result == (False, "")

    def test_check_value_enhanced_empty_threats_list(self) -> None:
        """Test empty threats list."""
        from djangoapi_guard.utils import _check_value_enhanced

        with patch("djangoapi_guard.utils.sus_patterns_handler") as mock_handler:
            mock_handler.detect = MagicMock(
                return_value={"is_threat": True, "threats": []}
            )

            result = _check_value_enhanced(
                value="test_value",
                context="test_context",
                client_ip="127.0.0.1",
                correlation_id="test-123",
            )

            assert result == (True, "Threat detected")

    def test_detect_penetration_attempt_real_path(self) -> None:
        """Test detect_penetration_attempt with real detection."""
        from djangoapi_guard.utils import detect_penetration_attempt

        mock_request = Mock(spec=HttpRequest)
        mock_request.META = {
            "REMOTE_ADDR": "127.0.0.1",
            "QUERY_STRING": "",
        }
        mock_request.GET = {}
        mock_request.path = "/test"
        mock_request.body = b""

        result = detect_penetration_attempt(mock_request)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], str)


class TestSecurityEventBusHttpsAndCloud:
    """Test SecurityEventBus HTTPS violation and cloud detection events."""

    def test_send_https_violation_event_route_specific(self) -> None:
        """Test send_https_violation_event with route-specific HTTPS requirement."""
        config = SecurityConfig()
        config.agent_enable_events = True

        mock_agent = Mock()
        mock_agent.send_event = MagicMock()

        event_bus = SecurityEventBus(mock_agent, config)

        mock_request = Mock(spec=HttpRequest)
        mock_request.build_absolute_uri = Mock(return_value="http://example.com/test")
        mock_request.scheme = "http"
        mock_request.META = {
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_USER_AGENT": "",
        }
        mock_request.path = "/test"
        mock_request.method = "GET"

        route_config = RouteConfig()
        route_config.require_https = True

        mock_guard_agent = MagicMock()
        mock_event_class = MagicMock()
        mock_guard_agent.SecurityEvent = mock_event_class
        sys.modules["guard_agent"] = mock_guard_agent

        try:
            event_bus.send_https_violation_event(mock_request, route_config)
            assert mock_agent.send_event.call_count == 1
        finally:
            if "guard_agent" in sys.modules:
                del sys.modules["guard_agent"]

    def test_send_https_violation_event_global(self) -> None:
        """Test send_https_violation_event with global HTTPS enforcement."""
        config = SecurityConfig()
        config.agent_enable_events = True

        mock_agent = Mock()
        mock_agent.send_event = MagicMock()

        event_bus = SecurityEventBus(mock_agent, config)

        mock_request = Mock(spec=HttpRequest)
        mock_request.build_absolute_uri = Mock(return_value="http://example.com/test")
        mock_request.scheme = "http"
        mock_request.META = {
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_USER_AGENT": "",
        }
        mock_request.path = "/test"
        mock_request.method = "GET"

        mock_guard_agent = MagicMock()
        mock_event_class = MagicMock()
        mock_guard_agent.SecurityEvent = mock_event_class
        sys.modules["guard_agent"] = mock_guard_agent

        try:
            event_bus.send_https_violation_event(mock_request, None)
            assert mock_agent.send_event.call_count == 1
        finally:
            if "guard_agent" in sys.modules:
                del sys.modules["guard_agent"]

    def test_send_cloud_detection_events(self) -> None:
        """Test send_cloud_detection_events sends events correctly."""
        config = SecurityConfig()
        config.agent_enable_events = True

        mock_agent = Mock()
        mock_agent.send_event = MagicMock()

        event_bus = SecurityEventBus(mock_agent, config)

        mock_request = Mock(spec=HttpRequest)
        mock_request.META = {
            "REMOTE_ADDR": "1.2.3.4",
            "HTTP_USER_AGENT": "",
        }
        mock_request.path = "/test"
        mock_request.method = "GET"

        mock_cloud = Mock()
        mock_cloud.get_cloud_provider_details = Mock(return_value=("AWS", "1.0.0.0/8"))
        mock_cloud.agent_handler = mock_agent
        mock_cloud.send_cloud_detection_event = MagicMock()

        route_config = RouteConfig()
        route_config.block_cloud_providers = {"AWS"}

        mock_guard_agent = MagicMock()
        mock_event_class = MagicMock()
        mock_guard_agent.SecurityEvent = mock_event_class
        sys.modules["guard_agent"] = mock_guard_agent

        try:
            event_bus.send_cloud_detection_events(
                mock_request,
                "1.2.3.4",
                ["AWS"],
                route_config,
                mock_cloud,
                passive_mode=False,
            )
            mock_cloud.send_cloud_detection_event.assert_called_once()
            assert mock_agent.send_event.call_count >= 1
        finally:
            if "guard_agent" in sys.modules:
                del sys.modules["guard_agent"]


class TestSecurityCheckBase:
    """Test SecurityCheck base class."""

    def test_send_event_no_event_bus(self) -> None:
        """Test send_event when event_bus is None."""
        guard = Mock()
        guard.config = Mock()
        guard.config.passive_mode = False
        guard.logger = Mock()
        guard.event_bus = None

        from djangoapi_guard.core.checks.base import SecurityCheck

        class TestCheck(SecurityCheck):
            def check(self, request: HttpRequest) -> HttpResponse | None:
                return None

            @property
            def check_name(self) -> str:
                return "test"

        check = TestCheck(guard)
        mock_request = Mock(spec=HttpRequest)
        check.send_event("test", mock_request, "blocked", "reason")


class TestBehavioralProcessorEndpointId:
    """Test BehavioralProcessor endpoint ID generation."""

    def test_get_endpoint_id_no_endpoint(self) -> None:
        """Test get_endpoint_id when request cannot be resolved."""
        from djangoapi_guard.core.behavioral.context import BehavioralContext
        from djangoapi_guard.core.behavioral.processor import BehavioralProcessor

        context = BehavioralContext(
            config=Mock(),
            logger=Mock(),
            event_bus=Mock(),
            guard_decorator=Mock(),
        )
        processor = BehavioralProcessor(context)

        request = Mock(spec=HttpRequest)
        request.method = "GET"
        request.path = "/api/test"
        request.path_info = "/api/nonexistent-endpoint-xyz"

        endpoint_id = processor.get_endpoint_id(request)
        assert endpoint_id == "GET:/api/test"


class TestEventBusGeoIPException:
    """Test SecurityEventBus geo IP exception handling."""

    def test_send_middleware_event_with_geo_ip_exception(self) -> None:
        """Test middleware event when geo IP lookup raises exception."""
        config = SecurityConfig()
        config.agent_enable_events = True

        mock_agent = Mock()
        mock_agent.send_event = MagicMock()

        mock_geo_ip = Mock()
        geo_exception = Exception("GeoIP failure")
        mock_geo_ip.get_country = Mock(side_effect=geo_exception)

        event_bus = SecurityEventBus(mock_agent, config, mock_geo_ip)

        mock_request = Mock(spec=HttpRequest)
        mock_request.META = {
            "REMOTE_ADDR": "192.168.1.1",
            "HTTP_USER_AGENT": "TestAgent",
        }
        mock_request.path = "/test"
        mock_request.method = "GET"

        mock_guard_agent = MagicMock()
        mock_event_class = MagicMock()
        mock_guard_agent.SecurityEvent = mock_event_class
        sys.modules["guard_agent"] = mock_guard_agent

        try:
            event_bus.send_middleware_event(
                event_type="suspicious_request",
                request=mock_request,
                action_taken="logged",
                reason="test reason",
            )

            assert mock_agent.send_event.call_count == 1
        finally:
            if "guard_agent" in sys.modules:
                del sys.modules["guard_agent"]


def test_integration_all_edge_cases() -> None:
    """Integration test to ensure all edge cases work together."""
    from datetime import datetime, timezone

    config = SecurityConfig()
    config.enable_redis = False
    config.enable_agent = False
    config.enable_dynamic_rules = False

    drm = DynamicRuleManager(config)
    from djangoapi_guard.models import DynamicRules

    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    drm._send_rule_received_event(rules)

    rlm = RateLimitManager(config)
    rlm.redis_handler = None
    result = rlm._get_redis_request_count("127.0.0.1", 1000.0, 900.0)
    assert result is None

    shm = SecurityHeadersManager()
    shm.cors_config = None
    methods, headers = shm._get_validated_cors_config()
    assert methods == ["GET", "POST"]
    assert headers == ["*"]

    spm = SusPatternsManager()
    result = spm._remove_default_pattern("nonexistent")
    assert result is False
