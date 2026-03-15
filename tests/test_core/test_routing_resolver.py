import os
from unittest.mock import Mock

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

import pytest
from django.http import HttpRequest

from djangoapi_guard.core.routing.context import RoutingContext
from djangoapi_guard.core.routing.resolver import RouteConfigResolver
from djangoapi_guard.decorators.base import BaseSecurityDecorator, RouteConfig


@pytest.fixture
def mock_config() -> Mock:
    """Create mock config."""
    config = Mock()
    config.block_cloud_providers = {"AWS", "GCP"}
    return config


@pytest.fixture
def mock_guard_decorator() -> Mock:
    """Create mock guard decorator."""
    decorator = Mock(spec=BaseSecurityDecorator)
    route_config = RouteConfig()
    route_config.bypassed_checks = {"rate_limit"}
    decorator.get_route_config = Mock(return_value=route_config)
    return decorator


@pytest.fixture
def routing_context(mock_config: Mock, mock_guard_decorator: Mock) -> RoutingContext:
    """Create routing context."""
    return RoutingContext(
        config=mock_config,
        logger=Mock(),
        guard_decorator=mock_guard_decorator,
    )


@pytest.fixture
def resolver(routing_context: RoutingContext) -> RouteConfigResolver:
    """Create RouteConfigResolver instance."""
    return RouteConfigResolver(routing_context)


class TestRouteConfigResolver:
    """Test RouteConfigResolver class."""

    def test_init(self, routing_context: RoutingContext) -> None:
        """Test RouteConfigResolver initialization."""
        resolver = RouteConfigResolver(routing_context)
        assert resolver.context == routing_context

    def test_get_guard_decorator_from_context(
        self, resolver: RouteConfigResolver, mock_guard_decorator: Mock
    ) -> None:
        """Test get_guard_decorator from context."""
        result = resolver.get_guard_decorator()
        assert result == mock_guard_decorator

    def test_get_guard_decorator_none_when_context_has_none(self) -> None:
        """Test get_guard_decorator when context has no decorator."""
        context = RoutingContext(config=Mock(), logger=Mock(), guard_decorator=None)
        resolver = RouteConfigResolver(context)

        result = resolver.get_guard_decorator()
        assert result is None

    def test_get_route_config_no_decorator(self) -> None:
        """Test get_route_config when no guard decorator available."""
        context = RoutingContext(config=Mock(), logger=Mock(), guard_decorator=None)
        resolver = RouteConfigResolver(context)

        mock_request = Mock(spec=HttpRequest)
        mock_request.path_info = "/test"
        result = resolver.get_route_config(mock_request)
        assert result is None

    def test_get_route_config_no_matching_route(
        self,
        resolver: RouteConfigResolver,
        mock_guard_decorator: Mock,
    ) -> None:
        """Test get_route_config when no route matches."""
        mock_request = Mock(spec=HttpRequest)
        mock_request.path_info = "/api/nonexistent-xyz"

        result = resolver.get_route_config(mock_request)
        assert result is None

    def test_should_bypass_check_no_config(self, resolver: RouteConfigResolver) -> None:
        """Test should_bypass_check with no route config."""
        result = resolver.should_bypass_check("rate_limit", None)
        assert result is False

    def test_should_bypass_check_specific_check(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test should_bypass_check with specific check in bypassed_checks."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"rate_limit", "ip_check"}

        result = resolver.should_bypass_check("rate_limit", route_config)
        assert result is True

    def test_should_bypass_check_all_checks(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test should_bypass_check with 'all' in bypassed_checks."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"all"}

        result = resolver.should_bypass_check("any_check", route_config)
        assert result is True

    def test_should_bypass_check_not_bypassed(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test should_bypass_check when check is not bypassed."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"ip_check"}

        result = resolver.should_bypass_check("rate_limit", route_config)
        assert result is False

    def test_get_cloud_providers_from_route_config(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test get_cloud_providers_to_check from route config."""
        route_config = RouteConfig()
        route_config.block_cloud_providers = {"Azure", "AWS"}

        result = resolver.get_cloud_providers_to_check(route_config)
        assert result is not None
        assert set(result) == {"Azure", "AWS"}

    def test_get_cloud_providers_from_global_config(
        self, resolver: RouteConfigResolver
    ) -> None:
        route_config = RouteConfig()

        result = resolver.get_cloud_providers_to_check(route_config)
        assert result is not None
        assert set(result) == {"AWS", "GCP"}

    def test_get_cloud_providers_none_when_no_config(
        self, resolver: RouteConfigResolver
    ) -> None:
        result = resolver.get_cloud_providers_to_check(None)
        assert result is not None
        assert set(result) == {"AWS", "GCP"}

    def test_get_cloud_providers_none_when_empty(self) -> None:
        """Test get_cloud_providers_to_check when both configs are empty."""
        config = Mock()
        config.block_cloud_providers = set()
        context = RoutingContext(config=config, logger=Mock(), guard_decorator=None)
        resolver = RouteConfigResolver(context)

        result = resolver.get_cloud_providers_to_check(None)
        assert result is None

    def test_route_config_class_based_view(
        self, mock_config: Mock, mock_guard_decorator: Mock
    ) -> None:
        """class-based view with _guard_route_id."""
        from unittest.mock import patch as mock_patch

        context = RoutingContext(
            config=mock_config,
            logger=Mock(),
            guard_decorator=mock_guard_decorator,
        )
        resolver = RouteConfigResolver(context)

        # Create a mock view that simulates a CBV
        mock_view_class = Mock()
        mock_view_class._guard_route_id = "test_route"
        mock_view_func = Mock()
        mock_view_func.view_class = mock_view_class
        # view_func itself doesn't have _guard_route_id
        del mock_view_func._guard_route_id

        mock_match = Mock()
        mock_match.func = mock_view_func

        mock_request = Mock(spec=HttpRequest)
        mock_request.path_info = "/test"

        with mock_patch(
            "djangoapi_guard.core.routing.resolver.resolve",
            return_value=mock_match,
        ):
            result = resolver.get_route_config(mock_request)

        mock_guard_decorator.get_route_config.assert_called_with("test_route")
        assert result is not None

    def test_route_config_decorated_view(
        self, mock_config: Mock, mock_guard_decorator: Mock
    ) -> None:
        """regular view with _guard_route_id (no view_class)."""
        from unittest.mock import patch as mock_patch

        context = RoutingContext(
            config=mock_config,
            logger=Mock(),
            guard_decorator=mock_guard_decorator,
        )
        resolver = RouteConfigResolver(context)

        mock_view_func = Mock()
        mock_view_func._guard_route_id = "my_route"
        # No view_class attribute
        del mock_view_func.view_class

        mock_match = Mock()
        mock_match.func = mock_view_func

        mock_request = Mock(spec=HttpRequest)
        mock_request.path_info = "/test"

        with mock_patch(
            "djangoapi_guard.core.routing.resolver.resolve",
            return_value=mock_match,
        ):
            result = resolver.get_route_config(mock_request)

        mock_guard_decorator.get_route_config.assert_called_with("my_route")
        assert result is not None
