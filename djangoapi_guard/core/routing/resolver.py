from typing import Any

from django.http import HttpRequest
from django.urls import Resolver404, resolve

from djangoapi_guard.core.routing.context import RoutingContext
from djangoapi_guard.decorators.base import BaseSecurityDecorator, RouteConfig


class RouteConfigResolver:
    """
    Resolver for route configuration and decorator matching.

    Handles all routing-related operations including decorator access,
    route matching, bypass checking, and configuration resolution.
    """

    def __init__(self, context: RoutingContext):
        """
        Initialize the RouteConfigResolver.

        Args:
            context: RoutingContext with all required dependencies
        """
        self.context = context

    def get_guard_decorator(self, app: Any = None) -> BaseSecurityDecorator | None:
        """
        Get the guard decorator instance from context.

        Args:
            app: Unused, kept for API compatibility

        Returns:
            BaseSecurityDecorator instance or None if not available
        """
        return self.context.guard_decorator if self.context.guard_decorator else None

    def get_route_config(self, request: HttpRequest) -> RouteConfig | None:
        """
        Get route-specific security configuration from decorators.

        Args:
            request: The incoming request

        Returns:
            RouteConfig if found, None otherwise
        """
        guard_decorator = self.context.guard_decorator
        if not guard_decorator:
            return None

        try:
            match = resolve(request.path_info)
            view_func = match.func
            # Handle class-based views
            if hasattr(view_func, "view_class"):
                view_func = view_func.view_class
            if hasattr(view_func, "_guard_route_id"):
                route_id = view_func._guard_route_id
                return guard_decorator.get_route_config(route_id)
        except Resolver404:
            pass

        return None

    def should_bypass_check(
        self, check_name: str, route_config: RouteConfig | None
    ) -> bool:
        """
        Check if a security check should be bypassed.

        Args:
            check_name: Name of the check to evaluate
            route_config: Route-specific configuration (optional)

        Returns:
            True if check should be bypassed, False otherwise
        """
        if not route_config:
            return False
        return (
            check_name in route_config.bypassed_checks
            or "all" in route_config.bypassed_checks
        )

    def get_cloud_providers_to_check(
        self, route_config: RouteConfig | None
    ) -> list[str] | None:
        """
        Get list of cloud providers to check (route-specific or global).

        Args:
            route_config: Route-specific configuration (optional)

        Returns:
            List of provider names or None
        """
        if route_config and route_config.block_cloud_providers:
            return list(route_config.block_cloud_providers)
        if self.context.config.block_cloud_providers:
            return list(self.context.config.block_cloud_providers)
        return None
