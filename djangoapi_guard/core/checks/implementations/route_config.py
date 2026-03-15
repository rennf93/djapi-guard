from django.http import HttpRequest, HttpResponse

from djangoapi_guard.core.checks.base import SecurityCheck
from djangoapi_guard.utils import extract_client_ip


class RouteConfigCheck(SecurityCheck):
    """
    Extracts and attaches route configuration to request state.

    This is not a blocking check, but prepares context for other checks.
    """

    @property
    def check_name(self) -> str:
        return "route_config"

    def check(self, request: HttpRequest) -> HttpResponse | None:
        """Extract route config and attach to request state."""
        route_config = None
        if self.middleware.route_resolver is not None:
            route_config = self.middleware.route_resolver.get_route_config(request)
        request._guard_route_config = route_config
        request._guard_client_ip = extract_client_ip(
            request, self.config, self.middleware.agent_handler
        )
        return None
