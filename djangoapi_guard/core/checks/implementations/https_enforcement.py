from django.http import HttpRequest, HttpResponse

from djangoapi_guard.core.checks.base import SecurityCheck


class HttpsEnforcementCheck(SecurityCheck):
    """Check and enforce HTTPS requirements."""

    @property
    def check_name(self) -> str:
        return "https_enforcement"

    def _is_request_https(self, request: HttpRequest) -> bool:
        is_https: bool = request.scheme == "https"

        if (
            self.config.trust_x_forwarded_proto
            and self.config.trusted_proxies
            and request.META.get("REMOTE_ADDR", "")
        ):
            remote_addr: str = str(request.META.get("REMOTE_ADDR", ""))
            if self._is_trusted_proxy(remote_addr):
                forwarded_proto: str = str(
                    request.META.get("HTTP_X_FORWARDED_PROTO", "")
                )
                is_https = is_https or forwarded_proto.lower() == "https"

        return is_https

    def _is_trusted_proxy(self, connecting_ip: str) -> bool:
        """Check if connecting IP is a trusted proxy."""
        from ipaddress import ip_address, ip_network

        for proxy in self.config.trusted_proxies:
            if "/" not in proxy:
                if connecting_ip == proxy:
                    return True
            else:
                if ip_address(connecting_ip) in ip_network(proxy, strict=False):
                    return True
        return False

    def _create_https_redirect(self, request: HttpRequest) -> HttpResponse:
        """
        Create HTTPS redirect response with custom modifier if configured.

        Delegates to ErrorResponseFactory for redirect creation.
        """
        if self.middleware.response_factory is not None:
            return self.middleware.response_factory.create_https_redirect(request)
        https_url = request.build_absolute_uri().replace("http://", "https://", 1)
        return HttpResponse(
            content="",
            status=301,
            headers={"Location": https_url},
        )

    def check(self, request: HttpRequest) -> HttpResponse | None:
        """Check HTTPS enforcement."""
        route_config = getattr(request, "_guard_route_config", None)

        https_required = (
            route_config.require_https if route_config else self.config.enforce_https
        )
        if not https_required:
            return None

        if self._is_request_https(request):
            return None

        if self.middleware.event_bus is not None:
            self.middleware.event_bus.send_https_violation_event(request, route_config)

        if not self.config.passive_mode:
            return self._create_https_redirect(request)

        return None
