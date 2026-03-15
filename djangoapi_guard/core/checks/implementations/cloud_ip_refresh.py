import time

from django.http import HttpRequest, HttpResponse

from djangoapi_guard.core.checks.base import SecurityCheck


class CloudIpRefreshCheck(SecurityCheck):
    """Refresh cloud IP ranges periodically."""

    @property
    def check_name(self) -> str:
        return "cloud_ip_refresh"

    def check(self, request: HttpRequest) -> HttpResponse | None:
        """Refresh cloud IP ranges if needed."""
        if (
            self.config.block_cloud_providers
            and time.time() - self.middleware.last_cloud_ip_refresh
            > self.config.cloud_ip_refresh_interval
        ):
            self.middleware.refresh_cloud_ip_ranges()
        return None
