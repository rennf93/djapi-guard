from django.http import HttpRequest, HttpResponse

from djangoapi_guard.core.checks.base import SecurityCheck
from djangoapi_guard.utils import log_activity


class RequestLoggingCheck(SecurityCheck):
    """Log incoming requests."""

    @property
    def check_name(self) -> str:
        return "request_logging"

    def check(self, request: HttpRequest) -> HttpResponse | None:
        """Log the request."""
        log_activity(request, self.logger, level=self.config.log_request_level)
        return None
