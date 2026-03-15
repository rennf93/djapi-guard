from dataclasses import dataclass
from logging import Logger

from djangoapi_guard.core.events import SecurityEventBus
from djangoapi_guard.core.responses import ErrorResponseFactory
from djangoapi_guard.core.routing import RouteConfigResolver
from djangoapi_guard.core.validation import RequestValidator
from djangoapi_guard.models import SecurityConfig


@dataclass
class BypassContext:
    """Context for bypass handler operations."""

    config: SecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
    route_resolver: RouteConfigResolver
    response_factory: ErrorResponseFactory
    validator: RequestValidator
