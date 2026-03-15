from dataclasses import dataclass
from logging import Logger

from djangoapi_guard.decorators.base import BaseSecurityDecorator
from djangoapi_guard.models import SecurityConfig


@dataclass
class RoutingContext:
    """
    Context for routing and decorator configuration resolution.

    Provides minimal dependencies needed for route matching and
    configuration resolution through clean dependency injection pattern.
    """

    config: SecurityConfig
    logger: Logger

    guard_decorator: BaseSecurityDecorator | None = None
