from dataclasses import dataclass
from logging import Logger

from djangoapi_guard.core.events import SecurityEventBus
from djangoapi_guard.models import SecurityConfig


@dataclass
class ValidationContext:
    """Context for request validation operations."""

    config: SecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
