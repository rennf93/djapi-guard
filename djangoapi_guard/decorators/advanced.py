import json
import logging
from collections.abc import Callable
from typing import Any

from django.http import HttpRequest, HttpResponse

from djangoapi_guard.decorators.base import BaseSecurityMixin

_logger = logging.getLogger("djangoapi_guard.decorators.advanced")


class AdvancedMixin(BaseSecurityMixin):
    def time_window(
        self, start_time: str, end_time: str, timezone: str = "UTC"
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.time_restrictions = {
                "start": start_time,
                "end": end_time,
                "timezone": timezone,
            }
            return self._apply_route_config(func)

        return decorator

    def suspicious_detection(
        self, enabled: bool = True
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.enable_suspicious_detection = enabled
            return self._apply_route_config(func)

        return decorator

    def honeypot_detection(
        self, trap_fields: list[str]
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            def honeypot_validator(request: HttpRequest) -> HttpResponse | None:
                def _has_trap_field_filled(data: dict[str, Any]) -> bool:
                    return any(field in data and data[field] for field in trap_fields)

                def _validate_form_data() -> HttpResponse | None:
                    try:
                        form = request.POST
                        if _has_trap_field_filled(dict(form)):
                            return HttpResponse("Forbidden", status=403)
                    except Exception:
                        _logger.debug("Failed to validate form data", exc_info=True)
                        return None
                    return None

                def _validate_json_data() -> HttpResponse | None:
                    try:
                        json_data = json.loads(request.body)
                        if json_data and _has_trap_field_filled(json_data):
                            return HttpResponse("Forbidden", status=403)
                    except Exception:
                        _logger.debug("Failed to validate JSON data", exc_info=True)
                        return None
                    return None

                if request.method not in ["POST", "PUT", "PATCH"]:
                    return None

                content_type = request.META.get("CONTENT_TYPE", "")

                if "application/x-www-form-urlencoded" in content_type:
                    return _validate_form_data()
                elif "application/json" in content_type:
                    return _validate_json_data()

                return None

            route_config = self._ensure_route_config(func)
            route_config.custom_validators.append(honeypot_validator)
            return self._apply_route_config(func)

        return decorator
