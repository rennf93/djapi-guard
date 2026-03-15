import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from typing import Any, cast
from unittest.mock import MagicMock, Mock

import pytest
from django.http import HttpRequest

from djangoapi_guard import SecurityConfig, SecurityDecorator


@pytest.fixture
def security_config() -> SecurityConfig:
    return SecurityConfig(enable_redis=False, enable_agent=False)


@pytest.fixture
def decorator(security_config: SecurityConfig) -> SecurityDecorator:
    return SecurityDecorator(security_config)


class TestHoneypotEdgeCases:
    def test_honeypot_form_exception_caught(self, decorator: SecurityDecorator) -> None:
        mock_func = Mock()
        mock_func.__name__ = mock_func.__qualname__ = "test_func"
        mock_func.__module__ = "test_module"

        honeypot_decorator = decorator.honeypot_detection(["trap_field"])
        decorated_func = honeypot_decorator(mock_func)

        route_id = cast(Any, decorated_func)._guard_route_id
        route_config = decorator.get_route_config(route_id)
        assert route_config is not None
        validator = route_config.custom_validators[0]

        mock_request = MagicMock(spec=HttpRequest)
        mock_request.method = "POST"
        mock_request.META = {"CONTENT_TYPE": "application/x-www-form-urlencoded"}
        type(mock_request).POST = property(
            lambda self: (_ for _ in ()).throw(Exception("Form parsing error"))
        )

        result = validator(mock_request)
        assert result is None

    def test_honeypot_non_post_method(self, decorator: SecurityDecorator) -> None:
        mock_func = Mock()
        mock_func.__name__ = mock_func.__qualname__ = "test_func"
        mock_func.__module__ = "test_module"

        honeypot_decorator = decorator.honeypot_detection(["trap_field"])
        decorated_func = honeypot_decorator(mock_func)

        route_id = cast(Any, decorated_func)._guard_route_id
        route_config = decorator.get_route_config(route_id)
        assert route_config is not None
        validator = route_config.custom_validators[0]

        mock_request = MagicMock(spec=HttpRequest)
        mock_request.method = "GET"

        result = validator(mock_request)
        assert result is None

        mock_request.method = "DELETE"
        result = validator(mock_request)
        assert result is None

    def test_honeypot_unsupported_content_type(
        self, decorator: SecurityDecorator
    ) -> None:
        mock_func = Mock()
        mock_func.__name__ = mock_func.__qualname__ = "test_func"
        mock_func.__module__ = "test_module"

        honeypot_decorator = decorator.honeypot_detection(["trap_field"])
        decorated_func = honeypot_decorator(mock_func)

        route_id = cast(Any, decorated_func)._guard_route_id
        route_config = decorator.get_route_config(route_id)
        assert route_config is not None
        validator = route_config.custom_validators[0]

        mock_request = MagicMock(spec=HttpRequest)
        mock_request.method = "POST"
        mock_request.META = {"CONTENT_TYPE": "text/plain"}

        result = validator(mock_request)
        assert result is None

        mock_request.META = {"CONTENT_TYPE": "multipart/form-data"}
        result = validator(mock_request)
        assert result is None

    @pytest.mark.parametrize(
        "method",
        ["GET", "DELETE", "OPTIONS", "HEAD"],
    )
    def test_honeypot_various_non_modifying_methods(
        self, decorator: SecurityDecorator, method: str
    ) -> None:
        mock_func = Mock()
        mock_func.__name__ = mock_func.__qualname__ = "test_func"
        mock_func.__module__ = "test_module"

        honeypot_decorator = decorator.honeypot_detection(["trap_field"])
        decorated_func = honeypot_decorator(mock_func)

        route_id = cast(Any, decorated_func)._guard_route_id
        route_config = decorator.get_route_config(route_id)
        assert route_config is not None
        validator = route_config.custom_validators[0]

        mock_request = MagicMock(spec=HttpRequest)
        mock_request.method = method

        result = validator(mock_request)
        assert result is None

    @pytest.mark.parametrize(
        "method",
        ["POST", "PUT", "PATCH"],
    )
    def test_honeypot_modifying_methods_without_content_type(
        self, decorator: SecurityDecorator, method: str
    ) -> None:
        mock_func = Mock()
        mock_func.__name__ = mock_func.__qualname__ = "test_func"
        mock_func.__module__ = "test_module"

        honeypot_decorator = decorator.honeypot_detection(["trap_field"])
        decorated_func = honeypot_decorator(mock_func)

        route_id = cast(Any, decorated_func)._guard_route_id
        route_config = decorator.get_route_config(route_id)
        assert route_config is not None
        validator = route_config.custom_validators[0]

        mock_request = MagicMock(spec=HttpRequest)
        mock_request.method = method
        mock_request.META = {"CONTENT_TYPE": "application/xml"}

        result = validator(mock_request)
        assert result is None
