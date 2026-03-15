import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from typing import Any

import pytest

from djangoapi_guard.handlers.behavior_handler import BehaviorTracker
from djangoapi_guard.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    return SecurityConfig(enable_redis=False, enable_agent=False)


@pytest.fixture
def tracker(security_config: SecurityConfig) -> BehaviorTracker:
    return BehaviorTracker(security_config)


class TestHandleArrayMatchEdgeCases:
    def test_handle_array_match_part_not_in_dict(
        self, tracker: BehaviorTracker
    ) -> None:
        current: dict[str, Any] = {"other_field": [1, 2, 3]}
        part = "missing_field[]"
        expected = "test"

        result = tracker._handle_array_match(current, part, expected)
        assert result is False

    def test_handle_array_match_not_a_list(self, tracker: BehaviorTracker) -> None:
        current: dict[str, Any] = {"items": "not_a_list"}
        part = "items[]"
        expected = "test"

        result = tracker._handle_array_match(current, part, expected)
        assert result is False

    def test_handle_array_match_current_not_dict(
        self, tracker: BehaviorTracker
    ) -> None:
        current: list[str] = ["not", "a", "dict"]
        part = "items[]"
        expected = "test"

        result = tracker._handle_array_match(current, part, expected)
        assert result is False


class TestTraverseJsonPathEdgeCases:
    def test_traverse_json_path_missing_key(self, tracker: BehaviorTracker) -> None:
        data: dict[str, Any] = {"level1": {"level2": "value"}}
        path = "level1.missing.level3"

        result = tracker._traverse_json_path(data, path)
        assert result is None

    def test_traverse_json_path_not_a_dict(self, tracker: BehaviorTracker) -> None:
        data: dict[str, str] = {"level1": "string_value"}
        path = "level1.level2"

        result = tracker._traverse_json_path(data, path)
        assert result is None

    def test_traverse_json_path_root_not_dict(self, tracker: BehaviorTracker) -> None:
        data: list[str] = ["not", "a", "dict"]
        path = "some.path"

        result = tracker._traverse_json_path(data, path)
        assert result is None

    def test_traverse_json_path_success(self, tracker: BehaviorTracker) -> None:
        data: dict[str, Any] = {"level1": {"level2": {"level3": "found"}}}
        path = "level1.level2.level3"

        result = tracker._traverse_json_path(data, path)
        assert result == "found"


class TestMatchJsonPatternEdgeCases:
    def test_match_json_pattern_non_dict_in_path(
        self, tracker: BehaviorTracker
    ) -> None:
        data: dict[str, str] = {"result": "string_not_dict"}
        pattern = "result.nested==value"

        result = tracker._match_json_pattern(data, pattern)
        assert result is False

    def test_match_json_pattern_missing_key_in_path(
        self, tracker: BehaviorTracker
    ) -> None:
        data: dict[str, Any] = {"result": {"status": "win"}}
        pattern = "result.missing.key==value"

        result = tracker._match_json_pattern(data, pattern)
        assert result is False

    @pytest.mark.parametrize(
        "data,pattern",
        [
            ({"other": [1, 2, 3]}, "items[]==test"),
            ({"items": "not_a_list"}, "items[]==test"),
            ({"level1": "not_dict"}, "level1.level2==value"),
        ],
    )
    def test_match_json_pattern_edge_cases(
        self, tracker: BehaviorTracker, data: dict[str, Any], pattern: str
    ) -> None:
        result = tracker._match_json_pattern(data, pattern)
        assert result is False
