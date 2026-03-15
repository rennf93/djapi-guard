"""Tests for cloud IP handling - adapted from Flask Guard."""

import ipaddress
import itertools
import os
from collections.abc import Generator
from unittest.mock import MagicMock, Mock, patch

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

import pytest

from djangoapi_guard.handlers.cloud_handler import (
    CloudManager,
    cloud_handler,
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
    fetch_gcp_ip_ranges,
)


@pytest.fixture
def mock_httpx_client() -> Generator[Mock, None, None]:
    """Mock httpx.Client for all fetch functions."""
    with patch(
        "djangoapi_guard.handlers.cloud_handler.httpx.Client"
    ) as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_client_class.return_value.__exit__ = Mock(return_value=False)
        yield mock_client


def test_fetch_aws_ip_ranges(mock_httpx_client: Mock) -> None:
    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.json.return_value = {
        "prefixes": [
            {"ip_prefix": "192.168.0.0/24", "service": "AMAZON"},
            {"ip_prefix": "10.0.0.0/8", "service": "EC2"},
        ]
    }
    mock_httpx_client.get.return_value = mock_response

    result = fetch_aws_ip_ranges()
    assert ipaddress.IPv4Network("192.168.0.0/24") in result
    assert ipaddress.IPv4Network("10.0.0.0/8") not in result


def test_fetch_gcp_ip_ranges(mock_httpx_client: Mock) -> None:
    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.json.return_value = {
        "prefixes": [{"ipv4Prefix": "172.16.0.0/12"}, {"ipv6Prefix": "2001:db8::/32"}]
    }
    mock_httpx_client.get.return_value = mock_response

    result = fetch_gcp_ip_ranges()
    assert ipaddress.IPv4Network("172.16.0.0/12") in result
    assert ipaddress.IPv6Network("2001:db8::/32") in result
    assert len(result) == 2


def test_fetch_azure_ip_ranges(mock_httpx_client: Mock) -> None:
    mock_html_response = Mock()
    mock_html_response.raise_for_status = Mock()
    mock_html_response.text = """
    Some HTML content
    manually <a href="https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20230515.json">
    More HTML content
    """
    mock_json_response = Mock()
    mock_json_response.raise_for_status = Mock()
    mock_json_response.json.return_value = {
        "values": [
            {"properties": {"addressPrefixes": ["192.168.1.0/24", "2001:db8::/32"]}}
        ]
    }
    mock_httpx_client.get.side_effect = [mock_html_response, mock_json_response]

    result = fetch_azure_ip_ranges()
    assert ipaddress.IPv4Network("192.168.1.0/24") in result
    assert ipaddress.IPv6Network("2001:db8::/32") in result
    assert len(result) == 2


def test_cloud_ip_ranges() -> None:
    with (
        patch("djangoapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws,
        patch("djangoapi_guard.handlers.cloud_handler.fetch_gcp_ip_ranges") as mock_gcp,
        patch(
            "djangoapi_guard.handlers.cloud_handler.fetch_azure_ip_ranges"
        ) as mock_azure,
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}
        mock_gcp.return_value = {ipaddress.IPv4Network("172.16.0.0/12")}
        mock_azure.return_value = {ipaddress.IPv4Network("10.0.0.0/8")}

        cloud_handler._refresh_sync()

        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        assert not cloud_handler.is_cloud_ip("192.168.0.1", {"GCP"})
        assert cloud_handler.is_cloud_ip("172.16.0.1", {"GCP"})
        assert cloud_handler.is_cloud_ip("10.0.0.1", {"Azure"})
        assert not cloud_handler.is_cloud_ip("8.8.8.8", {"AWS", "GCP", "Azure"})


def test_cloud_ip_refresh() -> None:
    with (
        patch("djangoapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws,
        patch("djangoapi_guard.handlers.cloud_handler.fetch_gcp_ip_ranges") as mock_gcp,
        patch(
            "djangoapi_guard.handlers.cloud_handler.fetch_azure_ip_ranges"
        ) as mock_azure,
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}
        mock_gcp.return_value = {ipaddress.IPv4Network("172.16.0.0/12")}
        mock_azure.return_value = {ipaddress.IPv4Network("10.0.0.0/8")}

        cloud_handler._refresh_sync()
        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})

        mock_aws.return_value = {ipaddress.IPv4Network("192.168.1.0/24")}
        cloud_handler.refresh()

        assert not cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        assert cloud_handler.is_cloud_ip("192.168.1.1", {"AWS"})


def test_cloud_ip_refresh_subset() -> None:
    with (
        patch("djangoapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws,
        patch("djangoapi_guard.handlers.cloud_handler.fetch_gcp_ip_ranges") as mock_gcp,
        patch(
            "djangoapi_guard.handlers.cloud_handler.fetch_azure_ip_ranges"
        ) as mock_azure,
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}
        mock_gcp.return_value = {ipaddress.IPv4Network("172.16.0.0/12")}
        mock_azure.return_value = {ipaddress.IPv4Network("10.0.0.0/8")}

        providers = ["AWS", "GCP", "Azure"]
        for r in range(1, 4):
            for combo in itertools.combinations(providers, r):
                provider_set = set(combo)
                cloud_handler.ip_ranges = {"AWS": set(), "GCP": set(), "Azure": set()}
                cloud_handler._refresh_sync(provider_set)

                if "AWS" in provider_set:
                    assert cloud_handler.is_cloud_ip("192.168.0.1")
                if "GCP" in provider_set:
                    assert cloud_handler.is_cloud_ip("172.16.0.1")
                if "Azure" in provider_set:
                    assert cloud_handler.is_cloud_ip("10.0.0.1")

                if "AWS" not in provider_set:
                    assert not cloud_handler.is_cloud_ip("192.168.0.1")
                if "GCP" not in provider_set:
                    assert not cloud_handler.is_cloud_ip("172.16.0.1")
                if "Azure" not in provider_set:
                    assert not cloud_handler.is_cloud_ip("10.0.0.1")


def test_cloud_ip_ranges_error_handling() -> None:
    # Reset cloud handler ranges so prior test data doesn't interfere
    cloud_handler.ip_ranges = {"AWS": set(), "GCP": set(), "Azure": set()}

    with (
        patch(
            "djangoapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges",
            side_effect=Exception("AWS error"),
        ),
        patch(
            "djangoapi_guard.handlers.cloud_handler.fetch_gcp_ip_ranges",
            side_effect=Exception("GCP error"),
        ),
        patch(
            "djangoapi_guard.handlers.cloud_handler.fetch_azure_ip_ranges",
            side_effect=Exception("Azure error"),
        ),
    ):
        # After resetting, even attempting refresh (which errors) keeps ranges empty
        cloud_handler._refresh_sync({"AWS", "GCP", "Azure"})
        assert not cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        assert not cloud_handler.is_cloud_ip("172.16.0.1", {"GCP"})
        assert not cloud_handler.is_cloud_ip("10.0.0.1", {"Azure"})


def test_cloud_ip_ranges_invalid_ip() -> None:
    assert not cloud_handler.is_cloud_ip("invalid_ip", {"AWS", "GCP", "Azure"})


def test_fetch_aws_ip_ranges_error(mock_httpx_client: Mock) -> None:
    mock_httpx_client.get.side_effect = Exception("API failure")
    result = fetch_aws_ip_ranges()
    assert result == set()


def test_fetch_gcp_ip_ranges_error(mock_httpx_client: Mock) -> None:
    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.json.side_effect = Exception("Invalid JSON")
    mock_httpx_client.get.return_value = mock_response
    result = fetch_gcp_ip_ranges()
    assert result == set()


def test_cloud_manager_refresh_handling() -> None:
    with (
        patch("djangoapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws,
        patch("djangoapi_guard.handlers.cloud_handler.fetch_gcp_ip_ranges") as mock_gcp,
        patch(
            "djangoapi_guard.handlers.cloud_handler.fetch_azure_ip_ranges"
        ) as mock_azure,
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}
        mock_gcp.return_value = {ipaddress.IPv4Network("172.16.0.0/12")}
        mock_azure.return_value = {ipaddress.IPv4Network("10.0.0.0/8")}

        cloud_handler.ip_ranges["AWS"] = set()
        assert len(cloud_handler.ip_ranges["AWS"]) == 0

        cloud_handler.refresh()
        assert len(cloud_handler.ip_ranges["AWS"]) == 1


def test_is_cloud_ip_ipv6() -> None:
    assert not cloud_handler.is_cloud_ip("2001:db8::1", {"AWS"})


def test_fetch_azure_ip_ranges_url_not_found(mock_httpx_client: Mock) -> None:
    mock_html_response = Mock()
    mock_html_response.raise_for_status = Mock()
    mock_html_response.text = "HTML without download link"
    mock_httpx_client.get.return_value = mock_html_response

    result = fetch_azure_ip_ranges()
    assert result == set()


def test_fetch_azure_ip_ranges_download_failure(mock_httpx_client: Mock) -> None:
    mock_html_response = Mock()
    mock_html_response.raise_for_status = Mock()
    mock_html_response.text = '<a href="https://download.microsoft.com/valid.json">'
    mock_download_response = Mock()
    mock_download_response.raise_for_status.side_effect = Exception("Download failed")

    mock_httpx_client.get.side_effect = [mock_html_response, mock_download_response]

    result = fetch_azure_ip_ranges()
    assert result == set()


def test_cloud_handler_get_cloud_provider_details() -> None:
    """Test get_cloud_provider_details."""
    manager = CloudManager()
    manager.ip_ranges = {"AWS": set(), "GCP": set(), "Azure": set()}
    network = ipaddress.ip_network("10.0.0.0/8")
    manager.ip_ranges["AWS"] = {network}

    result = manager.get_cloud_provider_details("10.1.2.3")

    assert result is not None
    assert result[0] == "AWS"
    assert result[1] == "10.0.0.0/8"


def test_cloud_handler_get_cloud_provider_details_invalid_ip() -> None:
    """Test get_cloud_provider_details with invalid IP."""
    manager = CloudManager()
    manager.ip_ranges["AWS"] = {ipaddress.ip_network("10.0.0.0/8")}

    result = manager.get_cloud_provider_details("not-an-ip")

    assert result is None
