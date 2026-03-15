"""Tests for IP Ban Manager - adapted from Flask Guard."""

import os
import time

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

from djangoapi_guard.handlers.ipban_handler import ip_ban_manager
from djangoapi_guard.models import SecurityConfig


def test_ip_ban_manager() -> None:
    """Test the IPBanManager."""
    ip = "192.168.1.1"

    assert not ip_ban_manager.is_ip_banned(ip)

    ip_ban_manager.ban_ip(ip, 1)
    assert ip_ban_manager.is_ip_banned(ip)

    time.sleep(1.1)
    assert not ip_ban_manager.is_ip_banned(ip)


def test_automatic_ip_ban() -> None:
    """Test the automatic IP banning via middleware."""
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=False,
        enable_ip_banning=True,
        enable_penetration_detection=True,
        auto_ban_threshold=3,
        auto_ban_duration=300,
    )

    ip = "192.168.1.2"
    for _ in range(config.auto_ban_threshold):
        ip_ban_manager.ban_ip(ip, config.auto_ban_duration)

    assert ip_ban_manager.is_ip_banned(ip)


def test_reset_ip_ban_manager() -> None:
    """Test the IPBanManager reset method."""
    ip_ban_manager.ban_ip("test_ip", 3600)
    ip_ban_manager.reset()
    assert not ip_ban_manager.is_ip_banned("test_ip")


def test_ban_ip_concurrent_access() -> None:
    """Test concurrent ban access."""
    ip = "192.168.1.100"
    for _ in range(10):
        ip_ban_manager.ban_ip(ip, 1)
    assert ip_ban_manager.is_ip_banned(ip)


def test_ip_ban_manager_ban_and_expire() -> None:
    """Test ban expires after duration."""
    ip = "192.168.1.50"
    ip_ban_manager.ban_ip(ip, 1)
    assert ip_ban_manager.is_ip_banned(ip)

    time.sleep(1.1)
    assert not ip_ban_manager.is_ip_banned(ip)


def test_ip_ban_manager_multiple_bans() -> None:
    """Test multiple IPs can be banned."""
    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    for ip in ips:
        ip_ban_manager.ban_ip(ip, 3600)
        assert ip_ban_manager.is_ip_banned(ip)

    ip_ban_manager.reset()
    for ip in ips:
        assert not ip_ban_manager.is_ip_banned(ip)


def test_ip_ban_manager_unban() -> None:
    """Test unbanning an IP."""
    ip = "10.0.0.10"
    ip_ban_manager.ban_ip(ip, 3600)
    assert ip_ban_manager.is_ip_banned(ip)

    ip_ban_manager.unban_ip(ip)
    assert not ip_ban_manager.is_ip_banned(ip)


def test_ip_ban_not_banned() -> None:
    """Test checking an IP that was never banned."""
    assert not ip_ban_manager.is_ip_banned("1.2.3.4")
