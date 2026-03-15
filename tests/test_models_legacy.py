import pytest

from djangoapi_guard.models import SecurityConfig


class TestSecurityConfig:
    def test_default_config(self) -> None:
        config = SecurityConfig()
        assert config.rate_limit == 10
        assert config.rate_limit_window == 60
        assert config.auto_ban_threshold == 10
        assert config.auto_ban_duration == 3600
        assert config.enforce_https is False
        assert config.passive_mode is False
        assert config.enable_redis is True
        assert config.redis_prefix == "djangoapi_guard:"

    def test_custom_config(self) -> None:
        config = SecurityConfig(
            rate_limit=100,
            rate_limit_window=120,
            enforce_https=True,
            passive_mode=True,
        )
        assert config.rate_limit == 100
        assert config.rate_limit_window == 120
        assert config.enforce_https is True
        assert config.passive_mode is True

    def test_ip_validation(self) -> None:
        config = SecurityConfig(
            whitelist=["192.168.1.1", "10.0.0.0/8"],
            blacklist=["172.16.0.1"],
        )
        assert config.whitelist is not None
        assert "192.168.1.1" in config.whitelist
        assert "10.0.0.0/8" in config.whitelist
        assert "172.16.0.1" in config.blacklist

    def test_invalid_ip_raises(self) -> None:
        with pytest.raises(ValueError):
            SecurityConfig(whitelist=["not_an_ip"])

    def test_invalid_cidr_raises(self) -> None:
        with pytest.raises(ValueError):
            SecurityConfig(blacklist=["invalid/33"])

    def test_cloud_providers_validation(self) -> None:
        config = SecurityConfig(block_cloud_providers={"AWS", "GCP", "Invalid"})
        assert config.block_cloud_providers is not None
        assert "AWS" in config.block_cloud_providers
        assert "GCP" in config.block_cloud_providers
        assert "Invalid" not in config.block_cloud_providers

    def test_agent_config_requires_api_key(self) -> None:
        with pytest.raises(ValueError, match="agent_api_key"):
            SecurityConfig(enable_agent=True)

    def test_dynamic_rules_requires_agent(self) -> None:
        with pytest.raises(ValueError, match="enable_agent"):
            SecurityConfig(enable_dynamic_rules=True)

    def test_trusted_proxy_validation(self) -> None:
        config = SecurityConfig(
            trusted_proxies=["10.0.0.1", "172.16.0.0/12"],
            trusted_proxy_depth=2,
        )
        assert len(config.trusted_proxies) == 2
        assert config.trusted_proxy_depth == 2

    def test_invalid_proxy_depth(self) -> None:
        with pytest.raises(ValueError):
            SecurityConfig(trusted_proxy_depth=0)

    def test_exclude_paths_default(self) -> None:
        config = SecurityConfig()
        assert "/docs" in config.exclude_paths
        assert "/favicon.ico" in config.exclude_paths
