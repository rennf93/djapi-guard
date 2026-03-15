from django.test import RequestFactory

from djangoapi_guard.models import SecurityConfig
from djangoapi_guard.utils import (
    extract_client_ip,
    is_ip_allowed,
    is_user_agent_allowed,
    setup_custom_logging,
)


class TestExtractClientIp:
    def test_basic_ip_extraction(self) -> None:
        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.1"
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        ip = extract_client_ip(request, config)
        assert ip == "192.168.1.1"

    def test_trusted_proxy(self) -> None:
        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "10.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "203.0.113.50, 10.0.0.1"
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            trusted_proxies=["10.0.0.1"],
        )
        ip = extract_client_ip(request, config)
        assert ip == "203.0.113.50"

    def test_untrusted_proxy_ignores_forwarded_for(self) -> None:
        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "10.0.0.5"
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        ip = extract_client_ip(request, config)
        assert ip == "192.168.1.1"

    def test_no_remote_addr(self) -> None:
        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = ""
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        ip = extract_client_ip(request, config)
        assert ip == "unknown"


class TestIsIpAllowed:
    def test_allowed_ip(self) -> None:
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        assert is_ip_allowed("192.168.1.1", config) is True

    def test_blacklisted_ip(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            blacklist=["192.168.1.1"],
        )
        assert is_ip_allowed("192.168.1.1", config) is False

    def test_whitelisted_ip(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            whitelist=["192.168.1.1"],
        )
        assert is_ip_allowed("192.168.1.1", config) is True

    def test_cidr_blacklist(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            blacklist=["192.168.1.0/24"],
        )
        assert is_ip_allowed("192.168.1.50", config) is False

    def test_invalid_ip(self) -> None:
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        assert is_ip_allowed("invalid", config) is False


class TestIsUserAgentAllowed:
    def test_allowed_agent(self) -> None:
        config = SecurityConfig(enable_redis=False, enable_agent=False)
        assert is_user_agent_allowed("Mozilla/5.0", config) is True

    def test_blocked_agent(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            blocked_user_agents=["BadBot"],
        )
        assert is_user_agent_allowed("BadBot/1.0", config) is False

    def test_case_insensitive(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=False,
            blocked_user_agents=["badbot"],
        )
        assert is_user_agent_allowed("BADBOT/1.0", config) is False


class TestSetupLogging:
    def test_basic_logging(self) -> None:
        logger = setup_custom_logging()
        assert logger is not None
        assert logger.name == "djangoapi_guard"
