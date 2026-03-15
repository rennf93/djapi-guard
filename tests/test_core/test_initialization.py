import os
from unittest.mock import MagicMock, Mock, patch

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

import django

django.setup()

import pytest

from djangoapi_guard.core.initialization.handler_initializer import HandlerInitializer
from djangoapi_guard.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    """Create a security config."""
    config = SecurityConfig()
    config.enable_redis = True
    config.enable_agent = False
    config.enable_dynamic_rules = False
    config.block_cloud_providers = set()
    return config


@pytest.fixture
def mock_redis_handler() -> Mock:
    """Create mock Redis handler."""
    handler = Mock()
    handler.initialize = MagicMock()
    handler.initialize_agent = MagicMock()
    return handler


@pytest.fixture
def mock_agent_handler() -> Mock:
    """Create mock agent handler."""
    handler = Mock()
    handler.start = MagicMock()
    handler.initialize_redis = MagicMock()
    return handler


@pytest.fixture
def mock_geo_ip_handler() -> Mock:
    """Create mock GeoIP handler."""
    handler = Mock()
    handler.initialize_redis = MagicMock()
    handler.initialize_agent = MagicMock()
    return handler


@pytest.fixture
def mock_rate_limit_handler() -> Mock:
    """Create mock rate limit handler."""
    handler = Mock()
    handler.initialize_redis = MagicMock()
    handler.initialize_agent = MagicMock()
    return handler


@pytest.fixture
def mock_guard_decorator() -> Mock:
    """Create mock guard decorator."""
    decorator = Mock()
    decorator.initialize_agent = MagicMock()
    return decorator


@pytest.fixture
def initializer(
    security_config: SecurityConfig,
    mock_redis_handler: Mock,
    mock_agent_handler: Mock,
    mock_geo_ip_handler: Mock,
    mock_rate_limit_handler: Mock,
    mock_guard_decorator: Mock,
) -> HandlerInitializer:
    """Create HandlerInitializer instance."""
    return HandlerInitializer(
        config=security_config,
        redis_handler=mock_redis_handler,
        agent_handler=mock_agent_handler,
        geo_ip_handler=mock_geo_ip_handler,
        rate_limit_handler=mock_rate_limit_handler,
        guard_decorator=mock_guard_decorator,
    )


class TestHandlerInitializer:
    """Test HandlerInitializer class."""

    def test_init(
        self,
        initializer: HandlerInitializer,
        security_config: SecurityConfig,
        mock_redis_handler: Mock,
    ) -> None:
        """Test initializer initialization."""
        assert initializer.config == security_config
        assert initializer.redis_handler == mock_redis_handler

    def test_initialize_redis_handlers_disabled(
        self, security_config: SecurityConfig
    ) -> None:
        """Test Redis initialization when disabled."""
        security_config.enable_redis = False
        initializer = HandlerInitializer(config=security_config)

        initializer.initialize_redis_handlers()

    def test_initialize_redis_handlers_no_handler(
        self, security_config: SecurityConfig
    ) -> None:
        """Test Redis initialization when no handler provided."""
        initializer = HandlerInitializer(config=security_config, redis_handler=None)

        initializer.initialize_redis_handlers()

    def test_initialize_redis_handlers_basic(
        self,
        initializer: HandlerInitializer,
        mock_redis_handler: Mock,
        mock_geo_ip_handler: Mock,
        mock_rate_limit_handler: Mock,
    ) -> None:
        """Test basic Redis handler initialization."""
        with (
            patch("djangoapi_guard.handlers.cloud_handler.cloud_handler") as mock_cloud,
            patch(
                "djangoapi_guard.handlers.ipban_handler.ip_ban_manager"
            ) as mock_ipban,
            patch(
                "djangoapi_guard.handlers.suspatterns_handler.sus_patterns_handler"
            ) as mock_sus,
        ):
            mock_cloud.initialize_redis = MagicMock()
            mock_ipban.initialize_redis = MagicMock()
            mock_sus.initialize_redis = MagicMock()

            initializer.initialize_redis_handlers()

            mock_redis_handler.initialize.assert_called_once()

            mock_ipban.initialize_redis.assert_called_once_with(mock_redis_handler)
            mock_geo_ip_handler.initialize_redis.assert_called_once_with(
                mock_redis_handler
            )
            mock_rate_limit_handler.initialize_redis.assert_called_once_with(
                mock_redis_handler
            )
            mock_sus.initialize_redis.assert_called_once_with(mock_redis_handler)

    def test_initialize_redis_handlers_with_cloud(
        self,
        initializer: HandlerInitializer,
        security_config: SecurityConfig,
        mock_redis_handler: Mock,
    ) -> None:
        """Test Redis initialization with cloud providers blocked."""
        security_config.block_cloud_providers = {"AWS", "GCP"}

        with (
            patch("djangoapi_guard.handlers.cloud_handler.cloud_handler") as mock_cloud,
            patch(
                "djangoapi_guard.handlers.ipban_handler.ip_ban_manager"
            ) as mock_ipban,
            patch(
                "djangoapi_guard.handlers.suspatterns_handler.sus_patterns_handler"
            ) as mock_sus,
        ):
            mock_cloud.initialize_redis = MagicMock()
            mock_ipban.initialize_redis = MagicMock()
            mock_sus.initialize_redis = MagicMock()

            initializer.initialize_redis_handlers()

            mock_cloud.initialize_redis.assert_called_once()

    def test_initialize_redis_handlers_no_optional_handlers(
        self, security_config: SecurityConfig, mock_redis_handler: Mock
    ) -> None:
        """Test Redis initialization without optional handlers."""
        initializer = HandlerInitializer(
            config=security_config,
            redis_handler=mock_redis_handler,
            geo_ip_handler=None,
            rate_limit_handler=None,
        )

        with (
            patch("djangoapi_guard.handlers.cloud_handler.cloud_handler") as mock_cloud,
            patch(
                "djangoapi_guard.handlers.ipban_handler.ip_ban_manager"
            ) as mock_ipban,
            patch(
                "djangoapi_guard.handlers.suspatterns_handler.sus_patterns_handler"
            ) as mock_sus,
        ):
            mock_cloud.initialize_redis = MagicMock()
            mock_ipban.initialize_redis = MagicMock()
            mock_sus.initialize_redis = MagicMock()

            initializer.initialize_redis_handlers()

            mock_redis_handler.initialize.assert_called_once()

    def test_initialize_agent_for_handlers_no_agent(
        self, security_config: SecurityConfig
    ) -> None:
        """Test agent initialization when no agent provided."""
        initializer = HandlerInitializer(config=security_config, agent_handler=None)

        initializer.initialize_agent_for_handlers()

    def test_initialize_agent_for_handlers_basic(
        self,
        initializer: HandlerInitializer,
        mock_agent_handler: Mock,
        mock_rate_limit_handler: Mock,
    ) -> None:
        """Test basic agent handler initialization."""
        with (
            patch("djangoapi_guard.handlers.cloud_handler.cloud_handler") as mock_cloud,
            patch(
                "djangoapi_guard.handlers.ipban_handler.ip_ban_manager"
            ) as mock_ipban,
            patch(
                "djangoapi_guard.handlers.suspatterns_handler.sus_patterns_handler"
            ) as mock_sus,
        ):
            mock_cloud.initialize_agent = MagicMock()
            mock_ipban.initialize_agent = MagicMock()
            mock_sus.initialize_agent = MagicMock()

            initializer.initialize_agent_for_handlers()

            mock_ipban.initialize_agent.assert_called_once_with(mock_agent_handler)
            mock_rate_limit_handler.initialize_agent.assert_called_once_with(
                mock_agent_handler
            )
            mock_sus.initialize_agent.assert_called_once_with(mock_agent_handler)

    def test_initialize_agent_for_handlers_with_cloud(
        self,
        initializer: HandlerInitializer,
        security_config: SecurityConfig,
        mock_agent_handler: Mock,
    ) -> None:
        """Test agent initialization with cloud providers."""
        security_config.block_cloud_providers = {"AWS"}

        with (
            patch("djangoapi_guard.handlers.cloud_handler.cloud_handler") as mock_cloud,
            patch(
                "djangoapi_guard.handlers.ipban_handler.ip_ban_manager"
            ) as mock_ipban,
            patch(
                "djangoapi_guard.handlers.suspatterns_handler.sus_patterns_handler"
            ) as mock_sus,
        ):
            mock_cloud.initialize_agent = MagicMock()
            mock_ipban.initialize_agent = MagicMock()
            mock_sus.initialize_agent = MagicMock()

            initializer.initialize_agent_for_handlers()

            mock_cloud.initialize_agent.assert_called_once_with(mock_agent_handler)

    def test_initialize_agent_for_handlers_with_geoip(
        self,
        initializer: HandlerInitializer,
        mock_agent_handler: Mock,
        mock_geo_ip_handler: Mock,
    ) -> None:
        """Test agent initialization with GeoIP handler."""
        with (
            patch("djangoapi_guard.handlers.cloud_handler.cloud_handler") as mock_cloud,
            patch(
                "djangoapi_guard.handlers.ipban_handler.ip_ban_manager"
            ) as mock_ipban,
            patch(
                "djangoapi_guard.handlers.suspatterns_handler.sus_patterns_handler"
            ) as mock_sus,
        ):
            mock_cloud.initialize_agent = MagicMock()
            mock_ipban.initialize_agent = MagicMock()
            mock_sus.initialize_agent = MagicMock()

            initializer.initialize_agent_for_handlers()

            mock_geo_ip_handler.initialize_agent.assert_called_once_with(
                mock_agent_handler
            )

    def test_initialize_dynamic_rule_manager_disabled(
        self, security_config: SecurityConfig
    ) -> None:
        """Test dynamic rule manager when disabled."""
        initializer = HandlerInitializer(config=security_config)

        initializer.initialize_dynamic_rule_manager()

    def test_initialize_dynamic_rule_manager_no_agent(
        self, security_config: SecurityConfig
    ) -> None:
        """Test dynamic rule manager when no agent."""
        security_config.enable_dynamic_rules = False
        initializer = HandlerInitializer(config=security_config, agent_handler=None)

        initializer.initialize_dynamic_rule_manager()

    def test_initialize_dynamic_rule_manager_enabled(
        self,
        initializer: HandlerInitializer,
        security_config: SecurityConfig,
        mock_agent_handler: Mock,
        mock_redis_handler: Mock,
    ) -> None:
        """Test dynamic rule manager initialization."""
        security_config.enable_dynamic_rules = (
            False  # Keep disabled to avoid agent validation
        )

        with patch(
            "djangoapi_guard.handlers.dynamic_rule_handler.DynamicRuleManager"
        ) as MockDRM:
            mock_drm_instance = Mock()
            mock_drm_instance.initialize_agent = MagicMock()
            mock_drm_instance.initialize_redis = MagicMock()
            MockDRM.return_value = mock_drm_instance

            # Manually set enable_dynamic_rules for the initializer path
            initializer.config.enable_dynamic_rules = True

            initializer.initialize_dynamic_rule_manager()

            MockDRM.assert_called_once_with(security_config)
            mock_drm_instance.initialize_agent.assert_called_once_with(
                mock_agent_handler
            )
            mock_drm_instance.initialize_redis.assert_called_once_with(
                mock_redis_handler
            )

    def test_initialize_dynamic_rule_manager_no_redis(
        self, security_config: SecurityConfig, mock_agent_handler: Mock
    ) -> None:
        """Test dynamic rule manager without Redis."""
        initializer = HandlerInitializer(
            config=security_config,
            agent_handler=mock_agent_handler,
            redis_handler=None,
        )
        initializer.config.enable_dynamic_rules = True

        with patch(
            "djangoapi_guard.handlers.dynamic_rule_handler.DynamicRuleManager"
        ) as MockDRM:
            mock_drm_instance = Mock()
            mock_drm_instance.initialize_agent = MagicMock()
            mock_drm_instance.initialize_redis = MagicMock()
            MockDRM.return_value = mock_drm_instance

            initializer.initialize_dynamic_rule_manager()

            mock_drm_instance.initialize_redis.assert_not_called()

    def test_initialize_agent_integrations_no_agent(
        self, security_config: SecurityConfig
    ) -> None:
        """Test agent integrations when no agent."""
        initializer = HandlerInitializer(config=security_config, agent_handler=None)

        initializer.initialize_agent_integrations()

    def test_initialize_agent_integrations_full(
        self,
        initializer: HandlerInitializer,
        mock_agent_handler: Mock,
        mock_redis_handler: Mock,
        mock_guard_decorator: Mock,
    ) -> None:
        """Test full agent integrations initialization."""
        mock_init_handlers = MagicMock()
        mock_init_drm = MagicMock()
        with (
            patch.object(
                initializer, "initialize_agent_for_handlers", mock_init_handlers
            ),
            patch.object(initializer, "initialize_dynamic_rule_manager", mock_init_drm),
        ):
            initializer.initialize_agent_integrations()

            mock_agent_handler.start.assert_called_once()

            mock_agent_handler.initialize_redis.assert_called_once_with(
                mock_redis_handler
            )
            mock_redis_handler.initialize_agent.assert_called_once_with(
                mock_agent_handler
            )

            mock_init_handlers.assert_called_once()

            mock_guard_decorator.initialize_agent.assert_called_once_with(
                mock_agent_handler
            )

            mock_init_drm.assert_called_once()

    def test_initialize_agent_integrations_no_redis(
        self, security_config: SecurityConfig, mock_agent_handler: Mock
    ) -> None:
        """Test agent integrations without Redis."""
        initializer = HandlerInitializer(
            config=security_config,
            agent_handler=mock_agent_handler,
            redis_handler=None,
        )

        with (
            patch.object(initializer, "initialize_agent_for_handlers", MagicMock()),
            patch.object(initializer, "initialize_dynamic_rule_manager", MagicMock()),
        ):
            initializer.initialize_agent_integrations()

            mock_agent_handler.initialize_redis.assert_not_called()

    def test_initialize_agent_integrations_no_decorator(
        self, security_config: SecurityConfig, mock_agent_handler: Mock
    ) -> None:
        """Test agent integrations without decorator."""
        initializer = HandlerInitializer(
            config=security_config,
            agent_handler=mock_agent_handler,
            guard_decorator=None,
        )

        with (
            patch.object(initializer, "initialize_agent_for_handlers", MagicMock()),
            patch.object(initializer, "initialize_dynamic_rule_manager", MagicMock()),
        ):
            initializer.initialize_agent_integrations()

            mock_agent_handler.start.assert_called_once()

    def test_initialize_agent_integrations_decorator_no_method(
        self, security_config: SecurityConfig, mock_agent_handler: Mock
    ) -> None:
        """Test agent integrations with decorator lacking initialize_agent."""
        decorator_no_method = Mock(spec=[])
        initializer = HandlerInitializer(
            config=security_config,
            agent_handler=mock_agent_handler,
            guard_decorator=decorator_no_method,
        )

        with (
            patch.object(initializer, "initialize_agent_for_handlers", MagicMock()),
            patch.object(initializer, "initialize_dynamic_rule_manager", MagicMock()),
        ):
            initializer.initialize_agent_integrations()

            mock_agent_handler.start.assert_called_once()
