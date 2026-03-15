---

title: API Reference - DjangoAPI Guard
description: Complete API documentation for DjangoAPI Guard security middleware and its components
keywords: djangoapi guard api, security middleware api, python api reference
---

API Reference Overview
======================

!!! info "Architecture"
    DjangoAPI Guard uses a modular core architecture. While the public API remains unchanged, the internal implementation is organized into specialized modules in `djangoapi_guard/core/`. See [Core Architecture](core-architecture.md) for details.

___

Core Components
---------------

Middleware & Configuration
----------------------------

- **[DjangoAPIGuard](security-middleware.md)**: The main middleware that handles all security features
- **[SecurityConfig](../tutorial/configuration/security-config.md)**: Configuration class for all security settings
- **[SecurityDecorator](decorators.md)**: Route-level security decorator system

Handler Components
------------------

- **[IPBanManager](ipban-manager.md)**: Manages IP banning functionality
- **[IPInfoManager](ipinfo-manager.md)**: Handles IP geolocation using IPInfo's database
- **[SusPatternsManager](sus-patterns.md)**: Manages suspicious patterns for threat detection
- **[CloudManager](cloud-manager.md)**: Handles cloud provider IP range detection
- **[RateLimitManager](ratelimit-manager.md)**: Handles rate limiting functionality
- **[RedisManager](redis-manager.md)**: Handles Redis connections and atomic operations
- **[BehaviorTracker](behavior-manager.md)**: Handles behavioral analysis and monitoring
- **[SecurityHeadersManager](security-headers.md)**: Manages security headers

Utilities
---------

- **[Utilities](utilities.md)**: Helper functions for logging and request analysis

___

Key Classes and Instances
-------------------------

```python
# Core middleware and configuration
from djangoapi_guard.middleware import DjangoAPIGuard
from djangoapi_guard.models import SecurityConfig

# Security decorators
from djangoapi_guard.decorators import SecurityDecorator, RouteConfig

# Handler classes and their pre-initialized instances
from djangoapi_guard.handlers.cloud_handler import CloudManager, cloud_handler
from djangoapi_guard.handlers.ipban_handler import IPBanManager, ip_ban_manager
from djangoapi_guard.handlers.ratelimit_handler import RateLimitManager, rate_limit_handler
from djangoapi_guard.handlers.redis_handler import RedisManager, redis_handler
from djangoapi_guard.handlers.suspatterns_handler import SusPatternsManager, sus_patterns_handler
from djangoapi_guard.handlers.behavior_handler import BehaviorTracker, BehaviorRule

# Special case - requires parameters
from djangoapi_guard.handlers.ipinfo_handler import IPInfoManager
```
