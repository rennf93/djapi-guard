---

title: Core Architecture - DjangoAPI Guard
description: Internal architecture documentation for DjangoAPI Guard's modular core system
keywords: core architecture, modular design, security checks, middleware internals
---

Core Architecture (Internal)
=============================

!!! warning "Internal Implementation Details"
    The `djangoapi_guard/core/` modules documented here are **internal implementation details** and should NOT be imported directly. Always use the public API.

___

Overview
--------

DjangoAPI Guard uses a modular core architecture that separates security concerns into specialized, independently testable modules.

Module Overview
----------------

```text
djangoapi_guard/core/
├── checks/              # Security check pipeline (Chain of Responsibility)
├── events/              # Event bus and metrics collection
├── initialization/      # Handler initialization logic
├── responses/           # Response creation and processing
├── routing/             # Route configuration resolution
├── validation/          # Request validation utilities
├── bypass/              # Security bypass handling
└── behavioral/          # Behavioral rule processing
```

___

Security Check Pipeline
-----------------------

17 checks execute in order:

1. **RouteConfigCheck** - Extract route config and client IP
2. **EmergencyModeCheck** - Emergency mode
3. **HttpsEnforcementCheck** - HTTPS enforcement
4. **RequestLoggingCheck** - Log request
5. **RequestSizeContentCheck** - Validate size/content
6. **RequiredHeadersCheck** - Check required headers
7. **AuthenticationCheck** - Verify authentication
8. **ReferrerCheck** - Check referrer
9. **CustomValidatorsCheck** - Custom validators
10. **TimeWindowCheck** - Time-based access
11. **CloudIpRefreshCheck** - Periodic maintenance
12. **IpSecurityCheck** - IP whitelist/blacklist
13. **CloudProviderCheck** - Cloud provider blocking
14. **UserAgentCheck** - User agent filtering
15. **RateLimitCheck** - Rate limiting
16. **SuspiciousActivityCheck** - Threat detection
17. **CustomRequestCheck** - Custom checks

___

See Also
--------

- [DjangoAPIGuard](security-middleware.md) - Main middleware documentation
- [API Overview](overview.md) - Complete API reference
- [Decorators](decorators.md) - Route-level security decorators
