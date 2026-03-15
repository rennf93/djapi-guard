---

title: Security Headers Manager - DjangoAPI Guard
description: Comprehensive HTTP security header management following OWASP best practices
keywords: security headers, CSP, HSTS, X-Frame-Options, OWASP headers
---

Security Headers Manager
========================

The Security Headers Manager provides comprehensive HTTP security header management following OWASP best practices.

___

Class Reference
---------------

```python
from djangoapi_guard.handlers.security_headers_handler import SecurityHeadersManager
security_headers_manager = SecurityHeadersManager()
```

Methods: `configure()`, `get_headers()`, `get_cors_headers()`, `validate_csp_report()`, `reset()`

___

Default Headers
---------------

| Header | Default Value |
|--------|--------------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |

___

Example Usage
-------------

```python
# settings.py
GUARD_SECURITY_CONFIG = SecurityConfig(
    security_headers={
        "enabled": True,
        "hsts": {"max_age": 31536000, "include_subdomains": True},
        "frame_options": "DENY",
    }
)
```

___

See Also
--------

- [HTTP Security Headers Tutorial](../tutorial/security/http-security-headers.md)
- [Security Configuration](../tutorial/configuration/security-config.md)
