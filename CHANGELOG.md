Changelog
=========

___

v2.0.0 (2026-03-26)
-------------------

Major Release (v2.0.0)
------------

- **Guard-Core migration**: DjAPI Guard is now a thin adapter over [guard-core](https://github.com/rennf93/guard-core), the framework-agnostic security engine. All security logic (17 checks, 8 handlers, detection engine) lives in guard-core; this package provides only the Django integration layer.
- **Production/Stable status**: Development status upgraded from Alpha to Production/Stable.
- **Zero breaking changes to public API**: All existing imports (`from djangoapi_guard import SecurityConfig`, `from djangoapi_guard import DjangoAPIGuard`, etc.) continue to work exactly as before.
- **Shared engine across frameworks**: The same security engine now powers [fastapi-guard](https://github.com/rennf93/fastapi-guard) and [flaskapi-guard](https://github.com/rennf93/flaskapi-guard), ensuring consistent security behavior across all three frameworks.

___

v1.0.1 (2026-03-16)
-------------------

Bug Fixes (v1.0.1)
------------

- **Per-endpoint rate limit check**: Fixed rate limit check to properly evaluate endpoint-specific rate limits. Previously, the rate limit check was only evaluating global rate limits.

___

v1.0.0 (2026-03-15)
-------------------

Initial Release (v1.0.0)
------------

- Initial release of Django API Guard
- IP whitelisting/blacklisting with CIDR support
- Rate limiting (global and per-endpoint)
- Automatic IP banning
- Penetration attempt detection
- User agent filtering
- Content type filtering
- Request size limiting
- Time-based access control
- Behavioral analysis and monitoring
- Custom authentication schemes
- Honeypot detection
- Redis integration for distributed environments
- Security headers management
- CORS configuration
- Emergency mode

___
