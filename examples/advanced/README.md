DjangoAPI Guard Advanced Example
=================================

This example demonstrates the full feature set of DjangoAPI Guard including Redis integration, security decorators, behavioral analysis, and advanced access control.

___

Running the example
-------------------

Using Docker Compose
--------------------

```bash
cd examples/advanced
docker compose up

# Restart
docker compose restart

# Stop
docker compose down
```

Running locally
---------------

```bash
cd examples/advanced
pip install -r requirements.txt
python manage.py runserver 0.0.0.0:8000
```

___

Available endpoints
-------------------

**Basic:**

- `/` - Root endpoint with API overview
- `/health` - Health check (excluded from security checks)
- `/api/info` - API information

**Rate Limiting:**

- `/api/limited` - Rate-limited to 5 requests per minute

**Authentication:**

- `/api/protected` - Requires Bearer token
- `/api/api-key` - Requires X-API-Key header

**Content Filtering:**

- `POST /api/json-only` - Only accepts application/json
- `POST /api/small-payload` - 1KB max request size

**Access Control:**

- `/api/local-only` - Restricted to local/private IPs

**Advanced:**

- `/api/business-hours` - Available only during 09:00-17:00 UTC
- `POST /api/honeypot` - Honeypot bot detection

**Behavioral Analysis:**

- `/api/monitored` - Usage monitoring (10 calls/hour)

**Admin:**

- `POST /api/admin/ban/<ip>` - Ban an IP (requires Bearer token)
- `POST /api/admin/unban/<ip>` - Unban an IP (requires Bearer token)

**Security Tests:**

- `/api/test/xss` - Test XSS detection (try `?q=<script>alert(1)</script>`)
- `/api/test/sqli` - Test SQL injection detection (try `?q=' OR 1=1 --`)

**Bypass:**

- `/api/unprotected` - Bypasses all security checks

___

Environment variables
---------------------

- `IPINFO_TOKEN` - Token for IPInfo geolocation (required for country blocking)
- `REDIS_URL` - URL for Redis connection (default: `redis://localhost:6379`)
- `REDIS_PREFIX` - Prefix for Redis keys (default: `djangoapi_guard:`)
- `DJANGO_SETTINGS_MODULE` - Django settings module (default: `advanced_project.settings`)

___

Configuration
-------------

See the configuration in `advanced_project/settings.py` for an example of how to configure DjangoAPI Guard with Redis, CORS, and all advanced features.
