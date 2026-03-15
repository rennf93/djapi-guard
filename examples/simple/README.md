DjangoAPI Guard Simple Example
==============================

This example demonstrates how to use DjangoAPI Guard as middleware in your Django application.

___

Running the example
-------------------

Using Docker Compose (from repo root)
--------------------------------------

```bash
# Start the example app and Redis
docker compose up

# Restart
docker compose restart

# Stop
docker compose down
```

Running locally
---------------

```bash
cd examples/simple
pip install -r requirements.txt
python manage.py runserver 0.0.0.0:8000
```

___

Available endpoints
-------------------

- `/` - Root endpoint with API overview
- `/health` - Health check (excluded from security checks)
- `/api/info` - API information
- `/api/data` - Sample data endpoint
- `/api/test/xss` - Test XSS detection (try `?q=<script>alert(1)</script>`)
- `/api/test/sqli` - Test SQL injection detection (try `?q=' OR 1=1 --`)

___

Environment variables
---------------------

- `IPINFO_TOKEN` - Token for IPInfo geolocation (required for country blocking)
- `REDIS_URL` - URL for Redis connection (default: `redis://localhost:6379`)
- `REDIS_PREFIX` - Prefix for Redis keys (default: `djangoapi_guard:`)

___

Configuration
-------------

See the configuration in `example_project/settings.py` for an example of how to set up the middleware with `GUARD_SECURITY_CONFIG`.
