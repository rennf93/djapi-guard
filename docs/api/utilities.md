---

title: Utilities API - DjangoAPI Guard
description: Helper functions and utilities for logging, security checks, and request handling
keywords: security utilities, logging functions, security checks, request handling
---

Utilities
=========

The `utils` module provides helper functions for security operations.

___

Logging Functions
-----------------

```python
def setup_custom_logging(log_file: str | None = None, log_format: str = "text") -> logging.Logger:
    """Setup custom logging for DjangoAPI Guard."""

def log_activity(request, logger, log_type="request", reason="", passive_mode=False, trigger_info="", level="WARNING"):
    """Universal logging function for all types of requests and activities."""
```

___

Security Check Functions
------------------------

```python
def is_user_agent_allowed(user_agent: str, config: SecurityConfig) -> bool:
    """Check if user agent is allowed."""

def is_ip_allowed(ip: str, config: SecurityConfig, ipinfo_db=None) -> bool:
    """Check if IP address is allowed."""

def detect_penetration_attempt(request: HttpRequest) -> tuple[bool, str]:
    """Detect potential penetration attempts using the Detection Engine."""

def extract_client_ip(request: HttpRequest, config: SecurityConfig, agent_handler=None) -> str:
    """Securely extract the client IP address from the request."""
```

___

Usage Examples
--------------

```python
from djangoapi_guard.utils import setup_custom_logging, detect_penetration_attempt

logger = setup_custom_logging("security.log")

# Check for penetration attempts
is_suspicious, trigger_info = detect_penetration_attempt(request)
```
