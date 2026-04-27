Changelog
=========

___

v3.0.0 (2026-04-26)
-------------------

Pipeline-first CORS via guard_core.cors_handler (v3.0.0)
--------------------------------------------------------

- **Breaking** — Preflight `OPTIONS` requests are now subject to the security pipeline. Previously the middleware short-circuited preflights ahead of `_execute_security_pipeline` (the `if config.enable_cors and request.method == "OPTIONS"` block at line 227), allowing banned IPs and rate-limited clients to preflight freely.
- **Fixed** — Cross-origin preflight requests to passthrough paths (e.g. `exclude_paths=["/health"]`) now receive a valid CORS response. Preflight handling runs ahead of the passthrough/bypass short-circuit so the browser permission check works for excluded paths.
- **Fixed** — Cross-origin GETs to passthrough/bypass paths now carry CORS headers on their responses.
- **Fixed (latent)** — `middleware.py` was importing `BaseSecurityDecorator` and `RouteConfig` from `guard_core.decorators.base` (the async path) when it should have been using `guard_core.sync.decorators.base`. Sync/async protocol mismatches cascaded from there. Surfaced after removing the `[[tool.mypy.overrides]] follow_imports = "skip"` block.
- **Fixed (latent)** — `cloud_handler.refresh(ttl=...)` was being called with a `ttl` kwarg the method does not accept; correct call is `refresh_async()`.
- **Fixed (latent)** — 4 tests passed `agent_model="..."` to `SecurityConfig`; that field does not exist on the model.
- **Internal** — CORS preflight handling moved to the shared `guard_core.sync.handlers.cors_handler.CorsHandler` module. Removed all six `[[tool.mypy.overrides]]` suppression blocks (`redis.*`, `guard_agent.*`, `guard_core.*`, `django.*`, `examples.*`, `example_app.*`/`advanced_app.*`). Installed `django-stubs` as dev dep; `redis` 7.x, `guard-core` 2.2.0, `guard-agent` 2.2.0 all ship `py.typed`. Stripped `[tool.uv.sources] guard-core` local-path block from committed pyproject.toml. Added `reset_ratelimit_singleton` autouse fixture to `tests/conftest.py` so test runs no longer accumulate rate-limit state across tests.
- **Requires** — `guard-core>=2.2.0` (declared as unconstrained `guard-core` in pyproject; documented here for upgrade guidance).

___

v2.2.0 (2026-04-25)
-------------------

guard-core 2.0.0 compatibility (v2.2.0)
---------------------------------------

- **Compat** — Requires guard-core 2.0.0 or newer. Adapter middleware updated to match the new `suspicious_request_counts: dict[str, dict[str, int]]` protocol shape and `DetectionResult` return type. User code that didn't reach into those internals is unaffected.
- **Changed** — `DjangoAPIGuard.suspicious_request_counts` is now `dict[str, dict[str, int]]` to mirror the per-IP, per-category counters introduced by guard-core 2.0.0.
- **Tests** — `tests/test_middleware.py` mocks for `detect_penetration_patterns` and `detect_penetration_attempt` now return `DetectionResult(is_threat=..., trigger_info=...)` instead of the legacy `(bool, str)` tuple.

___

v2.1.1 (2026-04-25)
-------------------

Integration fixes for OTel + enrichment pipeline (v2.1.1)
---------------------------------------------------------

- **Fixed** — After composite construction, `self.agent_handler` is rebound from the bare `guard-agent` client to the composite. Downstream callers that receive `middleware.agent_handler` (most notably `guard_core.utils.extract_client_ip → send_agent_event`) now route through the composite, so enrichment and OTel see every event.
- **Fixed** — `BehavioralContext` now receives `handler_initializer.behavior_tracker`, matching the guard-core 1.2.1 wiring. This closes the architectural gap so `guard.behavior.recent_event_count` populates end-to-end when `enable_enrichment=True`.
- **Added** — `tests/test_middleware_lifecycle.py` — regression tests pinning the agent_handler rebind and behavior_tracker threading, plus coverage for unbuilt-pipeline and early-decorator-handler paths.
- **Requires** — `guard-core>=1.2.1` for the matching OTLP endpoint normalization and `BehaviorTracker` wiring fixes. Install the latest with `uv add djapi-guard guard-core` or `pip install -U djapi-guard guard-core`.
- **User-visible impact** — Users with `enable_otel=True`, `enable_logfire=True`, or `enable_enrichment=True` previously saw silent drops on a portion of events because callers using `middleware.agent_handler` directly bypassed the composite handler. After this release every downstream caller routes through the composite, so all events flow through telemetry and enrichment as configured.

___

v2.1.0 (2026-04-24)
-------------------

Telemetry pipeline wiring fix (v2.1.0)
--------------------------------------

Adopts guard-core 1.1.0 and fixes a middleware wiring bug that prevented OpenTelemetry, Logfire, and event/metric/check-log muting from seeing anything emitted by the request-path security pipeline.

- **Fixed** — `DjangoAPIGuard.__init__` previously constructed `SecurityEventBus(agent_handler, ...)` and `MetricsCollector(agent_handler, ...)` in `_init_core_components()` using the bare `guard_agent` handler (or `None`). `_initialize_handlers()` then called `HandlerInitializer.initialize_agent_integrations()` which built a `CompositeAgentHandler` that no code path ever reached, because the event bus / metrics collector were already frozen on the bare handler. As a result, every event emitted through the request pipeline (`SecurityEventBus.send_middleware_event`) and every request metric bypassed OTel, Logfire, and the configured `muted_event_types` / `muted_metric_types` filter. This release splits construction into `_init_core_components()` (handler_initializer only), `_init_route_resolver()`, and `_build_event_bus_and_contexts()` — the last of which consults `handler_initializer.composite_handler` and uses `build_event_bus()` / `build_metrics_collector()` when the composite is available. `_initialize_handlers()` now re-invokes `_build_event_bus_and_contexts()` after `initialize_agent_integrations()` so the dependent contexts (`ResponseContext`, `ValidationContext`, `BypassContext`, `BehavioralContext`) bind to the post-init event bus.
- **Added** — `tests/test_middleware_wiring.py` — four regression tests that pin `mw.event_bus.agent_handler` and `mw.metrics_collector.agent_handler` to `CompositeAgentHandler` after instantiation when OTel or Logfire is enabled, and confirm all dependent contexts reference the post-init event bus.
- **Dependencies** — `guard-core>=1.1.0,<2.0.0`.
- **User-visible impact** — Users already setting `enable_otel=True` or `enable_logfire=True` on `SecurityConfig` were previously getting handler-path events only (ip_banned, rate_limited from `ip_ban_manager` / `rate_limit_handler`, etc.) — but never pipeline-path events (`penetration_attempt`, `authentication_failed`, `user_agent_blocked`, `https_enforced`, etc.) or request metrics (`guard.request.duration`, `guard.request.count`, `guard.error.count`). After this release, every event and every metric flows through the composite, which means OTel spans, Logfire logs, and all mute fields (`muted_event_types`, `muted_metric_types`, `muted_check_logs`) work as documented. No `SecurityConfig` changes required; existing configurations produce strictly more telemetry, not less.
- **Tests** — `tests/test_middleware.py` — the two coverage tests that pinned the old `_init_routing_and_validation` guards (`test_init_routing_event_bus_none`, `test_init_routing_response_factory_none`) are replaced with `test_build_event_bus_handler_initializer_none` and `test_build_event_bus_route_resolver_none` covering the new guards in `_build_event_bus_and_contexts`.

___

v2.0.0 (2026-03-26)
-------------------

Major Release (v2.0.0)
------------

- **Guard-Core migration**: DjangoAPI Guard is now a thin adapter over [guard-core](https://github.com/rennf93/guard-core), the framework-agnostic security engine. All security logic (17 checks, 8 handlers, detection engine) lives in guard-core; this package provides only the Django integration layer.
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

- Initial release of DjangoAPI Guard
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
