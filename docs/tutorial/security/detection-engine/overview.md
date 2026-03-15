# Detection Engine

The DjangoAPI Guard Detection Engine is an enhanced pattern-based threat detection system that provides protection against common web application attacks through timeout-protected pattern matching and optional heuristic analysis.

## Overview

The Detection Engine introduces:

- **Timeout Protection**: Prevents ReDoS attacks through configurable execution timeouts
- **Content Preprocessing**: Truncates content while preserving potential attack patterns
- **Optional Semantic Analysis**: Heuristic-based detection for obfuscated attacks
- **Performance Tracking**: Monitors pattern execution times to identify slow patterns
- **Context-Aware Filtering**: Patterns only evaluated against relevant input sources
- **Singleton Architecture**: Centralized pattern management with lazy initialization

## Basic Usage

```python
# settings.py
from djangoapi_guard import SecurityConfig

GUARD_SECURITY_CONFIG = SecurityConfig(
    enable_penetration_detection=True,
    detection_compiler_timeout=2.0,
    detection_max_content_length=10000,
    detection_preserve_attack_patterns=True,
    detection_semantic_threshold=0.7,
    detection_slow_pattern_threshold=0.1,
    detection_monitor_history_size=1000,
)
```

## Configuration Reference

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enable_penetration_detection` | bool | `True` | Enable/disable detection engine |
| `detection_compiler_timeout` | float | `2.0` | Maximum seconds for pattern execution |
| `detection_max_content_length` | int | `10000` | Maximum characters to analyze |
| `detection_preserve_attack_patterns` | bool | `True` | Preserve potential attacks during truncation |
| `detection_semantic_threshold` | float | `0.7` | Threshold for semantic detection |
| `detection_anomaly_threshold` | float | `3.0` | Standard deviations for performance anomaly |
| `detection_slow_pattern_threshold` | float | `0.1` | Seconds to consider pattern slow |
| `detection_monitor_history_size` | int | `1000` | Number of metrics to keep |
| `detection_max_tracked_patterns` | int | `1000` | Maximum patterns to track |

## Next Steps

- Review [Detection Engine Components](components.md)
- See [Configuration Guide](configuration.md)
- Check [Performance Tuning](performance-tuning.md)
