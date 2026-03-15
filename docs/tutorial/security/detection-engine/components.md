# Detection Engine Components

## Component Overview

1. **ContentPreprocessor** - Truncates content while preserving attack patterns (`djangoapi_guard/detection_engine/preprocessor.py`)
2. **PatternCompiler** - Provides timeout-protected pattern matching (`djangoapi_guard/detection_engine/compiler.py`)
3. **SemanticAnalyzer** - Heuristic-based attack detection (`djangoapi_guard/detection_engine/semantic.py`)
4. **PerformanceMonitor** - Tracks execution metrics (`djangoapi_guard/detection_engine/monitor.py`)

## ContentPreprocessor

Intelligently truncates content to prevent excessive memory usage while preserving potential attack patterns. Looks for SQL keywords, script tags, path traversal patterns, and command injection indicators.

## PatternCompiler

Provides safe pattern compilation and execution with timeout protection against ReDoS attacks. Uses thread-based execution with configurable timeout.

## SemanticAnalyzer

Provides heuristic-based detection of obfuscated attacks including SQL Injection, XSS, Path Traversal, and Command Injection with scoring system.

## PerformanceMonitor

Tracks pattern execution performance with fixed-size deques, automatic cleanup of old metrics, and anomaly detection using statistical analysis.

## Configuration Impact

| Component | Required Configuration | Impact When Disabled |
|-----------|----------------------|---------------------|
| ContentPreprocessor | `detection_max_content_length > 0` | No content truncation |
| PatternCompiler | `detection_compiler_timeout > 0` | No timeout protection |
| SemanticAnalyzer | `detection_semantic_threshold > 0` | No heuristic detection |
| PerformanceMonitor | Always created | N/A |

## Next Steps

- Learn about [Configuration Options](configuration.md)
- Review [Performance Tuning](performance-tuning.md)
- See [Architecture Overview](architecture.md)
