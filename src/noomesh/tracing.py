# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Distributed tracing via OpenTelemetry.

Provides a ``@trace_span`` decorator and FastAPI middleware.
Everything is a no-op when:
  - The ``monitoring`` extra is not installed (opentelemetry not available)
  - ``OTEL_EXPORTER_OTLP_ENDPOINT`` is not set

Zero overhead in default deployment.
"""
from __future__ import annotations

import asyncio
import os
from functools import wraps
from typing import Optional

import structlog

logger = structlog.get_logger()

# Safe import — tracing is optional (monitoring extra)
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False

_tracer = None
_initialized = False


def init_tracing(service_name: str = "noo-gateway") -> bool:
    """Initialize OpenTelemetry tracing.

    Returns True if tracing was initialized, False if skipped (deps missing
    or no endpoint configured).
    """
    global _tracer, _initialized

    if _initialized:
        return _tracer is not None

    _initialized = True

    if not OTEL_AVAILABLE:
        logger.info("tracing_skipped", reason="opentelemetry not installed")
        return False

    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        logger.info("tracing_skipped", reason="OTEL_EXPORTER_OTLP_ENDPOINT not set")
        return False

    try:
        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        # Use TLS for OTel export when cluster TLS is configured
        _otel_insecure = os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "").lower()
        if _otel_insecure:
            insecure = _otel_insecure in ("1", "true", "yes")
        else:
            # Default: insecure only when no TLS CA is configured
            insecure = not os.getenv("NOO_TLS_CA", "")
        exporter = OTLPSpanExporter(endpoint=endpoint, insecure=insecure)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(service_name)
        logger.info("tracing_initialized", endpoint=endpoint, service=service_name)
        return True
    except Exception as e:
        logger.warning("tracing_init_failed", error=str(e))
        return False


def get_tracer():
    """Get the OTel tracer (None if tracing not initialized)."""
    return _tracer


def current_trace_id() -> Optional[str]:
    """Get current trace ID as a hex string, or None."""
    if not OTEL_AVAILABLE or _tracer is None:
        return None
    try:
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx and ctx.trace_id:
            return format(ctx.trace_id, '032x')
    except Exception:
        pass
    return None


def current_span_id() -> Optional[str]:
    """Get current span ID as a hex string, or None."""
    if not OTEL_AVAILABLE or _tracer is None:
        return None
    try:
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx and ctx.span_id:
            return format(ctx.span_id, '016x')
    except Exception:
        pass
    return None


def trace_span(name: str = None):
    """Decorator that creates an OTel span around a function.

    No-op if tracing not initialized. Works with both sync and async functions.
    """
    def decorator(func):
        span_name = name or f"{func.__module__}.{func.__qualname__}"

        if asyncio.iscoroutinefunction(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                if _tracer is None:
                    return await func(*args, **kwargs)
                with _tracer.start_as_current_span(span_name) as span:
                    try:
                        result = await func(*args, **kwargs)
                        return result
                    except Exception as e:
                        span.set_attribute("error", True)
                        span.set_attribute("error.message", str(e))
                        raise
            return async_wrapper
        else:
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                if _tracer is None:
                    return func(*args, **kwargs)
                with _tracer.start_as_current_span(span_name) as span:
                    try:
                        result = func(*args, **kwargs)
                        return result
                    except Exception as e:
                        span.set_attribute("error", True)
                        span.set_attribute("error.message", str(e))
                        raise
            return sync_wrapper
    return decorator


async def tracing_middleware(request, call_next):
    """FastAPI middleware that creates a root span per request.

    Adds trace_id as response header and injects into structlog context.
    No-op if tracing not initialized.
    """
    if _tracer is None:
        return await call_next(request)

    span_name = f"{request.method} {request.url.path}"
    with _tracer.start_as_current_span(span_name) as span:
        # Set request attributes
        span.set_attribute("http.method", request.method)
        span.set_attribute("http.url", str(request.url))
        span.set_attribute("http.route", request.url.path)

        # Inject trace_id into structlog context
        trace_id = current_trace_id()
        if trace_id:
            structlog.contextvars.bind_contextvars(trace_id=trace_id)

        response = await call_next(request)

        # Set response attributes
        span.set_attribute("http.status_code", response.status_code)

        # Add trace ID to response header
        if trace_id:
            response.headers["X-Trace-ID"] = trace_id

        # Clear structlog context
        structlog.contextvars.unbind_contextvars("trace_id")

        return response


def shutdown_tracing():
    """Flush and shut down the tracer provider."""
    if not OTEL_AVAILABLE or _tracer is None:
        return
    try:
        provider = trace.get_tracer_provider()
        if hasattr(provider, 'shutdown'):
            provider.shutdown()
        logger.info("tracing_shutdown")
    except Exception as e:
        logger.warning("tracing_shutdown_failed", error=str(e))
