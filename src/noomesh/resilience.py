# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Resilience patterns: retry logic, circuit breakers, graceful degradation"""
from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)
import logging

import httpx
import structlog


logger = structlog.get_logger(__name__)


# Retry decorator for LLM calls
def retry_llm_call(max_attempts: int = 3, min_wait: float = 2.0, max_wait: float = 10.0):
    """
    Retry decorator for LLM API calls with exponential backoff

    Args:
        max_attempts: Maximum number of retry attempts
        min_wait: Minimum wait time between retries (seconds)
        max_wait: Maximum wait time between retries (seconds)

    Returns:
        Decorated function with retry logic
    """
    return retry(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=1, min=min_wait, max=max_wait),
        retry=retry_if_exception_type((ConnectionError, TimeoutError, httpx.HTTPError)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )


# Retry decorator for tool execution
def retry_tool_execution(max_attempts: int = 2, min_wait: float = 1.0, max_wait: float = 5.0):
    """
    Retry decorator for tool execution with backoff

    Args:
        max_attempts: Maximum number of retry attempts
        min_wait: Minimum wait time between retries (seconds)
        max_wait: Maximum wait time between retries (seconds)

    Returns:
        Decorated function with retry logic
    """
    return retry(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=1, min=min_wait, max=max_wait),
        retry=retry_if_exception_type((ConnectionError, TimeoutError, httpx.HTTPError, OSError)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failures exceeded threshold, rejecting calls
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    failure_threshold: int = 5      # Failures before opening circuit
    success_threshold: int = 2      # Successes to close from half-open
    timeout: float = 60.0          # Seconds before trying half-open
    window_size: int = 10          # Rolling window for failure tracking


class CircuitBreaker:
    """
    Circuit breaker pattern to prevent cascading failures

    When a tool/service fails repeatedly, the circuit "opens" and rejects
    further calls for a timeout period. After timeout, it enters "half-open"
    state to test if the service recovered.
    """

    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        """
        Initialize circuit breaker

        Args:
            config: Circuit breaker configuration
        """
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[float] = None
        self.recent_calls: list[bool] = []  # True = success, False = failure

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function through circuit breaker

        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            CircuitBreakerOpenError: If circuit is open
            Exception: Any exception from the function
        """
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitState.HALF_OPEN
                logger.info("Circuit breaker entering HALF_OPEN state")
            else:
                raise CircuitBreakerOpenError(
                    f"Circuit breaker is OPEN. Last failure: {self.last_failure_time}"
                )

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise e

    def _on_success(self) -> None:
        """Handle successful call"""
        self.recent_calls.append(True)
        self._trim_window()

        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self._close_circuit()
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0

    def _on_failure(self) -> None:
        """Handle failed call"""
        self.recent_calls.append(False)
        self._trim_window()

        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.state == CircuitState.HALF_OPEN:
            self._open_circuit()
        elif self.state == CircuitState.CLOSED:
            if self._failure_threshold_exceeded():
                self._open_circuit()

    def _failure_threshold_exceeded(self) -> bool:
        """Check if failure threshold exceeded in recent window"""
        if len(self.recent_calls) < self.config.window_size:
            return False

        recent_failures = sum(1 for success in self.recent_calls if not success)
        return recent_failures >= self.config.failure_threshold

    def _should_attempt_reset(self) -> bool:
        """Check if enough time passed to attempt reset"""
        if self.last_failure_time is None:
            return True

        elapsed = time.time() - self.last_failure_time
        return elapsed >= self.config.timeout

    def _open_circuit(self) -> None:
        """Open the circuit"""
        self.state = CircuitState.OPEN
        self.success_count = 0
        logger.warning(
            f"Circuit breaker OPENED after {self.failure_count} failures"
        )

    def _close_circuit(self) -> None:
        """Close the circuit"""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        logger.info("Circuit breaker CLOSED - service recovered")

    def _trim_window(self) -> None:
        """Trim recent calls to window size"""
        if len(self.recent_calls) > self.config.window_size:
            self.recent_calls = self.recent_calls[-self.config.window_size:]

    @property
    def is_open(self) -> bool:
        """Check if circuit is open"""
        return self.state == CircuitState.OPEN

    def reset(self) -> None:
        """Manually reset circuit breaker"""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.recent_calls = []
        logger.info("Circuit breaker manually reset")


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open"""
    pass


class CircuitBreakerRegistry:
    """
    Registry for managing multiple circuit breakers (one per tool/service)
    """

    def __init__(self, default_config: Optional[CircuitBreakerConfig] = None):
        """
        Initialize registry

        Args:
            default_config: Default configuration for new circuit breakers
        """
        self.default_config = default_config or CircuitBreakerConfig()
        self.breakers: dict[str, CircuitBreaker] = {}

    def get(self, name: str) -> CircuitBreaker:
        """
        Get or create circuit breaker for a service

        Args:
            name: Service/tool name

        Returns:
            Circuit breaker instance
        """
        if name not in self.breakers:
            self.breakers[name] = CircuitBreaker(self.default_config)
        return self.breakers[name]

    def call(self, name: str, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function through named circuit breaker

        Args:
            name: Service/tool name
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result
        """
        breaker = self.get(name)
        return breaker.call(func, *args, **kwargs)

    def get_status(self) -> dict[str, dict]:
        """
        Get status of all circuit breakers

        Returns:
            Dictionary of circuit breaker states
        """
        return {
            name: {
                "state": breaker.state.value,
                "failure_count": breaker.failure_count,
                "success_count": breaker.success_count,
                "is_open": breaker.is_open,
            }
            for name, breaker in self.breakers.items()
        }

    def reset_all(self) -> None:
        """Reset all circuit breakers"""
        for breaker in self.breakers.values():
            breaker.reset()


@dataclass
class ToolExecutionResult:
    """Result of tool execution with graceful degradation support"""
    success: bool
    result: Optional[str] = None
    error: Optional[str] = None
    fallback_used: bool = False
    duration_ms: Optional[float] = None

    @classmethod
    def from_success(cls, result: str, duration_ms: float = 0.0) -> ToolExecutionResult:
        """Create successful result"""
        return cls(success=True, result=result, duration_ms=duration_ms)

    @classmethod
    def from_error(cls, error: str, duration_ms: float = 0.0) -> ToolExecutionResult:
        """Create error result"""
        return cls(success=False, error=error, duration_ms=duration_ms)

    @classmethod
    def from_fallback(cls, result: str, duration_ms: float = 0.0) -> ToolExecutionResult:
        """Create fallback result"""
        return cls(
            success=True,
            result=result,
            fallback_used=True,
            duration_ms=duration_ms
        )

    def get_output(self) -> str:
        """Get output string for LLM"""
        if self.success:
            prefix = "[FALLBACK] " if self.fallback_used else ""
            return f"{prefix}{self.result}"
        else:
            return f"Error: {self.error}"


def execute_with_fallback(
    primary: Callable,
    fallback: Optional[Callable] = None,
    fallback_message: str = "Primary execution failed, using fallback"
) -> ToolExecutionResult:
    """
    Execute function with fallback on failure

    Args:
        primary: Primary function to execute
        fallback: Fallback function if primary fails
        fallback_message: Message to include with fallback result

    Returns:
        Tool execution result
    """
    start_time = time.time()

    try:
        result = primary()
        duration_ms = (time.time() - start_time) * 1000
        return ToolExecutionResult.from_success(result, duration_ms)
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000

        if fallback:
            try:
                result = fallback()
                return ToolExecutionResult.from_fallback(
                    f"{fallback_message}: {result}",
                    duration_ms
                )
            except Exception as fallback_error:
                return ToolExecutionResult.from_error(
                    f"Primary failed: {e}. Fallback also failed: {fallback_error}",
                    duration_ms
                )
        else:
            return ToolExecutionResult.from_error(str(e), duration_ms)
