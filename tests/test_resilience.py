# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Test resilience features."""
import pytest
from noomesh.resilience import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitState,
    ToolExecutionResult,
)


def test_circuit_breaker_normal_operation():
    """Test circuit breaker in normal operation."""
    breaker = CircuitBreaker()

    # Successful calls
    result = breaker.call(lambda: "success")
    assert result == "success"
    assert breaker.state == CircuitState.CLOSED


def test_circuit_breaker_opens_on_failures():
    """Test circuit breaker opens after enough failures in the rolling window.

    Default config: failure_threshold=5, window_size=10.
    The breaker only checks the threshold once the window has at least
    window_size entries, so we need >= 10 calls with >= 5 failures.
    """
    breaker = CircuitBreaker(
        config=CircuitBreakerConfig(failure_threshold=3, window_size=5, timeout=60.0)
    )

    # Cause failures to fill the window
    for _ in range(5):
        try:
            breaker.call(lambda: (_ for _ in ()).throw(Exception("fail")))
        except CircuitBreakerOpenError:
            break
        except Exception:
            pass

    # Circuit should be open now
    assert breaker.is_open

    # Further calls should be rejected
    with pytest.raises(CircuitBreakerOpenError):
        breaker.call(lambda: "should fail")


def test_tool_execution_result():
    """Test tool execution result."""
    # Success
    result = ToolExecutionResult.from_success("result", 100.0)
    assert result.success
    assert result.result == "result"
    assert result.get_output() == "result"

    # Error
    result = ToolExecutionResult.from_error("error message", 50.0)
    assert not result.success
    assert result.error == "error message"
    assert "Error:" in result.get_output()

    # Fallback
    result = ToolExecutionResult.from_fallback("fallback result", 75.0)
    assert result.success
    assert result.fallback_used
    assert "[FALLBACK]" in result.get_output()
