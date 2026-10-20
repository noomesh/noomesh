# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""OpenAI-compatible LLM client for vLLM / llama.cpp backends.

Speaks the ``/v1/chat/completions`` API so it works with any OpenAI-
compatible inference server.  Implements the same :class:`LLMClient`
protocol as :class:`OllamaClient`.

This is the PRIMARY extension point for new inference backends: register a
:class:`~noomesh.backends.BackendProfile` with ``api_format="openai"`` and
``factory.build_llm_client`` will hand back this client — no new client
class needed.
"""
from __future__ import annotations

from .. import json_fast as json
from typing import Any, Dict, Generator, List, Optional

import httpx

# NOTE: TLS context resolved via provider rather
# than direct gateway.deps import. Module-level shims preserve the
# existing call-site syntax (`verify=ssl_verify()`); when HARNESS becomes
# its own repo it can swap the provider via a startup hook.
from noomesh._providers import default_http_context
def ssl_verify():
    return default_http_context().verify
def client_cert():
    return default_http_context().cert


class OpenAICompatError(Exception):
    """Raised when communication with an OpenAI-compatible server fails."""


def _friendly_error(exc: Exception, base_url: str, model: str) -> OpenAICompatError:
    if isinstance(exc, httpx.ConnectError):
        return OpenAICompatError(
            f"Cannot connect to inference server at {base_url}. "
            "Is the backend running?"
        )
    if isinstance(exc, httpx.TimeoutException):
        return OpenAICompatError(
            f"Request to inference server timed out ({base_url}). "
            "The model may be loading or the server is under heavy load."
        )
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status == 404:
            return OpenAICompatError(
                f"Model '{model}' not found on server at {base_url}."
            )
        return OpenAICompatError(
            f"Inference server returned HTTP {status} ({base_url}). "
            f"Details: {exc.response.text[:200]}"
        )
    return OpenAICompatError(f"Inference error: {exc}")


class OpenAICompatClient:
    """LLMClient that talks to ``/v1/chat/completions`` (vLLM, llama.cpp, etc.)."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        model: str = "default",
        options: Optional[Dict[str, Any]] = None,
        timeout: float = 120.0,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.options = options or {}
        # `headers`: the gateway's key when base_url is the gateway (a backend
        # ignores it).
        self.http = httpx.Client(timeout=timeout, verify=ssl_verify(), cert=client_cert(), headers=headers)

    def _url(self) -> str:
        return f"{self.base_url}/v1/chat/completions"

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        response_format: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        # Map Ollama-style options to OpenAI params
        if "temperature" in self.options:
            payload["temperature"] = self.options["temperature"]
        if "top_p" in self.options:
            payload["top_p"] = self.options["top_p"]
        if "num_predict" in self.options:
            payload["max_tokens"] = self.options["num_predict"]

        if tools:
            # Convert Ollama tool format to OpenAI format if needed
            payload["tools"] = [self._normalize_tool(t) for t in tools]
        if response_format:
            payload["response_format"] = {"type": response_format}

        try:
            response = self.http.post(self._url(), json=payload)
            response.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as exc:
            raise _friendly_error(exc, self.base_url, self.model) from exc

        data = response.json()
        # Translate OpenAI response to Ollama-compatible format
        return self._to_ollama_format(data)

    def chat_stream(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        response_format: Optional[str] = None,
    ) -> Generator[Dict[str, Any], None, None]:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": True,
        }
        if "temperature" in self.options:
            payload["temperature"] = self.options["temperature"]
        if "top_p" in self.options:
            payload["top_p"] = self.options["top_p"]
        if tools:
            payload["tools"] = [self._normalize_tool(t) for t in tools]
        if response_format:
            payload["response_format"] = {"type": response_format}

        try:
            with self.http.stream("POST", self._url(), json=payload) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if not line or line.strip() == "data: [DONE]":
                        continue
                    text = line
                    if text.startswith("data:"):
                        text = text[5:].strip()
                    if not text:
                        continue
                    try:
                        chunk = json.loads(text)
                    except json.JSONDecodeError:
                        continue
                    # Translate streaming chunk to Ollama format
                    delta = (chunk.get("choices") or [{}])[0].get("delta", {})
                    yield {
                        "message": {"content": delta.get("content", "")},
                        "done": chunk.get("choices", [{}])[0].get("finish_reason") is not None,
                    }
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as exc:
            raise _friendly_error(exc, self.base_url, self.model) from exc

    def embed(self, text: str, model: Optional[str] = None) -> List[float]:
        model_name = model or self.model
        payload = {"model": model_name, "input": text}
        url = f"{self.base_url}/v1/embeddings"
        try:
            response = self.http.post(url, json=payload)
            response.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as exc:
            raise _friendly_error(exc, self.base_url, self.model) from exc
        data = response.json()
        embeddings = data.get("data", [])
        if embeddings:
            return embeddings[0].get("embedding", [])
        raise RuntimeError("Unexpected embedding response format.")

    @staticmethod
    def _normalize_tool(tool: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure tool is in OpenAI function-calling format."""
        if "type" in tool and tool["type"] == "function":
            return tool  # Already OpenAI format
        # Ollama format: {"function": {"name": ..., "description": ..., "parameters": ...}}
        fn = tool.get("function", tool)
        return {
            "type": "function",
            "function": {
                "name": fn.get("name", ""),
                "description": fn.get("description", ""),
                "parameters": fn.get("parameters", {}),
            },
        }

    @staticmethod
    def _to_ollama_format(data: Dict[str, Any]) -> Dict[str, Any]:
        """Translate OpenAI chat completion response to Ollama-compatible format."""
        choices = data.get("choices", [])
        if not choices:
            return {"message": {"content": "", "role": "assistant"}}

        choice = choices[0]
        msg = choice.get("message", {})

        result: Dict[str, Any] = {
            "message": {
                "role": msg.get("role", "assistant"),
                "content": msg.get("content", "") or "",
            },
        }

        # Translate tool_calls if present
        tool_calls = msg.get("tool_calls")
        if tool_calls:
            result["message"]["tool_calls"] = [
                {
                    "function": {
                        "name": tc["function"]["name"],
                        "arguments": tc["function"].get("arguments", "{}"),
                    }
                }
                for tc in tool_calls
            ]

        return result
