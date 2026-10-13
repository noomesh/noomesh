# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

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


class OllamaError(Exception):
    """Raised when communication with the Ollama server fails."""


def _friendly_error(exc: Exception, base_url: str, model: str) -> OllamaError:
    if isinstance(exc, httpx.ConnectError):
        return OllamaError(
            f"Cannot connect to Ollama at {base_url}. "
            "Is the Ollama server running? Start it with: ollama serve"
        )
    if isinstance(exc, httpx.TimeoutException):
        return OllamaError(
            f"Request to Ollama timed out ({base_url}). "
            "The model may be loading or the server is under heavy load."
        )
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status == 404:
            return OllamaError(
                f"Model '{model}' not found on Ollama at {base_url}. "
                f"Pull it first with: ollama pull {model}"
            )
        return OllamaError(
            f"Ollama returned HTTP {status} ({base_url}). "
            f"Details: {exc.response.text[:200]}"
        )
    return OllamaError(f"Ollama error: {exc}")


def _endpoint(base_url: str, path: str) -> str:
    base = base_url.rstrip("/")
    if base.endswith("/api"):
        return f"{base}/{path.lstrip('/')}"
    return f"{base}/api/{path.lstrip('/')}"


class OllamaClient:
    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "gpt-oss:20b",
        options: Optional[Dict[str, Any]] = None,
        timeout: float = 120.0,
    ) -> None:
        self.base_url = base_url
        self.model = model
        self.options = options or {}
        self.http = httpx.Client(timeout=timeout, verify=ssl_verify(), cert=client_cert())

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
        if self.options:
            payload["options"] = self.options
        if tools:
            payload["tools"] = tools
        if response_format:
            payload["format"] = response_format

        url = _endpoint(self.base_url, "chat")
        try:
            response = self.http.post(url, json=payload)
            response.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as exc:
            raise _friendly_error(exc, self.base_url, self.model) from exc
        return response.json()

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
        if self.options:
            payload["options"] = self.options
        if tools:
            payload["tools"] = tools
        if response_format:
            payload["format"] = response_format

        url = _endpoint(self.base_url, "chat")
        try:
            with self.http.stream("POST", url, json=payload) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if not line:
                        continue
                    chunk = _parse_stream_chunk(line)
                    if chunk is None:
                        continue
                    yield chunk
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as exc:
            raise _friendly_error(exc, self.base_url, self.model) from exc

    def embed(self, text: str, model: Optional[str] = None) -> List[float]:
        model_name = model or self.model
        embed_payload = {"model": model_name, "input": text}
        url = _endpoint(self.base_url, "embed")
        response = self.http.post(url, json=embed_payload)
        if response.status_code != 404:
            response.raise_for_status()
            return _extract_embedding(response.json())

        legacy_payload = {"model": model_name, "prompt": text}
        legacy_url = _endpoint(self.base_url, "embeddings")
        legacy_response = self.http.post(legacy_url, json=legacy_payload)
        legacy_response.raise_for_status()
        return _extract_embedding(legacy_response.json())


def _parse_stream_chunk(line: str | bytes) -> Optional[Dict[str, Any]]:
    if isinstance(line, bytes):
        text = line.decode("utf-8", errors="ignore").strip()
    else:
        text = line.strip()
    if not text:
        return None
    if text.startswith("data:"):
        text = text[5:].strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _extract_embedding(data: Dict[str, Any]) -> List[float]:
    if "embedding" in data and isinstance(data["embedding"], list):
        return data["embedding"]
    if "embeddings" in data and isinstance(data["embeddings"], list):
        if data["embeddings"] and isinstance(data["embeddings"][0], list):
            return data["embeddings"][0]
    raise RuntimeError("Unexpected embedding response format.")
