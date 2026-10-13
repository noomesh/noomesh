# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Companion device sensor tools — camera, location, clipboard, screenshot, audio, battery."""
from __future__ import annotations

from typing import Any, ClassVar, List

from pydantic import Field

from ..tool_models import HttpMethod, ToolDef, register


def _extract_result(data: Any) -> str:
    """Extract the 'result' field from a device API response."""
    if isinstance(data, dict):
        result = data.get("result")
        if result is not None:
            if isinstance(result, str):
                return result
            import json
            return json.dumps(result, default=str, indent=2)
    if isinstance(data, str):
        return data
    import json
    return json.dumps(data, default=str, indent=2)


@register
class PaiDeviceCamera(ToolDef):
    """Capture a photo from a companion device camera. Returns image data
    and optionally an AI-generated description of the scene."""

    name: ClassVar[str] = "noo_device_camera"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/device/camera_capture"
    tags: ClassVar[List[str]] = ["devices", "companion"]

    describe: bool = Field(default=True, description="Whether to generate an AI description of the image")

    def format_response(self, data: Any) -> str:
        return _extract_result(data)


@register
class PaiDeviceLocation(ToolDef):
    """Get current GPS location from a companion device."""

    name: ClassVar[str] = "noo_device_location"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/device/location"
    tags: ClassVar[List[str]] = ["devices", "companion"]

    def format_response(self, data: Any) -> str:
        return _extract_result(data)


@register
class PaiDeviceClipboard(ToolDef):
    """Read current clipboard contents from a companion device."""

    name: ClassVar[str] = "noo_device_clipboard"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/device/clipboard"
    tags: ClassVar[List[str]] = ["devices", "companion"]

    def format_response(self, data: Any) -> str:
        return _extract_result(data)


@register
class PaiDeviceScreenshot(ToolDef):
    """Take a screenshot from a companion device. Returns image data
    and optionally an AI-generated description."""

    name: ClassVar[str] = "noo_device_screenshot"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/device/screenshot"
    tags: ClassVar[List[str]] = ["devices", "companion"]

    describe: bool = Field(default=True, description="Whether to generate an AI description of the screenshot")

    def format_response(self, data: Any) -> str:
        return _extract_result(data)


@register
class PaiDeviceAudio(ToolDef):
    """Record ambient audio from a companion device microphone."""

    name: ClassVar[str] = "noo_device_audio"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/device/ambient_audio"
    tags: ClassVar[List[str]] = ["devices", "companion"]

    duration_seconds: int = Field(default=5, description="Recording duration in seconds")

    def format_response(self, data: Any) -> str:
        return _extract_result(data)


@register
class PaiDeviceBattery(ToolDef):
    """Get battery status from a companion device."""

    name: ClassVar[str] = "noo_device_battery"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/v1/device/battery_status"
    tags: ClassVar[List[str]] = ["devices", "companion"]

    def format_response(self, data: Any) -> str:
        return _extract_result(data)
