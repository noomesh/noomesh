#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Prometheus exporter for NVIDIA GPU metrics using nvidia-ml-py (NVML).

Uses the official NVIDIA Management Library (NVML) Python bindings -
the same library that PyTorch, TensorFlow, etc. use to detect GPUs.
"""

import http.server
import os
import socketserver
import ssl
from typing import List, Dict, Optional

# nvidia-ml-py is the official NVIDIA Python library (pynvml module)
# pip install nvidia-ml-py
try:
    import pynvml
    NVML_AVAILABLE = True
except ImportError:
    NVML_AVAILABLE = False
    print("WARNING: pynvml not available, metrics will be empty")

PORT = 9400


def init_nvml() -> bool:
    """Initialize NVML library."""
    if not NVML_AVAILABLE:
        return False
    try:
        pynvml.nvmlInit()
        return True
    except Exception as e:
        print(f"Failed to initialize NVML: {e}")
        return False


def get_gpu_metrics() -> List[Dict]:
    """Query GPU metrics using NVML (same as PyTorch uses)."""
    if not NVML_AVAILABLE:
        return []

    try:
        device_count = pynvml.nvmlDeviceGetCount()
        gpus = []

        for i in range(device_count):
            handle = pynvml.nvmlDeviceGetHandleByIndex(i)

            # Get GPU name
            name = pynvml.nvmlDeviceGetName(handle)
            if isinstance(name, bytes):
                name = name.decode('utf-8')
            name = name.replace(" ", "_")

            # Temperature
            try:
                temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
            except:
                temp = 0

            # Power
            try:
                power_mw = pynvml.nvmlDeviceGetPowerUsage(handle)  # milliwatts
                power_watts = power_mw / 1000.0
            except:
                power_watts = 0

            try:
                power_limit_mw = pynvml.nvmlDeviceGetPowerManagementLimit(handle)
                power_limit_watts = power_limit_mw / 1000.0
            except:
                power_limit_watts = 0

            # Memory
            try:
                mem_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
                mem_used = mem_info.used
                mem_total = mem_info.total
            except:
                mem_used = 0
                mem_total = 0

            # Utilization
            try:
                util = pynvml.nvmlDeviceGetUtilizationRates(handle)
                gpu_util = util.gpu / 100.0  # Convert to ratio
                mem_util = util.memory / 100.0
            except:
                gpu_util = 0
                mem_util = 0

            # Fan speed (may not be available on laptops)
            try:
                fan_speed = pynvml.nvmlDeviceGetFanSpeed(handle)
            except:
                fan_speed = 0

            gpus.append({
                "index": str(i),
                "name": name,
                "temperature_celsius": float(temp),
                "power_draw_watts": float(power_watts),
                "power_limit_watts": float(power_limit_watts),
                "memory_used_bytes": float(mem_used),
                "memory_total_bytes": float(mem_total),
                "utilization_gpu_ratio": float(gpu_util),
                "utilization_memory_ratio": float(mem_util),
                "fan_speed_percent": float(fan_speed),
            })

        return gpus

    except Exception as e:
        print(f"Error querying NVML: {e}")
        return []


def format_prometheus_metrics(gpus: List[Dict]) -> str:
    """Format GPU metrics as Prometheus exposition format."""
    lines = []

    if not gpus:
        lines.append("# No GPUs detected or NVML unavailable")
        lines.append("nvidia_gpu_exporter_up 0")
        return "\n".join(lines)

    lines.append("nvidia_gpu_exporter_up 1")

    # Temperature
    lines.append("# HELP nvidia_gpu_temperature_celsius GPU temperature in Celsius")
    lines.append("# TYPE nvidia_gpu_temperature_celsius gauge")
    for gpu in gpus:
        lines.append(f'nvidia_gpu_temperature_celsius{{gpu_index="{gpu["index"]}",gpu_name="{gpu["name"]}"}} {gpu["temperature_celsius"]}')

    # Power draw
    lines.append("# HELP nvidia_gpu_power_draw_watts GPU power draw in watts")
    lines.append("# TYPE nvidia_gpu_power_draw_watts gauge")
    for gpu in gpus:
        lines.append(f'nvidia_gpu_power_draw_watts{{gpu_index="{gpu["index"]}",gpu_name="{gpu["name"]}"}} {gpu["power_draw_watts"]}')

    # Power limit
    lines.append("# HELP nvidia_gpu_power_limit_watts GPU power limit in watts")
    lines.append("# TYPE nvidia_gpu_power_limit_watts gauge")
    for gpu in gpus:
        lines.append(f'nvidia_gpu_power_limit_watts{{gpu_index="{gpu["index"]}",gpu_name="{gpu["name"]}"}} {gpu["power_limit_watts"]}')

    # Memory used
    lines.append("# HELP nvidia_gpu_memory_used_bytes GPU memory used in bytes")
    lines.append("# TYPE nvidia_gpu_memory_used_bytes gauge")
    for gpu in gpus:
        lines.append(f'nvidia_gpu_memory_used_bytes{{gpu_index="{gpu["index"]}",gpu_name="{gpu["name"]}"}} {gpu["memory_used_bytes"]}')

    # Memory total
    lines.append("# HELP nvidia_gpu_memory_total_bytes GPU memory total in bytes")
    lines.append("# TYPE nvidia_gpu_memory_total_bytes gauge")
    for gpu in gpus:
        lines.append(f'nvidia_gpu_memory_total_bytes{{gpu_index="{gpu["index"]}",gpu_name="{gpu["name"]}"}} {gpu["memory_total_bytes"]}')

    # GPU utilization
    lines.append("# HELP nvidia_gpu_utilization_gpu_ratio GPU utilization ratio (0-1)")
    lines.append("# TYPE nvidia_gpu_utilization_gpu_ratio gauge")
    for gpu in gpus:
        lines.append(f'nvidia_gpu_utilization_gpu_ratio{{gpu_index="{gpu["index"]}",gpu_name="{gpu["name"]}"}} {gpu["utilization_gpu_ratio"]}')

    # Memory utilization
    lines.append("# HELP nvidia_gpu_utilization_memory_ratio GPU memory utilization ratio (0-1)")
    lines.append("# TYPE nvidia_gpu_utilization_memory_ratio gauge")
    for gpu in gpus:
        lines.append(f'nvidia_gpu_utilization_memory_ratio{{gpu_index="{gpu["index"]}",gpu_name="{gpu["name"]}"}} {gpu["utilization_memory_ratio"]}')

    # Fan speed
    lines.append("# HELP nvidia_gpu_fan_speed_percent GPU fan speed percentage")
    lines.append("# TYPE nvidia_gpu_fan_speed_percent gauge")
    for gpu in gpus:
        lines.append(f'nvidia_gpu_fan_speed_percent{{gpu_index="{gpu["index"]}",gpu_name="{gpu["name"]}"}} {gpu["fan_speed_percent"]}')

    return "\n".join(lines)


class MetricsHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            gpus = get_gpu_metrics()
            content = format_prometheus_metrics(gpus)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(content.encode())
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress request logging


def _create_ssl_context() -> ssl.SSLContext:
    """The exporter's TLS: its service leaf, and a client cert REQUIRED.

    Fails loud. It used to return None when the files were missing and then
    serve GPU metrics over plain HTTP to anyone who could reach the port —
    and the compose file only set the paths when the host happened to export
    NOO_TLS_*, so plain HTTP was the common case, silently.
    """
    cert_file = os.getenv("NOO_TLS_CERT", "")
    key_file = os.getenv("NOO_TLS_KEY", "")
    ca_file = os.getenv("NOO_TLS_CA", "")
    missing = [name for name, path in (("NOO_TLS_CERT", cert_file), ("NOO_TLS_KEY", key_file), ("NOO_TLS_CA", ca_file))
               if not (path and os.path.isfile(path))]
    if missing:
        raise SystemExit(
            f"nvidia-exporter: refusing to serve metrics without TLS — missing {', '.join(missing)}. "
            "Issue the leaf with `noo security pki issue-service nvidia-exporter`."
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    ctx.load_verify_locations(cafile=ca_file)
    ctx.verify_mode = ssl.CERT_REQUIRED  # mTLS: the scraper's leaf
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


if __name__ == "__main__":
    if init_nvml():
        print(f"NVML initialized - {pynvml.nvmlDeviceGetCount()} GPU(s) found")
    else:
        print("NVML not available - running in degraded mode")

    ssl_ctx = _create_ssl_context()
    print(f"Starting nvidia-smi exporter on port {PORT} (HTTPS, client certificate required)")
    with socketserver.TCPServer(("", PORT), MetricsHandler) as httpd:
        httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
        httpd.serve_forever()
