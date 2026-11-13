# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""nvidia-exporter is a Prometheus target exactly while it serves.

Prometheus used to scrape a static `nvidia-exporter:9400`. On a CPU-only
controller the launchers never start the exporter, Docker's DNS has no
container to answer for, and the name went to the host's own resolver every
15 s (rehearsal 0.6.24-rc.3, idle window). The exporter now announces itself
by file_sd (monitoring/prometheus.yml, job nvidia_gpu): it writes
nvidia-exporter.json into NOO_PROM_SD_DIR once it serves and removes it on
SIGTERM. These run the real script, as PID-1-like a child as a test can.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "docker/nvidia-smi-exporter.py"


@pytest.fixture()
def tls(tmp_path: Path) -> dict[str, str]:
    assert shutil.which("openssl"), "openssl is needed to mint the exporter's test leaf"
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=nvidia-exporter", "-keyout", str(key), "-out", str(crt)],
        check=True, capture_output=True, timeout=60,
    )
    return {"NOO_TLS_CERT": str(crt), "NOO_TLS_KEY": str(key), "NOO_TLS_CA": str(crt)}


def _script_on_an_ephemeral_port(tmp_path: Path) -> Path:
    # The real script, with only its port changed: 9400 may be taken by a
    # real exporter on the machine running the tests.
    text = SCRIPT.read_text()
    assert text.count("\nPORT = 9400\n") == 1, "the exporter's PORT line moved: update this test"
    p = tmp_path / "exporter.py"
    p.write_text(text.replace("\nPORT = 9400\n", "\nPORT = 0\n"))
    return p


def _start(tmp_path: Path, tls: dict[str, str], sd_dir: Path | None) -> subprocess.Popen:
    env = {k: v for k, v in os.environ.items() if not k.startswith("NOO_")}
    env.update(tls)
    env["PYTHONUNBUFFERED"] = "1"
    if sd_dir is not None:
        env["NOO_PROM_SD_DIR"] = str(sd_dir)
    return subprocess.Popen(
        [sys.executable, str(_script_on_an_ephemeral_port(tmp_path))],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def _wait_for(pred, seconds: float = 20.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.05)
    return pred()


def test_it_announces_while_serving_and_withdraws_on_sigterm(tmp_path: Path, tls) -> None:
    sd = tmp_path / "sd"
    sd.mkdir()
    f = sd / "nvidia-exporter.json"
    proc = _start(tmp_path, tls, sd)
    try:
        assert _wait_for(f.exists), f"never announced; output: {proc.stdout.read() if proc.poll() is not None else '(running)'}"
        # PORT is 0 in this copy; the shipped script announces its own PORT (9400,
        # test_the_shipped_script_announces_port_9400).
        assert json.loads(f.read_text()) == [{"targets": ["nvidia-exporter:0"]}]
        assert not (sd / "nvidia-exporter.json.tmp").exists()
        proc.send_signal(signal.SIGTERM)
        rc = proc.wait(timeout=20)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    out = proc.stdout.read()
    assert rc == 0, f"SIGTERM did not exit cleanly (rc={rc}): {out}"
    assert not f.exists(), f"a stopped exporter is still a target: {out}"
    assert "announced nvidia-exporter:0" in out, out


def test_the_shipped_script_announces_port_9400() -> None:
    text = SCRIPT.read_text()
    assert "\nPORT = 9400\n" in text
    assert 'SD_TARGET = f"nvidia-exporter:{PORT}"' in text
    assert 'SD_FILE_NAME = "nvidia-exporter.json"' in text


def test_without_a_discovery_dir_it_serves_and_writes_nothing(tmp_path: Path, tls) -> None:
    proc = _start(tmp_path, tls, None)
    try:
        assert _wait_for(lambda: proc.poll() is not None or False, 2.0) is False, proc.stdout.read()
    finally:
        proc.send_signal(signal.SIGTERM)
        rc = proc.wait(timeout=20)
    assert rc == 0
    assert not list(tmp_path.rglob("nvidia-exporter.json*"))


def test_an_unwritable_dir_does_not_stop_it_serving(tmp_path: Path, tls) -> None:
    proc = _start(tmp_path, tls, tmp_path / "does-not-exist")
    try:
        # still running after the announce attempt: the gateway reads it directly
        assert _wait_for(lambda: proc.poll() is not None, 2.0) is False
    finally:
        proc.send_signal(signal.SIGTERM)
        rc = proc.wait(timeout=20)
    out = proc.stdout.read()
    assert rc == 0, out
    assert "could not announce" in out, out
