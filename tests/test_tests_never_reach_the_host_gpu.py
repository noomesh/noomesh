# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The test session never runs the host's `nvidia-smi` (followup i142).

conftest.py drops every PATH directory holding one, so the launcher tests
take the "no NVIDIA driver" answer CI runners take. On a WSL2 box with the
GPU busy, one host call blocked for 11 minutes and the launcher tests timed
out. A test that wants a GPU puts its own fake in its bindir."""
import shutil


def test_no_host_nvidia_smi_is_on_the_test_path():
    assert shutil.which("nvidia-smi") is None, shutil.which("nvidia-smi")
