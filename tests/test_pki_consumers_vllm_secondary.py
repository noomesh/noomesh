# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

from noomesh.pki.consumers import cert_consumers


def test_vllm_leaf_reaches_the_secondary_door():
    got = cert_consumers("services/vllm/service.crt", "service")
    assert got == ["noo-vllm", "noo-stunnel-vllm", "noo-stunnel-vllm-secondary", "noo-vllm-secondary"]
    assert cert_consumers("services/nats/service.crt", "service") == ["noo-nats", "noo-stunnel-nats"]
