# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The onboarding film shows real output, so scripts/demo/mask.pl must replace
anything that names a real machine or person with a consistent generic stand-in,
and must leave versions, timestamps and digests alone."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

MASK = Path(__file__).resolve().parents[1] / "scripts/demo/mask.pl"
pytestmark = pytest.mark.skipif(shutil.which("perl") is None, reason="perl is not installed")


def mask(text: str, **env: str) -> str:
    base = {k: v for k, v in os.environ.items() if not k.startswith("NOO_DEMO_")}
    r = subprocess.run(["perl", str(MASK)], input=text, capture_output=True, text=True, env={**base, **env}, check=True)
    return r.stdout


def test_ipv4_gets_a_consistent_documentation_address():
    out = mask("a 10.1.2.3 b 10.1.2.3 c 172.20.0.5\nagain 172.20.0.5 and 10.1.2.3\n")
    assert out == "a 192.0.2.1 b 192.0.2.1 c 192.0.2.2\nagain 192.0.2.2 and 192.0.2.1\n"


def test_loopback_unspecified_versions_and_timestamps_are_left_alone():
    s = "listen 127.0.0.1:8080 0.0.0.0 255.255.255.255 v0.6.0-rc.1 stack-v0.2.103 1.2.3 at 12:34:56 2026-10-10T19:03:42Z ::1\n"
    assert mask(s) == s


def test_octets_over_255_are_not_addresses():
    assert mask("build 999.1.1.1\n") == "build 999.1.1.1\n"


def test_ipv6_and_mac_are_masked():
    out = mask("v6 2a01:4f8:c0c:1::1 mac aa:bb:cc:dd:ee:ff v6 2a01:4f8:c0c:1::1 other fe80::1234\n")
    assert out == "v6 2001:db8::1 mac 00:00:00:00:00:00 v6 2001:db8::1 other 2001:db8::2\n"


def test_node_names_become_node_n_consistently_and_case_insensitively():
    out = mask("alpha online\nBETA offline\nGamma ok\nalpha again\n", NOO_DEMO_MASK_NAMES="alpha beta gamma")
    assert out == "node-1 online\nnode-2 offline\nnode-3 ok\nnode-1 again\n"


def test_names_inside_other_words_are_not_touched():
    s = "jalpha alphabet alpha-like-thing\n"
    assert mask(s, NOO_DEMO_MASK_NAMES="alpha") == s


def test_this_machine_is_always_node_1_and_extra_names_are_honoured():
    out = mask("peer alpha then box7 then beta\n", NOO_DEMO_HOSTNAME="box7", NOO_DEMO_MASK_NAMES="alpha beta")
    assert out == "peer node-2 then node-1 then node-3\n"


def test_tailnet_host_names_are_masked_as_nodes():
    out = mask("https://ctl.fake-tailnet.ts.net:8080 and ctl.fake-tailnet.ts.net\n")
    assert out == "https://node-1.tailnet.ts.net:8080 and node-1.tailnet.ts.net\n"
    assert "fake-tailnet" not in out


def test_emails_and_home_directories():
    out = mask("by person@mail.test or contact@noomesh.ai in /home/alice/.local/bin and /Users/bob/x and /home/you/ok\n")
    assert out == "by you@example.com or contact@noomesh.ai in /home/you/.local/bin and /home/you/x and /home/you/ok\n"


def test_secrets_are_masked():
    s = ("admin password: hunter2xyz\nTOKEN=abc123def\nghp_" + "A" * 36 + "\nnoo-ent1.AAAA.BBBB-cc\n"
         "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlMTIz\nkey " + "a1" * 32 + "\n")
    out = mask(s)
    for leaked in ("hunter2xyz", "abc123def", "ghp_", "AAAA.BBBB", "eyJhbGci", "a1a1a1a1"):
        assert leaked not in out, leaked
    assert out.count("********") == 6


def test_image_digests_survive_but_bare_hashes_do_not():
    digest = "sha256:" + "ab12" * 16
    assert mask(f"Digest: {digest}\n") == f"Digest: {digest}\n"
    assert "ab12ab12" not in mask("id " + "ab12" * 16 + "\n")


def test_colour_codes_survive_around_a_masked_value():
    out = mask("\x1b[1;32m10.9.8.7\x1b[0m ok\n")
    assert out == "\x1b[1;32m192.0.2.1\x1b[0m ok\n"


def test_a_last_line_without_a_newline_is_still_masked():
    assert mask("host host3") == "host node-1"


def test_the_fleet_names_are_masked_by_default():
    for name in ("host3", "host8", "host8", "host9", "host6", "host2", "host5", "host8-ma"):
        assert name not in mask(f"{name}\n"), name
