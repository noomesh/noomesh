# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Output the getting-started docs quote is the output the CLI prints.

The 2026-11-18 launch audit found quoted output that nothing compared: a
reader is told what to expect, and the code could change the words under the
doc. Like test_first_chat_prompt_parity, each test ties one quote to the
string in the code that prints it.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text()


def _flat(text: str) -> str:
    """Prose wraps; compare with every run of whitespace as one space."""
    return re.sub(r"\s+", " ", text)


def test_install_md_step_count_is_onboards():
    doc = _read("docs/getting-started/install.md")
    m = re.search(r"prints `step N/(\d+)`", _flat(doc))
    assert m, "install.md no longer quotes onboard's `step N/<total>` line"
    src = _read("noo-cli/src/onboard/mod.rs")
    titles = re.search(r"pub\(crate\) const STEP_TITLES: \[&str; (\d+)\]", src)
    assert titles, "onboard/mod.rs no longer declares STEP_TITLES"
    assert m.group(1) == titles.group(1), f"install.md says step N/{m.group(1)}; onboard has {titles.group(1)} steps"
    prompt = _read("noo-cli/src/onboard/prompt.rs")
    assert 'format!("step {step}/{total}' in prompt, "onboard no longer prints `step N/total`"


def test_install_md_client_only_is_whoamis_fresh_box_label():
    doc = _read("docs/getting-started/install.md")
    assert re.search(r'noo whoami\s+#\s*"client-only" on a fresh host', doc), "install.md no longer quotes whoami's fresh-host word"
    role = _read("noo-cli/src/role.rs")
    m = re.search(r'\(None, None\) => "([^"]+)"', role)
    assert m, "role.rs no longer has the fresh-box label"
    assert "client-only" in m.group(1), f"whoami's fresh-box label no longer says client-only: {m.group(1)!r}"


def test_setup_and_host_nodes_ending_is_upgrades():
    doc = _flat(_read("docs/cli/setup-and-host.md"))
    m = re.search(r"`--nodes` ends `(bundles staged for all N node\(s\)[^`]*)`", doc)
    assert m, "setup-and-host.md no longer quotes how `noo upgrade --nodes` ends"
    src = _read("noo-cli/src/commands/upgrade.rs")
    code = re.search(r'format!\("(bundles staged for all \{total\} node\(s\)[^"]*)"', src)
    assert code, "upgrade.rs no longer prints `bundles staged for all … node(s)`"
    assert m.group(1) == code.group(1).replace("{total}", "N"), f"doc {m.group(1)!r} != code {code.group(1)!r}"
