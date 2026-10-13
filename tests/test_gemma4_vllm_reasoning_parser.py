# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every gemma-4 vLLM launch path runs under the gemma4 reasoning parser
.

Without the parser vLLM drops gemma's special tokens, so the stream reaches
the gateway as a bare `thought\\n<reasoning><answer>` with NO boundary between
reasoning and answer. The gateway's virtual `<think>` (coordinator/agent_loop.rs)
then treats everything to end-of-stream as reasoning, and a nudged turn's
visible answer is swallowed. No heuristic over that stream is reliable, so the
fix is configuration: every launch script that handles gemma-4 must select the
parser, ask the image whether it registers it (an unknown name stops vLLM
booting), and pass `--reasoning-parser` on the command line.

Launch paths pinned: the node agent's `vllmEntrypointScript` (backends.go) and
the compose `vllm` and `vllm-secondary` services.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
PROBE = "M.list_registered()"


def _backends_script() -> str:
    src = (ROOT / "node-agent-go/internal/docker/backends.go").read_text()
    m = re.search(r"const vllmEntrypointScript = `(.*?)`\n", src, re.S)
    assert m, "vllmEntrypointScript not found in backends.go"
    return m.group(1)


def _compose_script(service: str) -> str:
    d = yaml.safe_load((ROOT / "docker-compose.cluster.yml").read_text())
    cmd = d["services"][service]["command"]
    return "\n".join(str(c) for c in cmd)


SCRIPTS = {
    "node-agent vllmEntrypointScript": _backends_script,
    "compose vllm": lambda: _compose_script("vllm"),
    "compose vllm-secondary": lambda: _compose_script("vllm-secondary"),
}


def _gemma4_arm(script: str) -> str:
    """The reasoning-parser `case` arm that matches gemma-4 model names."""
    i = script.index("reasoning parser")
    tail = script[i:]
    m = re.search(r"\*gemma-4\*\|\*gemma4\*[^\n]*\n(.*?)(?=\n\s*\*DeepSeek)", tail, re.S)
    assert m, "no gemma-4 arm in the reasoning-parser case"
    return m.group(0)


@pytest.mark.parametrize("name", sorted(SCRIPTS))
def test_gemma4_selects_the_gemma4_reasoning_parser(name):
    script = SCRIPTS[name]()
    arm = _gemma4_arm(script)
    assert re.search(r'VLLM_REASONING_PARSER="gemma4"|--reasoning-parser gemma4', arm), (
        f"{name}: the gemma-4 arm does not select the gemma4 reasoning parser"
    )
    assert PROBE in arm, (
        f"{name}: the gemma-4 arm does not ask the image whether it registers gemma4"
    )


@pytest.mark.parametrize("name", sorted(SCRIPTS))
def test_the_selected_reasoning_parser_reaches_the_command_line(name):
    script = SCRIPTS[name]()
    assert re.search(r"--reasoning-parser \$+VLLM_REASONING_PARSER|\$+REASON_ARG", script), (
        f"{name}: the chosen reasoning parser never reaches the vLLM command line"
    )
