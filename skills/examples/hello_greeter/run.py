#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""hello_greeter sandbox capability — the worked example for skill authors.

This is the former ``tools/custom/_example.py`` drop-in tool, rewritten as a
skill: same "hello, {name}" logic, but it executes in the
Docker sandbox via the node-agent instead of in-process in the worker pool.

Contract (see manifest.yml):
  input  (env SKILL_INPUT, JSON): {name: str = "world"}
  output (stdout, JSON):          {greeting: str}

Errors go to stderr with a non-zero exit code; the sandbox executor turns a
non-zero exit into a failed SandboxResult. No network, no filesystem writes —
the container runs with network=none and only /skill mounted.

To try it:
  cp -r skills/examples/hello_greeter ~/.pai/skills/hello_greeter
  pai skills run hello_greeter '{"name": "Mesh"}'
"""
import json
import os
import sys


def main() -> int:
    try:
        inputs = json.loads(os.environ.get("SKILL_INPUT", "{}"))
    except json.JSONDecodeError as e:
        print(f"invalid SKILL_INPUT JSON: {e}", file=sys.stderr)
        return 2

    name = inputs.get("name") or "world"
    if not isinstance(name, str):
        print("input 'name' must be a string", file=sys.stderr)
        return 2

    json.dump({"greeting": f"Hello, {name}!"}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
