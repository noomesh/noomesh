# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The `name` help on the log tools must not promise a form Loki does not carry.

Loki's `name` label is `noo-worker`; the docs said "without its noo- prefix",
so `name=worker` was documented and matched nothing. The gateway now accepts
both forms (logs_search.rs `name_matcher`); the help must say the labelled form.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from noomesh.mcp.tool_models import get_all_tools  # noqa: E402


def test_name_help_names_the_prefixed_label_and_not_the_old_promise() -> None:
    for tool in ("noo_logs_tail", "noo_logs_errors", "noo_logs_search"):
        cls = get_all_tools()[tool]
        desc = cls.model_fields["name_field"].description or ""
        assert "noo-worker" in desc, f"{tool}: {desc}"
        assert "without its" not in desc, f"{tool} still promises the bare label: {desc}"
