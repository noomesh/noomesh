# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""noo-eval — cluster evaluation harness.

Drives synthetic multi-node / multi-user / multi-location / (future)
multi-controller workloads against a live mesh cluster, collects metrics from
the existing Prometheus + cluster-status surface, and renders a self-contained
HTML evaluation report.

The whole harness pivots on one schema (:mod:`noo_eval.schema`): the live
:mod:`noo_eval.driver` emits a ``RunResult`` and the demo generator emits the
same shape, so :mod:`noo_eval.report` renders both identically.
"""

from .schema import RunResult

__all__ = ["RunResult"]
__version__ = "0.1.0"
