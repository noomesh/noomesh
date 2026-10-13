#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Verify gateway-rust/.sqlx still agrees with the live database schema.
#
# Read-only: writes nothing, exits non-zero on drift. Run it after applying a
# migration — `cargo check` will NOT catch a schema change, because a stale
# cache is internally consistent and compiles perfectly.
exec "$(dirname "${BASH_SOURCE[0]}")/sqlx-prepare.sh" --check
