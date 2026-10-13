# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# Pinned to `.python-version` at the repo root, like docker/Dockerfile.deps-core
# — tests/test_python_version_single_source.py fails if they drift.
#
# This was `python:3.11-slim` while every shipped image ran 3.12: CI's `build`
# job is the only thing that builds this file, so the one interpreter this repo
# gated a merge on was an interpreter nothing deployed.
# Docker Hub base via the GHCR mirror (.github/hub-mirror.txt): Hub rate-limits
# pulls per IP. Needs a ghcr.io login; without one, build with
# --build-arg HUB_MIRROR=docker.io.
ARG HUB_MIRROR=ghcr.io/noomesh/mirror
ARG PYTHON_VERSION=3.12
FROM ${HUB_MIRROR}/library/python:${PYTHON_VERSION}-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# git is required for the noo-trellion git dependency in pyproject.toml
RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /app/
COPY src /app/src

# noo-trellion is a PUBLIC git+https dependency (personifAI/trellion): no token
# is needed and the release passes none. The gh_pat secret mount below is
# optional (required=false) and only for a build against a private fork: pass
# it as a BuildKit secret (docker build --secret id=gh_pat,env=TOKEN) and clones
# are rewritten to HTTPS+token via GIT_CONFIG_* env vars, which vanish at the
# end of this RUN, so the token never lands in a layer.
RUN --mount=type=secret,id=gh_pat,required=false \
    if [ -s /run/secrets/gh_pat ]; then \
      export GIT_CONFIG_COUNT=1 \
        GIT_CONFIG_KEY_0="url.https://x-access-token:$(cat /run/secrets/gh_pat)@github.com/.insteadOf" \
        GIT_CONFIG_VALUE_0="ssh://git@github.com/"; \
    fi; \
    pip install --no-cache-dir -e ".[web,mcp,pgvector]"

# Not a service image. CI's `build` job compiles this file as the install
# gate for pyproject.toml; no compose service runs it. It used to end with
# `EXPOSE 8000` + `uvicorn noo_mesh.server.agent_api:app --host 0.0.0.0`, a
# plain-HTTP all-interfaces server for a package that no longer exists. The
# CMD now only proves the installed package imports.
CMD ["python", "-c", "import noomesh"]
