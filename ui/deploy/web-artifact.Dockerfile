# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# The web console artifact image: nothing but the built static tree at /dist.
# `FROM scratch` means there's no runtime, no shell, no packages — the gateway
# never *runs* this image, it only copies files out of it:
#
#   COPY --from=ghcr.io/noomesh/mesh-ui-web:vX /dist /var/www
#
# The publish workflow sets the build context to apps/web/dist (produced by
# `npm run build -w @metis/web`), so `COPY . /dist` ships exactly that tree
# and nothing else.
FROM scratch
COPY . /dist
