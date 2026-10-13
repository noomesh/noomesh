# Hardened llama.cpp image

`Dockerfile.llamacpp` builds `llama-server` from upstream llama.cpp source,
pinned to an immutable git ref (`LLAMACPP_REF`; a moving ref is refused), on a
Docker Hardened Images base (`${DHI_REGISTRY}/uv:0-debian13-dev`, both
stages), running as nonroot. It is the same CPU/OpenBLAS capability class as
upstream `ghcr.io/ggml-org/llama.cpp:server`, hardened for the release.

## It ships

The release workflow (`.github/workflows/images-release.yml`) builds this
Dockerfile for `linux/amd64` and publishes it as
`ghcr.io/noomesh/llamacpp:<stack-tag>`, a normal row in the signed stack lock.
`docker-compose.dist.yml`, the node agent's default and `noo stack` staging
all pull that image. ARM nodes use the upstream multi-arch image instead
(building this one for arm64 would be a from-source compile nothing asks for).

## Building it yourself

```
scripts/build-hardened-llamacpp.sh [amd64|arm64]     # default: host arch
LLAMACPP_REF=b9628 scripts/build-hardened-llamacpp.sh arm64
```

Run from the repo root. It buildx-builds `docker/Dockerfile.llamacpp` on the
controller (native for the host arch, qemu-emulated for a foreign one) and
tags the result `pai-assistant/llamacpp:<arch>` (and `:latest` for the host
arch); `noo cluster sync-images <node> --image pai-assistant/llamacpp:<arch>`
ships it to an edge node.

## Where nodes look

A node prefers, in order: a release-pinned image (when the deployment carries
a release pin), then a local build tagged `pai-assistant/llamacpp:<arch>` or
`:latest` when one exists on that node, and only then the upstream
`ghcr.io/ggml-org/llama.cpp:server`. `LLAMACPP_IMAGE` overrides this
resolution on both the node agent and the `docker-compose.cluster.yml`
service.
