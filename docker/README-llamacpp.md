# Hardened llama.cpp image

`Dockerfile.llamacpp` builds `llama-server` from upstream llama.cpp source,
pinned to an immutable git ref (`LLAMACPP_REF`; a moving ref is refused), on a
Docker Hardened Images base (`${DHI_REGISTRY}/uv:0-debian13-dev`, both
stages), running as nonroot. It is the same CPU/OpenBLAS capability class as
upstream `ghcr.io/ggml-org/llama.cpp:server`, hardened for the release.

## It ships

The release workflow (`.github/workflows/images-release.yml`) builds this
Dockerfile for `linux/amd64,linux/arm64` and publishes it as
`ghcr.io/noomesh/llamacpp:<stack-tag>`, a normal row in the signed stack lock.
`docker-compose.dist.yml`, the node agent's default and `noo stack` staging
all pull that image, on ARM nodes too (noomesh-internal i323). There is no
upstream fallback: a node with this image neither local nor staged for its arch
refuses the start and names the restage command.

## The CUDA image

`Dockerfile.llamacpp-cuda` is the GPU build of the same llama.cpp ref
(`LLAMACPP_REF`, the same moving-ref refusal, the same env interface and
CMD), published as `ghcr.io/noomesh/llamacpp-cuda:<stack-tag>` for
`linux/amd64` only. Its bases are NVIDIA's `nvidia/cuda:12.9.1-devel` and
`-runtime` (Ubuntu 24.04), digest-pinned and pulled through the GHCR mirror
of Docker Hub; it runs as `nonroot` (65532), like the CPU image.

CUDA 12.9, not 13: CUDA 13 dropped every GPU below compute capability 7.5,
which would leave the Pascal cards (GTX 10xx, compute 6.1) behind. A CUDA 12
binary also runs on newer drivers (the 580 series included).

GPU code (`CUDA_ARCHITECTURES`): real cubins for `61` (Pascal), `75`
(Turing), `86` (Ampere consumer), `89` (Ada) and `120` (Blackwell consumer),
plus `61-virtual`, compute_61 PTX. PTX is compiled by the driver on first use
and only runs on its own or a NEWER GPU, so it is the forward fallback for
every GPU without a cubin (Volta, A100, Hopper, data-centre Blackwell; the
first start compiles for minutes, once) and nothing runs below compute 6.1.
Never `native`. The backends are loadable modules (`GGML_BACKEND_DL`), so
the image starts on a machine with no NVIDIA driver and simply lists no CUDA
device (CI runs it that way).

Who downloads it (about 3 GB: the CUDA 12.9 runtime base alone is 2.4 GB
compressed): only a node that starts llamacpp on its GPU. The node agent
takes the CUDA image when the placement is not `cpu` and the node has an
NVIDIA GPU of compute 6.1 or newer and the NVIDIA container runtime;
everything else, ARM nodes included, runs the CPU image above. It is not a
compose service, so `noo onboard` and `noo stack` never pull it, and a roll
stages it on the controller only when some node has such a placement (else
`noo cluster place` stages it the first time one is placed).
`LLAMACPP_CUDA_IMAGE` overrides it, as `LLAMACPP_IMAGE` does the CPU image.

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

A node with a release pin (`NOO_IMAGE_PREFIX` and `NOO_IMAGE_TAG`) runs these
images from its release and never falls back: not staged for its arch is a
refusal naming the restage command. A box with no release pin (a dev box)
runs upstream `ghcr.io/ggml-org/llama.cpp:server` (CPU) or `:server-cuda`
(GPU). A local build (`pai-assistant/llamacpp:<arch>`) is never a default: it
runs only where `LLAMACPP_IMAGE` / `LLAMACPP_CUDA_IMAGE` (node agent and the
`docker-compose.cluster.yml` service) or a placement's image names it
(`node-agent-go/internal/docker/backends.go` `llamacppDefaultImage`,
`llamacppCUDADefaultImage`). The CUDA image is chosen only for a GPU start on
a node that can use it (NVIDIA GPU, the nvidia runtime, compute 6.1 or
higher); everywhere else the CPU image, as cpu.
