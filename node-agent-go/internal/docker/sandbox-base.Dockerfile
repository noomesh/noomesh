# noo-sandbox-base — default runtime image for sandboxed capability containers.
#
# Contract (what a capability container gets from the executor):
#   - env  SKILL_INPUT : the capability's inputs, serialised as JSON
#   - mount /skill     : the capability directory (manifest.yml + run.py),
#                        bind-mounted read-only from the node's host filesystem
#   - command          : `python /skill/run.py` unless the manifest overrides it
#   - output           : the capability prints its result as JSON on stdout;
#                        stderr is captured for diagnostics; non-zero exit = failure
#   - isolation        : network none/restricted per manifest, memory-limited,
#                        run as the non-root `sandbox` user below
#
# Deliberately minimal: today's builtin capabilities (text_summarizer, ...)
# use ONLY the Python standard library, so this image adds no packages on
# top of python:3.12-slim. Do NOT grow this image speculatively — a
# capability that needs third-party libraries should specify its own image
# in its manifest (`container.image:`) instead of fattening the shared base.
#
# Distribution, and why this file lives in the node-agent's source tree:
#
#   - x86 workers get a `docker save` tar over the artifact rail
#     (`noo cluster sync-images` → the agent's /pull kind=image).
#   - arm64 workers BUILD it themselves. The base is multi-arch, so a node
#     building locally gets its own arch for free — no cross-build on the
#     controller, no qemu, no registry. The agent embeds THIS file
#     (`sandbox_base.go`) and builds from it, so nothing is ever handed a
#     Dockerfile by a caller: an endpoint that built whatever it was sent
#     would be remote code execution wearing a build's clothes.
#   - the controller builds it via the compose "build-only" profile, which
#     points here (docker-compose.cluster.yml `sandbox-base`).
#
# One copy, three consumers. It used to live at docker/Dockerfile.sandbox-base;
# it moved because `go:embed` cannot reach outside its module, and a second
# copy inside the module would have been a declaration needing a guard.
#
# Build by hand: docker build -f node-agent-go/internal/docker/sandbox-base.Dockerfile -t noo-sandbox-base:latest .

FROM python:3.12-slim

# Survive the rebuild script's `docker image prune -a` pass — no container
# stays running from this image between capability invocations, so without
# the keep label it would be pruned as "unused" on every rebuild.
LABEL pai.image.role=base
LABEL pai.image.keep=true

# Non-root user for capability code. The executor mounts /skill read-only
# and passes inputs via env, so nothing here needs write access or root.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 1000 sandbox
USER sandbox
WORKDIR /home/sandbox

# No ENTRYPOINT/CMD: the executor always supplies the command explicitly
# (default `python /skill/run.py`).
