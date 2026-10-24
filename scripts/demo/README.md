# The onboarding film

`record-onboarding.sh` films a stranger's first run (install, `noo onboard`, a
first chat) with [vhs](https://github.com/charmbracelet/vhs) and renders a GIF
and an MP4 into `demo-out/` (git-ignored). The commands are scripted and typed
at a steady pace; the output is whatever the machine really prints.

| File | What it is |
|---|---|
| `onboarding.tape.in` | the film, as a template; `@INSTALL_URL@` and `@PLAYBACK_SPEED@` are filled in |
| `smoke.tape.in` | a harmless tape (a fake `noo` printing made-up sensitive values) that proves vhs, ttyd, ffmpeg and the masker work |
| `mask.pl` | the output filter: real names, IPs and secrets become generic stand-ins |
| `record-onboarding.sh` | guard rails, fills the templates, runs vhs, checks for leaks and failed steps, makes a contact sheet |
| `studio.sh` | makes a throwaway Ubuntu 24.04 box with its own Docker, films inside it, deletes it; `cache` keeps the stack's images on this host between boxes (see below) |

## Quick start

```bash
scripts/demo/record-onboarding.sh --smoke                     # anywhere: checks the toolchain
NOO_DEMO_SANDBOX=1 scripts/demo/record-onboarding.sh --speed 2   # on a CLEAN sandbox only
```

## The studio: film in a throwaway box (recommended)

```bash
scripts/demo/studio.sh up                 # a clean Ubuntu 24.04 + its own Docker engine, host node-1, user you
scripts/demo/studio.sh record --smoke     # proves the whole chain with nothing public needed
scripts/demo/studio.sh record --speed 2   # the real film (needs the public install)
scripts/demo/studio.sh down               # deletes the box and its volume
```

Two containers: the **box** (Ubuntu 24.04 with **systemd as PID 1** and Docker as a unit:
Docker-in-Docker, `--privileged`, memory cap `NOO_STUDIO_MEM`, default 10g, images in a named
volume) and the **recorder** (the vhs image), which types into the box with `docker exec`. The box
image (`noo-demo-box:base`: systemd, Docker from Docker's apt repository, the film's user) is built
once on your machine and cached; `docker rmi noo-demo-box:base` rebuilds it. With systemd in the
box, the host node agent and `noo-hostd` the film installs run as units, as on a real box: the
node registers, and the prep step prints no "Failed to connect to bus" lines (take 7, 2026-10-24,
on a box without it). The box has a generic host name and user by construction, the
stack the film onboards lives and dies inside it, and its own Docker pulls images anonymously,
so it is a real stranger's first run. In box mode the recorder's guard rails inspect the box,
not your machine, and only accept a container the studio labelled `noo-demo-box=1`.

## Pulling from here: the cache

```bash
scripts/demo/studio.sh cache up        # a pull-through cache of ghcr.io on this host (once)
scripts/demo/studio.sh up              # a box made now pulls ghcr.io through it
scripts/demo/studio.sh cache status    # running? how full?
scripts/demo/studio.sh cache purge     # delete the blobs, the certificate and the network
```

A fresh box pulls the whole stack (about 10 GB) from ghcr.io, and `down` deletes
the box's images with the box. The cache keeps that download on this host, in a
named volume that survives `down`, so the second fresh box costs LAN time, not
internet time. What the film shows is unchanged: a real `docker pull
ghcr.io/noomesh/...`, the real layer list, the real digests — the lock pins every
image by digest, so a cached image cannot differ from the public one. The
install itself (`curl | sh` from the release repo) and the model download are not
cached.

How it works, and why this way: Docker Engine's `registry-mirrors` setting
applies to Docker Hub only, and the engine ignores containerd's `hosts.toml`
for other registries, so a mirror for ghcr.io cannot be configured. Instead the
cache *answers as* ghcr.io inside the box: it is the registry image in proxy
mode (`REGISTRY_PROXY_REMOTEURL=https://ghcr.io`, anonymous, public images
only) listening on :443 with a certificate for `ghcr.io` signed by a throwaway
CA the studio makes once (`demo-out/cache/`, keys never leave it). A box made
while the cache runs is born on the cache's network with `ghcr.io` in its hosts
file pointing at the cache, and trusts that CA in its system store and in
`/etc/docker/certs.d/ghcr.io/`. Nothing else in the box is configured, and a
box made while the cache is down is a plain stranger's machine. `up` proves the
box reaches the cache as `ghcr.io` before it says ready. A box outlives a `cache
down` badly (its `ghcr.io` points at nothing): bring the cache back, or make a
fresh box.

What the first real take proves: the proxy serves the registry API (`/v2/`
manifests and blobs, by tag and by digest). Anything the stack fetches from
ghcr.io outside that API would fail inside the box with the cache's name
resolution; the recorder's failed-step check catches it, and the fix is either
to teach the cache or to film that step without it.

Costs and cautions: about 10 GB of images and a model download, a slow CPU-only chat step, and
`--privileged`. The recorder container is given the host's Docker socket (so it can reach the
box); it is short-lived and ours. `up` refuses if free memory is below the cap, so it does not
squeeze a machine that is serving inference. If a stale Docker Hub login breaks pulls, the
studio pulls its public base image anonymously.

**Failed steps.** The film shell records the exit status of every command typed into it. If any
step failed, the takes are renamed `*.FAILED.*` and the run fails, so a broken take is never
mistaken for a publishable one. A take where nothing could be recorded fails too.

## What gets masked

Everything `noo` and the installer print goes through `mask.pl` before it reaches
the film, and the same stand-in is used every time a real value reappears:

| Real | Shown as |
|---|---|
| node names (this machine first), tailnet host names | `node-1`, `node-2`, `node-3.tailnet.ts.net` |
| IPv4 addresses | `192.0.2.1`, `192.0.2.2` (the documentation range) |
| IPv6 addresses | `2001:db8::1` |
| MAC addresses, e-mail addresses, other users' home paths | `00:00:00:00:00:00`, `you@example.com`, `/home/you` |
| tokens, API keys, entitlements, passwords, long opaque strings | `********` |

Left alone: loopback, versions, timestamps, image digests, the public `noomesh.ai` addresses.
`NOO_DEMO_MASK_NAMES="alpha beta"` masks extra names. A new kind of sensitive value is a
new rule in `mask.pl` plus a case in `tests/test_demo_mask.py`.

**The recorder proves it worked.** It logs the output raw and masked, then checks that no
sensitive value found in the raw log survives in the masked one. If one does, the GIF, the
MP4 and the logs are deleted and the run fails (it prints a count, never the values). The raw
log is always deleted. This catches a rule that missed something; it does not see what is
not routed through the masker (the typed commands, and the prompt, which is forced to
`you@server`).

## Rules

- **Clean sandbox only** (the studio's box satisfies this by itself; the rest of this bullet
  is for filming on a bare machine). The film installs `noo` and onboards a whole stack on
  the machine it runs on. The script refuses without `NOO_DEMO_SANDBOX=1`, if
  `noo` or `~/.noo` already exists, or if the host name is a fleet node. Use a
  fresh Ubuntu 24.04 VM or the host2 sandbox, with a generic host name.
- **Needs the public install.** It fetches the install URL anonymously and stops
  if that does not answer. The URL comes from `noo-cli/install.sh`'s declared
  release repo, so it follows the org move by itself.
- **Review before publishing.** `demo-out/contact-sheet.png` has one frame every
  5 seconds. The masker and the leak check catch the known kinds of value; your eyes
  catch the rest.
- **The GIF is made from the MP4.** vhs renders a GIF with one palette over every frame, which
  holds the whole film in memory: a 20-minute take was killed at a 7 GB cap and, uncapped, took a
  19 GiB WSL2 host down twice (2026-10-23/24). The tape outputs the MP4 only; the recorder then
  runs a streaming ffmpeg pass (one palette per frame, `NOO_DEMO_GIF_FPS` 8, `NOO_DEMO_GIF_WIDTH`
  800) for `onboarding.gif`. The recorder container is capped (`NOO_STUDIO_REC_MEM`, 6g) as a
  backstop. Do not film on a WSL2 host that also runs a model: the box (10g) plus the render do not
  fit beside it.
- **What the cache does not cover.** The cache fronts ghcr.io only. The Ollama image comes from
  Docker Hub, and the chat model `noo onboard` pulls comes from registry.ollama.ai; both go to
  the internet on every fresh box. A cold `noo onboard` took 40 minutes on one host and stalled at
  1.8 KB/s on the model pull on another, so the tape's wait is 60 minutes and a stalled pull is
  not the film's fault. The cache volume can be seeded from another host:
  `docker run --rm -v noo-demo-cache:/c alpine tar c -C /c . | ssh other 'docker volume create noo-demo-cache && docker run --rm -i -v noo-demo-cache:/c alpine tar x -C /c'`.
- **Pace.** vhs films in real time, and a first-run image pull takes minutes.
  `--speed 2` plays the whole film faster. For a tighter cut, `scripts/demo/cut.sh IN.mp4 OUT.mp4 EDITS`
  speeds up the stretches that are only the network and captions them on screen
  ("Pulling the stack images: ~13 GB, as fast as your network (8x)"), one edit per line
  (`START END SPEED [CAPTION]`), without refilming. Take 7 (5.6 min at 2x) cut to 2.7 min that way.
- **The GIF is the teaser, the MP4 is the film.** `NOO_DEMO_GIF_RANGE=START:SECONDS` makes the
  GIF from one stretch; the defaults (`NOO_DEMO_GIF_FPS` 8, `NOO_DEMO_GIF_WIDTH` 800, whole take)
  still make hundreds of MB from a five-minute take.
- **`noo stack status`, not `noo cluster status`.** The node registers about a minute after
  onboard (the host agent's first heartbeat); the tape does not wait for it. Before the box had
  systemd it never registered at all (take 7, "no nodes").
- The non-interactive wizard (`--ci --skip-tailscale`) is what is filmed because
  it is the path the release rehearsals exercise. An interactive take needs the
  wizard's prompts typed in; add them to the template after one dry take.

## Installing the tools (Ubuntu 24.04)

```bash
sudo apt update && sudo apt install -y ffmpeg ttyd
echo 'deb [trusted=yes] https://repo.charm.sh/apt/ /' | sudo tee /etc/apt/sources.list.d/charm.list
sudo apt update && sudo apt install -y vhs
```
