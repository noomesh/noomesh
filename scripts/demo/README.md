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
| `studio.sh` | makes a throwaway Ubuntu 24.04 box with its own Docker, films inside it, deletes it (see below) |

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

Two containers: the **box** (Docker-in-Docker, `--privileged`, memory cap `NOO_STUDIO_MEM`,
default 10g, images in a named volume) and the **recorder** (the vhs image), which types into
the box with `docker exec`. The box has a generic host name and user by construction, the
stack the film onboards lives and dies inside it, and its own Docker pulls images anonymously,
so it is a real stranger's first run. In box mode the recorder's guard rails inspect the box,
not your machine, and only accept a container the studio labelled `noo-demo-box=1`.

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
- **Pace.** vhs films in real time, and a first-run image pull takes minutes.
  `--speed 2` plays the whole film faster; for a tighter cut, film in chunks
  (separate tapes) and speed up the waits with ffmpeg
  (`-filter:v "setpts=PTS/4"` on a clip).
- The non-interactive wizard (`--ci --skip-tailscale`) is what is filmed because
  it is the path the release rehearsals exercise. An interactive take needs the
  wizard's prompts typed in; add them to the template after one dry take.

## Installing the tools (Ubuntu 24.04)

```bash
sudo apt update && sudo apt install -y ffmpeg ttyd
echo 'deb [trusted=yes] https://repo.charm.sh/apt/ /' | sudo tee /etc/apt/sources.list.d/charm.list
sudo apt update && sudo apt install -y vhs
```
