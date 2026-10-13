# Supported and tested hardware

For someone about to add a node. It says which machines the maintainers run
today, which are expected to work, which are not supported yet, and how to
check a box before spending an enrollment token on it. Versions as of
2026-10-10: stack v0.2.102, CLI 0.5.89.

## Tested

These are the combinations the maintainers test on, on current releases.

| OS | Arch | Hardware | Backends observed running | Tier |
|---|---|---|---|---|
| Pop!_OS 24.04 LTS (Ubuntu noble base) | x86_64 | Laptop, NVIDIA RTX 3060 Laptop 6 GB, 64 GB RAM | Ollama (chat and embeddings) | 2 |
| Ubuntu 22.04 (jammy) under WSL2 on Windows | x86_64 | NVIDIA RTX 3080 Laptop 16 GB, 20 GB RAM | vLLM (a 12B 4-bit chat model) | 2 |
| Ubuntu 24.04 (noble) | aarch64 | Raspberry Pi 4 Model B, 4 GB | Ollama embeddings (CPU) | 4 (edge) |
| macOS on Apple M4 | arm64 | Mac mini, 24 GB unified memory | Ollama, native via Homebrew (no Docker) | 2 |

The tier is derived from the facts a node reports; see
[../cli/fleet.md](../cli/fleet.md) for the rule and the override.

## Expected to work, not regularly tested

- Ubuntu 22.04 and 24.04 on bare metal.
- Debian 12 (bookworm) and 13 (trixie).
- Ubuntu derivatives that set `UBUNTU_CODENAME` in `/etc/os-release`: Linux
  Mint, Zorin OS, elementary OS, KDE neon. Host prep resolves a derivative
  to its Ubuntu base by `UBUNTU_CODENAME` and installs Docker from Docker's
  own repository for that base, rather than letting the Docker installer
  guess.
- Raspberry Pi OS (raspbian).
- NVIDIA Jetson (unified memory): tier 1 when CUDA is available and at least
  10 GB is usable.

## Not supported yet

- Fedora, RHEL, Rocky and Arch. Prep falls back to Docker's convenience
  script and prints a warning. It may work, but it is not tested.
- Immutable or atomic distributions (Fedora Silverblue, ChromeOS, NixOS):
  prep installs packages.
- Windows natively. Use WSL2.
- Linux without systemd.
- Devices whose only accelerator is an NPU: there is no runtime for one yet.
- Intel Macs.

## Requirements for every Linux node

- systemd.
- A user with sudo.
- Outbound HTTPS to the controller on `:8080`. The paste joins the tailnet
  by default (`--skip-tailscale` opts out).
- The NVIDIA **driver** already installed when the box has a GPU. Prep
  installs the container toolkit, not the driver.
- Docker and `acl` are installed by prep if missing.
- A data root on a disk that is mounted at boot. Drives under
  `/media/<user>/` are mounted by the desktop at login, so a node that
  restarts unattended will not see them: add an `/etc/fstab` entry and point
  `--data-root` at the mount.

## What fits where

Advisory. Place with `noo cluster place <node> <backend|harness>
<model|auto>`; add `--role chat|embed|rerank` to choose the role, and see
[../cli/fleet.md](../cli/fleet.md) for the rest. A placement that is too big
for the node is refused.

| Memory | Place | Example |
|---|---|---|
| 16 GB or more of CUDA VRAM | vLLM, a 12B 4-bit chat model | `noo cluster place <node> vllm auto` |
| 8 to 12 GB VRAM | Ollama, a 12B model | `noo cluster place <node> ollama auto` |
| 6 GB VRAM or less | Ollama, a 2B to 4B model, or embeddings only | `noo cluster place <node> ollama auto --role embed` |
| Pi class (4 GB, CPU only) | Embeddings only | `noo cluster place <node> ollama auto --role embed` |
| Apple unified memory | Ollama, up to roughly three quarters of RAM | `noo cluster place <node> ollama auto` |

`auto` picks a model the node can hold. Name one explicitly if you want a
particular model.

## Check a machine before you enroll it

`noo enroll` runs a preflight before it spends the token. It prints
`prep-check:` lines, one per check, in the form
`prep-check: ok|warn|FAIL <what> — <remedy>`, and ends with
`prep-check: platform=<family> codename=<codename> pkg=<apt|dnf|pacman|none>`.
A `FAIL` stops enrollment before the redeem, so the token is not spent and
the same paste can be re-run once the problem is fixed. A `warn` never
stops anything. `--skip-prep` skips the preflight along with host prep. The
preflight changes nothing on the machine.

To read the same facts yourself:

```sh
grep -E '^(ID|ID_LIKE|VERSION_CODENAME|UBUNTU_CODENAME)=' /etc/os-release
nvidia-smi --query-gpu=name,memory.total --format=csv    # GPU boxes only
```

`UBUNTU_CODENAME` is what prep uses to pick Docker's repository for an
Ubuntu derivative.

## Known issue: Docker from the wrong repository

Fixed in this release for new enrollments. A Pop!_OS box prepped by an older
CLI may have Docker from Docker's **Debian trixie** repository, because
Docker's installer did not recognise the OS and fell back to Debian:

```sh
grep ^deb /etc/apt/sources.list.d/docker.list
# deb [...] https://download.docker.com/linux/debian trixie stable   <- wrong base
```

It works while it works. To move it to the matching Ubuntu repository,
rewrite the file for your Ubuntu base and refresh. This reinstalls Docker
packages on the next upgrade and restarts the daemon, so do it in a
maintenance window:

```sh
. /etc/os-release
sudo sed -i -E "s#linux/debian [a-z]+#linux/ubuntu ${UBUNTU_CODENAME}#" /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install --only-upgrade docker-ce docker-ce-cli containerd.io
```

Check the `grep` output again afterwards. A node that is working does not
need this.

## Getting a device added to the tested list

Open an issue with the `prep-check:` output and your `/etc/os-release`, or
write to `contact@noomesh.ai`.
