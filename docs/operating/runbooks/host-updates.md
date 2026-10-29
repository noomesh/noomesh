---
title: "Host updates"
domain: "operations"
---

# Host updates

How to update the operating system on the controller and the nodes without
taking the mesh down. The short version: everyday packages update freely;
the **platform** packages — kernel, GPU driver, Docker, Tailscale — are held
on every Linux node and released one node at a time, a canary first and the
controller last.

This exists because a routine `apt upgrade` on a controller can move the
kernel, the NVIDIA driver, Docker, compose and Tailscale in one run. Tailscale
can restart into a silent control-plane stall, the next boot can hang on the
new kernel, and the fallback kernel may have no GPU driver. Recovery then
needs hands at the console and several reboots.

## Two classes of package

| Class | What | How it updates |
|---|---|---|
| everyday | libraries, applications, the desktop, security fixes | freely, any time, on any node |
| platform | kernel meta-packages, the NVIDIA driver and container toolkit, Docker (`docker-ce`, `-cli`, compose, buildx, `containerd.io`), `tailscale` | held; released on purpose, one node at a time |

The platform set is what the stack depends on: compose 2.40 or newer, a GPU
runtime the backends can use, and Tailscale for the tailnet bind and the
`ts.net` door. A Docker upgrade also restarts every container on the node.

## Hold the platform packages (once per Linux node)

The package names differ by distribution (Pop!_OS ships `linux-system76`,
Ubuntu `linux-generic`, Raspberry Pi OS its own kernel packages), so hold
whatever of the set is installed rather than a fixed list:

```sh
dpkg-query -W -f='${Package}\n' \
  | grep -E '^(linux-(generic|image-generic|headers-generic|system76)|linux-image-rpi.*|raspberrypi-kernel|nvidia-(driver|dkms|utils|kernel-common|kernel-source)-[0-9]+|system76-driver-nvidia|nvidia-container-toolkit(-base)?|libnvidia-container(1|-tools)|docker-ce(-cli)?|docker-(compose|buildx)-plugin|containerd\.io|tailscale)$' \
  | xargs -r sudo apt-mark hold
apt-mark showhold
```

`sudo apt upgrade` then lists these as "kept back". That is the point; it is
not an error.

Not covered here: a **WSL2** node's kernel and GPU driver come from Windows
(update them through Windows Update and the NVIDIA Windows driver, on the same
canary-first rule); a **macOS** node has no apt, and its agent updates with
the `noo` CLI.

## Release a platform update

1. **Pick a canary**: a worker whose loss does not stop anything, with the
   same kind of GPU as the nodes that will follow (an NVIDIA node for an
   NVIDIA driver change).
2. **Unhold only what you are moving** on the canary, upgrade, and reboot:
   ```sh
   sudo apt-mark unhold <packages>
   sudo apt upgrade
   sudo reboot
   ```
3. **Verify** from the controller:
   ```sh
   noo cluster verify <canary>
   ```
   Every row should pass. Besides the node's own invariants, `verify` reads
   what the node's `noo-hostd` reports about the host: which kernel the next
   boot runs (`next boot`), whether the NVIDIA module exists for it and for
   the fallback entry (`gpu driver`), whether the EFI System Partition has room
   and holds an intact copy of the next boot's initramfs (`boot partition`;
   FAIL on a truncated copy, WARN on a full ESP or an outsized initramfs from
   uncompressed DKMS modules; the FAIL remedy pins a known-good entry with
   `bootctl set-default` FIRST and says not to run `kernelstub` while the ESP
   lacks room, because kernelstub rotates the `*-previous` fallback copies),
   whether the platform packages are held
   (`holds`), and whether Tailscale is connected to its control plane and not
   just to its peers (`tailnet control`). On the node: `nvidia-smi` lists the GPU (NVIDIA
   nodes), `tailscale status` shows the node online, and
   `journalctl -u tailscaled | grep "long-poll timed out"` is empty.
4. **Let it run for a day.** A Tailscale stall can take minutes
   to appear, and nothing on the noomesh side notices it.
5. **The other workers**, one at a time, verifying each.
6. **The controller last**, when someone is at its console, after the
   pre-reboot check below.
7. **Re-hold** on every node: run the hold command again.

## Before rebooting the controller

`noo cluster verify <controller-node>` answers most of this: the `next boot`,
`gpu driver`, `boot partition`, `holds` and `tailnet control` rows are the checks below, read
from the node itself.

- **The fallback kernel is the one running now.** On Pop!_OS the boot menu's
  "oldkern" entry is whatever kernelstub last moved there, and it can
  be a kernel with no NVIDIA module. Before a kernel change, record the
  running kernel (`uname -r`) — if the new one fails, that is the entry to
  boot, and
  ```sh
  sudo kernelstub -k /boot/vmlinuz-<running> -i /boot/initrd.img-<running>
  ```
  makes it the default again.
- **The GPU driver is built for the new kernel.** `dkms status` lists the
  NVIDIA module against it. Necessary, not sufficient: a module can be
  built and the boot still hang. Only the canary proves a kernel and driver
  pair boots.
- **The tailnet bind survives the boot order.** With `NOO_BIND_MODE=tailnet`,
  `noo doctor exposure` must not report `boot_safe: false`; if it does, it
  prints the one-line sysctl that fixes it.

## If the controller does not come back

1. At the console: if it is stuck on the logo, press **Esc** to see the boot
   messages.
2. Power off, power on holding **Space** (Pop!_OS, systemd-boot) and choose
   the previous kernel. If that also hangs, press **e** on the entry and add
   `nomodeset` to boot without the GPU driver.
3. Once up, make the known-good kernel the default (kernelstub, above) and
   read the failed boot with `journalctl -b -1`. A boot that hung before the
   root filesystem mounted leaves no journal at all.
4. The stack restarts on its own. `noo cluster verify` confirms every node
   reconnected; `docker ps -a` shows any backend left in `Created` by a boot
   without the GPU driver (safe to remove).

## If the GPU does not answer when the stack starts

A GPU fault at container start (the CDI error `error getting device handle
for index '0': Unknown Error`, an `nvidia-container-cli` or NVML error) holds
only the services that need the GPU. The launcher names each one ("… is
held: the GPU did not answer when it started"), starts everything else (the
gateway, the database, monitoring, the embed doors) and exits 75, which
`noo upgrade --stack` reports as "stack up except <service>". The CPU
embedder (profile `embed-cpu`, when enabled) takes the embeddings
meanwhile; the gateway already treats it as a peer endpoint.

`noo cluster verify --controller` keeps the hold visible in its
`GPU services` row. A GPU driver fault clears with a reboot of the host;
then `noo stack start` starts the held services.
