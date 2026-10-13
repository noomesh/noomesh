# WSL2 Disk Footprint

If your controller runs inside a WSL2 distro, the distro is a sparse `.vhdx`
file on Windows, and ext4 never hands freed blocks back to the host. So
`docker system prune` reclaims space *inside* the distro while the `.vhdx`
on Windows stays the same size or keeps growing. Four layers keep that under
control; apply all four and the manual compact becomes rare.

See what Docker is holding first:

```bash
docker system df -v
```

## Layer 1 — compose-level log caps (already in the stack)

`docker-compose.cluster.yml` defines an `x-default-logging` anchor
(`json-file`, `max-size: 50m`, `max-file: 3`) and applies it to every
service. Without it the json-file driver writes unbounded stdout/stderr to
`/var/lib/docker/containers/<id>/<id>-json.log`, the single biggest source
of silent disk creep on a long-running stack.

Nothing to do for new containers. To apply it to containers created before
the cap existed, recreate them: `noo stack restart --force`.

## Layer 2 — daemon-level fallback (one-time host setup)

For containers the stack does not manage (build helpers, ad-hoc
`docker run`s, side projects), set the same caps at the daemon so they
inherit them. Inside WSL:

```bash
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json >/dev/null <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "50m", "max-file": "3" },
  "builder": { "gc": { "enabled": true, "defaultKeepStorage": "5GB" } }
}
EOF
sudo systemctl restart docker      # or restart from the Docker Desktop UI if it owns the daemon
```

The `builder.gc` block caps the BuildKit cache, which otherwise grows
monotonically across rebuilds. It is a backstop for direct `docker build`s;
the stack's own rebuild prunes itself (layer 3).

## Layer 3 — rebuild-time pruning (already in the stack)

`scripts/noomesh-rebuild.sh` (what `noo stack rebuild` runs) prunes after
each build:

- `docker image prune -f` — dangling images from this build
- `docker builder prune -f --reserved-space <NOO_BUILD_CACHE_KEEP>` (default
  `20GB`; the older `--keep-storage` flag is used on daemons that predate
  the rename) — on a failed build the cache is dropped entirely
- `docker volume prune -f` — orphaned anonymous volumes
- after the stack is up, `docker image prune -a -f` for unused tagged
  images, sparing anything labelled `noo.image.keep=true`
- truncates any container log that has already grown past 60 MB (the cap
  in layer 1 only rotates files created after it was set)

So a normal rebuild cycle leaves disk usage roughly constant.

## Layer 4 — periodic `.vhdx` compact (the only thing that shrinks the file)

Layers 1–3 prevent growth; only `Optimize-VHD` with WSL shut down actually
shrinks the file. `scripts/wsl-vhdx-compact.ps1` does it end to end: it
finds the distro's `ext4.vhdx` through the WSL registry (works for
`wsl --import`ed distros on any drive, not only Store installs under
`LOCALAPPDATA`), runs `wsl --shutdown`, runs `Optimize-VHD`, and prints the
before/after sizes. Override discovery with `-DistroName <name>` or
`-VhdxPath <path>`.

Because the script shuts WSL down, a scheduled run must execute a
**Windows-native copy** — a `\\wsl.localhost\…` path becomes unreachable
mid-run. From an elevated PowerShell:

```powershell
$dst = "$env:LOCALAPPDATA\pai\wsl-vhdx-compact.ps1"
New-Item -ItemType Directory -Force (Split-Path $dst) | Out-Null
Copy-Item "\\wsl.localhost\Ubuntu\home\<your-wsl-user>\noomesh\scripts\wsl-vhdx-compact.ps1" $dst -Force

# run it once
& $dst

# or schedule it weekly
$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File $dst"
$trigger   = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -RunLevel Highest
Register-ScheduledTask -TaskName 'PAI WSL VHDX Compact' -Action $action -Trigger $trigger -Principal $principal
```

Re-copy the script after editing it. Each run appends one JSON line
(`ts`, `vhdx`, `before_mb`, `after_mb`, `reclaimed_mb`) to
`logs/vhdx-compact.jsonl` beside the repo when reachable, else to
`%LOCALAPPDATA%\pai\vhdx-compact.jsonl`. If a typical weekly compact
reclaims less than a few hundred MB, layers 1–3 are doing their job and
you can drop the schedule to monthly.

## When the compact does not help

If the `.vhdx` stays large after a compact, the growth is in **named
volumes** — `postgres-data`, `redis-data`, `nats-data`, `ollama-data`,
`hf-cache`, `noo-data` — which no prune touches because they hold your
data and model weights. `docker system df -v` shows them under
`LOCAL VOLUMES`. Deleting from those is a separate decision: model weights
can be re-pulled (`noo models pull`), ingested knowledge cannot.

## Two Docker disks

Docker Desktop and some WSL setups put image layers (containerd) on one
virtual disk and volumes on another. `df` inside the distro then reports
the wrong disk for the space you are chasing. Read `docker system df -v`
rather than `df`, and never reap containerd leases by hand to free image
space — a lease can be pinning the read-write layer of a *running*
container, and deleting it turns into silent write failures inside that
container. Use `noo stack clean --cache` / `--images` (which go through
Docker's own reference counting) and the bounded reclaim that the
`disk_watermark` autonomy location can queue for noo-hostd.
