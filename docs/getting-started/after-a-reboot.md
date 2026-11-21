# After a power cut or reboot

What comes back by itself when the machines in a noomesh cluster restart,
how to see what did not, and the command that brings back each case that
does not come back on its own yet. Done when `noo cluster verify` exits 0.

## For people

### What comes back by itself

| Machine | What restarts on its own |
|---|---|
| **The controller** | Docker restarts the stack's containers. Then `noo-hostd` runs a boot restore once: it rewrites the secret files (they live in memory and a reboot empties them), starts the containers that need them and any stopped core service, and retries for about two minutes while Docker is still starting. Where `noo-hostd` is a user service, it runs at boot only if that user has linger on (see below). |
| **A Linux node** | Docker restarts the backends that were running, and the node agent starts at boot and reconnects. If the controller is not up yet, the backends keep serving; the agent logs once `the controller cannot be reached at <url> since <time>: nothing is reconciled until it answers; running backends keep running`, starts nothing new, and logs once more when the controller answers. A backend someone stopped stays stopped across the reboot; once the controller answers, the node starts it again if the cluster still places it there. |
| **A Mac node** | Its node agent starts at boot. Its Ollama does not, yet: see below. |
| **A kiosk seat** | Its display starts at boot, except, before 0.6.30, a dedicated seat on a machine with a desktop installed: see below. |

Give it a few minutes, then:

```bash
noo cluster verify --wait
```

It waits for the gateway and for rows that are still starting, then lists
what is not right, each row with the command that fixes it. Exit 0 means
everything came back. A node that reads "not reported yet" right after a
restart is timing, not a fault, and some rows, such as `ollama models`, may
be missing for the first minute: run it again after a minute (i1150).

### Known cases that do not come back on their own yet

Each one has a followup that removes the need for the step.

- **A network storage mount the controller uses did not come back.** A hung
  network mount (an NFS share whose server lost power) makes `noo upgrade`
  and any `docker` call that touches it wait without saying why. Bring the
  storage server back first: a `hard` mount resumes by itself once it
  answers (observed: a waiting `noo upgrade` moved on within seconds of the
  server returning, with nothing done on the controller). Do not
  force-unmount it to get past the wait: processes are blocked on it.
  Check with `timeout 5 stat <mount>` before you upgrade (a bare `stat`
  can hang too). (i1149: bounded calls and a verify row for hung mounts.)
- **The controller's stack did not come back until someone logged in.**
  `noo-hostd` restores the stack at boot. Its unit file says how it starts
  (`<user>` is the account that installed noomesh):
  - `/etc/systemd/system/noo-hostd.service` exists: a system service; it
    starts at boot, and this case does not apply;
  - otherwise `~<user>/.config/systemd/user/noo-hostd.service`: a user
    service, which starts at boot only if
    `loginctl show-user <user> -p Linger` says `Linger=yes`.

  Turn it on with `sudo loginctl enable-linger <user>`, then `noo stack restart`
  for this boot (`noo stack start` if that does not bring it back).
  From 0.6.30, `noo onboard` turns linger on, and `noo cluster verify` warns
  in a `hostd at boot` row, with this command, when it is off. (i1160.)
- **A dedicated kiosk seat on a machine that also has a desktop installed
  stays black** (0.6.29 and earlier). Its display waits behind the boot
  splash, which nothing tells to quit. At the seat: `sudo plymouth quit`; the
  display comes up at once. From 0.6.30 a NEW seat comes back after a reboot
  by itself. An EXISTING seat needs one command, once, on the seat, because
  a seat runs nothing as root after it is enrolled. On the seat, as the seat
  user: `sudo ~/.local/libexec/noo-seat/noo kiosk seat-sync --migrate` (a
  seat set up before 0.6.10: `sudo /usr/local/libexec/noo-seat/noo kiosk
  seat-sync --migrate`), or re-run kiosk setup. Verify's `kiosk unit` row
  for that seat warns until it is done. (i1153.)
- **`noo stack start` failed with "image pull failed 3 times"** while the
  network was still coming up (0.6.29 and earlier): a start pulled images
  even when all of them were present. Run `noo stack restart` (it never
  contacts the image registry), or wait for the network and run
  `noo stack start` again. (From 0.6.30 a start with every image present
  says "nothing to pull" and makes no registry connection; i1184.)
- **Logs stopped arriving and the gateway says `loki_down` while Loki is
  running** (only with monitoring turned on): Loki refuses every write once
  the disk holding its data is 90% full, with the same error it gives when
  shutting down. Free space on that disk; Loki resumes by itself within
  about 10 seconds (it checks the disk that often). (i1145.)
- **A backend's log looks empty, or ends at the moment of the stop, after
  an unclean stop** (a power cut, or the machine or VM killed): Docker can
  stop reading a container's log at the point where the stop cut it off,
  without an error, so a long tail shows only older lines and a `since`
  shows nothing. The newest lines are still there: `noo cluster logs <node>
  <backend>` with its default tail, or the logs in the console/Loki. It
  clears when that log rotates or the container is recreated. From 0.6.30
  `noo cluster logs` says so when it happens, with the time Docker stopped
  reading and the container's start. (i1225.)
- **A node came back on a new local address** (no tailnet): the
  `node_unreachable` alert, or verify's `agent certificate` row, says its
  certificate does not cover the address it now reports. Run
  `noo cluster verify <node>` and follow the row. If the address really is
  that node's (check on the node with `ip -brief addr`), the fix is
  `noo security pki push-nodes <node> --prove` (on 0.6.29, the plain
  `noo security pki push-nodes <node>`). A node on the tailnet is not
  affected, and needs no address reservation in your router. The
  controller's own address is different: without a tailnet it must not move
  ([without-a-tailnet.md](without-a-tailnet.md)).
  If verify instead shows the node's `agent address` row refused because
  another node claims the address, the new address belongs to a stale
  record, so the node keeps its old one and stays unreachable. Check that
  other node (`noo cluster verify <other>`); if it is gone, remove its record
  with `noo cluster forget <other>`, and the new address is accepted on the
  node's next heartbeat. Do not push a certificate: `--prove` refuses an
  address another node holds.
- **A Mac node's Ollama is not running.** Nothing registers it to start at
  boot: it starts only if it was set up to start at the node user's login,
  and that user has logged in. As the node's user, run
  `HOMEBREW_NO_ANALYTICS=1 brew services start ollama` (it starts now and
  at each login of that user). (i1156.)
- **A model file was never shipped to a node** (0.6.28 and earlier): the
  backend shows as running but crash-loops without its file. From the
  controller: `noo cluster sync-model-files <node> -m <file.gguf>`. The node
  pulls and verifies the file, and the backend finds it on its next restart
  (observed: serving about a minute later, no re-place). (Fixed in 0.6.29,
  i1154a: the node waits for the file and never starts the backend without
  it; `noo cluster show <node>` shows a `gguf_unavailable` start refusal
  instead, retried on every pass.)
- **`llamacpp offload` says a GPU model runs on the CPU** (0.6.28): that
  row can read "placed on gpu runs on the CPU … update the NVIDIA driver"
  while the model is on the GPU, because that llama.cpp build prints no
  offload line. Nothing needs fixing; a request pinned to the node shows
  the real speed: `noo inference run 'hi' -m <model> -n <node> --strict-node`.
  (Fixed in 0.6.29: the row reads OK with nvidia-smi's evidence, or not
  checked.)

The data disk itself not mounting is a separate refusal with its own page:
[data-root-recovery.md](../operating/runbooks/data-root-recovery.md). On a
node (0.6.30), a data disk that mounts late is refused, not written to. The
agent starts no backend and fetches nothing onto the empty mount point, and
it carries on by itself once the mount appears.

### Before the next power cut: powering on is the machine's setting

Nothing in noomesh can turn a machine on. Set each one to start when power
returns:

- **A PC or server:** in its firmware (BIOS/UEFI) setup, set "restore on AC
  power loss" (the name varies) to on or to the last state.
- **A desktop Mac (mini, Studio, iMac):** `sudo pmset autorestart 1`;
  laptops may ignore it. With FileVault on, a Mac that restarts stops at the
  unlock screen until someone types the password, and nothing runs until
  then, the node agent included.

## For agents

- **Diagnose, read-only:** `noo --json cluster verify --wait`; each failing
  row names the observed fact and its remedy. `noo cluster status` shows
  which nodes reported in. On the controller, hostd logs
  `BOOT-RESTORE WARN … still down: <services>` when a core service did not
  come back; `noo stack restart` is then the documented next step (it never
  contacts the image registry), and `noo stack start` the one after it.
- **A node that comes up before its controller** logs once `the controller
  cannot be reached at <url> since <time>: nothing is reconciled until it
  answers; running backends keep running`, and once
  `the controller at <url> answers again after <duration> away` when it does.
  `noo cluster verify` on that node says the same and lists the node-side
  checks. Report it; the node needs nothing while it waits.
- **Never** unmount (least of all force-unmount) or remount a filesystem, restart a host service
  (`systemctl`, `launchctl`, `brew services`), run `plymouth`, or reboot a
  machine. Each case above is the person's, at that machine.
- **A node address that moved:** never re-issue a certificate yourself
  (`push-nodes`, `--prove`); report the row and the address the node now
  has. **Loki refusing writes:** report the disk's use (`df`); never delete
  data to free space.
- **Never run `noo upgrade` while a mount may be hung:** it waits without
  saying why (i1149). Report the mount first.
- **Report** what you observed and the verify row it showed as (its `id`
  from [reference/verify-rows.md](../reference/verify-rows.md)), and name
  the case above that matches, with its command for the person.
