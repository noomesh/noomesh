# After a power cut or reboot

What comes back by itself when the machines in a noomesh cluster restart,
how to see what did not, and the command that brings back each case that
does not come back on its own yet. Done when `noo cluster verify` exits 0.

## For people

### What comes back by itself

| Machine | What restarts on its own |
|---|---|
| **The controller** | Docker restarts the stack's containers. Then `noo-hostd` runs a boot restore once: it rewrites the secret files (they live in memory and a reboot empties them), starts the containers that need them and any stopped core service, and retries for about two minutes while Docker is still starting. Where `noo-hostd` is a user service, it runs at boot only if that user has linger on (see below). |
| **A Linux node** | Docker restarts the backends that were running, and the node agent starts at boot and reconnects. If the controller is not up yet, the backends keep serving; the agent logs once `the controller cannot be reached at <url> since <time>: nothing is reconciled until it answers; running backends keep running`, starts nothing new, and logs once more when the controller answers. A backend someone stopped stays stopped until then. |
| **A Mac node** | Its node agent starts at boot. Its Ollama does not, yet: see below. |
| **A kiosk seat** | Its display starts at boot, except a dedicated seat on a machine with a desktop installed: see below. |

Give it a few minutes, then:

```bash
noo cluster verify --wait
```

It waits for the gateway and for rows that are still starting, then lists
what is not right, each row with the command that fixes it. Exit 0 means
everything came back. A node that reads "not reported yet" right after a
restart is timing, not a fault: run it again after a minute (i1150).

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
  for this boot (`noo stack start` if that does not bring it back). (i1160, #1507: 0.6.30's onboard turns it on, and verify gets
  a `hostd at boot` row.)
- **A dedicated kiosk seat on a machine that also has a desktop installed
  stays black.** Its display waits behind the boot splash, which nothing
  tells to quit. At the seat: `sudo plymouth quit`. The display comes up at
  once. (i1153: the fix is planned for 0.6.30; this step goes when it lands.)
- **`noo stack start` failed with "image pull failed 3 times"** while the
  network was still coming up (0.6.29 and earlier): a start pulled images
  even when all of them were present. Run `noo stack restart` (it never
  contacts the image registry), or wait for the network and run
  `noo stack start` again. (From 0.6.30 a start with every image present
  says "nothing to pull" and makes no registry connection; i1184.)
- **Logs stopped arriving and the gateway says `loki_down` while Loki is
  running** (only with monitoring turned on): Loki refuses every write once
  the disk holding its data is 90% full, with the same error it gives when
  shutting down. Free space on that disk; Loki checks every ten seconds and
  resumes by itself. (i1145.)
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
- **A Mac node's Ollama is not running.** Nothing registers it to start at
  boot: it starts only if it was set up to start at the node user's login,
  and that user has logged in. As the node's user, run
  `HOMEBREW_NO_ANALYTICS=1 brew services start ollama` (it starts now and
  at each login of that user). (i1156: `noo enroll` will register it as a
  boot service.)
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
[data-root-recovery.md](../operating/runbooks/data-root-recovery.md).

### Before the next power cut: powering on is the machine's setting

Nothing in noomesh can turn a machine on. Set each one to start when power
returns:

- **A PC or server:** in its firmware (BIOS/UEFI) setup, set "restore on AC
  power loss" (the name varies) to on or to the last state.
- **A Mac:** `sudo pmset autorestart 1`. With FileVault on, a Mac that
  restarts stops at the unlock screen until someone types the password, so
  it comes back only after that.

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
