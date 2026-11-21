# After a power cut or reboot

What comes back by itself when the machines in a noomesh cluster restart,
how to see what did not, and the command that brings back each case that
does not come back on its own yet. Done when `noo cluster verify` exits 0.

## For people

### What comes back by itself

| Machine | What restarts on its own |
|---|---|
| **The controller** | Docker restarts the stack's containers. Then `noo-hostd` runs a boot restore once: it rewrites the secret files (they live in memory and a reboot empties them), starts the containers that need them and any stopped core service, and retries for about two minutes while Docker is still starting. |
| **A Linux node** | Its node agent starts at boot, reconnects to the controller and starts the backends placed on it. |
| **A Mac node** | Its node agent starts at boot. Its Ollama does not, yet: see below. |
| **A kiosk seat** | Its display starts at boot, except on some dedicated seats: see below. |

Give it a few minutes, then:

```bash
noo cluster verify --wait
```

It waits for the gateway and for rows that are still starting, then lists
what is not right, each row with the command that fixes it. Exit 0 means
everything came back.

### Known cases that do not come back on their own yet

Each one has a followup that removes the need for the step.

- **A network storage mount the controller uses did not come back.** A hung
  network mount (an NFS share whose server lost power) makes `noo upgrade`
  and any `docker` call that touches it wait without saying why. Bring the
  storage server back first; a hard mount resumes by itself once it
  answers. Check with `timeout 5 stat <mount>` before you upgrade.
  (i1149: bounded calls and a verify row for hung mounts.)
- **A dedicated kiosk seat stays black.** Its display waits behind the boot
  splash, which on some seats is never told to quit. At the seat:
  `sudo plymouth quit`. The display comes up at once. (i1153.)
- **A Mac node's Ollama is not running.** It is registered to start when
  the node's user logs in, not at boot. Log in on the Mac, or as the node's
  user run `HOMEBREW_NO_ANALYTICS=1 brew services start ollama`. (i1156:
  `noo enroll` will register it as a boot service.)
- **A model file was never shipped to a node** (0.6.28 and earlier): the
  backend shows as running but crash-loops without its file. From the
  controller: `noo cluster sync-model-files <node>`. (i1154a.)

The data disk itself not mounting is a separate refusal with its own page:
[data-root-recovery.md](../operating/runbooks/data-root-recovery.md).

## For agents

- **Diagnose, read-only:** `noo --json cluster verify --wait`; each failing
  row names the observed fact and its remedy. `noo cluster status` shows
  which nodes reported in. On the controller, hostd logs
  `BOOT-RESTORE WARN … still down: <services>` when a core service did not
  come back; `noo stack start` is then the documented next step.
- **Never** unmount or remount a filesystem, restart a host service
  (`systemctl`, `launchctl`, `brew services`), run `plymouth`, or reboot a
  machine. Each case above is the person's, at that machine.
- **Never run `noo upgrade` while a mount may be hung:** it waits without
  saying why (i1149). Report the mount first.
- **Report** what you observed and the verify row it showed as (its `id`
  from [reference/verify-rows.md](../reference/verify-rows.md)), and name
  the case above that matches, with its command for the person.
