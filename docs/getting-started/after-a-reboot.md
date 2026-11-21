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
| **A kiosk seat** | Its display starts at boot, except a dedicated seat on a machine with a desktop installed: see below. |

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
  storage server back first: a `hard` mount resumes by itself once it
  answers (observed: a waiting `noo upgrade` moved on within seconds of the
  server returning, with nothing done on the controller). Do not
  force-unmount it to get past the wait: processes are blocked on it.
  Check with `timeout 5 stat <mount>` before you upgrade (a bare `stat`
  can hang too). (i1149: bounded calls and a verify row for hung mounts.)
- **A dedicated kiosk seat on a machine that also has a desktop installed
  stays black.** Its display waits behind the boot splash, which nothing
  tells to quit. At the seat: `sudo plymouth quit`. The display comes up at
  once. (i1153: fixed in 0.6.30.)
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
  (observed: serving about a minute later, no re-place). (Fixed in 0.6.29:
  i1154a.)
- **`llamacpp offload` says a GPU model runs on the CPU** (0.6.28): that
  row can read "placed on gpu runs on the CPU … update the NVIDIA driver"
  while the model is on the GPU, because that llama.cpp build prints no
  offload line. Nothing needs fixing; a request pinned to the node shows
  the real speed. (Fixed in 0.6.29.)

The data disk itself not mounting is a separate refusal with its own page:
[data-root-recovery.md](../operating/runbooks/data-root-recovery.md).

## For agents

- **Diagnose, read-only:** `noo --json cluster verify --wait`; each failing
  row names the observed fact and its remedy. `noo cluster status` shows
  which nodes reported in. On the controller, hostd logs
  `BOOT-RESTORE WARN … still down: <services>` when a core service did not
  come back; `noo stack start` is then the documented next step.
- **Never** unmount (least of all force-unmount) or remount a filesystem, restart a host service
  (`systemctl`, `launchctl`, `brew services`), run `plymouth`, or reboot a
  machine. Each case above is the person's, at that machine.
- **Never run `noo upgrade` while a mount may be hung:** it waits without
  saying why (i1149). Report the mount first.
- **Report** what you observed and the verify row it showed as (its `id`
  from [reference/verify-rows.md](../reference/verify-rows.md)), and name
  the case above that matches, with its command for the person.
