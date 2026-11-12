# Start over

An install went wrong and you want your machines back to "never installed",
so you can run the install line again. This page is that path. It removes
noomesh, its data and its secrets. It does not touch the rest of your machine.

Two commands do almost all of it:

- `noo offboard` tears down the **controller** (the box you ran the install
  line on), including its own node.
- `noo cluster teardown-node` tears down each **other node**, from the
  controller, while the controller is still up.

Order matters. Tear down the other nodes first, then the controller. A node
whose controller is already gone has no one left to tell it to leave (see
[If you wiped the controller first](#if-you-wiped-the-controller-first)).

`noo stack reset` and `noo stack clean --deep` are **not** this. They wipe
and rebuild in place and keep `.env`, the model cache and other files (see
[Not the same thing](#not-the-same-thing-stack-reset-and-stack-clean)).

## One machine

Everything on one box (the usual first install):

```sh
noo offboard --check                 # what is installed (read-only; exit 1 = something is there)
noo offboard -y --purge-secrets      # remove it all, secrets included
noo offboard --check                 # exit 0: nothing of noomesh is left
```

`offboard` walks the steps in order:

1. it stops the self-heal daemons;
2. it removes the stack: its containers, its volumes (**all data**) and its networks;
3. it removes the pulled images;
4. it removes the host daemons and their files under `/etc/noo` (keys,
   certificates, secrets);
5. it removes the storage root, the cluster CA from the OS trust store, and
   the Tailscale serve config and identity;
6. it removes the install home.

`-y` accepts each step. Three things need their own flag:

- `--purge-secrets` deletes the age key and `~/.config/mesh` (the CLI's
  login and its model cache). Without the flag an interactive run asks,
  and the answer defaults to No.
- `--uninstall` also removes the `noo` binary and its shell completion. Leave
  it off if you are about to reinstall: the install line replaces the binary.
- `--keep-tailnet` keeps this machine on your tailnet.

Then run the install line from the [install guide](install.md) again.

## A controller and other nodes

On the controller, with its stack running:

```sh
noo cluster teardown-node --all --factory -y    # every node except this box
noo offboard -y --purge-secrets                 # then the controller, as above
noo offboard --check
```

`teardown-node` does not log in to the node. It leaves a signed teardown
order where the node collects its updates. The node picks it up on its next
fetch and dismantles itself:

- the agent and its update timer stop;
- the noomesh binaries and `/etc/noo` are removed;
- with `--factory` (or `--purge-data`), its data root (models and caches)
  goes too.

The controller waits up to four minutes for the node to collect the order.
It then waits until the node stops reporting in, prints
`<node>: teardown verified`, and removes the node's certificates and its
entry in the registry.

`--factory` is `--purge-data` plus `--purge-tailscale`:

- The node always logs out of Tailscale.
- `--purge-tailscale` also removes the Tailscale package (only if noomesh
  installed it) and deletes the node's **device record** from your tailnet.
- Without it, and with no terminal to ask you on, the record is kept. The
  node's next enroll then registers as `<name>-1`. The command says so, and
  you can delete the record in the Tailscale admin console.

One node at a time, keeping its data:

```sh
noo cluster teardown-node gpu-2 -y
```

**A node that is switched off** cannot collect its order, so switch it on
before you run the command. For hardware that is gone for good, drop it
from the registry instead:

```sh
noo cluster forget gpu-2 --purge-tailscale
```

### If you wiped the controller first

The nodes still have their agent, and they still trust the old controller.
Their next enroll against a new controller is refused. On each such node:

```sh
sudo noo-deenroll                    # add --purge-data to drop its models and caches
```

## What stays on purpose

Starting over removes noomesh. These things belong to your machine, not to
noomesh, and are left alone:

- Docker, and its build cache;
- the NVIDIA driver and container toolkit;
- the Tailscale package on the controller;
- your backups in `~/noo-backups`;
- on a node, `/var/log/noo-deenroll.log`, the record of its own teardown.

## Not the same thing: stack reset and stack clean

These keep the install and rebuild parts of it:

- `noo stack reset --dist` wipes and **reinstalls** in place. It runs a deep
  clean, the setup wizard and a start. `.env` is never deleted: with
  `--keep-env` it is put back as it was, and without it the wizard may
  rewrite it.
- `noo stack clean --deep -y` wipes the database, cache and bus data under
  the data root, the PKI and the noomesh secret files. It keeps:
  - `.env`;
  - the model cache;
  - everything else under the data root.
  It also removes **every unused Docker image on the machine**, not only
  noomesh's.

See [stack and data](../cli/stack-and-data.md#clean-up-or-start-over) for
every flag.
