# Add a node

Covers: putting a second machine to work for your cluster, from the controller's token to a node that `noo cluster verify` passes.

Does not cover: the controller's own install ([install.md](install.md)), kiosk displays (a display is a seat, never a node: [kiosk.md](kiosk.md)), or removing a node ([start-over.md](start-over.md)).

## For people

On the **controller**, mint a one-time token for the new node:

```sh
noo cluster bootstrap-token create --node <node>
```

It prints one line that starts with `noo enroll`. On the **new machine**, install `noo` the same way you did on the controller ([install.md](install.md)), then paste that line as that machine's own user. It asks once for that machine's sudo password.

Back on the **controller**, hand the node its configuration and wait until it has applied it (this can take up to half an hour the first time):

```sh
noo cluster provision <node> --wait
noo cluster verify <node>
```

The node is ready when `verify` shows no FAIL. Each row that fails names the command that fixes it.

## For agents

<!-- fa: check every command, flag, refusal and remedy below against noo-cli before this merges -->

- **Mint** on the controller: `noo cluster bootstrap-token create --node <node>`.
  - Options: `[--ttl <1h|30m|24h|secs>] [--cidr <cidr>] [--role <role>]`,
    `[--with-tailscale|--no-tailscale]`.
  - The token is single-use and bound to `<node>`.
  - It prints the enrollment line (`noo enroll <noo1.blob>`). Treat the line as a
    secret: never write it to a file or a log, and never pass it in argv to
    another tool.
- **Refusals at mint:**
  - `node_name` must be ≤ 64 characters of `[a-zA-Z0-9._-]`;
  - `localhost` and `node-agent` are refused (every node certificate carries
    them);
  - a name another machine already holds is refused at redemption, before the
    token is spent.
- **Enroll** on the node: `noo enroll <noo1.blob>`, the exact line mint printed.
  There is no `noo enroll <controller-url>` form.
  - Without Tailscale: `--skip-tailscale`.
  - It runs as the node's own user and asks for a sudo password once, unless that
    machine has passwordless sudo. Otherwise a person runs it. Never run `sudo` on
    a remote node yourself.
- **Provision** on the controller: `noo cluster provision <node> --wait [<secs>]`.
  It stages the node's signed bundle and blocks until the node has enrolled and
  applied it, which can take up to 30 minutes on a first install. Run it in the
  background, or stage it and poll `noo --json cluster verify <node>`.
- **Check (the one "done" test):** `noo --json cluster verify <node> --wait`.
  Exit 0 means done; exit 1 means run each failing row's remedy.
  - Any `"verdict": "fail"` row is a blocker; its `remedy` is the command to run.
  - For a new node, the rows that matter first are `agent address`,
    `agent certificate` and `harness egress`.
- **Without a tailnet,** behind a proxy or Docker Desktop, the node's
  certificate can miss the address the controller dials (`agent certificate`
  FAIL). Fix it with `noo security pki push-nodes <node>` when the row offers
  it. When it gives no remedy, the address is another node's: stop and report.
