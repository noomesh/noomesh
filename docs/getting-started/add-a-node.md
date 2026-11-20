# Add a node

Covers: putting a second machine to work for your cluster, from the controller's token to a node that `noo cluster verify` passes.

Does not cover: the controller's own install ([install.md](install.md)), kiosk displays (a display is a seat, never a node: [kiosk.md](kiosk.md)), or removing a node ([start-over.md](start-over.md)).

## For people

On the **controller**, mint a one-time token for the new node:

```sh
noo cluster bootstrap-token create --node <node>
```

It prints two steps for the new machine: install `noo` (skip it if `noo --version` already works there), then a `noo enroll noo1.…` line. Run both on the **new machine** as your own user; enroll asks for your sudo password (a person types it, unless that machine has passwordless sudo).

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
  - It prints two steps for the node: install `noo` (skip it if `noo --version`
    works), then the enrollment line (`noo enroll noo1.…`).
  - The line holds a single-use token: don't paste it into chats, issues or
    logs. It is spent on first use, and an unused one expires (`--ttl`).
- **Refusals at mint:**
  - `node_name` must be ≤ 64 characters of `[a-zA-Z0-9._-]`;
  - `localhost` and `node-agent` are refused (every node certificate carries
    them);
  - a name another machine already holds is refused at redemption, before the
    token is spent.
- **Enroll** on the node: `noo enroll <noo1.blob>`, the exact line mint printed.
  There is no `noo enroll <controller-url>` form.
  - Without Tailscale: `--skip-tailscale`.
  - Run it on the node AS ITS OWN USER, not under sudo. It calls `sudo` itself,
    several times (`tailscale up`, reading the root-owned PKI anchor, host prep),
    and a person types the password unless that machine has passwordless sudo.
    Never wrap it in sudo yourself.
- **Provision** on the controller: `noo cluster provision <node> --wait [<secs>]`.
  It stages the node's signed bundle, waits for the node's first heartbeat, then
  waits until it has applied its bundle (up to 1800 s by default). Run it in the
  background, pass a smaller number, or poll `noo --json cluster verify <node>`.
- **Check (the one "done" test):** `noo --json cluster verify <node> --wait`.
  Exit 0 means done; exit 1 means run each failing row's remedy.
  - Any `"verdict": "fail"` row is a blocker; its `remedy` is the command to run.
  - For a new node, the rows that matter first are `agent address`,
    `agent certificate` and `harness egress`.
- **Without a tailnet,** behind a proxy or Docker Desktop, the node's
  certificate can miss the address the controller dials (`agent certificate`
  FAIL). Fix it with `noo security pki push-nodes <node>` when the row offers
  it. When it gives no remedy, the address is another node's: stop and report.
