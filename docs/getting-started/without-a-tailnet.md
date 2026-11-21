# Nodes joined by a cable, or without a tailnet

The advanced path: a cluster whose machines reach each other by their local
network addresses (or over a direct Ethernet or Thunderbolt cable) instead of
a tailnet. The tailnet is the default and the easy path: every machine keeps a
name that does not change, so nothing here applies to it. Choose this page only
when a tailnet is not an option.

On this path, a router that hands out a new address after a power cut breaks
things: the nodes lose the controller, or the controller loses a node, until a
command is run. The tailnet path does not have that problem. That is the
reason to prefer the default. Done when `noo cluster verify` exits 0 and you
have made the controller's address one that does not move.

Covers: when to choose it, what it needs, the steps as they work on 0.6.29,
what breaks when an address moves and the command that fixes each case.

Does not cover: the default path ([add-a-node.md](add-a-node.md)), the
controller's own install ([install.md](install.md)), or a power cut on the
default path ([after-a-reboot.md](after-a-reboot.md)).

## For people

### When to choose it

- **Use the tailnet if you can.** It works across networks, survives every
  address change and needs no step on this page.
- Choose this path when the machines must not join a tailnet, or all sit on
  one local network you control.

### What it needs

- **An address for the controller that does not move.** Every node keeps the
  address it enrolled with and is never told a new one. If your router gives
  the controller a new address (after a power cut, say), every node loses it.
  Reserve the controller's address in your router (often called a DHCP
  reservation), or give it a name your network resolves.
- **Worker addresses may move**, but each move needs one command (below).
- **A direct cable** (Ethernet or Thunderbolt, no router) gives each end only
  a self-assigned address (169.254.x.x). noomesh refuses those as a node's
  address today. Give each end of the cable a fixed private address in its
  network settings instead. Not yet tested: whether this works end to end,
  and whether a tailnet uses the cable by itself (the commands to check that
  are under "Check which path traffic takes").

### The steps on 0.6.29

On the **controller**:

1. Onboard without Tailscale. Answer the question that follows with your local
   network, so other machines can reach the gateway. `noo doctor exposure`
   shows what that opens.
2. Set `services.gateway_url` in `noomesh.yaml` to the address nodes will use,
   for example `https://192.0.2.10:8080` (your controller's reserved address,
   or its name), then restart the gateway:

   ```sh
   noo stack restart gateway
   ```

   Until this is set, minting a token refuses: the controller would hand out
   an address no other machine can reach.
3. Mint a token for the new node, without a tailnet key:

   ```sh
   noo cluster bootstrap-token create --node <node> --no-tailscale
   ```

On the **new machine**, run the two lines it printed, adding `--skip-tailscale`
to the enroll line:

```sh
noo enroll noo1.<blob> --skip-tailscale
```

Back on the **controller**:

```sh
noo cluster provision <node> --wait
noo cluster verify <node>
```

### When an address moves

- **A node's certificate does not cover the address the controller dials.**
  verify's `agent certificate` row FAILs, and the agent's log shows
  `tls: bad certificate`. This happens behind a proxy or Docker Desktop, after
  a worker's address changed, and on 0.6.29 after a roll (`noo upgrade`) on a
  node whose enrollment address is not the one the controller dials.
  Fix it with:

  ```sh
  noo security pki push-nodes <node>
  ```

  If the row gives no command, the address belongs to another node: stop and
  find out why before issuing anything.
- **The controller's address changed.** Every node lost the controller, and
  nothing sent from the controller reaches them. Give the controller its old
  address back (reserve it in your router, then restart the machine).
  Otherwise: set `services.gateway_url` to the new address, restart the
  gateway, and enroll each node again with a fresh token (the steps above).
  Not yet run end to end on 0.6.29.

### Check which path traffic takes

On one end of a cable, with both machines on a tailnet (not yet run):

```sh
tailscale status
tailscale ping <other-machine>
ip route get <address from the ping>
```

`tailscale status` says `direct` or `relay` for the other machine. `tailscale ping`
prints the address it went `via` and the time; well under a millisecond
suggests the cable. `ip route get` names the interface (on macOS,
`route get <address>`).

## For agents

- Read-only. Diagnose with `noo --json cluster verify <node>`; the rows that
  matter here are `agent certificate`, `agent address`, `agent metrics` and
  (from 0.6.30) `controller address`.
- Never re-issue (`push-nodes`, `issue-node`), re-enroll, or edit a node's
  `/etc/noo/controller-url` or agent env yourself: report the row, its detail
  and its remedy to a person. An `agent certificate` FAIL with no remedy means
  the address is another node's: report it as that.
- `noo cluster provision` on a node whose address moved re-issues its
  certificate for its enrollment address, not its current one: never offer it
  as the fix for `agent certificate`.
- A node address of 169.254.x.x or fe80:: is refused by the gateway today;
  report it, do not work around it.
- The direct-cable statements on this page are marked not yet tested: say so
  when you repeat them.
