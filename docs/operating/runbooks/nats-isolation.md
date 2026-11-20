# NATS isolation

This page moved into
[security/networks-and-containers.md](../../security/networks-and-containers.md#nats-grants-render-them-before-upgrading-agents):
the node principal's NATS grants, and why they are rendered and the bus
reloaded before any node agent that pulls bulk embedding work is upgraded.

The history of the shared NATS user's retirement (the
`NOO_NATS_LEGACY_SHARED_CREDS` bridge, which a comment in
`monitoring/nats/nats-tls.conf` points here for) is in
[security-release-upgrade.md](security-release-upgrade.md).
