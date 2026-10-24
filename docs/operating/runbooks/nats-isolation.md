# NATS isolation: grant changes and upgrade order

The node principal's NATS grants are rendered into `users.conf` by
`noo cluster nats-users render`. NATS drops a denied publish and reports
success to the caller, so a node whose grant is missing a subject does not
fail: it keeps heartbeating and silently does nothing.

## Grants before agents

Render the grants and reload NATS **before** upgrading any node agent that
pulls bulk embedding work. Such an agent binds an existing JetStream pull
consumer on stream `WORK_EMBED`, which needs three publish grants that an
older `users.conf` does not carry:

- `$JS.API.CONSUMER.INFO.WORK_EMBED.*`
- `$JS.API.CONSUMER.MSG.NEXT.WORK_EMBED.*`
- `$JS.ACK.WORK_EMBED.*.>`

```sh
noo cluster nats-users render
docker kill -s HUP noo-nats      # render signals it too; this is the fallback
```

A node never creates or deletes these consumers and has no stream API: the
gateway declares the stream and the consumers. Upgrading the agent first
leaves it unable to pull, with nothing logged on either side.

See [security-release-upgrade.md](security-release-upgrade.md) (step C2) for
the full bus rollout and the credential rotation that follows a render.
