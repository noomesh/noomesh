# Networks and container hardening

What each Docker network carries, who may reach the database and the cache,
and which hardening the long-running controller containers run under.

## Networks

| Network | Internal | Members | Purpose |
|---|---|---|---|
| `noo-cluster` | no (external to compose, created by the launcher) | gateway, worker, trellion, the bus, the inference backends and their stunnel doors, the monitoring images, `model-cache` | everything that talks to the gateway |
| `noo-db` | **yes** | `postgres`, `redis`, and their clients: gateway, worker (and `worker-extra`), trellion, and the add-ons that use the database (trellion-intel, evolve) | the only network Postgres and Redis answer on |
| `noo-pg-host` | no | `postgres` only | lets Docker publish Postgres' host port |
| `noo-sandbox` | **yes** | gateway, worker, trellion, `sandbox` | the code-execution link, no egress |
| `noo-browser` | no | gateway, worker, trellion, `browser` | the headless browser, which has to reach the web |

### Postgres and Redis are on `noo-db` only

A container on `noo-cluster` that is not a database client has no route to
`postgres:5432` or `redis:6379`. That matters because `noo-cluster` holds
software that parses untrusted input (inference backends reading model files,
nginx, the monitoring images, tool code in the worker): a compromise of one of
them reaches the database only if it can open a connection, and it cannot.
The TLS client-certificate requirement and the role passwords stay in front of
the database as before; the network is what keeps a leaf stolen from another
container from being tried against them.

`noo-db` is `internal: true`, and Docker does not publish a port for a
container attached only to internal networks. Postgres' host publish
(`127.0.0.1:5433`, or `POSTGRES_BIND` for a warm standby) therefore goes
through `noo-pg-host`, a bridge that holds Postgres and nothing else.
Redis publishes no port.

`tests/test_db_networks_are_isolated.py` holds the member list. Adding a
service to `noo-db` is a reviewed edit of that file.

### Why `pg_hba.conf` does not map certificate names to roles

Every TCP client already needs a certificate from the cluster CA **and** its
role password. Narrowing that to "only the gateway's, the worker's and
trellion's leaf" inside Postgres is not expressible: a `map=` is accepted
only for the ident, peer, gssapi, sspi and cert methods, not for
`scram-sha-256`, and `clientcert=verify-full` without a map requires the
certificate's CN to equal the database role, while the stack's leaves are
named for the service holding them and several roles share one leaf. The
`cert` method would take a map but would remove the password from the TCP
path. The network above is the control instead. Redis cannot restrict clients
by certificate name at all.

The `local` (unix socket) rules stay `trust`: the socket exists only inside
the container, the backup script, `noo security secrets rotate` and the
health check connect over it as the role `noo` from an OS user that is not
named `noo` (so `peer` would refuse them), and first initialisation runs
before any role exists. Reaching it takes `docker exec`, which is
root-equivalent on the host already.

## Backend doors

Each inference backend that has no TLS listener of its own sits behind a
stunnel sidecar that requires a client certificate from the cluster CA
(`verify = 2`). The TEI, TEI GPU and reranker doors additionally pin the peer
by the DNS name in its leaf (`checkHost`): only the gateway, worker, trellion,
trellion-intel and evolve leaves pass the handshake, so a node's or a
monitoring container's certificate is refused. The ollama, ollama-embed,
ollama-embed-cpu and llamacpp doors are also dialled by the controller's own
node-agent with its node certificate, whose names a static file cannot list
and which stunnel cannot match by organisation, so they require a cluster
certificate without naming the caller.

## Container hardening

| Service | `cap_drop` | `no-new-privileges` | Read-only root filesystem |
|---|---|---|---|
| `sandbox` | ALL (plus the few it adds back) | yes | yes |
| `gateway` | ALL | yes | no |
| `worker`, `worker-extra` | ALL | yes | no |

The gateway and the worker run as an unprivileged user, bind ports above 1024
and use no capability, so dropping all of them removes nothing they need.
Their root filesystem stays writable: the gateway writes the mounted
`noomesh.yaml`, prompts and compose override and starts helper processes that
write under their home and `/tmp`, and the worker's tools write where the
operator's configuration points. The worker mounts `noomesh.yaml` read-only
because nothing in it writes the file; the gateway's settings route does, so
the gateway keeps it read-write.

`NOO_NODE_AGENT_PRIVILEGED` defaults to `false` for the opt-in
`node-agent-compose` lane. The containerised agent holds no Docker socket and
never uses the GPU itself, so it needs no privilege; set it to `true` only for
a deliberate bootstrap that must reach a device.
