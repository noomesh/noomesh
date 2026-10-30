// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Per-command usage: argument syntax + a one-line description for every
//! native command in `main::NATIVE`. Rendered by `noo <words> --help` and by
//! the "did not understand these arguments" usage error (exit 2). A test in `main.rs` pins this table to the registry 1:1,
//! so adding a native command without a usage line fails the build's tests.
//!
//! Conventions: syntax lists the command's OWN arguments only (no `noo`, no
//! command words, no globals); `<x>` required, `[x]` optional, `...`
//! repeatable, ` | ` alternatives. Descriptions are one imperative
//! sentence, no trailing period.

pub const USAGE: &[(&[&str], &str, &str)] = &[
    (&["whoami"], "", "Report what this box is: controller, node, both, or client-only"),
        (&["cluster", "status"], "", "List nodes: tier, status, RUNNING backends, CAPABILITIES by role, CAN-RUN"),
        (&["cluster", "verify"], "[<node>...] [--controller] [--wait]", "Assert every invariant a node and the controller must meet; exit 1 with the remedy"),
        (&["cluster", "invite"], "", "Mint a tagged tailscale auth key and print the `noo enroll --via-tailnet <url>` line"),
        (&["cluster", "down"], "<backend> [--node <node>] [-y|--yes]", "Stop a backend on one node or all nodes; destructive, asks for confirmation (-y)"),
        (&["cluster", "desired"], "<node>", "Alias of show: the node in full, with its desired config and every placement"),
        (&["cluster", "proposals"], "[--status <s>] [--limit <n>]", "List the enrollment proposals agents filed, with each host in full"),
        (&["cluster", "show"], "<node>", "Show one node in full: hardware, agent version, tier drift, bus principal, roles"),
        (&["cluster", "forget"], "<node> [--purge-tailscale] [-y|--yes]", "Remove a dead node's row, KV entry and enrollments; --purge-tailscale drops its device"),
        (&["cluster", "place"], "<node> <backend|harness> <model|auto> [--on cpu|gpu] [--env KEY=VALUE]... [--kind noo|claude-code|copilot|codex] [--role chat|embed|rerank] [--port <port>] [--tls] [--image <image>] [--stopped] [--force]", "Declare a backend and model in a role on a node, on cpu or gpu; auto-tunes unless --env"),
        (&["cluster", "unplace"], "<node> <backend> [--role chat|embed|rerank] [--model <model>]", "Remove a placement, or one embed model; a container keeps running, a harness is stopped"),
        (&["cluster", "fit"], "<node> [--with <backend> <model> [--on cpu|gpu] [--role <role>] [--env KEY=VALUE]...]", "Show whether placements fit a node's GPU memory and RAM, with or without one more"),
        (&["cluster", "class", "list"], "", "Show the model classes consumers may send as `model`, with candidate placement and health"),
        (&["cluster", "class", "set"], "<class> <node>/<backend>[=<model>]... [--degraded <node>/<backend>[=<model>]]... [--alias <name>]... [--pool]", "Declare a model class: failover order, or --pool to share the load; --degraded ones last"),
        (&["cluster", "class", "unset"], "<class>", "Forget a declared model class and its aliases; the derived class of its model takes over"),
        (&["cluster", "prefer"], "[<purpose> <model|class> | <purpose> --clear]", "Show or set which model a stack purpose (knowledge, graph) tries first"),
        (&["cluster", "embedding-space", "list"], "", "Show each embedding space, its model and the nodes serving it"),
        (&["cluster", "embedding-space", "set"], "<space> <model> [--dims <n>]", "Declare an embedding space: a purpose bound to one embedding model"),
        (&["cluster", "embedding-space", "unset"], "<space>", "Forget an embedding space; the default (knowledge) cannot be removed"),
        (&["cluster", "embedding-space", "migrate"], "<space> <model> | <space> --complete | <space> --cancel", "Re-embed a space into a new model: start, complete or cancel"),
        (&["cluster", "logs"], "[<node>] [<service>] [-b|--backend <backend>] [-n|--tail <n>]", "Tail logs for a noo-* container or host service (harness, agent) on one node or all"),
        (&["cluster", "restart-agent"], "<node>", "Ask the gateway to restart a node's node-agent"),
        (&["cluster", "maintenance"], "<node> on --reason <text> [--until <duration>] | <node> off | list", "Mute a known-down node's operator alerts (operator-only); the daily summary still lists it"),
        (&["cluster", "gpu", "hold"], "<node> [--reason <text>] [--operation <id>] [--timeout <secs>] [--immediate] [--force]", "Drain, then pause a node's GPU backends, held as an owned lease until released (operator)"),
        (&["cluster", "gpu", "release"], "<node> [--operation <id> --generation <n>] [--force] [--now]", "End a GPU hold by its lease (or any with --force); backends resume when free, or now"),
        (&["cluster", "reserve"], "<addon>/<workload> [--node <node>] [--hand-over <reservation-id>] [--timeout <secs>]", "Reserve a GPU for an add-on workload: drain the pool there, pause it, start the workload"),
        (&["cluster", "reservations"], "", "List the GPU reservations the nodes hold: id, workload, holder, node, state"),
        (&["cluster", "release"], "<reservation-id> [--force]", "Release a reservation: drain and stop the workload, give the GPU back (holder or --force)"),
        (&["cluster", "workloads"], "", "List the workloads the installed add-ons declare (container, GPU need, drain route)"),
        (&["cluster", "profile"], "<node> [--set <key=value>]... [--clear <key>]... [--clear-all] [--bench]", "Show a node's harness profile with each value's source; set overrides; bench its model"),
        (&["cluster", "init-secret"], "", "Generate and print a fresh random cluster secret locally (no gateway call)"),
        (&["cluster", "set-config"], "<node> [--usage shared|dedicated|default] [--harness auto|manual|off] [--loop-budget <n>|default] [--data-root <path>] [--models-dir <path>] [--ip <ip>] [--tier <n>] [--gpu-model <model>] [--vram-gb <n>] [--min-battery <pct>] [--require-wifi <bool>] [--block-thermal <s,s>] [--policy-default] [--vendor-kinds <kind,kind>|none]", "Update a node's stored config row with only the given fields"),
        (&["cluster", "clear-cooldowns"], "", "Clear backend auto-start cooldown backoff on every node"),
        (&["cluster", "teardown-node"], "<node> | --all [--purge-data] [--purge-tailscale] [--factory] [-y|--yes]", "Dismantle one node or --all via a signed teardown bundle, verify silence, then forget"),
        (&["cluster", "provision"], "<node> [<tier>] [--harness auto|manual|off] [--wait [<secs>]] [--stage-only] [--move-data]", "Stage a node's signed bundle; --wait blocks until enrolled, --stage-only skips the apply"),
        (&["cluster", "sync-model-files"], "[<node>...] [-m|--model <file>]... [--dry-run]", "Dispatch a job per node to pull GGUF weights from the controller store and verify them"),
        (&["cluster", "bootstrap-token", "create"], "[--ttl <1h|30m|24h|secs>] [--role <role>] [--cidr <cidr>] [--node <name>] [--with-tailscale|--no-tailscale]", "Mint a single-use enrollment token and print the node enrollment one-liner"),
        (&["cluster", "bootstrap-token", "list"], "", "List bootstrap tokens with status, creator, expiry and redeeming IP"),
        (&["cluster", "bootstrap-token", "revoke"], "<id>", "Revoke a bootstrap token by id (idempotent)"),
        (&["cluster", "bootstrap-token"], "", "Print bootstrap-token subcommand usage (create, list, revoke)"),
        (&["cluster", "set-primary"], "[--to <target>] --promoted [-y|--yes]", "Move the primary-controller role; promote Postgres on the target first, then --promoted"),
        (&["cluster", "sync-images"], "[<node>...] [-i|--image <img>]... [--images <a,b>] [--restart|--no-restart] [--all] [--stage-only] [--lock] [--arch <a,b>] [--all-images]", "Stage images on the artifact rail, then nodes pull them (--stage-only: stage, no pull)"),
        (&["cluster", "upgrade-agents"], "[<node>...] [-y|--yes]", "Restage node agents serially in signed bundles over the pull rail; asks to confirm (-y)"),
        (&["cluster", "upgrade-hostd"], "<node>... [--skip-build] [-y|--yes|--force]", "Roll noo-hostd to the named nodes over the pull rail as a signed bundle"),
        (&["cluster", "upgrade-applier"], "<node>... [-y|--yes|--force]", "Ship the current noo-apply to nodes over the rail; asks for confirmation (-y)"),
        (&["cluster", "restart-backends"], "<node> <noo-svc>... [-y|--yes|--force]", "Restart noo-* backend containers on a node via a rail-delivered bundle"),
        (&["cluster", "host-telemetry", "apply"], "[<node>...] [--all] [--include-controller] [-y|--yes]", "Switch off tailscaled's log upload on nodes over the pull rail, one at a time"),
        (&["cluster", "host-telemetry"], "", "Print host-telemetry subcommand usage (apply)"),
        (&["cluster", "vendor", "stage"], "[<kind> [--fleet] | --all] [--os linux|macos] [--arch x86_64|aarch64]", "Fetch the vendor CLIs the nodes need on the controller, checked against their pins"),
        (&["cluster", "vendor", "status"], "", "List staged vendor CLIs per platform, and which nodes need which"),
        (&["cluster", "vendor", "install"], "<node> <kind>...", "Carry these vendor CLIs on a node whatever its placement names; restage to deliver"),
        (&["cluster", "vendor"], "", "Print vendor subcommand usage (stage, status, install)"),
        (&["cluster", "push-secrets"], "[<node>...] [--dry-run] [--explain] [--gateway-container <name>] [--sops-file <path>] [-y|--yes]", "Stage fleet-wide secrets from env.sops as a bundle each node collects"),
        (&["cluster", "nats-users", "render"], "[--rotate] [--dry-run] [-y|--yes]", "Mint per-principal NATS passwords from the gateway registry and render users.conf"),
        (&["cluster", "nats-creds", "rotate"], "<node|gateway|worker|trellion|trellion_intel>... [--mint-only] [--restart] [-y|--yes]", "Rotate a bus credential: nodes deliver over the rail; others re-render + recreate"),
        (&["cluster", "import-model"], "<node> <name> [--place] [--role chat|embed|rerank] [-b|--backend <backend>]", "Import a store model or a staged ollama:<tag> into a node's ollama"),
        (&["cluster", "ship-model"], "<hf_id> <node> [--name <name>] [--quant <quant>] [--place] [-b|--backend <backend>]", "Convert an HF model to GGUF and have a node import it; needs a source checkout"),
        (&["cluster", "clean"], "<node>|all [--deep] [-y|--yes]", "Remove this stack's containers on node(s) through their agents; --deep removes images too"),
        (&["cluster", "seed"], "[-f|--file <path>] [--export] [--dry-run]", "Apply (or export) the cluster desired state from config/cluster-seed.yaml"),
    (&["security", "pki", "status"], "", "List every certificate under the PKI dir with expiry and days left"),
    (&["security", "pki", "init"], "", "Generate the cluster CA in the PKI dir (refuses to overwrite an existing one)"),
    (&["security", "pki", "issue"], "<node_id> <ip> [--days <n>] [--san <name>]...", "Issue a node certificate signed by the cluster CA (adds the tailnet IP SAN)"),
    (&["security", "pki", "issue-service"], "<service> [--days <n>] [--san <name>]...", "Issue a service certificate with this box's derived names; --san adds more"),
    (&["security", "pki", "issue-gateway"], "[<hostname>] [<ip>] [--days <n>] [--extra-ip <ip>]... [--extra-san <san>]...", "Issue the dual-purpose gateway certificate (defaults gateway/127.0.0.1)"),
    (&["security", "pki", "issue-sso-key"], "[--force]", "Issue the Grafana SSO key pair (pki/sso/); --force re-mints and logs Grafana out"),
    (&["security", "pki", "rotate"], "<node_id> <ip> [--days <n>]", "Hidden: alias of `pki issue` (local files only; not delivered)"),
    (&["security", "pki", "fix-modes"], "[--dry-run]", "Repair PKI key modes now (upgrade and issue do too); print sudo lines for the rest"),
    (&["security", "pki", "issue-client"], "<operator> [--days <n>] [--force]", "Issue and register your operator client certificate for posture writes (key 0600, own dir)"),
    (&["security", "pki", "rotate-client"], "<operator> [--days <n>]", "Replace your operator certificate: register the new one, then revoke the old"),
    (&["security", "pki", "revoke-client"], "<operator> [--thumbprint <tp> | --others] [-y|--yes]", "Revoke an operator's certificates (bare: ALL of them); asks for confirmation (-y)"),
    (&["security", "user", "list"], "", "List user accounts with scopes, role, and login stats"),
    (&["security", "user", "create"], "<username> [--scope <scope>]... [--password-stdin]", "Create a user account (read-only unless --scope is given; prompts for password)"),
    (&["security", "user", "grant-role"], "<username> -r|--role <role>...", "Grant extra KB roles to a user"),
    (&["security", "user", "revoke-role"], "<username> -r|--role <role>...", "Revoke KB roles from a user"),
    (&["security", "user", "list-roles"], "", "List extra KB role grants across all users"),
    (&["security", "user", "link"], "<username> <channel> <channel_user_id> [--name <display>]", "Link a channel identity to a user account"),
    (&["security", "user", "unlink"], "<channel> <channel_user_id>", "Remove a channel identity link"),
    (&["security", "user", "links"], "<username>", "List the channel identities linked to a user"),
    (&["security", "user", "set-password"], "<username> [--password-stdin]", "Set a user's password (prompts unless --password-stdin)"),
    (&["security", "admin-password", "reset"], "[--stdout] [--yes]", "On the controller, no login: reset the admin, end its sessions, show the new password once"),
    (&["security", "user", "set-scopes"], "<username> --scope <scope>...", "Replace a user's auth scopes with the given set (admin-only)"),
    (&["security", "user", "allowance"], "<username> [-t|--tokens <n>] [-p|--period day|week|month] [--clear]", "Show, set or clear a user's standing token allowance per period (setting is admin-only)"),
    (&["security", "user", "set-org"], "<username> <org_id>", "Assign a user to an org"),
    (&["security", "user", "disable"], "<username> [-y|--yes]", "Disable a user account (undo with `user enable`); asks for confirmation (-y)"),
    (&["security", "user", "enable"], "<username>", "Re-enable a disabled user account"),
    (&["security", "user", "erase"], "<username> [--yes] [--keep-account]", "Erase a user's data (dry-run preview without --yes; -y executes)"),
    (&["security", "user", "proposals"], "", "List agent-filed user proposals and their status"),
    (&["security", "user", "decide"], "<id> (--approve | --deny) [--reason <text>]", "Approve or deny a user proposal (prints a generated password once)"),
    (&["security", "team", "list"], "", "List registered teams with members and doc counts"),
    (&["security", "team", "create"], "<name> [--description <text>]", "Create a team and its team:<name> KB role"),
    (&["security", "team", "delete"], "<name> [--force] [--yes]", "Delete a team; asks for confirmation (-y); --force deletes with members/docs"),
    (&["security", "team", "link-space"], "<team> <channel> <space_id>", "Link a channel space to a team as a shared space"),
    (&["security", "team", "unlink-space"], "<channel> <space_id>", "Unlink a channel space from its team"),
    (&["security", "team", "spaces"], "<team>", "List the channel spaces linked to a team"),
    (&["security", "org", "list"], "", "List orgs with member counts"),
    (&["security", "org", "create"], "<org_id> [--name <name>] [--description <text>]", "Create an org"),
    (&["security", "tailnet", "policy"], "[--merge | --push] [--yes]", "Compare live tailnet policy to declared; --merge adds what is missing, --push replaces"),
    (&["security", "audit", "verify"], "", "Verify audit hashes, the chain, and its head against the exported head (operator-only)"),
    (&["security", "audit", "list"], "[--since <30m|24h|7d|time>] [--event <type>] [--actor <name>] [-n <limit>] [--cursor <c>]", "List security audit rows, newest first, with source address (operator-only)"),
    (&["security", "at-rest", "status"], "[--json]", "Show TPM facts, how to enable one, and your recorded at-rest encryption decision"),
    (&["security", "at-rest", "opt-out"], "", "Record that you accept unencrypted data at rest (audited; needs your own login)"),
    (&["security", "at-rest", "opt-in"], "", "Withdraw the at-rest opt-out (audited; needs your own login)"),
    (&["security", "at-rest", "create-volume"], "[--size <GiB>] [--pcrs 7|none|auto] [--defer-recovery-key] [--dry-run]", "Create the TPM-unlocked encrypted state volume; shows its recovery key once"),
    (&["security", "at-rest", "seal"], "[--pcrs 7|none|auto] [--dry-run]", "Seal the age key to this TPM; unsealed into RAM at boot, plaintext kept until finalize"),
    (&["security", "at-rest", "finalize"], "[--dry-run] [-y|--yes]", "Remove the plaintext age key once a reboot unsealed it and a fresh backup decrypts"),
    (&["security", "at-rest", "migrate"], "[--dry-run] [--rollback] [--yes] [--confirm-offbox <phrase>]", "Move this controller's state onto the encrypted volume: backup first, reversible"),
    (&["security", "at-rest", "wipe-plaintext"], "[--dry-run] [--hours <N>] [--confirm <phrase>]", "Delete the old plaintext state after a verified migration and a day of healthy running"),
    (&["security", "at-rest", "recovery-key"], "[--dry-run]", "Enroll a new recovery key, shown once; the old one is removed only after you confirm"),
    (&["security", "at-rest", "reenroll"], "[--pcrs 7|none|auto] [--dry-run]", "Re-enroll the TPM after a firmware or Secure Boot change and reseal the age key"),
    (&["security", "at-rest", "preflight-firmware"], "[--json]", "Before a BIOS or firmware update: check the recovery key and a fresh backup"),
    (&["security", "posture", "list"], "", "List security posture gates: running vs desired value (operator-only)"),
    (&["security", "posture", "set"], "<key> <value>", "Set a posture gate; needs an operator cert (`pki issue-client`); restart to apply"),
    (&["security", "posture", "apply-profile"], "<profile> [--include-bridges]", "Apply a posture profile (needs an operator cert); leaves rollout bridges; restart to apply"),
    (&["security", "service-key", "issue"], "<consumer> [--scopes <scope>]... [--note <text>] [--rpm <n>] [--user <username>]", "Issue a service key, shown once; scopes default to chat,embeddings,rerank,classify,mcp"),
    (&["security", "service-key", "list"], "[--all] [--callers]", "List service keys (hashes only); --all adds revoked ones, --callers retired add-on callers"),
    (&["security", "service-key", "revoke"], "<consumer> [--disable-account] [-y|--yes]", "Revoke a consumer's keys, for good (-y); --disable-account also kills issued tokens"),
    (&["security", "service-key", "rotate"], "<consumer> [--scopes <scope>]... [--note <text>]", "Rotate a consumer's key; scopes and rpm kept, old key live until `retire`"),
    (&["security", "service-key", "retire"], "<consumer>", "Finish a rotation: deactivate the superseded key, once the new one has been used"),
    (&["security", "service-key", "provision"], "<name> [--scopes <s>]... [--wait <secs>] [-y]", "Show the declared grant and confirm, then mint, store, recreate and PROVE the key"),
    (&["security", "service-key", "set-quota"], "<consumer> <rpm>", "Set the per-minute request cap for a consumer's keys (0 = uncapped)"),
    (&["security", "service-key", "self"], "[--note <label>]", "Mint or rotate the caller's own MCP key (raw key shown once)"),
    (&["security", "service-key", "self-status"], "", "Show whether the caller has an active MCP key and when it was used"),
    (&["security", "service-key", "self-revoke"], "", "Revoke the caller's own MCP key"),
    (&["security", "generate-secret"], "[<type>] [--length <bytes>]", "Print a random secret: general (jwt, cluster alike) or fernet; --length not for fernet"),
    (&["security", "entitlement", "keygen"], "[--out <file>]", "Hidden: create the entitlement signing key, mode 600 (vendor builds only)"),
    (&["security", "entitlement", "issue"], "--sub <customer> (--terms <version>|--no-terms) [--tier intelligent] [--features a,b] [--days <n>] [--id <id>] [--addon <name>=<registry>:<key>[,<key>]]... [--pull-host <host>] [--bind-key <hex>] [--key <file>]", "Hidden: sign an entitlement token for a customer (vendor builds only)"),
    (&["security", "entitlement", "install"], "<token> [--enable] [--ci] [--accept-terms <version>]", "Verify and store a token as NOO_ENTITLEMENT; --enable mints and switches on what it grants"),
    (&["security", "entitlement", "show"], "", "Show the installed entitlement, its validity, and which add-ons it unlocks"),
    (&["security", "entitlement", "verify"], "<token>", "Verify a token offline against this build's entitlement key"),
    (&["security", "entitlement", "pubkey"], "", "Print this controller's add-on key (hex) for the vendor to bind the entitlement to"),
    (&["security", "release-sign"], "<file> [--seed-file <path>] [--out <file.sig>]", "Hidden: sign sha256sums.txt with the release key (CI only)"),
    (&["security", "release-verify"], "<file> [<file.sig>]", "Verify a release manifest signature against the keys baked into this build"),
    (&["security", "addon-lock", "sign"], "--addon <name> --version <v> --source-commit <sha> --supports <tag>[,<tag>]... --image <name>=<ref@digest>... [--base <image>=<digest>] [--file <name>=<path>]... [--registry <root>] --seed-file <path|-> --out <path>", "Hidden: sign an add-on lock with the add-on's own key (add-on CI only)"),
    (&["security", "addon-lock", "verify"], "<path> --key <pubkey>... --addon <name> --registry <root> [--sig <path>] [--stack <tag>] [--files-dir <dir>] [--dev-key <pubkey>]...", "Verify a signed add-on lock against the add-on's release keys and registry root"),
    (&["security", "secrets", "tidy"], "[-y|--yes]", "Thin the store to secrets only: move config to .env, drop retired keys, blank .env copies"),
    (&["security", "secrets", "audit"], "[--sops-file <path>] [--env-file <path>]", "Compare env.sops against .env by digest and report findings (no values shown)"),
    (&["security", "secrets", "resync"], "<key>... | --all [--dry-run] [--sops-file <path>] [--pg-container <c>] [--pg-db <db>] [--pg-superuser <user>]", "Make Postgres role passwords match the values already in the SOPS store"),
    (&["backups", "status"], "", "Where backups go, how many there are, and whether an off-site copy was ever decided"),
    (&["backups", "setup"], "[--set <ssh:…|dir:…|s3:…|portable|none>]", "Decide where a copy of each backup goes; asks unless --set is given"),
    (&["security", "secrets", "remove"], "<key>... [--yes] [--dry-run] [--sops-file <path>]", "Remove unused keys from env.sops; refuses any key something reads, keeps a backup"),
    (&["security", "secrets", "rotate"], "<key>... [--all-generated] [--dry-run] [--yes] [--prompt] [--set-from-stdin] [--stdout] [--restart] [--sops-file <path>] [--pg-container <c>] [--pg-db <db>] [--pg-superuser <user>]", "Rotate secrets in env.sops, Postgres and the backup files atomically; confirms unless -y"),
    (&["security", "secrets", "reveal"], "<NAME> [--no-clipboard] [--stdout] [--sops-file <path>]", "Show one human-held secret once on this terminal and offer it to the clipboard"),
    (&["security", "scan"], "[--strict]", "Scan this install's or node's posture; exit 1 on a CRITICAL, or any finding with --strict"),
    (&["security", "pki", "rotate-all"], "[--warn-days <n>] [--new-days <n>] [--yes] [--reload | --no-reload] [--no-deliver]", "Re-issue expiring certs, deliver to nodes, restart consumers; asks for confirmation (-y)"),
    (&["security", "pki", "rotate-ca"], "[--ca-days <n>] [--leaf-days <n>] [--yes] [--retire-old]", "Cross-signed CA rotation across every node; asks for confirmation (-y)"),
    (&["security", "pki", "rotate-signing-key"], "[<node>] [--deliver-only] [--yes]", "Mint the fleet code-signing key and deliver its public half to every node (-y to confirm)"),
    (&["security", "secrets", "absorb-files"], "[-y|--yes]", "Fold file credentials and legacy secrets/*.txt into env.sops; shreds what reads back (-y)"),
    (&["security", "pki", "issue-node"], "<node> [<ip>] [--days <n>] [--mint-only]", "Issue a node cert and deliver it, waiting for the node to confirm it applied"),
    (&["security", "pki", "push-nodes"], "[<node>] [--days <n>] [--yes]", "Re-issue node certs plus ca.crt and stage them on the pull rail for each node"),
    (&["security", "trust-ca"], "[<ca_path>]", "Install the cluster CA into the OS trust store (default $NOO_PKI_DIR/ca.crt)"),
    (&["security", "untrust-ca"], "[--yes]", "Remove the cluster CA (by name) from the OS trust store; asks for confirmation (-y)"),
    (&["jobs", "list"], "[--limit <n>] [--status <s>] [--node <id>]", "List queued and running jobs from the gateway job queue"),
    (&["heartbeat", "status"], "", "Show heartbeat scheduler state, task counts and last tick age"),
    (&["heartbeat", "list"], "", "List configured heartbeat tasks with schedule, action and next run"),
    (&["heartbeat", "run"], "<task-id>", "Run a heartbeat task now; quick tasks print their result, slow ones are queued to history"),
    (&["heartbeat", "history"], "[<task-id>] [--task-id <id>] [--run <run-id>] [--limit <n>]", "Show recent heartbeat task runs, optionally filtered by task or a run id prefix"),
    (&["heartbeat", "export"], "[--output <file>]", "Export all heartbeat tasks as portable JSON, stripping run timestamps"),
    (&["heartbeat", "toggle"], "<task-id> [--on|--off]", "Flip or explicitly set a heartbeat task's enabled state"),
    (&["heartbeat", "set-schedule"], "<task-id> \"<cron>\"", "Change only a heartbeat task's schedule; channels, recipients and config stay as they are"),
    (&["heartbeat", "proposals"], "[<proposal-id>]", "List task proposals; with an id, every field and a diff against the live task"),
    (&["heartbeat", "review-existing"], "", "After an upgrade: approve existing tasks and saved recipients one by one (people only)"),
    (&["heartbeat", "approve"], "<proposal-id>", "Approve a task proposal at a terminal (shows it all; type the task id; people only)"),
    (&["heartbeat", "reject"], "<proposal-id> [--reason <text>]", "Reject a task proposal; nothing is created or changed"),
    (&["memory", "search"], "<query> [--user <user>]", "Search memory by pgvector similarity, optionally scoped to one user"),
    (&["memory", "stats"], "", "Show memory storage, conversation and tool-usage statistics"),
    (&["memory", "health"], "", "Print the memory subsystem health report"),
    (&["memory", "tool-stats"], "[--days <n>]", "Show tool call counts and success rates over the last N days"),
    (&["memory", "embed"], "[--watch]", "Start the background embedding worker, optionally watching progress"),
    (&["memory", "embed-status"], "[--watch]", "Show embedding worker state and record counts, optionally polling"),
    (&["memory", "embed-stop"], "", "Stop the background embedding worker"),
    (&["recall", "status"], "", "Show recall memory (System 1 recall) status"),
    (&["recall", "videos"], "", "List recall memory files with record counts and sizes"),
    (&["recall", "search"], "<query> [--top-k <k>]", "Search compressed recall memory and rank results by score"),
    (&["recall", "prominent"], "[--top-k <k>]", "List the most prominent recall records by access and relevance"),
    (&["recall", "stats"], "", "Show recall lifecycle statistics"),
    (&["recall", "lifecycle-stats"], "", "Hidden: alias of `recall stats`"),
    (&["models", "cached"], "", "List models currently loaded on running node backends"),
    (&["models", "pull"], "<model> [--backend <b>]", "Pull onto the gateway's Ollama; whisper:<size> / piper:<voice> stage a voice model"),
    (&["models", "fetch"], "<hf_repo> <file.gguf> [--revision <rev>] [--force]", "Download a GGUF from Hugging Face, or stage ollama:<tag> from the registry, into the store"),
    (&["stack", "status"], "", "Show stack container status (from docker ps)"),
    (&["stack", "logs"], "[<service>...] [--follow] [--tail <n>]", "Show container logs for one service or compose logs for many"),
    (&["stack", "restart"], "[--profile <p>] [--force] [<service>...]", "Restart services by status name or add-on key; --force recreates (reloads env, secrets)"),
    (&["stack", "start"], "[--profile <p>] [--pull] [--build] [--dist] [--dev] [--tag <tag>]", "Start the stack via scripts/noomesh-start.sh"),
    (&["stack", "stop"], "[--volumes [-y|--yes]]", "Stop the stack; --volumes deletes the database and every volume, after a typed confirm"),
    (&["stack", "rebuild"], "[<service>...] [-q|--quick] [--no-cache] [--profile <p>] [--gateway-engine <e>] [--node-engine <e>] [-b|--background]", "Rebuild stack images in the foreground, or queue it for noo-hostd with --background"),
    (&["stack", "rebuild-status"], "[--follow]", "Show the latest background stack-rebuild result and log"),
    (&["stack", "clean"], "[--volumes] [--images] [--all] [--deep] [--cache] [--hf-cache] [-y]", "Remove Docker resources; asks for confirmation, -y answers every prompt too"),
    (&["jobs", "run"], "<prompt> [--async] [--priority <n>] [--backend <b>] [--node <id>] [-t <secs>] [--type <type>]", "Submit an inference job and poll until it finishes unless --async"),
    (&["jobs", "status"], "<job-id> [--wait]", "Show one job record, optionally polling until it reaches a terminal state"),
    (&["jobs", "submit"], "[--type <t>] [--priority <n>] [--backend <b>] [--payload <json>]", "Submit a job with a raw JSON payload and print its id (a prompt: jobs run --async)"),
    (&["jobs", "history"], "[--limit <n>]", "Show recently completed jobs with status and duration"),
    (&["jobs", "cancel"], "<job-id> [-y]", "Cancel a job; destructive, asks for confirmation (-y)"),
    (&["jobs", "reprioritize"], "<job-id> <priority>", "Change a queued job's priority"),
    (&["jobs", "scheduler"], "", "Show job scheduler status and counters"),
    (&["jobs", "pause"], "", "Pause the job scheduler"),
    (&["jobs", "resume"], "", "Resume the job scheduler"),
    (&["jobs", "drain"], "<node-id>", "Drain a node so the scheduler stops sending it jobs"),
    (&["jobs", "undrain"], "<node-id>", "Undrain a node so the scheduler sends it jobs again"),
    (&["models", "list"], "[--backend <b>] [--tier <n>] [--limit <n>] [--refresh]", "List popular models per backend from the HuggingFace catalog cache"),
    (&["models", "search"], "<query> [--backend <b>] [--limit <n>]", "Search HuggingFace for models, with cached offline fallback"),
    (&["models", "info"], "<model>", "Show detailed HuggingFace info for a model, including gating hints"),
    (&["models", "recommended"], "[--tier <n>] [--arch <a>] [--refresh]", "Recommend models for a hardware tier, auto-detected from the cluster"),
    (&["models", "ollama"], "[--limit <n>] [--refresh]", "List popular Ollama-compatible models from the catalog"),
    (&["models", "huggingface"], "[<query>] [--limit <n>]", "Search HuggingFace models (default query \"mistral instruct awq\")"),
    (&["memory", "conversations"], "[--user <user>] [--limit <n>]", "List recent conversations with message counts and previews"),
    (&["recall", "archive"], "", "Archive new conversations into recall memory"),
    (&["recall", "lifecycle"], "[--dry-run] [-y]", "Run the recall lifecycle (prune, elevate, compact) after confirming, or preview it"),
    (&["recall", "refresh"], "[--dry-run] [-y]", "Archive new conversations then run the lifecycle (prunes); --dry-run previews"),
    (&["recall", "test"], "", "Hidden: retired; points at `recall status` and `recall lifecycle`"),
    (&["heartbeat", "add"], "<name> <schedule> [--action <a>] [--prompt <p>] [--channel <c>] [--recipient <r>]", "Add a scheduled heartbeat task with an id derived from its name"),
    (&["heartbeat", "import"], "<file>", "Import heartbeat tasks from an export file and reload the scheduler"),
    (&["stack", "sync-assets"], "", "Refresh the standalone deploy slice from this binary's embedded assets"),
    (&["heartbeat", "remove"], "<task-id> [-y]", "Delete a heartbeat task; destructive, asks for confirmation (-y)"),
    (&["stack", "reset"], "[--dist] [--tag <tag>] [--ci] [--keep-env] [-y]", "Deep clean, onboard and restart the stack; destructive, confirms (-y)"),
    (&["stack", "sandbox"], "<up [--fresh]|status|run <cmd>...|rehearse|down [--keep-data]>", "Manage a throwaway docker-in-docker Mesh stack isolated from live"),
    (&["stack", "ollama"], "[--container <name>] [<ollama-args>...]", "Run an ollama command inside the noo-ollama container (default: list)"),
    (&["models", "switch"], "<model> [--backend <b>] [-y|--yes]", "Switch the active model: rewrites .env/noomesh.yaml, restarts; asks (-y)"),
    (&["models", "refresh"], "[--backend <b>] [--llm]", "Rebuild the model catalog cache from HuggingFace, bypassing the TTL"),
    (&["health"], "", "Probe gateway /health and report per-dependency state; exit 5 if degraded"),
    (&["inference", "run"], "<prompt> [-m <model>] [-b <backend>] [-n <node> [--strict-node]] [-u <user>] [--max-tokens <n>] [-t <temperature>]", "Run one direct model inference through the gateway and print the response"),
    (&["db", "status"], "", "Show gateway health and every migration stamp (mesh/trellion/evolve); --json supported"),
    (&["doctor", "docker"], "", "Detect unclean-shutdown docker damage (ghosts, empty names) and print recovery"),
    (&["doctor", "privileges"], "", "Report standing power on this box: sudoers drop-ins, gate binaries, SSH keys"),
    (&["doctor", "orphans"], "", "Report containers compose still runs that no compose file declares"),
    (&["doctor", "secrets"], "", "Report containers running a secret value that .env has moved past"),
    (&["doctor", "exposure"], "", "Report which published ports are reachable from outside the tailnet"),
    (&["doctor", "strangers"], "[--minutes N]", "Gateway callers the tailnet does not account for, and any caller in a refusal storm"),
    (&["enroll"], "<noo1.blob> | --url <u> --token <t> | --via-tailnet <u> [--ca-sha256 <hex>] [--ts-authkey <k>] [--node <name>] [--skip-tailscale] [--skip-prep] [--data-root <dir>] [--resume]", "Enroll this machine as a worker of the given controller"),
    (&["db", "verify-plane"], "[<db>]", "Run scripts/verify-privilege-plane.sh against a database (default noo)"),
    (&["db", "current"], "", "Show the migration stamp of each system (mesh runner, trellion alembic, evolve)"),
    (&["db", "history"], "", "List the mesh runner's ported chain with applied/pending markers, plus other stamps"),
    (&["db", "upgrade"], "[heads]", "Apply pending mesh migrations via the gateway, then trellion's memory step"),
    (&["config", "get"], "[<section>|cli]", "Print gateway runtime config, whole or one section; `cli` reads this machine's prefs"),
    (&["config", "set"], "<section> <updates-json>", "Update a gateway config section from JSON (no confirm); `cli` writes local prefs"),
    (&["config", "launch-render"], "compose-env | addons | override | systems [<file>]", "Hidden: render one noomesh.yaml section for the launcher scripts (internal)"),
    (&["config", "launch-check"], "bind-sources [--data-root <dir>] [--no-deps] [--skip <service>]... [<service>...] | system-credentials [<noomesh.yaml>] | secrets-at-rest [<dir>] | state-root [<dir>]", "Hidden: pre-start refusals: bind sources, credentials, plaintext secrets, closed volume"),
    (&["logs", "errors"], "[-c|--container <container>] [-m|--minutes <min>] [-n|--limit <limit>] [--node <id>] [--name <n>] [--source <s>] [--since <t>] [--until <t>]", "List recent warning/error lines across the fleet (Loki, else a container scan)"),
    (&["logs", "tail"], "<container> | -c|--container <container> | --name <n> [-l|--lines <lines>] [-n|--node <node>] [--source <s>] [--since <t>] [--until <t>] [--grep <regex>]", "Print the last N log lines of one container or unit, optionally on a given node"),
    (&["logs", "search"], "[<text>] [-n|--node <node>] [--name <n>] [-c|--container <c>] [--source <s>] [--level <l>] [--since <t>] [--until <t>] [-l|--limit <n>] [--newest] [-q|--query <logql>]", "Search the fleet's logs in Loki by node, name, level, time window and text"),
    (&["approval", "list"], "", "List pending tool-execution approval requests"),
    (&["approval", "pending"], "", "Hidden: same as approval list"),
    (&["approval", "stats"], "", "Show approval-queue counts (total/approved/denied/pending/timed out/expired)"),
    (&["approval", "status"], "", "Show the exec-approval system status as JSON"),
    (&["rag", "query"], "<question> [-s|--strategy <strategy>] [-p|--persona <persona-id>] [--personal]", "Ask the KB; --personal explicitly includes your Google sources for a human login"),
    (&["rag", "status"], "", "Show PageIndex RAG table counts and embedder state"),
    (&["rag", "docs"], "[--untagged] [--audience <role>] [--match <glob>] [--title <text>] [--limit <n>]", "List every document with audience, source and who ingested it; filterable"),
    (&["rag", "doc"], "<id>", "Show one document: audience, provenance, audience history and a text preview"),
    (&["rag", "ingest"], "<path>... [-t <title>] [-r] [--audience <role>[,<role>]]", "Ingest text files or a folder; audience defaults to you, share with team:<name> or company"),
    (&["rag", "scan"], "[-s|--source folders|drives|all]", "Run one synchronous ingest scan of watched folders and/or drives"),
    (&["rag", "deduplicate"], "[--dry-run] [-y]", "Delete duplicate (doc_id, page_no) pages, keeping the newest; confirms first"),
    (&["rag", "retag"], "(--match <glob> | --doc-id <id>) --role <r>[,<r>] [--relabel] [--apply] [--limit <n>]", "Change which audience documents belong to; dry-run unless --apply"),
    (&["rag", "hold"], "(--title-prefix <p> | --doc <id>...) [--reason <r>] [--apply]", "Keep documents but take them out of embedding and search; dry-run unless --apply"),
    (&["rag", "unhold"], "(--title-prefix <p> | --doc <id>...) [--apply]", "Make held documents eligible for embedding and search again; dry-run unless --apply"),
    (&["rag", "held"], "[--reason <r>] [--export <file>]", "List held documents; --export writes every held id and title to a file"),
    (&["rag", "purge"], "--reason <r> [--apply] [-y]", "Delete the documents held under a reason (irreversible); dry-run unless --apply"),
    (&["graph", "stats"], "", "Show knowledge-graph entity/edge counts"),
    (&["graph", "search"], "<query>", "Search knowledge-graph entities by name (ILIKE match)"),
    (&["graph", "detail"], "<entity-id>", "Print one knowledge-graph entity as JSON"),
    (&["graph", "neighbors"], "<entity-id> [-H <hops>]", "Walk edges from an entity up to N hops (default 1, gateway clamps 1-5)"),
    (&["graph", "navigate"], "<question> [-H <hops>] [-s <entity-id>]...", "Navigate the graph for a question; saved as a walk (Intelligent tier)"),
    (&["graph", "recluster"], "[-m <min-size>] [-r <resolution>] [--wait|--no-wait]", "Rebuild entity clusters (Intelligent tier; minutes); --no-wait prints the operation id"),
    (&["graph", "entity-cleanup"], "[--apply] [--examples <n>] [--max-delete <n>] [--yes]", "Find junk entities (a, x_t, 0.003); dry run unless --apply, which asks first (admin)"),
    (&["graph", "prune", "restore"], "--run <id>", "Restore the entities one cleanup run staged (operator; within 30 days)"),
    (&["graph", "clusters", "audit"], "", "Audit how clusters mix audience tiers and what a non-admin sees (admin; read-only)"),
    (&["ops"], "[--status <s>] [--mine] [--limit <n>]", "Hidden: same as ops list"),
    (&["ops", "list"], "[--status <s>] [--mine] [--limit <n>]", "List your asynchronous operations, newest first (an admin sees everyone's)"),
    (&["ops", "show"], "<id> [--wait]", "Show one operation: status, progress, result or error; --wait blocks until it finishes"),
    (&["ops", "cancel"], "<id>", "Cancel an operation: stops the gateway-side wait (the worker run may continue)"),
    (&["ops", "types"], "", "List what can run as an operation, how long each waits and how long a run may take"),
    (&["walks"], "[--q <text>] [--top-k <n>]", "Recall your own saved graph threads (nearest --q, else the latest)"),
    (&["walks", "show"], "<id>", "Show one of your saved threads: what you asked, the path, and why it ranked"),
    (&["walks", "settings"], "[--save on|off]", "Show or set whether your graph walks are saved as threads (default on)"),
    (&["walks", "stats"], "[--user <account>]", "Count saved threads by kind, status and account (operator and above; counts only)"),
    (&["walks", "view"], "<account> [--limit <n>]", "Print an account's saved threads verbatim (admin only; every view is audited)"),
    (&["autonomy", "status"], "", "Show autonomy engine state and its configured locations"),
    (&["autonomy", "locations"], "", "Hidden: same as autonomy status"),
    (&["autonomy", "audit"], "[-n|--limit <n>]", "List recent autonomy audit entries (default 20)"),
        (&["autonomy", "decisions"], "[-n|--limit <n>] [-l|--location <name>]", "What the disarmed autonomy locations would have done — the evidence for arming one"),
    (&["autonomy", "enable"], "", "Enable the autonomy engine"),
    (&["autonomy", "disable"], "", "Disable the autonomy engine"),
    (&["proactive", "status"], "", "Show proactive agent state and rule counts"),
    (&["proactive", "rules"], "", "List configured proactive rules"),
    (&["channels", "status"], "", "List configured channel adapters (traffic counters are not tracked)"),
    (&["channels", "export"], "[--output <file>]", "Export user links, team spaces and saved recipients as portable JSON"),
    (&["channels", "import"], "<file>", "Import channel state from an export file (idempotent; users must exist)"),
    (&["agents", "list"], "", "List agent roles with max tool loops and preferred tools"),
    (&["agents", "peer", "list"], "[-c]", "List registered A2A peer agents; -c shows connected peers only"),
    (&["agents", "peer", "card"], "", "Print this gateway's public A2A AgentCard (/.well-known/agent.json)"),
    (&["workflow", "list"], "", "List available workflows with step counts"),
    (&["workflow", "run"], "<name> [-i <key=value>]...", "Run a workflow synchronously and print per-step status (600s)"),
    (&["prompt-skills", "list"], "", "List prompt skill templates with priority and fitness"),
    (&["prompt-skills", "info"], "<name>", "Show one prompt skill's metadata and content"),
    (&["prompt-skills", "get"], "<name>", "Hidden: alias of `prompt-skills info`"),
    (&["prompt-skills", "proposals"], "[--status <s>] [--limit <n>]", "List runtime skills awaiting promotion, with who filed them"),
    (&["browser", "status"], "", "List active browser-automation sessions"),
    (&["browser", "open"], "<url> [-n <node>]", "Navigate a browser-automation session to a URL and print title plus text preview"),
    (&["browser", "stop"], "[<session-id>]", "Stop one browser session, or every session when no id is given"),
    (&["tools", "list"], "[--node <node-id>]", "List registered cluster tools (base/specialized shown only when reported), or one node's"),
    (&["tools", "select"], "<prompt>", "Hidden: retired, it previewed a matcher the agent does not use"),
    (&["tools", "info"], "<tool-name>", "Show one tool's registry entry"),
    (&["controller", "promote"], "[--name <n>] [--restage-nodes] [-y|--yes]", "Claim the controller role name on the tailnet, re-issue cert and restart gateway"),
    (&["controller", "demote"], "[--name <hostname>] [-y|--yes]", "Release the controller role name back to the machine hostname and reset serve"),
    (&["migrate", "export"], "[-o <file>] [--passphrase-file <f>]", "Seal controller state (secrets, age key, PKI, env, pg_dump) into one archive"),
    (&["migrate", "import"], "<archive> [--passphrase-file <f>] [--data-root <dir>]", "Forward to `noo onboard --from-archive <f>` to restore a controller from an archive"),
    (&["offboard"], "[--check] [-y|--yes] [--keep-tailnet] [--purge-secrets] [--uninstall]", "Tear a standalone controller down to bare prep; destructive, confirms each step (-y)"),
    (&["bundle", "export"], "<out.tar.gz>", "Write the embedded standalone deploy slice as a bundle plus .sha256 sidecar"),
    (&["skills", "list"], "", "List containerized skills from the local registry dirs (no gateway)"),
    (&["skills", "info"], "<name>", "Show one skill's full manifest from the local registry scan"),
    (&["skills", "run"], "<name> <input-json> [-n <node>]", "Run a skill in its sandbox container through the gateway, on the node it picks or -n"),
    (&["skills", "scaffold"], "<name> [-d <dir>]", "Generate a skill skeleton (manifest.yml + run.py) in the user skills dir"),
    (&["onboard"], "[--tui|--web [--port <n>]] [--non-interactive|--ci] [--dry-run] [--reconfigure] [--standalone [--bundle <url|path>]] [--from-archive <f> [--passphrase-file <f>]] [--only <sections>] [--skip-tailscale] [--skip-security] [--skip-storage] [--skip-services] [--skip-trellion] [--skip-model] [--skip-channels] [--mcp-door|--no-mcp-door] [--skip-addons] [--secrets-backend sops]", "Run the setup wizard to bootstrap a controller (secrets, PKI, .env, compose, model)"),
    (&["config", "show"], "[--config <path>]", "Print noomesh.yaml: --config, $NOO_CONFIG, ./noomesh.yaml, ~/.config/mesh/config.yaml"),
    (&["config", "export-effective"], "[-o <file>]", "Export the effective runtime config (autonomy + KB rules/grants) as YAML"),
    (&["agents", "send"], "<to> <text…> [--from <agent>] [--agent <name>] [--harness <h>] [--thread <id>] [--kind message|task|result|ack|note] [--ref <msg-id>]… [--body <json>]", "Send a message to an agent, a thread, or * (broadcast; operator-only); recorded as you"),
    (&["agents", "inbox"], "[--agent <id>] [--unread] [--limit <n>]", "Messages to --agent (any recipient if omitted), newest first; = messages --to"),
    (&["agents", "thread"], "<thread-id>", "Every message in a thread, oldest first"),
    (&["agents", "presence"], "[--owner <account>]", "Live MCP windows under an account, each by the name mail can address"),
    (&["agents", "messages"], "[--agent <id>] [--from <id>] [--to <id>] [--user <u>] [--node <n>] [--harness <h>] [--kind <k>] [--since <rfc3339>] [--limit <n>] [--threads]", "Review agent traffic by agent, user, node or harness (operator); --threads lists threads"),
    (&["agents", "archive", "list"], "", "List the archived agent-mail files (month, messages, size); operator"),
    (&["agents", "archive", "export"], "<YYYY-MM|file> [--decrypt] [--out <path>]", "Write an archived month as JSONL, sealed; --decrypt opens it (audited, needs --out)"),
    (&["tasks", "create"], "<objective> [--model <m>] [--budget <loops>] [-t|--token-budget <tokens>]", "Give the agent an objective to loop on until done (needs `noo auth login`)"),
    (&["tasks", "list"], "[--state <s>] [--user <u>] [-n|--limit <n>]", "List tasks: yours, or everyone's as an operator"),
    (&["tasks", "show"], "<id>", "One task: state, loops, last note, result"),
    (&["tasks", "stop"], "<id> | --via addon:<name> [--user <u>]", "Stop a task, or revoke an add-on's background work with --via (--user: operators)"),
    (&["tasks", "resubmit"], "<id> [-t|--token-budget <tokens>]", "Give a task more tokens; one stopped out of tokens resumes from its checkpoint"),
    (&["tasks", "answer"], "<id> <text>...", "Answer the question a task asked you; a new loop starts with your answer"),
    (&["agents", "collaborate"], "<task> [-r <roles-csv>]", "Run a multi-agent collaboration on a task and print each role's output (300s)"),
    (&["agents", "peer", "dispatch"], "<agent-id> <task> [-r <role>]", "Dispatch a task to an A2A peer agent and print the task id"),
    (&["channels", "test"], "<channel> <recipient> [-m <message>]", "Send a real test message through a channel adapter to a recipient"),
    (&["inference", "agent"], "<prompt>", "Run a prompt through the gateway agent runner and print the response"),
    (&["prompt-skills", "create"], "<name> [-f <file>] [-d <description>] [--tags <csv>] [-p <priority>]", "Create a prompt skill from a file or stdin content"),
    (&["prompt-skills", "evolve"], "[-o <observation>] [--skill <name>] [--role <role>] [--apply]", "Propose (or with --apply, write) an LLM-evolved prompt skill"),
    (&["prompt-skills", "decide"], "<id> (--promote | --reject) [--reason <text>]", "Promote a reviewed runtime skill to instructions, or reject it"),
    (&["logs", "containers"], "[-n|--node <node-id>]", "List Docker containers across cluster nodes via the node-agents"),
    (&["logs", "query"], "<logql> [-l|--limit <limit>]", "Run a raw LogQL query against Loki and print streams and lines"),
    (&["logs", "status"], "", "Report Loki connectivity and node-registry availability"),
    (&["chat"], "[--model <m>] [--message <text>]", "Chat with the cluster gateway: streaming REPL, or one-shot with --message"),
    (&["systems", "status"], "", "Show each manifest system's enabled state and whether its credentials exist"),
    (&["systems", "enable"], "<name> [--dry-run]", "Enable a database-extending system and mint its credentials if absent"),
    (&["systems", "disable"], "<name> [--dry-run]", "Clear a system's enable intent; keeps its role, schema and data"),
    (&["approval", "approve"], "<request-id>", "Approve a pending tool-execution request"),
    (&["approval", "deny"], "<request-id> [-r|--reason <reason>]", "Deny a pending tool-execution request"),
    (&["voice", "transcribe"], "<file> [--model <m>] [--language <l>] [-o <file>] [--timestamps]", "Transcribe an audio file through the gateway's whisper service"),
    (&["voice", "synthesize"], "<text> [-o <file>] [--backend <b>] [--voice <v>] [--speed <s>]", "Synthesize speech via the gateway and write audio to a file (default speech.*)"),
    (&["voice", "speak"], "<text> [--backend <b>] [--voice <v>] [--speed <s>]", "Synthesize speech via the gateway and play it with the first system player found"),
    (&["voice", "status"], "", "Report STT/TTS backend availability as seen by the gateway"),
    (&["voice", "voices"], "[--backend <b>]", "List installed TTS voices, optionally filtered by backend"),
    (&["plugins", "list"], "", "List executable noo-<name> shim plugins found on PATH and in the plugins dir"),
    (&["tools", "export"], "[-o <path>] [--check] [--force]", "Write the full tool registry to config/tools.json; --check diffs without writing"),
    (&["mcp", "tools"], "", "List the MCP hub's unified tool catalog via a streamable-http JSON-RPC exchange"),
    (&["mcp", "external-setup"], "[-G <gateway-url>] [--save]", "Hidden: retired recipe printer for the external MCP door; exits 2"),
    (&["mcp", "server", "add"], "<id> --transport http --url <u> [--header K=$NAME]... [--kind tool|device] [--audience a,b] [--note <t>] [--disabled]", "Register an http MCP server the node dials (record only; secrets as $NAME refs)"),
    (&["mcp", "server", "list"], "", "List registered external MCP servers with placement and tool counts"),
    (&["mcp", "server", "show"], "<id>", "Show one external MCP server: spec, audience, placements, discovered tools"),
    (&["mcp", "server", "enable"], "<id>", "Enable a registered external MCP server"),
    (&["mcp", "server", "disable"], "<id>", "Disable a registered external MCP server without removing it"),
    (&["mcp", "server", "remove"], "<id> [-y|--yes]", "Remove an external MCP server record and its placements; confirms unless -y"),
    (&["mcp", "place"], "<id> <node> [--stopped]", "Declare which registered node dials an external MCP server"),
    (&["mcp", "unplace"], "<id> <node>", "Remove an external MCP server's placement from a node"),
    (&["mcp", "import"], "[<file>] [--dry-run]", "Upsert external MCP servers and placements from a YAML data file"),
    (&["mcp", "export"], "[-f|--file <path>]", "Snapshot the external MCP server registry as an importable YAML data file"),
    (&["auth", "connect"], "google [--drive] [--gmail] [--pair]", "Connect Google in a browser; --pair displays a code to approve on your phone"),
    (&["auth", "login"], "[<username>] [-u <username>] [--password-stdin]", "Log in to the gateway and store a per-user access/refresh credential"),
    (&["auth", "status"], "", "Show which credential this CLI would use and whether the gateway accepts it"),
    (&["auth", "logout"], "", "Revoke the stored refresh token server-side and delete the local credential"),
    (&["usage"], "[-m <YYYY-MM> | --all-time] [-g node|model|backend|source|user|consumer|day]", "Show token-usage totals for a month or all time, grouped by a dimension"),
    (&["usage", "me"], "[-p|--period day|week|month] [-u|--user <user>]", "Show your token spend this period: node, cloud and harness apart, and your allowance"),
    (&["upgrade"], "[--check] [--version <X.Y.Z>] [--stack] [--nodes] [--seats|--no-seats] [--all] [--tag <vX.Y.Z>] [--controller] [--allow-unsigned] [--force] [--skip-gateway-key-check] [--allow-downgrade] [--stage2] [--channel <public|rollback|custom>] [--release-repo <owner/repo>] [--image-prefix <registry/path>] [--base-registry <registry/path>] [--yes]", "Self-update noo, optionally stack, nodes and kiosk seats; --channel moves release channel"),
    (&["addons", "list"], "", "Show every add-on: declared, effective and whether the licence grants it"),
    (&["addons", "show"], "<name>", "Show one add-on's switch, pin, and the database, workloads and inputs its bundle declares"),
    (&["addons", "enable"], "<name> [--force] [--lock <path|https-url>] [--provision-only]", "Pin an add-on's signed lock, mint credentials, declare it ON (--provision-only: DB only)"),
    (&["addons", "check"], "<bundle-dir> [--name <addon>]", "Enable's guard + resources checks on a bundle dir; not routes.json, signature, key, image"),
    (&["addons", "trust-key"], "<name> <pubkey> [--registry <host/path>] [--dev] [--expires <dur>]", "Trust a third-party add-on's signing key; --dev --expires (max 30d): a temporary dev key"),
    (&["addons", "untrust-key"], "<name> [<pubkey>] [--dev]", "Stop trusting a third-party add-on's signing key; --dev removes its dev key(s)"),
    (&["addons", "set"], "<name> --delegate tasks|off", "Let an add-on act on a person's tasks (needs its manifest to declare it too)"),
    (&["addons", "disable"], "<name>", "Declare an add-on OFF in noomesh.yaml; restart applies it"),
    (&["addons", "upgrade"], "[<name>...] [--check] [--allow-downgrade] [--lock <path|https-url>]", "Re-resolve add-ons' signed locks for this stack, pull by digest and re-pin"),
    (&["addons", "verify"], "", "Re-verify add-on locks offline and compare local and running images with the pins"),
    (&["addons", "launch-pins"], "[--root <dir>] <tag> [<name>...]", "Hidden: print verified add-on image pins for the launcher (internal)"),
    (&["addons", "launch-resources"], "--root <d> --tag <t> --project <p> --network <n> <name>...", "Hidden: write add-ons' declared runtime inputs for the launcher (internal)"),
    (&["addons", "rotate-secret"], "<name> <resource>", "Give an add-on's declared shared secret a new value; restart the add-on to apply"),
    (&["kiosk", "enroll"], "<blob> [--controller <https://…>] [--dry-run]", "Enroll this display as a kiosk seat (never a node); its CLI + assets then ride the rail"),
    (&["kiosk", "invite"], "<display-name> [--expiry-minutes <n>] [--url <https://…ts.net>]", "Controller: tag:kiosk, its two rules, a tagged auth key, the display's commands"),
    (&["kiosk", "labels"], "on|off|status", "Controller: entity names on the kiosk graph (kiosk.graph_labels; audited, no restart)"),
    (&["kiosk", "reload"], "", "Reload the page on the display and report the console build either side"),
    (&["kiosk", "seat-sync"], "[--migrate [--print]]", "Hidden: the seat's sync tick (internal); --migrate moves an old root seat, run once"),
    (&["kiosk", "seat-token"], "<seat-name> [--ttl <1h|30m|secs>] [--controller <https://…>]", "Controller: mint a one-time role=seat token; prints the seat's `noo kiosk enroll <blob>`"),
    (&["kiosk", "serve"], "[--port <n>]", "Hidden: the display's local proxy, run by kiosk-serve.service (internal)"),
    (&["kiosk", "setup"], "--mode dedicated|shared --url <https://…ts.net> [--vt <n>] [--user <name>] [--view health|graph] [--rotate <secs>] [--poll <secs>] [--quality lean|full] [--browser <bin>] [--dry-run] [-y|--yes]", "Install the display seat: kiosk user, cage + Chromium unit, token launcher, watchdog"),
    (&["kiosk", "status"], "", "Report the seat: units, mint, expiry, heartbeat, graph labels (no privilege needed)"),
    (&["kiosk", "teardown"], "[-y|--yes]", "Remove the seat's units and files; keeps the kiosk user; asks for confirmation (-y)"),
];

/// Is `word` a command GROUP this binary serves natively?
///
/// Exists so a diagnostic can tell "there is no such subcommand" apart from
/// "this whole group needs the Python install". `noo security keys list`
/// used to answer the second — sending an operator to install Python for a
/// group of 40-odd native subcommands, because the only thing wrong was the
/// word `keys` (the verb is `service-key`).
pub fn is_native_group(word: &str) -> bool {
    USAGE.iter().any(|(w, _, _)| w.first() == Some(&word))
}

/// The native next words under the command path `prefix` (`["cluster",
/// "class"]` -> `list`, `set`, `unset`), in declaration order, deduplicated.
/// Hidden rows (aliases, retired verbs) still dispatch; they are not offered.
pub fn subcommands_under(prefix: &[&str]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for (w, _, about) in USAGE.iter() {
        if about.starts_with("Hidden:") {
            continue;
        }
        if w.len() > prefix.len() && w[..prefix.len()] == *prefix {
            let sub = w[prefix.len()];
            if !out.contains(&sub) {
                out.push(sub);
            }
        }
    }
    out
}

/// True when `words` is a complete command row (not just a group prefix).
pub fn is_command(words: &[&str]) -> bool {
    USAGE.iter().any(|(w, _, _)| *w == words)
}

/// (syntax, description) for exactly these command words.
pub fn lookup(words: &[&str]) -> Option<(&'static str, &'static str)> {
    USAGE
        .iter()
        .find(|(w, _, _)| *w == words)
        .map(|(_, s, d)| (*s, *d))
}

/// A native group (or nested group) followed by a word or flag it does not
/// own. `path` is the deepest command path that parsed (`cluster class`),
/// `unknown` the first token after it, `near` the nearest real next word:
/// `--verify` is the subcommand `verify` typed as a flag; `verfy` is a typo.
#[derive(Debug)]
pub(crate) struct Misuse {
    pub path: Vec<String>,
    pub unknown: Option<String>,
    pub near: Option<&'static str>,
}

/// `argv` (starting at the command word) names a native group but not a
/// command under it. `None` when the first word is not a native group, or
/// when a complete command row is followed by arguments (those are its
/// arguments, not a verb).
pub(crate) fn native_group_misuse(argv: &[String]) -> Option<Misuse> {
    argv.first().filter(|w| is_native_group(w))?;
    // Walk down while the next word extends a known command path.
    let mut path: Vec<&str> = vec![argv[0].as_str()];
    for tok in &argv[1..] {
        if tok.starts_with('-') || is_command(&path) {
            break;
        }
        if subcommands_under(&path).contains(&tok.as_str()) {
            path.push(tok.as_str());
        } else {
            break;
        }
    }
    if is_command(&path) && argv.len() > path.len() {
        return None;
    }
    let subs = subcommands_under(&path);
    let unknown = argv.get(path.len()).cloned();
    let near = unknown.as_ref().and_then(|tok| {
        let bare = tok.trim_start_matches('-');
        if bare.is_empty() {
            return None;
        }
        subs.iter()
            .copied()
            .find(|s| *s == bare)
            .or_else(|| subs.iter().copied().find(|s| crate::edit_distance(s, bare) <= 2))
    });
    Some(Misuse { path: path.iter().map(|s| s.to_string()).collect(), unknown, near })
}

#[cfg(test)]
mod tests {
    /// By design, `--break-glass` is gone. No usage line
    /// may offer it, nor the shared-secret opt-in it set.
    #[test]
    fn no_usage_line_offers_break_glass() {
        for (words, syntax, about) in super::USAGE {
            let line = format!("{} {syntax} {about}", words.join(" "));
            assert!(!line.contains("break-glass") && !line.contains("BREAK_GLASS"), "{line}");
        }
        let main = include_str!("main.rs");
        let banner = main.split("ui::muted(\"Globals:").nth(1).expect("the globals banner").split('\n').next().unwrap();
        assert!(!banner.contains("break-glass"), "{banner}");
    }

    /// The hardware-target and usage-profile flags are on the help lines.
    #[test]
    fn place_fit_and_set_config_name_the_target_and_usage_flags() {
        let (syntax, desc) = super::lookup(&["cluster", "place"]).expect("place");
        assert!(syntax.contains("[--on cpu|gpu]") && desc.contains("cpu or gpu"), "{syntax} / {desc}");
        let (syntax, desc) = super::lookup(&["cluster", "fit"]).expect("fit");
        assert!(syntax.contains("[--on cpu|gpu]") && desc.contains("RAM"), "{syntax} / {desc}");
        let (syntax, _) = super::lookup(&["cluster", "set-config"]).expect("set-config");
        assert!(syntax.contains("[--usage shared|dedicated|default]"), "{syntax}");
        assert!(syntax.contains("[--vendor-kinds <kind,kind>|none]"), "{syntax}");
        let (syntax, _) = super::lookup(&["cluster", "vendor", "install"]).expect("vendor install");
        assert_eq!(syntax, "<node> <kind>...");
    }

    /// `noo security at-rest status|opt-out|opt-in` (i10a) are on the help
    /// lines, with `--json` on status and the "your own login" requirement on
    /// the two writers.
    #[test]
    fn at_rest_verbs_are_on_the_help_lines() {
        let (syntax, desc) = super::lookup(&["security", "at-rest", "status"]).expect("at-rest status");
        assert_eq!(syntax, "[--json]");
        assert!(desc.contains("TPM"), "{desc}");
        for verb in ["opt-out", "opt-in"] {
            let (syntax, desc) = super::lookup(&["security", "at-rest", verb]).unwrap_or_else(|| panic!("at-rest {verb}"));
            assert_eq!(syntax, "");
            assert!(desc.contains("own login"), "{verb}: {desc}");
        }
        assert_eq!(
            super::subcommands_under(&["security", "at-rest"]),
            vec!["status", "opt-out", "opt-in", "create-volume", "seal", "finalize", "migrate", "wipe-plaintext", "recovery-key", "reenroll", "preflight-firmware"]
        );
        // i10a PR-C: the volume, with the deferral that is the only way to run it without a terminal.
        let (syntax, desc) = super::lookup(&["security", "at-rest", "create-volume"]).expect("at-rest create-volume");
        assert!(syntax.contains("--defer-recovery-key") && syntax.contains("--size <GiB>"), "{syntax}");
        assert!(desc.contains("recovery key once"), "{desc}");
        // i10a PR-D: the migration, and the separate verb that deletes.
        let (syntax, desc) = super::lookup(&["security", "at-rest", "migrate"]).expect("at-rest migrate");
        assert!(syntax.contains("--dry-run") && syntax.contains("--rollback"), "{syntax}");
        assert!(desc.contains("backup first"), "{desc}");
        let (syntax, desc) = super::lookup(&["security", "at-rest", "wipe-plaintext"]).expect("at-rest wipe-plaintext");
        assert!(syntax.contains("--confirm") && syntax.contains("--hours"), "{syntax}");
        assert!(desc.contains("Delete"), "{desc}");
        // i10a PR-E: rotation, re-enrollment, firmware preflight.
        let (_, d) = super::lookup(&["security", "at-rest", "recovery-key"]).expect("at-rest recovery-key");
        assert!(d.contains("only after you confirm"), "{d}");
        let (syntax, _) = super::lookup(&["security", "at-rest", "reenroll"]).expect("at-rest reenroll");
        assert!(syntax.contains("--pcrs 7|none|auto"), "{syntax}");
        assert!(super::lookup(&["security", "at-rest", "preflight-firmware"]).is_some());
    }
}

#[cfg(test)]
mod misuse_tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_flag_typed_subcommand_is_matched_to_the_subcommand() {
        let m = native_group_misuse(&argv(&["cluster", "--verify"])).expect("misuse");
        assert_eq!(m.path, vec!["cluster"]);
        assert_eq!(m.near, Some("verify"));
    }

    #[test]
    fn a_typo_gets_the_nearest_subcommand_and_garbage_gets_none() {
        let m = native_group_misuse(&argv(&["cluster", "verfy"])).expect("misuse");
        assert_eq!(m.near, Some("verify"));
        let m = native_group_misuse(&argv(&["cluster", "--zzzzzzzz"])).expect("misuse");
        assert_eq!(m.near, None);
        assert!(native_group_misuse(&argv(&["definitelynotacommand"])).is_none());
    }

    #[test]
    fn the_unknown_token_is_the_one_after_the_deepest_parsed_level() {
        let m = native_group_misuse(&argv(&["cluster", "bogus", "chat-default", "host3/vllm"])).expect("misuse");
        assert_eq!(m.unknown.as_deref(), Some("bogus"));
        // i136a: `class` parsed; `show` is the wrong word, not `class`.
        let m = native_group_misuse(&argv(&["cluster", "class", "show", "chat-default"])).expect("misuse");
        assert_eq!(m.path, vec!["cluster", "class"]);
        assert_eq!(m.unknown.as_deref(), Some("show"));
        let m = native_group_misuse(&argv(&["cluster", "class", "lst"])).expect("misuse");
        assert_eq!(m.near, Some("list"));
        // a complete nested command with arguments is not a misuse
        assert!(native_group_misuse(&argv(&["cluster", "class", "set", "chat-default", "host3/vllm"])).is_none());
        // `security keys list`: the verb is `service-key`
        let m = native_group_misuse(&argv(&["security", "keys", "list"])).expect("misuse");
        assert_eq!(m.unknown.as_deref(), Some("keys"));
        assert!(subcommands_under(&["security"]).contains(&"service-key"));
    }
}
