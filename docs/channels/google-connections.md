# Google accounts and source setup

**Connections** is available in both console editions to signed-in users.
Connect multiple Google accounts, verify their emails through Google, and save
several Drive/Gmail source selections under each account. Installer and user
instructions are in [Connect external accounts](../getting-started/integrations.md).

Authorization, encrypted token storage, refresh, resource listing and private
background sync are implemented. Saving a source does not start ingestion:
choose **Start private sync** after selecting folders, a drive or Gmail labels.
The existing installation-wide service-account Drive watcher remains independent.

## API and ownership

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/api/connections` | Own accounts, verified emails, actual granted scopes, source drafts and provider readiness; no credentials |
| POST | `/api/connections/oauth/start` | Start owner-bound authorization for `provider`, `services`, `client_kind`, optional owned `account_id`; desktop requires loopback `redirect_uri` |
| GET | `/api/connections/oauth/callback` | Public static no-store HTML returns the authorization response to the initiating console tab; no token exchange or account changes |
| POST | `/api/connections/oauth/complete` | Authenticated exchange using `session_id`, `completion_token`, `state`, `code` |
| POST | `/api/connections/oauth/cancel` | Cancel an owned `session_id` |
| GET | `/api/connections/accounts/{id}/resources` | Own folders, shared drives, or Gmail labels using `service=folders\|drives\|gmail` and optional `page` |
| POST | `/api/connections/accounts` | Prepare an account draft from `label` and optional unverified `email_hint` |
| DELETE | `/api/connections/accounts/{id}` | Remove own account, local encrypted credentials, pending reconnects, sync jobs and imported content; no provider revocation |
| POST | `/api/connections/sources` | Save a source draft from `account_id`, `name`, typed `policy` |
| DELETE | `/api/connections/sources/{id}` | Remove own source and imported content |
| POST | `/api/connections/sources/{id}/sync` | Start or pause own private sync with `enabled` |
| POST | `/api/connections/search` | Search own encrypted imported content with `query`, optional `limit` |

Every API mutation takes its owner from the authenticated Noomesh account,
including Operator/Admin. Internal/service credentials without a user are
refused. Composite foreign keys enforce owner consistency. Cross-user ids
have the same response as missing ids. Account erasure also removes credentials
and pending authorization, including with `keep_account` enabled.

## Personal ingestion and retrieval

The personal corpus lives in `noo_integration_documents`, separate from the
shared KB's documents, chunks, embeddings, graph, retagging and caches. Titles,
text, provider links and item IDs are encrypted using the integration vault with
owner/source/item authenticated context. Sync cursors are encrypted with a
separate purpose context. The shared worker does not receive these plaintext
records or the vault key. Host administrators remain trusted with the running
controller and its encryption keys.

The sync request accepts only `enabled`; its owner comes from the authenticated
Noomesh account. Jobs persist that owner through a composite source foreign key.
Each provider page and cursor commit together, after rechecking the user, source,
account, lease and generation. Expired/replaced leases, pause, disconnect and
erasure prevent a late page from restoring content. Failures retry with bounded
backoff; five consecutive failures stop automatic retries until the user restarts
sync. A completed scan removes items no longer present in the provider selection.
Disconnect/source deletion cascade through jobs and stored personal documents.

Identical content and provider IDs from different users/accounts remain independent:
deduplication uses `(owner_uuid, source_id, item_key)`, never a global content hash.
No caller can supply roles, owner, visibility or a job lease. Google sharing does
not grant Noomesh access. Admin and unrestricted KB roles do not override the
personal owner check. Internal/service identities, delegated MCP/agent/harness
credentials and shared-room turns receive no personal evidence. Credential
`act` and `harness` provenance survives HTTP-to-principal conversion, signed
bus messages and deferred replay; request bodies cannot remove those markers.

Owner-only lexical search runs over a bounded decrypted window and returns
snippets/citations. Shared KB queries exclude personal content by default.
A human standalone HTTP request can explicitly set `include_personal: true`
(`noo rag query "question" --personal`) to add personal results on the gateway
after shared retrieval. Native model tools never opt in, and credential-bound
`act` or `harness` markers refuse private reads even on explicit opt-in.
Here, "human" means an ordinary login credential such as `noo auth login`;
it is not proof that a person is at the keyboard. A local process holding
that credential has the user's authority. Keep login credentials private;
give agents their own delegated credentials, which cannot opt in.
Query bodies cannot choose another owner. Personal excerpts never reach shared
workers or graph/walk stores, and there is no personal result cache.

Unreadable private documents are skipped with `unavailable: true`. A private
failure never takes down shared retrieval: opted-in responses carry
`personal_sources_unavailable: true` and keep shared answers/citations.
Corrupt cursors or stored policies are marked `error`/`storage` under the claimed
row lock and committed individually before the queue moves on to healthy users.
An explicit owner restart resets a stopped job after the underlying problem is
corrected. Vault errors, row contents and policies are not logged or returned.
Fixed warning categories record private-read failures and quarantined jobs
without owner IDs, source IDs, titles, content, tokens or provider errors.
Do not rotate `NOO_INTEGRATIONS_KEY` in place: the wrong key makes stored
credentials, documents and cursors unreadable, and affected sources stop.
Restore the original key and have each owner restart their stopped sources.
If the key is lost, reconnect and re-import; there is no automatic key rotation.

**Persisted Noomesh chat is excluded in this batch.** Existing transcript,
conversation-memory and training-export permissions allow operators to read
other users' histories. Source ownership alone would not protect excerpts copied
there. Personal retrieval therefore refuses coordinator turns, conversation-bound
tool calls and shared rooms, and the chat context loader does not inject this
corpus. Private chat needs transcript/export isolation before activation. Users
can search from the CLI/standalone API; manually copying results into a shared
or operator-visible conversation follows that destination's existing permissions.
The personal corpus is absent from shared graph/list/export tables. Source removal
does not rewrite any manually copied text, past conversations or backups.

Current limits: 1,000 documents per source, 32 KiB text per document, 1 MiB provider
response, 20 items per page, 5,000 folders per traversal and a 1,000-document
retrieval window per owner. Search reports `truncated` when that window caps.
Drive checks metadata every 30 minutes; an idle Gmail source waits six hours
between scans. Gmail scan starts for one Noomesh user are at least one minute
apart across all their sources and gateway instances, including manual restarts;
their Gmail pages are also started at least one second apart per user.
Gmail `historyId` and Drive file `version`
revisions skip unchanged bodies and keep document ciphertext, row versions and
timestamps untouched. This is a bounded metadata rescan, not Gmail history/Drive
changes-stream sync. The encrypted cursor carries the revision inventory and
seen-item set; completion prunes items no longer in the selected snapshot without
rewriting unchanged document rows. Gmail examines at most 100 list pages and
2,000 message metadata records per scan, dividing pages across selected labels.
It selects up to 1,000 newest messages by `internalDate` among the examined
items. Google does not guarantee list order, so this is a best-effort window,
not necessarily the newest across the entire mailbox. At completion, items
outside the selected window are deleted from Noomesh; nothing is deleted at Google.
Drive caps at 1,000 supported
documents in traversal order, with each listing ordered by modification time.
Provider revision semantics: [Gmail messages](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages)
and [Drive files](https://developers.google.com/workspace/drive/api/reference/rest/v3/files).
Initial import supports Gmail plain-text bodies
and Drive text/plain, text/markdown, text/csv and Google Docs exports; attachments,
HTML-only messages, binary formats and oversized items are skipped. Semantic
embeddings, private graph extraction and binary parsers are not enabled for this
corpus; they must preserve the same owner boundary before being introduced.

PostgreSQL-backed cross-user tests run provider fixture parsing, encrypted
commit, resume/replay, search, admin isolation, pause/disconnect/erasure and stale
snapshot deletion. They also check that no shared KB table is needed by this path.

## Authorization lifecycle

The generic integration engine owns expiring ten-minute sessions, PKCE S256,
state, one-time consumption, identity deduplication and token encryption. Google
supplies the reviewed endpoints/scopes and verified UserInfo identity. Immutable
Google `sub`, scoped to the Noomesh owner and provider, identifies an account;
email hints never establish identity. The same Google identity can be linked
by separate Noomesh users without crossing their credential boundaries.

Only hashes of state and the completion ticket are stored in session columns.
The PKCE verifier and callback/client settings are encrypted. Session completion
requires the same authenticated owner and a ticket that never travels to Google
or through a URL. Atomic claiming prevents callback replay; final storage rechecks the claimed session under the same user-row lock as erasure. Cancellation or erasure during provider exchange prevents the grant from being saved. A mismatched
owner, state or ticket cannot consume the legitimate session.

The web callback uses a state-specific same-origin BroadcastChannel. It works
with the console's isolated browser windows, contains no server credentials,
and cannot perform account changes. The originating tab retains the completion
ticket in memory and performs the authenticated exchange. Closing it requires
starting again. The desktop helper instead listens on an ephemeral IPv4
loopback port on the browser's computer and completes via the same API.

Access/refresh tokens are ChaCha20-Poly1305 encrypted using a domain-separated
key derived from `NOO_INTEGRATIONS_KEY`, with independent random nonces and
owner/provider/account authenticated context. Encryption never falls back to
plaintext. Refreshes serialize on the account/credential rows; rotated refresh
tokens replace their predecessors atomically. `invalid_grant` marks an account
`reauth_required`. Client changes require reconnection. Token values and raw
provider errors are never API responses or application log messages.

Google's actual granted scopes determine capabilities, including partial
consent. Drive folder and Gmail label selections are use policies, not narrower
Google authorization. Draft metadata remains separate from the explicit
`sync_enabled` control; the metadata status cannot activate a job.

## Provider extension points

`gateway-rust/src/integrations/provider.rs` registers reviewed endpoint and
scope definitions; `oauth.rs` holds the reusable lifecycle and Google resource
adapter; `crypto.rs` implements the vault. Storage is in
`gateway-rust/src/repo/integrations.rs`; personal corpus/queue storage is in
`repo/integration_content.rs` and pairing storage in `repo/integration_pairing.rs`. The mesh migration
`106_integration_pairing` adds owner-bound, single-use CLI-to-phone handoffs.
`noo auth connect google --pair` displays a ten-minute code and a phone URL.
The same signed-in Noomesh owner reviews the device and services on the phone,
then completes the existing Web OAuth flow. CLI polling receives only status
and the connected account ID. Completion and credential storage commit
together; cancellation and user erasure also remove pending grants. See the
[phone setup guide](../getting-started/integrations.md#approve-from-your-phone-with-a-pairing-code).

`105_integration_oauth` adds credentials, sessions, verified identity and
account authorization status after the original source-draft migration.

Add a provider definition and identity/resource adapter, then register its
configuration and any provider-issued secret through the existing secret
registry and file delivery. Do not accept arbitrary owner-supplied endpoint
URLs. OAuth credentials stay separate from source policy and token material
never enters the list contract. Contracts are maintained in the server/UI
OpenAPI files and regenerated TypeScript types.

`107_integration_content` adds the separate encrypted personal corpus and durable owner-bound sync queue. `108_integration_pacing` adds the per-user Gmail scan-start interval.

## Release rehearsal without Google credentials

Build the gateway libtest executable from the reviewed worktree using
`scripts/cargo-docker.sh test --locked --no-run --bin noo-gateway`. Cargo prints
the executable under `gateway-rust/target/debug/deps/noo_gateway-…`. Then run:

```bash
python3 scripts/test-google-integrations-rehearsal.py \
  --gateway-tests gateway-rust/target/debug/deps/noo_gateway-REPLACE-WITH-BUILT-HASH
```

The runner requires Python 3.10+ and Docker. It uses locally available
`pgvector/pgvector:pg18` and `rust:1-bookworm` images; use `--postgres-image` and
`--runner-image` for the release runner's reviewed mirrors. It never pulls an
image implicitly. The JSON result identifies the checkout, dirty state, binary
hash, actual image IDs and passing test counts. Rebuild after changing source;
the binary hash is evidence of the tested artifact, not a freshness guarantee.

PostgreSQL runs on a new internal Docker network, without published ports or
host storage. Its fixture-only trust authentication is confined to that network.
The test runner receives a synthetic database DSN, a read-only test executable
and no installation config, TLS keys, Google registrations or secret store.
The runner removes only the database/network it created. It contacts no Google
endpoint; OAuth and provider responses are deterministic fixtures, with HTTP
stubs on loopback where needed. No real mailbox or Drive content is fetched.

The rehearsal first proves that a missing test DSN fails rather than silently
skipping. Each suite must execute its minimum test count, without failures or
ignored tests. CI also sets `NOO_REQUIRE_GOOGLE_REHEARSAL=1` for its real-database
gateway runs, so losing the DSN fails those integration checks.

| Boundary | Rehearsal coverage |
| --- | --- |
| Multiple users/accounts | Both Gmail and Drive, identical provider IDs/content, independent accounts/sources, cross-user and administrator refusals |
| OAuth and pairing | PKCE, verified identity, partial consent, refresh, state/ticket replay, expiry, wrong owner/origin and cancellation during completion |
| Pause and concurrency | Lease expiry/replacement, duplicate pages, competing workers, late writes after pause/disconnect |
| Disconnect and erasure | Production account/source removal cascades and user erasure prevent content or pending grants being restored |
| Private search | Only the authenticated user sees snippets; service principals, shared rooms, disabled users and persisted conversation/tool contexts receive no personal evidence |
| Agent and failure boundaries | Actual MCP-minted JWTs through real auth/principal middleware cannot read private sources with either delegation marker; opt-in is boolean and human-only; corrupt rows degrade search and poisoned jobs cannot block another owner |
| Snapshot bounds and pruning | Unchanged Gmail/Drive scans download no bodies and preserve row versions/timestamps/ciphertext; 1,001 Gmail messages complete newest-first, prune stale rows and leave another owner's identical message untouched |
| Response protection | Callback CSP and no-store headers, strict request shapes, owner resolution for User/Operator/Admin |
| Migration compatibility | Existing `103_pg_stat_statements` preserved; new migrations `104_connection_drafts` through `108_integration_pacing` follow it |

This is the component rehearsal. General still owns the review, combined
0.6.14 batch build and signed-stack rehearsal. Record the tested head and
results in the PR/release handoff. The controller's required secret names,
conditions and file destinations are in the
[runtime secret inventory](../getting-started/integrations.md#controller-runtime-secret-inventory).

After the roll, the operator separately verifies the exact registered HTTPS
callback and reachable phone console, provisions secrets through `env.sops`,
and tests a real Noomesh user with `noo auth connect google --pair`. Choose a
small Drive folder and Gmail label, explicitly start sync, verify owner search,
then verify a second user/admin cannot retrieve the first user's data. Pause,
disconnect and confirm imported content disappears on removal. Automated
fixtures do not substitute for this real-content and two-user acceptance.
