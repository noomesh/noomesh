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
personal owner check. Internal/service identities and shared-room turns receive
no personal evidence.

Owner-only lexical search runs over a bounded decrypted window and returns
snippets/citations. The normal KB query and coordinator context add those results
after shared retrieval, without publishing them to shared workers or graph/walk
stores. Query bodies cannot choose another owner. The personal corpus is excluded
from shared listing/graph/export APIs because those tables never contain it.
There is no personal result cache. Content returned to a user's conversation is
part of that user's conversation history; removing a source does not rewrite
past conversations or backups.

Current limits: 1,000 documents per source, 32 KiB text per document, 1 MiB provider
response, 20 items per page, 5,000 folders per traversal and a 1,000-document
retrieval window per owner. Search reports `truncated` when that window caps.
Sync repeats every 30 minutes. Initial import supports Gmail plain-text bodies
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
`gateway-rust/src/repo/integrations.rs`. The mesh migration
`105_integration_pairing` adds owner-bound, single-use CLI-to-phone handoffs.
`noo auth connect google --pair` displays a ten-minute code and a phone URL.
The same signed-in Noomesh owner reviews the device and services on the phone,
then completes the existing Web OAuth flow. CLI polling receives only status
and the connected account ID. Completion and credential storage commit
together; cancellation and user erasure also remove pending grants. See the
[phone setup guide](../getting-started/integrations.md#approve-from-your-phone-with-a-pairing-code).

`104_integration_oauth` adds credentials, sessions, verified identity and
account authorization status after the original source-draft migration.

Add a provider definition and identity/resource adapter, then register its
configuration and any provider-issued secret through the existing secret
registry and file delivery. Do not accept arbitrary owner-supplied endpoint
URLs. OAuth credentials stay separate from source policy and token material
never enters the list contract. Contracts are maintained in the server/UI
OpenAPI files and regenerated TypeScript types.

`106_integration_content` adds the separate encrypted personal corpus and durable owner-bound sync queue.
