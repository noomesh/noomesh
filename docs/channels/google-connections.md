# Google accounts and source setup

**Connections** is available in both console editions to signed-in users.
Connect multiple Google accounts, verify their emails through Google, and save
several Drive/Gmail source selections under each account. Installer and user
instructions are in [Connect external accounts](../getting-started/integrations.md).

Authorization, encrypted token storage, refresh and resource listing are
implemented. Source selections remain drafts: ingestion, search and background
sync for these connections are not implemented. The existing service-account
Drive watcher remains independent. Account drafts are still available before
an installer configures OAuth.

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
| DELETE | `/api/connections/accounts/{id}` | Remove own account, local encrypted credentials, pending reconnects and source drafts; no provider revocation |
| POST | `/api/connections/sources` | Save a source draft from `account_id`, `name`, typed `policy` |
| DELETE | `/api/connections/sources/{id}` | Remove own source draft |

Every API mutation takes its owner from the authenticated Noomesh account,
including Operator/Admin. Internal/service credentials without a user are
refused. Composite foreign keys enforce owner consistency. Cross-user ids
have the same response as missing ids. Account erasure also removes credentials
and pending authorization, including with `keep_account` enabled.

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
Google authorization. The source table remains in draft state until a later
implementation provides ingestion and activation.

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
