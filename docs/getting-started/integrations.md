# Connect external accounts on a local installation

After the installer enables Google, open **Connections**, choose Drive, Gmail,
or both, click **Connect Google**, sign in and approve access. Repeat for each
Google account. Each Noomesh user owns their connections; work and personal
accounts can each have several source selections.

Saving source settings does not start ingestion. Choose **Start private sync**
after selecting folders, a drive or Gmail labels. Imported content stays private
to the connecting Noomesh user, including from other application administrators.
The older shared Drive watcher remains separate with different audience rules.

Google application registration is a one-time publisher or installer task.
Ordinary users do not each need a Google Cloud project. A local installation
still needs internet access to Google. Noomesh stores encrypted account tokens
in its own database; this flow needs no Noomesh cloud token store.

## For people

### Choose the installation's sign-in path

| Installation | Setup | User action |
| --- | --- | --- |
| Console at a stable HTTPS address | Installer-owned Google **Web application** client and registered callback | Click **Connect Google** in Connections |
| Browser on a computer with the Noomesh CLI | Publisher-registered or installer-owned **Desktop app** client | Run `noo auth connect google`; approve in the system browser |
| Remote controller, browser on a laptop | Either the registered HTTPS console callback or CLI helper on the laptop | Use the configured console button or run the helper locally against that controller |

The helper listens temporarily on `127.0.0.1` on the computer running it. Running
it over SSH on the controller does not create a callback on your laptop. The
helper uses your existing Noomesh CLI login and trusted gateway connection.
It sends the authorization response to that gateway; access and refresh tokens
are exchanged there and never returned to the CLI or browser.
[Google desktop authorization](https://developers.google.com/identity/protocols/oauth2/native-app)

#### Approve from your phone with a pairing code

On the execution computer, run:

```bash
noo auth connect google --pair
# Or choose a service:
noo auth connect google --gmail --pair
```

The CLI displays an HTTPS link and a code such as `ABCDE-FGHJK`, then waits.
On your phone, open that link, sign in to **the same Noomesh account as the
CLI**, enter the code, and review the device and requested services. Continue
to Google, choose an account, and approve access. The phone returns to Noomesh
and the waiting CLI reports success. Run the command again to add another
Google account. The phone flow uses a full-page redirect, without pop-ups or
installing a phone app. A QR code is not required.

Codes expire after ten minutes and can start authorization only once. A code
does not sign the phone in to Noomesh. Cancellation on the phone stops the
waiting CLI; closing the CLI leaves a request that expires automatically.
Requests are private to their Noomesh owner, including when an operator or
administrator connects an account. A successful grant is saved together with
the pairing result, so a cancelled or expired request cannot save credentials
after Google responds. No Google tokens are sent to the execution CLI or phone.

**Installer setup:** this mode needs a **Web application** OAuth client with
the installation's exact HTTPS callback registered in Google, plus its secret
and the integration encryption key. Use the existing
`/api/connections/oauth/callback` callback. The link comes from that callback's
origin and opens `/#/connect`; the phone must be able to reach it with a
trusted certificate. For a Tailscale-only installation, the phone must join
the same tailnet and its access policy must permit the console port.
The existing Desktop-only registration is sufficient for the local-browser
helper, but does not enable this browser-only phone flow. A publisher-operated
authorization relay for arbitrary installer hostnames is not included.

This is Noomesh's own pairing handoff around ordinary provider authorization.
Google's TV/device-code flow does not support the Gmail or `drive.readonly`
scopes used here. Other integration adapters can reuse the pairing endpoints,
expiry, owner checks, phone return and CLI polling with their registered Web
OAuth application; they must still implement provider identity and scopes.
[Google device-flow scopes](https://developers.google.com/identity/protocols/oauth2/limited-input-device#allowedscopes)

A publisher or installer can preconfigure a registered Desktop client ID in
YAML and import its Google-issued credential through the encrypted secret store.
These are runtime installation settings; gateway release binaries do not read
OAuth registrations from the build environment. Desktop clients are public and
use PKCE: the issued Desktop credential is a token-endpoint parameter, not proof
that a distributed application can keep a secret. Google can require it for
both code exchange and refresh. A Web client secret belongs only to the
installation's gateway and must never ship in shared customer binaries.

| Item | Where it belongs |
| --- | --- |
| Desktop client ID | Runtime installation configuration; public application registration |
| Desktop issued credential | Encrypted installation secret store; Google token-endpoint parameter with PKCE |
| Web client ID | Runtime installation configuration; public ID |
| Web client secret | Encrypted installation secret store, delivered only to the gateway |
| Google account access and refresh tokens | Encrypted database records owned by the signed-in Noomesh user |
| Pairing code and completion ticket | Short-lived setup state; private responses disable caching |

Pairing changes where users approve access, not Google's authorization
mechanism. Keep clients while installations or saved grants still use them.
Deleting an OAuth client invalidates its associated tokens; changing clients
requires reconnecting accounts.
[Google client deletion](https://support.google.com/cloud/answer/15549257)

The read-only Drive and Gmail scopes are broad Google permissions; folder/label
policies do not narrow them at Google. Public customer use needs the appropriate
Google app verification and assessment review. External apps in Testing issue
refresh tokens that expire after seven days for these scopes, so reconnecting
periodically is expected in testing.
[Scope verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification),
[refresh-token expiry](https://developers.google.com/identity/protocols/oauth2#expiration)

### Prepare Google for a test installation

Use an isolated Noomesh instance with its own database, data root and encrypted
secret store. See [multiple instances](multi-instance.md). Use separate Google
projects for testing and production.

1. In [Google Cloud Console](https://console.cloud.google.com/), create or choose
   a development project. Enable **Google Drive API** and **Gmail API** for the
   services you will test.
2. In **Google Auth platform**, configure Branding, Audience and Data Access.
   For personal Google accounts, use **External → Testing** and add each Google
   email as a test user. Workspace-only Internal apps have organization limits.
3. Add the scopes used by this adapter: `openid`, `email`,
   `https://www.googleapis.com/auth/drive.readonly` and/or
   `https://www.googleapis.com/auth/gmail.readonly`.
4. Under **Clients**, create the matching client type from the table below.

| Client | Google registration | Noomesh setting |
| --- | --- | --- |
| Desktop helper | **Desktop app** | `desktop_client_id` |
| Browser console | **Web application**; authorized redirect URI exactly `https://YOUR-CONSOLE/api/connections/oauth/callback` | `web_client_id`, `web_redirect_uri` and encrypted web client secret |

For both Noomesh integration clients, select **Use this client for an
AI-powered agent**. These clients are intended to authorize agent workflows
that retrieve Google context on the user's behalf. The designation does not
grant extra scopes or permissions. Google documents it as a creation-time
setting; choose it before creating each client. Keep any future conventional
Google login client separate from these integration clients.
[Google client setup](https://developers.google.com/workspace/guides/create-credentials)

Use the console's actual browser origin, including a non-default port. This
implementation requires HTTPS for the web path. Google must accept that
hostname; arbitrary LAN IPs and `.local` names are unsuitable for web clients.
The browser must reach the callback; Google does not need an inbound connection
to your controller for this redirect. A reverse proxy must preserve the callback
route, avoid recording its query string, and allow the console's same-origin
OAuth API requests. See [Google callback rules](https://developers.google.com/identity/protocols/oauth2/web-server#uri-validation).

Testing grants for these scopes, including refresh tokens, normally expire
after seven days. Add all accounts you plan to test; a test-user list supports
up to 100 users. Personal/development use can qualify for verification
exceptions; wider distribution requires reviewing Google's verification rules.
Drive/Gmail read scopes are restricted scopes. Installing locally does not
remove the publisher's obligations.
[Google audience settings](https://support.google.com/cloud/answer/15549945),
[verification exceptions](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification#exceptions-verification-requirements)

### Configure Noomesh once

#### Optional: check the project with the Google Cloud CLI

Install the [Google Cloud CLI](https://docs.cloud.google.com/sdk/docs/install-sdk),
then run these commands in your own terminal. Sign in with the Google account
that manages the existing project:

```bash
gcloud auth login
gcloud projects describe PROJECT_NUMBER --format='yaml(projectId,projectNumber,name,lifecycleState)'
gcloud services list --enabled --project=PROJECT_ID
```

Replace `PROJECT_NUMBER` and use the returned `projectId` for `PROJECT_ID`.
To enable the two APIs for this test project:

```bash
gcloud services enable drive.googleapis.com gmail.googleapis.com --project=PROJECT_ID
```

CLI sign-in authorizes project administration. Users still connect their own
Google accounts through Noomesh's consent flow. Configure the Web/Desktop
clients, test users and consent scopes in Google Auth platform as described
above. The similarly named `gcloud iam oauth-clients` commands manage federated
workforce/IAP clients; those are separate from this Google-account integration.
[Workforce OAuth applications](https://docs.cloud.google.com/iam/docs/workforce-manage-oauth-app)

Reusing a project lets you keep its existing application setup. Dedicated
Noomesh test clients within that project keep callback and credential changes
separate from PersonifAI or another application. If an old Web client secret
is unavailable, create a separate test client instead of rotating an existing
application's secret just to obtain a value for Noomesh.

#### Application settings and encrypted secrets

In the installation's `noomesh.yaml`, set the clients you will use. IDs and
callback URLs are public configuration; keep secrets out of YAML:

```yaml
integrations:
  providers:
    google:
      desktop_client_id: "YOUR-DESKTOP-CLIENT.apps.googleusercontent.com"
      web_client_id: "YOUR-WEB-CLIENT.apps.googleusercontent.com"
      web_redirect_uri: "https://YOUR-CONSOLE/api/connections/oauth/callback"
```

Omit the unused client fields. Desktop-only setup needs no web callback.
For an installer-owned Desktop client, import its issued `client_secret` as
`NOO_GOOGLE_DESKTOP_CLIENT_SECRET` through the encrypted secret store. Keep it
paired with the Desktop ID; the Web client has a separate credential.
Changing this configuration requires restarting the gateway.

`NOO_INTEGRATIONS_KEY` is a generated 32-byte installation encryption secret.
New onboarding generates it through the existing encrypted secret registry.
For an existing installation, use the secrets reconfiguration flow:

```bash
noo onboard --reconfigure --only secrets --secrets-backend sops
```

`noo upgrade --stack` also generates a missing integration key in `env.sops`
before deploying the new gateway. It preserves any existing key and refuses a
blank key or unreadable encrypted store rather than replacing it.

For the Desktop path, import the Google-issued parameter through
`noo security secrets rotate NOO_GOOGLE_DESKTOP_CLIENT_SECRET --set-from-stdin`.
For the web path, import the Google-issued client secret through
`noo security secrets rotate NOO_GOOGLE_OAUTH_CLIENT_SECRET --set-from-stdin`,
using a secure stdin source. Follow [Noomesh secrets](../security/secrets.md)
for encrypted storage, consumer recreation and verification. The gateway reads
these secrets from its file-backed delivery; do not put them in Compose command
lines or ordinary YAML. Verify after applying the configuration and restarting
the gateway that Connections reports the appropriate authorization path ready.

#### Controller runtime secret inventory

All three integration secrets belong in the controller installation's encrypted
`secrets/env.sops`. Never duplicate their values in `.env`, `noomesh.yaml`, a
Compose overlay, a shell argument, a support transcript or a release artifact.
The launcher decrypts the store into protected runtime files; Compose gives
only the gateway the read-only files listed below. `_FILE` settings are delivery
pointers, not extra credentials to enter into the store.

| Store key | Required for | Provisioning and gateway delivery |
| --- | --- | --- |
| `NOO_INTEGRATIONS_KEY` | Every Google connection, token refresh, private sync and search | Generated by the Noomesh secret registry with 32 random bytes. Delivered through `NOO_INTEGRATIONS_KEY_FILE=/run/secrets/noo_integrations_key`. Use a different key for each independent installation. |
| `NOO_GOOGLE_OAUTH_CLIENT_SECRET` | Web console and CLI-to-phone pairing | Google-issued **Web application** client secret matching `web_client_id`. Import via secure stdin; delivered through `NOO_GOOGLE_OAUTH_CLIENT_SECRET_FILE=/run/secrets/noo_google_oauth_client_secret`. |
| `NOO_GOOGLE_DESKTOP_CLIENT_SECRET` | Local CLI/browser loopback authorization | Google-issued **Desktop app** credential matching `desktop_client_id`. Import via secure stdin; delivered through `NOO_GOOGLE_DESKTOP_CLIENT_SECRET_FILE=/run/secrets/noo_google_desktop_client_secret`. It is optional when offering only the phone/Web path. |

For a phone-only controller, provision the integration key and Web secret; add
the Desktop credential only if local-browser authorization is offered too.
The client IDs, callback URL and source-selection policies are public runtime
settings in `noomesh.yaml`, not secrets. Existing Noomesh login, database and
TLS credentials continue through their existing encrypted provisioning; this
feature introduces no additional Google API key, service-account JSON, gcloud
login, phone password or shared pairing secret.

User access/refresh tokens are created by OAuth and stored only as encrypted
owner-bound database records. Pairing/session tickets and sync cursors are
generated by Noomesh, not manually provisioned in `env.sops`. A connected
account's Google password is never requested or stored by Noomesh.

Use `noo security secrets audit` to check store classification and
`noo cluster verify --controller` to check delivery after the targeted gateway
recreation. Do not reveal values to prove readiness. The encrypted store and
its off-repository age identity are installation backup material, not part of
the source/release bundle. Import the controller's own configuration; never
copy a test instance's database, account grants or encryption key into it.

Back up the encrypted store and database together. Losing or rotating
`NOO_INTEGRATIONS_KEY` makes existing encrypted grants unreadable; reconnect
every account unless its ciphertext has been migrated to the new key. The same
key protects imported documents and sync cursors, so losing it also requires
re-importing personal content. Preserve it across ordinary upgrades. There
is no plaintext fallback. Provider outages leave saved credentials intact.

#### Move setup to another controller

Deploy the reviewed gateway, CLI, UI and migrations through the normal stack
release. Configure that controller's exact HTTPS callback in both Google and
its `integrations.providers.google.web_redirect_uri`. An existing trusted
HTTPS console address can use its normal port; the NODE-A test's extra port is
not required on other hosts. Preserve callbacks still used by other installs.

Import the installer-owned Web secret through that controller's encrypted
secret workflow and generate its own integration encryption key. Use an
existing real Noomesh user on both the execution CLI and approving phone.
Run `noo auth connect google --pair` against this controller and verify that
the displayed phone URL belongs to it. Reconnect each Google account there;
do not copy the NODE-A test user's credentials or database rows into another
installation. The private test app's credentials are not publisher defaults.

Removing a verified account deletes local credentials and source settings and
cancels older pending authorizations for that provider and Noomesh owner,
including a Google response already in flight. Other connected accounts stay
connected. Cached resource lists for the removed account are cleared from the
UI. Removal does not revoke Google's application grant: manage that separately
in Google account permissions when needed. Integration connection, removal,
pairing-start and cancellation audits contain Noomesh identifiers and outcomes,
without Google emails, tokens, codes, selected content or message bodies.

### Connect and choose content

1. Log into your own Noomesh account. In **Connections**, select Drive, Gmail,
   or both, then **Connect Google**. Allow this site's pop-up and approve access
   in Google's browser page. Return to Noomesh to see the verified email.
2. For desktop/helper setup, run `noo auth login` first if needed, then:

   ```bash
   noo auth connect google                 # Drive and Gmail
   noo auth connect google --drive         # Drive only
   noo auth connect google --gmail         # Gmail only
   ```

   Run this on the browser's computer. With a remote controller, use your CLI's
   existing gateway selection and trusted connection to that controller.
3. Under the connected account choose **Add source**. Select folders, one shared
   drive, all accessible Drive files, Gmail labels, or the mailbox. Gmail history
   defaults to 30 days. Folder and shared-drive lists support **Load more choices**.
4. Repeat **Connect Google** for another account. Reconnecting the same Google
   identity reuses its existing account within your Noomesh user. A reconnect
   button on an existing account requires that same Google identity. To change
   the allowed services, select the desired set before reconnecting.

5. Choose **Start private sync** on a source. Noomesh imports supported text,
   shows progress and skipped counts, and checks for changes every 30 minutes.
   Choose **Pause sync** to stop future reads; imported content remains searchable
   by you. Remove the source or account to delete its locally imported content.

Search your imported material through a standalone Noomesh KB query or the
owner-only `/api/connections/search` API.
For example: `noo rag query "apricot project notes" --personal`. Use the same
human Noomesh login that connected the account. Without `--personal`, a KB
query searches the shared corpus only. The HTTP equivalent is the literal
boolean `include_personal: true` on `/api/v1/rag/query`.
Delegated agent/MCP/harness credentials cannot read personal evidence even
when they request it. The owner-only search API is an explicit personal read
and applies the same human-credential restriction.
Personal source text is stored encrypted and retrieved only for your Noomesh
account. Automatic use in persisted Noomesh chat and conversation-bound tools is
disabled: existing transcript/export permissions allow operators to read other
users' histories. Standalone search keeps Google content out of those histories.
It is excluded from shared-room context and shared knowledge graphs;
Google file sharing does not share it with other Noomesh users. Removal does not
rewrite prior conversation history or backups.

If a private row cannot decrypt, search skips that row and reports
`unavailable: true`. An opted-in KB query reports
`personal_sources_unavailable: true` while preserving its shared results.
The CLI prints a notice for this condition. A broken stored cursor or source
policy stops only that source with a storage fault; other users' sync continues.

The initial importer supports Gmail plain-text bodies and Drive text files
(plain text, Markdown, CSV) and Google Docs. It skips attachments, HTML-only
messages, binary files and responses over 1 MiB. It retains the first 32 KiB per
document, supports up to 1,000 documents per source, and searches the most recent
1,000 imported documents across your sources. Narrow folders/labels/lookback for
larger accounts. Private semantic search and graph extraction are not enabled.

Google grants the scopes you approve; partial approval is supported. Source
folder/label selections constrain Noomesh use, not the token's Google
permissions. Gmail does not offer label-only OAuth grants. This adapter uses
read scopes and does not send mail or modify Drive files.
[Drive scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth),
[Gmail scopes](https://developers.google.com/workspace/gmail/api/auth/scopes)

### Troubleshooting and removal

| Symptom | Remedy |
| --- | --- |
| Console Connect is disabled | Check web client ID, HTTPS callback and file-delivered secrets; desktop-only configuration uses the CLI helper |
| Pop-up opens but nothing completes | Keep the originating console tab open; use a browser supporting BroadcastChannel; cancel and retry after 10 minutes |
| `redirect_uri_mismatch` | Match the registered web callback's scheme, host, port and path exactly |
| Helper callback fails | Run the helper on the browser's computer; allow its temporary loopback listener |
| Google refuses another account | Add it as a test user and check Workspace administrator restrictions |
| Refresh expires after seven days | Expected for a Google project still in Testing; reconnect |
| Folder/label listing fails | Reconnect with the required service approved; check the corresponding Google API is enabled |
| Installer changes client ID or encryption key | Reconnect affected accounts |

**Remove account** deletes that account's local credentials, source settings,
sync jobs and imported content.
It does not revoke Google's application grant or delete anything at Google.
For revocation, use [Google third-party connections](https://support.google.com/accounts/answer/13533235).
Revocation may affect other connections using the same Google application and
account. Source removal also deletes its local imported content. A response
already in flight cannot restore content after removal.

### Adding another provider

Configuration is grouped under `integrations.providers.<provider>`. The OAuth
session, vault and account lifecycle are shared. A new provider needs a reviewed
provider definition with endpoints/scopes and an identity/resource adapter;
users cannot supply arbitrary token or resource URLs. Its guide should explain
publisher registration, any installer-owned option, permissions, callbacks and
revocation. API tokens and service accounts need their own authentication
adapters. Google support does not automatically enable other providers.

## For agents

- **Connecting an account is the person's act:** Google's consent screen in
  their browser, or `noo auth connect google --pair` and the phone they
  approve on. Saving a source does not start a sync; starting it (**Start
  private sync**, or the `sync` call below) is the owner's choice.
- **Personal content is owner-only, and never yours by delegation.** A
  delegated credential (MCP door, agent, harness) receives no personal
  evidence. Its `include_personal` / `noo rag query --personal` is refused
  without an error: the reply answers from shared sources only and carries
  `personal_sources_refused: true`, so check that flag. Only the boolean
  `true` opts in at all. Never use a person's own login credential to opt
  in on their behalf.
- **Never rotate `NOO_INTEGRATIONS_KEY` in place:** the wrong key makes the
  stored credentials, documents and cursors unreadable (see below).
- The exact API, ownership rules, sync limits and the authorization
  lifecycle follow; they were `channels/google-connections.md`.

### API and ownership

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

### Personal ingestion and retrieval

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
erasure prevent a late page from restoring content. Only a lost grant (reconnect)
or a source over its limits stops a source until the user acts. Provider and
storage failures retry by themselves (status `failing`) on a backoff of 1, 2, 4 …
minutes, capped at an hour. A Google rate or quota refusal (429, or a 403 naming
a rate or quota reason) waits at least the `Retry-After` Google sent and shows as
fault `rate` or `quota`; a 403 for a missing scope asks the user to reconnect.
Pages are paced per owner across Drive and Gmail: one at a time, at most one a
second, and a new full Gmail scan at most once a minute. A completed scan removes items no longer present in the provider selection.
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

### Authorization lifecycle

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

### Provider extension points

`gateway-rust/src/integrations/provider.rs` registers reviewed endpoint and
scope definitions; `oauth.rs` holds the reusable lifecycle and Google resource
adapter; `crypto.rs` implements the vault. Storage is in
`gateway-rust/src/repo/integrations.rs`; personal corpus/queue storage is in
`repo/integration_content.rs` and pairing storage in `repo/integration_pairing.rs`. The mesh migration
`108_integration_pairing` adds owner-bound, single-use CLI-to-phone handoffs.
`noo auth connect google --pair` displays a ten-minute code and a phone URL.
The same signed-in Noomesh owner reviews the device and services on the phone,
then completes the existing Web OAuth flow. CLI polling receives only status
and the connected account ID. Completion and credential storage commit
together; cancellation and user erasure also remove pending grants. See the
[phone setup guide](#approve-from-your-phone-with-a-pairing-code).

`107_integration_oauth` adds credentials, sessions, verified identity and
account authorization status after the original source-draft migration.

Add a provider definition and identity/resource adapter, then register its
configuration and any provider-issued secret through the existing secret
registry and file delivery. Do not accept arbitrary owner-supplied endpoint
URLs. OAuth credentials stay separate from source policy and token material
never enters the list contract. Contracts are maintained in the server/UI
OpenAPI files and regenerated TypeScript types.

`109_integration_content` adds the separate encrypted personal corpus and durable owner-bound sync queue. `110_integration_pacing` adds the per-owner page pacing (`last_page`) and the Gmail scan-start interval.

### Release rehearsal without Google credentials

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
| Migration compatibility | Existing `105_request_trace` preserved; new migrations `106_connection_drafts` through `110_integration_pacing` follow it |

This is the component rehearsal. General still owns the review, combined
0.6.14 batch build and signed-stack rehearsal. Record the tested head and
results in the PR/release handoff. The controller's required secret names,
conditions and file destinations are in the
[runtime secret inventory](#controller-runtime-secret-inventory).

After the roll, the operator separately verifies the exact registered HTTPS
callback and reachable phone console, provisions secrets through `env.sops`,
and tests a real Noomesh user with `noo auth connect google --pair`. Choose a
small Drive folder and Gmail label, explicitly start sync, verify owner search,
then verify a second user/admin cannot retrieve the first user's data. Pause,
disconnect and confirm imported content disappears on removal. Automated
fixtures do not substitute for this real-content and two-user acceptance.
