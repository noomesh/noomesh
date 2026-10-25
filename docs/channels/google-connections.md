# Google account and source drafts

The console's **Connections** screen prepares private Google account and
source drafts. It is available in both console editions to signed-in users.
Several Google account drafts can belong to one Noomesh user, and each
account can have several Drive and Gmail sources.

For local installers preparing their own Google application, start with
[Connect external accounts on a local installation](../getting-started/integrations.md).
It explains application ownership, test users and callback networking.

This release saves metadata only. Google sign-in, token storage, resource
pickers, search and background synchronization are not implemented here.
Accounts show **Needs sign-in** and sources show **Draft**. Saving a draft
does not grant Google access or import content. The existing installation-wide
service-account Drive watcher is independent of these drafts.

## Prepare a connection

1. Open **Connections**, then **Add Google account**.
2. Name the account (for example, Work or Personal). An optional email is
   an unverified reminder of the account to use later.
3. Choose **Add source** under that account and select Google Drive or Gmail.
4. Choose the intended content: folders, one drive, or all accessible Drive
   files; selected Gmail labels or the mailbox. Gmail defaults to the past
   30 days. Save the source draft.

Folder, drive and label selection happens through the future resource
picker after sign-in; empty selections are valid drafts. All sources are
private and read only. Removing an account draft also removes its source
drafts. This is local metadata removal, not Google token revocation.

## API and ownership

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/api/connections` | Own account/source drafts and provider readiness |
| POST | `/api/connections/accounts` | Create a Google account draft from `label` and optional `email_hint` |
| DELETE | `/api/connections/accounts/{id}` | Remove own account draft and its sources |
| POST | `/api/connections/sources` | Create a source from `account_id`, `name`, and a typed `policy` |
| DELETE | `/api/connections/sources/{id}` | Remove own source draft |

The owner comes from the authenticated account, including for Operator and
Admin callers. Cluster/service credentials with no signed-in account are
refused. Another user's id receives the same 404 as a missing id. A composite
foreign key prevents attaching a source to another user's account.
Drafts are also removed during account erasure with `keep_account` enabled.

The mesh migration adds `noo_connected_accounts` and
`noo_connection_sources`; it does not alter existing watchers or credentials.
Both tables restrict status to the draft state. No request accepts provider
identity claims, granted scopes, credentials, activation, send or write access.
The API and generated TypeScript types are documented in the OpenAPI contract.

## OAuth integration boundary

The next implementation should verify Google's immutable account identity
through an account-bound, expiring OAuth transaction; protect state and PKCE;
store tokens in an encrypted credential store; and persist actual granted
scopes separately from requested content policies. Reconnecting the same
verified Google identity should reuse its account within that Noomesh owner.
The same Google account linked by different Noomesh users needs independent
ownership and access checks.

Gmail labels and Drive folder filters describe what Noomesh may use. They do
not imply that Google issued a token restricted to exactly those resources.
The future consent flow must explain that distinction. Connected status,
source activation and synchronization require a later migration and the
corresponding verified OAuth and data-access implementations.

Reference: [Google OAuth web-server flow](https://developers.google.com/identity/protocols/oauth2/web-server),
[Drive scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth),
[Gmail scopes](https://developers.google.com/workspace/gmail/api/auth/scopes).
