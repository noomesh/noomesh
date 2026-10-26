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

## Choose the installation's sign-in path

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

### Approve from your phone with a pairing code

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

## Prepare Google for a test installation

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

## Configure Noomesh once

### Optional: check the project with the Google Cloud CLI

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

### Application settings and encrypted secrets

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

For the Desktop path, import the Google-issued parameter through
`noo security secrets rotate NOO_GOOGLE_DESKTOP_CLIENT_SECRET --set-from-stdin`.
For the web path, import the Google-issued client secret through
`noo security secrets rotate NOO_GOOGLE_OAUTH_CLIENT_SECRET --set-from-stdin`,
using a secure stdin source. Follow [Noomesh secrets](../security/secrets.md)
for encrypted storage, consumer recreation and verification. The gateway reads
these secrets from its file-backed delivery; do not put them in Compose command
lines or ordinary YAML. Verify after applying the configuration and restarting
the gateway that Connections reports the appropriate authorization path ready.

Back up the encrypted store and database together. Losing or rotating
`NOO_INTEGRATIONS_KEY` makes existing encrypted grants unreadable; reconnect
every account unless its ciphertext has been migrated to the new key. There
is no plaintext fallback. Provider outages leave saved credentials intact.

### Move setup to another controller

Deploy the reviewed gateway, CLI, UI and migrations through the normal stack
release. Configure that controller's exact HTTPS callback in both Google and
its `integrations.providers.google.web_redirect_uri`. An existing trusted
HTTPS console address can use its normal port; the AWOLF test's extra port is
not required on other hosts. Preserve callbacks still used by other installs.

Import the installer-owned Web secret through that controller's encrypted
secret workflow and generate its own integration encryption key. Use an
existing real Noomesh user on both the execution CLI and approving phone.
Run `noo auth connect google --pair` against this controller and verify that
the displayed phone URL belongs to it. Reconnect each Google account there;
do not copy the AWOLF test user's credentials or database rows into another
installation. The private test app's credentials are not publisher defaults.

Removing a verified account deletes local credentials and source settings and
cancels older pending authorizations for that provider and Noomesh owner,
including a Google response already in flight. Other connected accounts stay
connected. Cached resource lists for the removed account are cleared from the
UI. Removal does not revoke Google's application grant: manage that separately
in Google account permissions when needed. Integration connection, removal,
pairing-start and cancellation audits contain Noomesh identifiers and outcomes,
without Google emails, tokens, codes, selected content or message bodies.

## Connect and choose content

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

Search your imported material through the normal Noomesh KB query or chat.
Personal source text is stored encrypted and retrieved only for your Noomesh
account. It is excluded from shared-room context and shared knowledge graphs;
Google file sharing does not share it with other Noomesh users. Removal does not
rewrite prior conversation history or backups.

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

## Troubleshooting and removal

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

## Adding another provider

Configuration is grouped under `integrations.providers.<provider>`. The OAuth
session, vault and account lifecycle are shared. A new provider needs a reviewed
provider definition with endpoints/scopes and an identity/resource adapter;
users cannot supply arbitrary token or resource URLs. Its guide should explain
publisher registration, any installer-owned option, permissions, callbacks and
revocation. API tokens and service accounts need their own authentication
adapters. Google support does not automatically enable other providers.
