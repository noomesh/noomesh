# Connect external accounts on a local installation

After the installer enables Google, open **Connections**, choose Drive, Gmail,
or both, click **Connect Google**, sign in and approve access. Repeat for each
Google account. Each Noomesh user owns their connections; work and personal
accounts can each have several source selections.

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

A publisher can bundle its registered Desktop client ID and Google-issued
Desktop credential using `NOO_GOOGLE_DESKTOP_CLIENT_ID` and
`NOO_GOOGLE_DESKTOP_CLIENT_SECRET` in the **gateway build environment**.
Installers using their own client supply its ID in YAML and import its issued
credential into the encrypted secret store. This repository does not ship
registered production credentials. Desktop clients are public and use PKCE:
the issued Desktop credential is a token-endpoint parameter, not proof that a
distributed application can keep a secret. Google can require this parameter
for both code exchange and refresh. A web client secret
belongs only on the installation that owns its web registration. Do not bundle
a publisher's confidential web secret in installers.
[Google client-type policy](https://developers.google.com/identity/protocols/oauth2/policies)

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

**This release completes authorization and source setup. It does not yet
import messages/documents, index them for search, or run background sync for
these new connections.** Source settings remain drafts. The existing
installation-wide service-account Drive watcher is a separate feature.

Google grants the scopes you approve; partial approval is supported. Source
folder/label selections constrain future Noomesh use, not the token's Google
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

**Remove account** deletes that account's local credentials and source drafts.
It does not revoke Google's application grant or delete anything at Google.
For revocation, use [Google third-party connections](https://support.google.com/accounts/answer/13533235).
Revocation may affect other connections using the same Google application and
account. Imported content deletion will be a separate concern when ingestion
is implemented.

## Adding another provider

Configuration is grouped under `integrations.providers.<provider>`. The OAuth
session, vault and account lifecycle are shared. A new provider needs a reviewed
provider definition with endpoints/scopes and an identity/resource adapter;
users cannot supply arbitrary token or resource URLs. Its guide should explain
publisher registration, any installer-owned option, permissions, callbacks and
revocation. API tokens and service accounts need their own authentication
adapters. Google support does not automatically enable other providers.
