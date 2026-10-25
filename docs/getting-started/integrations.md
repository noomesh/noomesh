# Connect external accounts on a local installation

The simplest intended experience is: install Noomesh, choose **Connect
Google**, sign in and approve access. The software publisher registers the
application with Google; ordinary users do not need their own cloud project.
Local installation does not by itself require installer-owned credentials.

Google's desktop flow can use a publisher-registered public client, PKCE,
the system browser and a loopback callback on that computer. It does not
require a Noomesh-hosted callback server. Tokens can be stored locally.
[Google desktop authorization](https://developers.google.com/identity/protocols/oauth2/native-app)

Noomesh can also run on a controller separate from the browser's computer.
That needs its own supported callback arrangement: for example, a native
helper on the browser's computer or a hosted connection service. A desktop
loopback callback alone does not reach a different controller. A confidential
web client's shared secret must not be bundled into distributed installers.
[Google client-type policy](https://developers.google.com/identity/protocols/oauth2/policies)

## Choose a setup model

| Model | Who registers the provider application? | User experience |
| --- | --- | --- |
| Publisher-registered desktop connection | Noomesh publisher | Intended simple local-desktop flow: connect, sign in, approve |
| Publisher-registered connection for a remote controller | Noomesh publisher | Requires a supported helper or connection service; its design must explain where credentials pass and are stored |
| Installer-owned application | Person running the installation | Advanced option: register a provider application and configure its credentials before users connect |

**All three authorization paths still need implementation in the current
scaffold.** The Google project/client instructions below cover the advanced
installer-owned option, not a prerequisite for every future Noomesh user.
Google still provides sign-in and APIs, so Gmail/Drive connections need
internet access. Application registration does not move Noomesh into Google
Cloud.

## What works in the current build

| Step | Availability |
| --- | --- |
| Save several Google account drafts and Drive/Gmail source drafts | Available in the Connections scaffold |
| Optionally create your own Google project and prepare its consent settings | Available in Google Cloud Console |
| Configure OAuth credentials in Noomesh or obtain its callback URL | Pending OAuth implementation |
| Sign in, choose actual folders/labels, read or synchronize Google data | Pending OAuth and provider adapters |

**The current Connections screen saves drafts only.** It has no OAuth
callback or supported integration credential settings. Creating a Google
project will not enable its disabled sign-in button. If you choose an
installer-owned application, complete the preparation below, then stop at
the OAuth handoff until your Noomesh release supports it.
There are no integration environment-variable names or secret-import
commands to run yet.

For the available UI, see [Google account and source drafts](../channels/google-connections.md).

## Who sets up what

| Person | One-time setup | Repeated when adding accounts |
| --- | --- | --- |
| Software publisher, for the simple connection path | Register suitable provider clients, enable APIs and complete applicable verification | Maintain the application registration and supported authorization flow |
| Installer/operator choosing their own application | Provider project/application, allowed callback address, installation credentials | Usually none; update provider settings when the installation address or required access changes |
| Noomesh user | A login on this Noomesh installation | Select a provider, sign in, approve access and choose content |
| Personal installer choosing their own application | Performs installer and user setup | Add each Google account independently |

Google's application registration identifies the publisher's or installer's application.
The user's OAuth grant authorizes access to that user's data. These are
separate from the user's Noomesh login. [Google credential types](https://developers.google.com/workspace/guides/create-credentials)

## Advanced: prepare an installation with your own application

The remaining setup steps use installer-owned credentials. One such Google
application can serve several Google accounts when its audience allows it;
each mailbox or folder does not need a separate cloud project.

Use an isolated development instance with its own data root, database and
credentials. Noomesh's [multiple-instance setup](multi-instance.md) covers
onboarding a second checkout, choosing an instance name and an unused port
offset. Use separate provider applications for test and production; for
Google, a separate development project also separates consent configuration.
[Google's development guidance](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification#exceptions-verification-requirements)

Decide which browser will perform sign-in and how it reaches Noomesh:

| Browser location | Address preparation |
| --- | --- |
| On the Noomesh computer | A localhost callback can work for local testing if the implemented flow supports it |
| On a laptop or phone, with Noomesh on another computer | Use a stable HTTPS hostname reachable by that browser and accepted by Google |

`localhost` means the browser's computer. On your phone it does not mean
your server. Google allows HTTP localhost redirects; other web callbacks
require HTTPS and an eligible hostname. Raw LAN IPs and names such as
`server.local` do not satisfy its web redirect rules. An address accepted by
your browser is not automatically accepted by Google. [Google redirect rules](https://developers.google.com/identity/protocols/oauth2/web-server#uri-validation)

The OAuth response returns through the browser. For that redirect, the
browser needs access to your callback; Google does not need a public inbound
connection to your controller. Provider webhooks are a separate matter.
[Google web authorization flow](https://developers.google.com/identity/protocols/oauth2/web-server)

## Prepare Google in your own account

### 1. Create the project and enable APIs

Open [Google Cloud Console](https://console.cloud.google.com/) using an
account allowed to manage projects. Create a project for your Noomesh test
installation and record its project ID. Enable **Google Drive API** and
**Gmail API** for the features you plan to test. [Google API setup](https://developers.google.com/identity/protocols/oauth2/web-server#prerequisites)

Use an OAuth client for this personal-account flow. The existing
service-account Drive watcher and Google Chat bot have their own setup in
[Google Chat](../channels/google-chat.md); their credentials are not the new
per-user account connection.

### 2. Set up consent and your test accounts

Under **Google Auth platform**, configure **Branding**, **Audience** and
**Data Access**. Give the application a recognizable name, such as
"My Noomesh Test", and your support/contact email. [Google consent setup](https://developers.google.com/workspace/guides/configure-oauth-consent)

For a personal Gmail account, choose **External**, keep publishing status
**Testing**, and add every Google email you will connect as a test user.
These are Google account addresses, not Noomesh usernames. **Internal** is
for eligible organization-owned projects and accounts in that organization;
a Workspace administrator can impose additional restrictions. [Google audience settings](https://support.google.com/cloud/answer/15549945)

Testing authorizations for Gmail/Drive, including refresh tokens, expire
after seven days. Reconnect when that happens. A test user list can contain
up to 100 accounts. [Google testing limits](https://support.google.com/cloud/answer/15549945)

Personal use and development/testing have verification exceptions. Local
hosting alone does not establish an exception for every deployment. Before
opening the installation to a wider audience, review the conditions for
your project. Publishing an application does not verify it. [Google verification exceptions](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification#exceptions-verification-requirements)

### 3. Review the intended access

The future adapter must provide the exact scope list for its features.
The following examples explain the distinction between Google permissions
and a Noomesh content selection; they do not activate the current scaffold.

| Google scope | What to understand |
| --- | --- |
| `https://www.googleapis.com/auth/drive.file` | Access to app-created or explicitly authorized files; includes file-management permission and does not promise recursive access to an arbitrary folder |
| `https://www.googleapis.com/auth/drive.readonly` | Broader Drive reading; a restricted scope |
| `https://www.googleapis.com/auth/gmail.readonly` | Gmail reading; a restricted scope, with no label-only authorization boundary |

A Noomesh folder/label filter can narrow what Noomesh uses without narrowing
everything the Google token permits. A read-only Noomesh source is also
separate from the permissions represented by the token. Review the actual
consent request before approving it. [Drive scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth),
[Gmail scopes](https://developers.google.com/workspace/gmail/api/auth/scopes)

## Complete the OAuth handoff when supported

**Stop here on the current build.** The steps in this section describe the
handoff to complete after OAuth support ships; the callback and credential
entry point are not implemented yet.

1. Obtain the exact callback URL from the supported Noomesh setup flow.
   There is no callback path to copy from this guide yet.
2. In **Google Auth platform → Clients**, create a **Web application**
   client for the server-based integration and register that callback as an
   authorized redirect URI. Review any agent-specific client option against
   the supported Noomesh flow before creating it. [Google client setup](https://developers.google.com/workspace/guides/create-credentials#web-application)
3. Match the callback exactly, including scheme, hostname, port, path and
   trailing slash. [Google callback requirements](https://developers.google.com/identity/protocols/oauth2/web-server#creatingcred)
4. Configure the client ID and any server-side client secret through the
   supported operator setup. App secrets belong in the installation's
   encrypted secret store, following [Noomesh secrets](../security/secrets.md).
   Account names and email hints in Connections are metadata fields.

Adding an arbitrary OAuth variable to the current secret store does not
enable sign-in: its consumer and credential setup still need implementation.
Per-user tokens must be handled by the future encrypted credential store;
users should not edit deployment files to add another account.

Once implemented, the intended user journey is: choose Google, sign in to
one account, approve the requested access, then select Drive/Gmail content.
Repeat for another account. Verify the account shown by Google each time;
an email hint in a draft is unverified. Start with a small content selection
and confirm results belong to the intended Noomesh user.

Google Cloud Pub/Sub setup is needed for Gmail's push notification option,
not for the consent redirect itself. A future polling adapter can keep
initial testing separate from webhook configuration. [Gmail notifications](https://developers.google.com/workspace/gmail/api/guides/push)

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Sign-in button is disabled | Expected on the current draft-only scaffold; credentials cannot activate it yet |
| `redirect_uri_mismatch` | Compare the registered and requested callback exactly |
| Callback opens the wrong computer or fails on a phone | Check which computer `localhost` refers to and whether the browser reaches the controller |
| Another Google account cannot authorize during testing | Add that Google address to the project's test users; check organization restrictions |
| `org_internal` | The account is outside the project's allowed organization |
| Reconnection is needed after seven days | Check whether the Google application is still in Testing |
| Application is unverified | Check the project you created and its audience; use the applicable personal/test exception, or complete verification for broader use |

For a connected application, Google lets you review and remove account
access through its [third-party connections controls](https://support.google.com/accounts/answer/13533235).
Revoking access stops future access; it does not erase content already stored
by an application. Current Noomesh draft removal only deletes draft metadata.

## Set up another provider

For each provider supported by a future adapter, its guide should distinguish
the publisher-configured connection path from any installer-owned option.
Users then add their own account connections. Some providers use API
tokens or service accounts rather than interactive OAuth, so their setup
guide must identify the authentication type explicitly.

Use the provider-specific guide for its registration page, callback rules,
permissions, quotas and revocation behavior. A provider needs an implemented
adapter before its credentials are useful in Noomesh. Google account drafts
do not imply that other providers are already available.
