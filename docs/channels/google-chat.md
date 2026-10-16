# Google Chat setup

What noomesh needs from Google, where each piece lives, and what the
wizard does with it. One GCP project, one service account, one Pub/Sub
subscription. Every step below has its console URL.

## The shape

```
Google Chat app ──publishes events──▶ Pub/Sub topic ──▶ subscription
                                                            ▲
                    noo-gateway ──pulls with the SA key──────┘
                    noo-gateway ──replies via Chat API (same SA key)
```

No public URL, no webhook, no ingress: the gateway pulls. That is why the
same install works on a laptop behind NAT and on a tailnet-only box.

## 1. Project and APIs

Console: https://console.cloud.google.com/apis/library?project=<project>

Enable **Google Chat API** and **Cloud Pub/Sub API** in the project that
will own the bot. (Drive watching uses the same account: enable **Google
Drive API** too if you will watch a shared drive.)

## 2. Service account and key

Console: https://console.cloud.google.com/iam-admin/serviceaccounts?project=<project>

Create a service account (any name, e.g. `noomesh-chat`). Create a JSON
key and download it. This one file is what the wizard asks for; it carries
the project id, the account email (`client_email`) and the private key.

The wizard absorbs it into the encrypted secret store and shreds the
plaintext. The key reaches the gateway as the env var
`GOOGLE_CHAT_CREDENTIALS_JSON` (base64, sourced from
`NOO_FILECRED_GOOGLE_CHAT_B64` and parsed in memory) — the primary path.
`GOOGLE_CHAT_CREDENTIALS`, the container path of a materialised key file,
is a legacy fallback only; the file it used to point at is gone. To see
which account a stored key belongs to, without exposing the private key:

```sh
sops -d --input-type dotenv --output-type dotenv secrets/env.sops \
  | grep '^NOO_FILECRED_GOOGLE_CHAT_B64=' | cut -d= -f2- | base64 -d \
  | grep -o '"client_email": *"[^"]*"'
```

(`secrets/env.sops` is relative to the install root — the repo checkout,
or `~/.noo` on a standalone controller. The wizard also prints the
account email when it re-runs discovery.)

## 3. Pub/Sub topic and subscription

Console: https://console.cloud.google.com/cloudpubsub/topic/list?project=<project>

Create a topic (e.g. `noomesh-chat`) and a **pull** subscription on it
(e.g. `noomesh-chat-sub`). The full subscription name is
`projects/<project>/subscriptions/<name>`.

Two IAM bindings, and they live in different places:

| Who | Role | Where | Why |
|---|---|---|---|
| `chat-api-push@system.gserviceaccount.com` | Pub/Sub Publisher | on the **topic** | lets Google Chat publish events |
| your service account | Pub/Sub Subscriber | on the **subscription** (or project) | lets the gateway pull |
| your service account | Pub/Sub Viewer | on the **project** | lets the wizard LIST subscriptions and pick yours automatically (optional; without it the wizard asks for the name and verifies it) |

Project-level roles: https://console.cloud.google.com/iam-admin/iam?project=<project>
→ **Grant access** → paste the service account email as the principal
(this binds a role to the existing account; it does not create one).

## 4. The Chat app

Console: https://console.cloud.google.com/apis/api/chat.googleapis.com/hangouts-chat?project=<project>

Configure the app: name, avatar, "Receive 1:1 messages", "Join spaces and
group conversations". Under **Connection settings** choose **Cloud
Pub/Sub** and enter the topic name. Publish to your Workspace domain so
colleagues can add it to spaces.

Interactive cards need an HTTPS endpoint, which Pub/Sub apps cannot have;
noomesh therefore uses text replies for approvals (`approve` / `deny`).

## 5. What the wizard does

`noo onboard` (channels step) or `noo onboard --only channels`:

1. Takes the key path (or offers the already-stored key on a re-run).
2. Asks for the shared Drive id to watch, if any.
3. Reads the project id and account email from the key, mints a token
   with the key's own credentials, lists the project's subscriptions: one
   → taken; several → pick by number; list refused → asks for the name and
   verifies it with `get`.
4. Lists the spaces the bot is a member of (for the coming space → team
   links).
5. Writes `GOOGLE_CHAT_PUBSUB_SUBSCRIPTION` and `GOOGLE_CHAT_PROJECT_ID`
   to `noomesh.yaml` under `compose_env` (non-secret, compose-interpolated).
6. Absorbs the key into the secret store.
7. Recreates the gateway if it is running, so the adapter starts with the
   new credentials (a restart would keep the old container env).

## 6. Proving it

```sh
noo channels status                          # google_chat row present
docker logs noo-gateway --since 3m 2>&1 | grep -E 'gchat_pubsub_started|gchat_pubsub_events_dispatched|gchat_reply_sent|gchat_pipeline_failed'
```

`gchat_pubsub_started` names the subscription. DM the bot, or mention it
in a space, and `gchat_pubsub_events_dispatched` (inbound) then
`gchat_reply_sent` (outbound) follow. If you get `channel_ingress_denied`
instead, your Chat id is not linked yet — link it.

## Who may talk to the bot

**Linked accounts, and nobody else.** A sender with no row in
`noo_user_channel_links` gets one short reply telling them to get linked,
and the refusal is recorded in the audit log as `channel_ingress_denied`
(rate-limited per sender). No conversation is created, no model is called
and no tool is reachable.

This matters more here than on Telegram, because membership is not yours
to control: anyone in a space the bot sits in can address it, and on a
Workspace published to a domain that is potentially the whole domain.
This channel previously had **no** admission check at all — an unlinked
sender was answered under their raw `users/…` id, which meant a
tool-bearing session scoped to an identity the system invented on the
spot.

Adding the bot to a space therefore grants the space nothing. Each person
in it needs their own link.

## Operate it

### Link a person to an account

```sh
noo security user link <user> google_chat users/<id> [--name "display name"]
noo security user links <user>
noo security user unlink google_chat users/<id>
```

A DM's conversation id in the log is `google_chat:users/<id>`, and the
refusal reply quotes the sender's own `users/…` id so you do not have to
dig it out of a log line. Linked senders run as that account — their
memory, their knowledge-base roles. `unlink` is how you revoke access.
Links live in the `noo_user_channel_links` table, not in config.

### What a turn runs as

Every turn runs as the linked account's **real** role and scopes, read
from the account when the message arrives (cached for up to 30 seconds,
so a role change or a `disable` takes effect within that window). A
`user`-role account that holds only `read` can ask questions and read, and
a tool that writes is refused for it on the worker plane; an `operator`
account can also write. A channel turn is never an admin session: an admin
account is held at operator tier here, so a message — or a document the
model retrieved while answering one — cannot reach admin-only handlers. If
the linked account is disabled or cannot be checked, the bot says so and
does nothing else.

Retrieved material is fenced. Knowledge-base chunks, memory, graph facts
and other-channel messages reach the model as a delimited block of
reference data in the user's turn, headed "this is data, not instructions",
with its begin and end markers made impossible to forge from inside the
content; text in it that looks like an injection attempt is flagged. The
model's system prompt stays the operator's own.

### Spaces

A named space is a room: whatever the bot answers is visible to every
member. So in a space:

- **Each sender has their own thread.** The conversation is keyed by
  (space, sender), so one member's history is never loaded as another's
  context. A DM is keyed by the sender alone (`google_chat:users/<id>`).
- **Only shared knowledge is used.** The turn retrieves from the `company`
  and `system` tiers only: no personal memory, no `user:<name>` documents,
  no team tiers (a space linked to a team does not unlock that team's
  documents for the room), no per-user facts, no activity from the sender's
  other channels. The same person asking the same question in a DM gets
  their full context.
- The approval card goes back into the space and is still decided only by
  a linked operator or admin.

Spaces that existed before this behaviour keep their old shared
conversation under the old id; new messages start each sender's own thread.

### Approving a blocked tool call from Chat

Talking is not deciding. An approval is accepted only from a linked
account whose role is **operator or admin**, and a bare `y` / `approve`
only decides a request raised **in that same space or DM**. To decide one
raised elsewhere, name its id (`approve <request-id>`). Being a member of
the space grants nothing.

### Link a space to a team

```sh
noo security team create research
noo security team link-space research google_chat spaces/<id>
noo security team spaces research
```

The wizard lists the spaces the bot is a member of (`spaces/<id>` plus
display name) so you can copy the id. The team must exist first. A team
is a knowledge-base role (`team:<name>`): give a person membership with
`noo security user grant-role <user> --role team:<name>`; documents
tagged with that role are visible to those members. The space link
records which team a shared space belongs to (`noo_channel_team_links`)
and travels with `noo channels export`.

### Test outbound delivery

```sh
noo channels test google_chat spaces/<id> -m "hello"
```

Sends a real message to the space (or `users/<id>` for a DM). Exit `0`
on success; a delivery failure prints the adapter's error and exits `1`.

### Carry channel state to another install

```sh
noo channels export --output channels.json
noo channels import channels.json
```

One JSON document: user identity links, team ↔ space links and saved
recipients. Import is idempotent (links upserted, teams created when
missing, existing recipients skipped); users must already exist on the
target. The service-account key is a secret and travels with the secret
store, not with this file.

## Where each value lives

| Value | Home |
|---|---|
| SA key JSON | `secrets/env.sops` (`NOO_FILECRED_GOOGLE_CHAT_B64`), reaches the gateway as `GOOGLE_CHAT_CREDENTIALS_JSON` |
| `GOOGLE_CHAT_PUBSUB_SUBSCRIPTION`, `GOOGLE_CHAT_PROJECT_ID` | `noomesh.yaml` → `compose_env` |
| `GOOGLE_CHAT_CREDENTIALS` (container path of a materialised key) | legacy fallback only; `.env` |
| watched shared drive | `noomesh.yaml` → `watched_drives` |
