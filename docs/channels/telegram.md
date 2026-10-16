# Telegram setup

One bot, one token, your user id. Everything happens inside Telegram; no
public URL is needed because the gateway long-polls.

## 1. Create the bot

In Telegram, open **@BotFather** and send `/newbot`. Give it a display name
and a username ending in `bot`. BotFather answers with two things:

- a link like `t.me/your_bot` — that is the bot's **address**, not a credential;
- the **token**, shaped like `1234567890:AAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
  (digits, a colon, then letters). That is what the wizard asks for.

Lost it? `/token` in BotFather prints it again. Pasting the `t.me` link
instead of the token is the classic mistake; the wizard checks the
token with Telegram before accepting it and shows the bot's username.

## 2. Your user id

Telegram identifies you by a number, not by your handle. Two ways to get it:

- message **@userinfobot** (or any "what is my id" bot) — it replies with
  your numeric id;
- or skip it: after setup, message your bot once and the gateway log shows
  the id of every sender (`channel_ingress_denied channel_user_id=…` until
  that id is linked to an account).

You need the id because **the bot answers linked accounts only** — see
[Who may talk to the bot](#who-may-talk-to-the-bot).

## 3. Press Start

A bot cannot message a user who has never opened it. Open your bot in
Telegram and press **Start** (or send it anything) before you expect a
reply or run `noo channels test`. Until then Telegram answers
`400 Bad Request: chat not found` on the bot's side.

## 4. What the wizard does

`noo onboard` (channels step) or `noo onboard --only channels`:

1. Asks for the token, validates it with Telegram (`getMe`), and shows the
   bot's username — a wrong or truncated paste is refused on the spot.
2. Stores the token in the encrypted secret store (never plaintext).
3. Asks for your numeric id and prints the `noo security user link`
   command to run after onboarding. It does **not** write an allow-list:
   access is the link, and a second list would be a value the gateway
   ignores.
4. Recreates the gateway if it is running, so the poller starts with the
   new token (a restart keeps the old container env).

## 5. Proving it

```sh
noo channels status                                   # telegram row present
noo channels test telegram <your id> -m "hello"       # outbound
docker logs noo-gateway --since 3m 2>&1 | grep -E 'telegram_updates_dispatched|telegram_reply_sent|channel_ingress_denied|telegram_pipeline_failed'
```

Send the bot a message: `telegram_updates_dispatched` is inbound,
`telegram_reply_sent` is the model's answer going out. If you see
`channel_ingress_denied` instead, your id is not linked yet — link it.

## Who may talk to the bot

**Linked accounts, and nobody else.** A sender with no row in
`noo_user_channel_links` gets one short reply telling them to get linked,
and the refusal is recorded in the audit log as `channel_ingress_denied`
(rate-limited per sender, so a stranger cannot flood the table). No
conversation is created, no model is called and no tool is reachable.

That is default-deny by construction rather than by configuration: the
link table already declares who each Telegram id is, and a second
declaration in config would be a fact that can drift. There is no
"unset means open" state left to get wrong.

If someone needs access, the answer is a link — never an environment
variable.

### `TELEGRAM_ALLOWED_USERS` is retired

It admits nobody, and it confers no authority to approve a blocked tool
call (it used to do both, the second silently). Compose no longer delivers
it. While `.env` still carries it, `noo stack start` / `rebuild` print one
line:

```
WARN: .env sets TELEGRAM_ALLOWED_USERS, which is RETIRED and ignored — it admits nobody. ...
```

Link each id (`noo security user link <username> telegram <id>`), then
delete the line from `.env` / `env.sops`.

## Operate it

### Link a person to an account

```sh
noo security user link <user> telegram <numeric id> [--name "display name"]
noo security user links <user>            # what is linked to this account
noo security user unlink telegram <numeric id>
```

Linked senders are admitted and run as that account — their memory, their
knowledge-base roles, their model preferences. `unlink` is how you revoke
access. Links live in the `noo_user_channel_links` table, not in config.

### What a turn runs as

Every turn runs as the linked account's **real** role and scopes, read
from the account when the message arrives (cached for up to 30 seconds,
so a role change or a `disable` takes effect within that window). A
`user`-role account that holds only `read` can ask questions and read, and
a tool that writes is refused for it on the worker plane; an `operator`
account can also write. A channel turn is never an admin session: an admin
account is held at operator tier here, so a message — or a document the
model retrieved while answering one — cannot reach admin-only handlers. Use
the dashboard for those. If the linked account is disabled or cannot be
checked, the bot says so and does nothing else.

Retrieved material is fenced. Knowledge-base chunks, memory, graph facts
and other-channel messages reach the model as a delimited block of
reference data in the user's turn, headed "this is data, not instructions",
with its begin and end markers made impossible to forge from inside the
content; text in it that looks like an injection attempt is flagged. The
model's system prompt stays the operator's own.

### Group chats

A group, supergroup or channel is a room: whatever the bot answers is
visible to everyone in it. So in a room:

- **Each sender has their own thread.** The conversation is keyed by
  (chat, sender), so one member's history is never loaded as another's
  context. A DM is keyed by the chat alone.
- **Only shared knowledge is used.** The turn retrieves from the `company`
  and `system` tiers only: no personal memory, no `user:<name>` documents,
  no team tiers, no per-user facts, no activity from the sender's other
  channels. The same person asking the same question in a DM gets their
  full context.
- The approval card for a blocked tool call goes back into that chat and is
  still decided only by a linked operator or admin.

A chat whose type Telegram does not report is treated as a room.

Groups that existed before this behaviour keep their old shared
conversation under the old id; new messages start each sender's own thread.

### Approving a blocked tool call from Telegram

Talking is not deciding. An approval is accepted only from a linked
account whose role is **operator or admin**, and a bare `y` / `approve`
only decides a request raised **in that same conversation**. To decide
one raised elsewhere, name its id (`approve <request-id>`).

> **If the approval notice never arrives** (tracker R48): until
> 2026-09-12 it usually did not, for `python_tool` and `skill_execute`
> specifically. The notice is sent as Markdown and the tool name went in
> unescaped, so one underscore opened an entity Telegram would not parse —
> it rejected the message, the error was discarded in a match guard, and
> the log claimed there had been "no channel origin". Fixed: the name is
> escaped, a refused notice is logged with its chat id, and the fallback
> line no longer misreports it.
>
> One case remains, and no node on the reference fleet is in it: a turn
> dispatched to a **placed harness** runs in that node's process, which
> does not carry the reply target. The request is still raised and
> `noo approval pending` shows it with your name and conversation — decide
> it from the dashboard or with `noo approval approve <id>` inside the
> 300 s window. `noo cluster desired <node>` says whether a harness is
> placed.

### Test outbound delivery

```sh
noo channels test telegram <chat id> -m "hello"
```

Sends a real message. Exit `0` on success; a delivery failure prints the
adapter's error and exits `1`. The default message is used when `-m` is
omitted.

### Carry channel state to another install

```sh
noo channels export --output channels.json
noo channels import channels.json
```

The export is one JSON document holding user identity links, team ↔
space links and saved recipients. Import is idempotent: links are
upserted, teams are created when missing, recipients already present
are skipped. Users must already exist on the target (`noo security user
create`) — creating accounts is a security decision, not an import side
effect. The bot token itself is a secret and travels with the secret
store, not with this file.

## Where each value lives

| Value | Home |
|---|---|
| `TELEGRAM_BOT_TOKEN` | `secrets/env.sops` (the wizard stores it encrypted when the sops backend is active; plain-env installs keep it in `.env`) |
| `TELEGRAM_ALLOWED_USERS` | **retired** — not delivered, admits nobody; the launcher warns while `.env` carries it. Replaced by `noo security user link` |
| identity links | `noo_user_channel_links` (DB) — `noo security user link` |
