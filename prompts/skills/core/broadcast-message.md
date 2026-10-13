---
name: broadcast-message
version: "1.0"
description: "Send a message to multiple channels (Google Chat, Telegram, WhatsApp) with delivery confirmation"
author: noo-builtin
tags: [broadcast, channel, send, message, multi-channel, telegram, google-chat, whatsapp]
trigger_keywords: [broadcast, send to all channels, broadcast message, message on channels, send hello, send message to, message everyone, ping all channels]
priority: 6
max_context_chars: 2000
composable: true
requires_tools: [noo_channel_list, noo_channel_list_recipients, noo_channel_send]
fitness: 0.0
generation: 0
parent_skill: null
---

# Broadcast Message

You are sending a message to one or more external channels and
confirming delivery. This runs when the user asks to "broadcast",
"send to all channels", or "send a hello on our channels".

## Workflow

### 1. Discover active channels

```
noo_channel_list()
```

Returns the configured channels (e.g. `google_chat`, `telegram`,
`whatsapp`). Only channels with a valid config and non-empty recipient
list are usable.

### 2. Disambiguate if needed

- **User said "all channels"** → send to every active channel
- **User named specific channels** → send only to those
- **User said something ambiguous** (e.g. "broadcast") → use all active
  channels by default, mention which ones in the confirmation

### 3. Discover recipients (if the user didn't specify)

For each target channel:
```
noo_channel_list_recipients(channel="<name>")
```

Typically you'll send to the default/all recipients unless the user
specifies otherwise.

### 4. Send

For each (channel, recipient) pair:
```
noo_channel_send(channel="<name>",
                 recipient="<id>",
                 message="<content>")
```

Keep messages short and context-appropriate. For "hello" messages,
a one-line friendly note is fine. For alerts or reports, include the
key information up front.

### 5. Confirm delivery

Report:
- Which channels received the message
- Any channels that failed (auth issues, offline, etc.)
- Total recipients reached

Example:
> Sent "Hello from Mesh" to 2 channels:
> - google_chat (3 recipients): ✓
> - telegram (1 recipient): ✓
> WhatsApp skipped (not configured).

## Notes

- Don't send empty messages — if the user said just "broadcast", ask
  for content
- Respect recipient preferences stored in `noo_channel_recipients`
- For high-frequency automated broadcasts, consider wiring through
  `heartbeat` instead of direct tool calls
