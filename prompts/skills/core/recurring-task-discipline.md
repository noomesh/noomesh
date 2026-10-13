---
name: recurring-task-discipline
version: "1.0"
description: "Cron syntax + channel injection + action selection for creating scheduled heartbeat tasks"
author: noo-builtin
tags: [heartbeat, scheduler, recurring, cron]
trigger_keywords: [schedule, recurring, daily, weekly, every, briefing]
priority: 8
max_context_chars: 1800
composable: true
requires_tools: [noo_heartbeat_list_actions, noo_heartbeat_create_task]
fitness: 0.0
generation: 0
parent_skill: null
---

# Recurring Task Creation Discipline

You are creating a scheduled (recurring) task via `noo_heartbeat_create_task`. Follow these rules — they are the difference between a task that runs cleanly and one that silently fails or fires at the wrong time.

## 1. Translate the user's English schedule to cron

Cron fields, in order: `minute hour day-of-month month day-of-week`.
Day-of-week: 0=Sun, 1=Mon, …, 6=Sat (cron's standard form).

Cookbook — use these directly, do not reinvent:

| User says                  | Cron expression   |
|----------------------------|-------------------|
| every morning (8am)        | `0 8 * * *`       |
| every evening (6pm)        | `0 18 * * *`     |
| every night (10pm)         | `0 22 * * *`     |
| every weekday morning      | `0 8 * * 1-5`     |
| every monday at 9am        | `0 9 * * 1`       |
| every friday at 5pm        | `0 17 * * 5`      |
| every weekend morning      | `0 9 * * 0,6`     |
| daily at midnight          | `0 0 * * *`       |
| hourly                     | `0 * * * *`       |
| every 15 minutes           | `*/15 * * * *`    |
| every 4 hours              | `0 */4 * * *`     |
| first of every month at 9am| `0 9 1 * *`       |
| every sunday at noon       | `0 12 * * 0`      |

If the user gives a specific time, use that minute/hour. If they only say "morning" assume `0 8 * * *`. If they don't specify a time at all for a daily task, ASK — don't pick silently.

## 2. Pick the right action

If you have not yet, call `noo_heartbeat_list_actions` to see the canonical list. Common ones:

- `daily_briefing` — generic cluster + KB + jobs summary
- `cluster_health` — node/backend status report
- `rag_reindex` — trigger embedding for stale docs
- `memory_cleanup` — prune old conversations
- `custom_prompt` — run an arbitrary prompt through the coordinator (use this for "research X every week" style requests)

For anything that doesn't match a canonical action exactly, use `custom_prompt` and put the actual instruction in `config.prompt`.

## 3. Always populate `config.notified_channels`

If you don't specify where the result goes, the report fires into the void. When the user is talking to you over a channel (Google Chat, Telegram, etc.), the inbound `channel` is auto-injected for you when omitted — but it's still safer to set it explicitly. Pattern:

```json
{
  "name": "Weekly AI research summary",
  "action": "custom_prompt",
  "schedule": "0 9 * * 1",
  "config": {
    "prompt": "Research the latest developments in <topic>. Cite sources with URLs and structure as a report.",
    "notified_channels": ["google_chat"]
  }
}
```

For report-style recurring tasks, ALSO set `drive_folder_id` (or accept the default `NOO_REPORTS_DRIVE_FOLDER_ID`) so the full report lands in Drive and the chat gets a link instead of a wall of text.

## 4. Confirm before creating destructive or high-frequency tasks

- Anything more frequent than every 15 minutes — confirm with the user (likely overkill, or a typo).
- Anything that calls `memory_cleanup`, `rag_reindex`, or other mutators — confirm.
- Anything that hits external APIs (web_search, channel sends) — read the cron back to the user in plain English BEFORE calling `noo_heartbeat_create_task`.

Echo format: "I'll set this to run **every Monday at 9 AM Eastern**, posting to **this Google Chat space**. Confirm?"

## 5. After creation, list to verify

Call `noo_heartbeat_list_tasks` after a `create_task` to confirm the task is registered with the right schedule. If the user wants it tested without waiting for the next cron tick, call `noo_heartbeat_run_task` once.

## 6. Don't repeat the create call

If `noo_heartbeat_create_task` returns successfully (you get a task_id), the task is created. Do NOT call it again in the same turn "to be sure" — that creates duplicates that all fire at the same time.
