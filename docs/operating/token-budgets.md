# Token budgets

A task can carry a **token budget** beside its loop budget, and a person can
carry a standing **allowance** per period. Both are one number of tokens:
prompt plus completion, whatever ran them.

- The task's owner sets the task's budget when they create it
  (`noo tasks create <objective> --token-budget <n>`) and can change it
  while the task runs (`noo tasks resubmit <id> --token-budget <n>`).
- An operator sets a person's allowance
  (`noo security user allowance <user> --tokens <n> --period month`; the
  period is `day`, `week` or `month`). No allowance means no standing cap.

## The four rules

1. **It is a switch that says no more turns.** When the task's budget or
   its owner's allowance is spent, no further loop starts.
2. **The running turn is never interrupted.** The check happens between
   loops, before the next one starts. A loop that crosses the budget
   finishes; its tool results stand and the task checkpoints. Nothing is
   cut off mid-turn and nothing is sent into a turn while it runs.
3. **The task stops in a state you can act on, two ways.**
   - **Resubmit**: give it more tokens
     (`noo tasks resubmit <id> --token-budget <n>`). It resumes from its
     checkpoint. If the allowance was what ran out, an operator raises it
     (or the period turns over) and a plain `noo tasks resubmit <id>`
     resumes it.
   - **Ask for clarification**: a loop that cannot go on without you asks
     one question (the `noo_task_ask` tool; a CLI harness ends its answer
     with `NOO_QUESTION: <question>`). The question is posted to the task's
     thread, and at the next boundary the task waits. Your answer
     (`noo tasks answer <id> <text>`) starts a **new** loop whose prompt
     carries the question and your answer.

   Either way nothing is re-run and nothing is lost.
4. **Cloud is tracked as cloud.** Every loop's tokens are recorded with the
   task and the backend that served them. Spend served by a cloud provider
   (`cloud-anthropic`, `cloud-openai`, `cloud-gemini`) is reported
   separately from spend served by your nodes, and a CLI harness's spend
   separately per harness kind. Your budget is one number; the accounting
   shows the columns side by side and never merges them.

## Reading a task

`noo tasks show <id>` shows `tokens` (spent, of the budget, and what is
left) and the owner's `allowance`. A parked task shows why:

| `budget_state` | What it means | What to do |
|---|---|---|
| `exhausted` | the task's budget or the owner's allowance is spent; the reason, with the numbers, is the last note | `noo tasks resubmit <id> --token-budget <n>` |
| `awaiting_clarification` | a loop asked you a question; it is the last note and in the task's thread | `noo tasks answer <id> <text>` |

A parked task is `checkpointed`, never `failed`. It is not handed back to
a harness when one restarts, and it is not reported stale: it waits for
you.

## Reading spend

`noo usage me` shows your spend this period in three columns: node, cloud,
and one row per harness kind, with your allowance and what is left.
Operators can read anyone's with `--user`.

A money figure (`cost`) is added per column when the
`NOO_MODEL_COST_USD_PER_MTOK` setting prices the model: a JSON object of
model-name prefix to US dollars per million tokens, longest prefix wins,
for example `{"claude-": 6.0, "gpt-4o": 5.0}`. It is reported only; budgets
are counted in tokens.

## Limits of this release

- The answer to a question is given with `noo tasks answer`, the
  `POST /api/tasks/{id}/answer` route or the `noo_task_answer` door tool.
  A reply typed into the task's thread is recorded there but does not yet
  restart the task.
- Allowances are per person. Per-organisation allowances are not built yet.

API reference: [Tasks](../reference/api.md#tasks-routestasksrs) and the
[harness rail](../reference/harness-protocol.md).
