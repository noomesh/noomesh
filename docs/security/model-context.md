# What the model reads as instructions

Covers: which text reaches a model as instructions and which as data.

Only text the operator controls is in the system message: the persona
prompt, the shipped runbooks and the shipped (core) prompt skills.
Everything a third party could have written travels instead as one fenced
data block at the head of the user's own message, marked as data, with the
begin and end markers made unforgeable and likely injection lines flagged:
retrieved documents, graph facts, memory, other-channel messages, video
recall, conversation summaries and recall (they are built from past
messages), skills written at runtime (evolved, through the API, the
`noo_prompt_skills_create` tool or the evolve add-on) and companion-device
reports, and the live cluster listing (node ids and the backends each node
reports: a node writes those strings, not the operator). Only the operator's
static guidance about how to use `noo_cluster_status` stays in the system
message, and it names no node. The block is removed again before the session is cached.

Evolved skills are data for this reason: anyone with prompt-skill write
access, an agent through `noo_prompt_skills_create`, or the evolve add-on can
write one. Core skills ship with the product and cannot be edited at runtime,
so they stay instructions.

### Promoting a skill

A person can turn a reviewed runtime skill into instructions. A skill written
at runtime has one of three states:

| State | Where it travels |
|---|---|
| `evolved` (the default for everything written at runtime) | the fenced data block in the user's message |
| `promoted` | the system message, next to core skills |
| `rejected` | nowhere: it is never injected, and it does not take a selection slot |

Every create, and every update that changes a skill's name, description or
body, files a pending proposal (an update that only moves the score or the
tags does not). `noo prompt-skills proposals` lists them;
`noo prompt-skills decide <id> --promote` or `--reject` decides one, and
records who decided and when in `noo_prompt_skill_proposals` and as an audit
row (`prompt_skill_promoted`, `prompt_skill_rejected`). A decision can be
reversed the same way.

- **The decision is on the text.** It is stored with a hash of the name,
  description and body that were reviewed. Edit a promoted skill and the hash no
  longer matches: the skill is `evolved` again and a new proposal is pending.
  The skill file is never read for its state, so a file that says
  `trust: promoted` is still `evolved`.
- **A person decides.** The decision routes need an operator or admin login and
  refuse a worker-delegated token, a harness token, an MCP-door key, a service
  identity and an account that is not an enabled user, as the exec-approval
  decisions do. The evolve add-on's write scope does not open them.
- **The split cannot be forged.** The system half is everything before the first
  evolved header, so a skill body that quotes a header can only push more text
  into the frame. The skills catalog in the system message lists only core and
  promoted skills.
- **Failure is data.** If the decisions cannot be loaded (the database is down,
  or migration 096 is not applied) every runtime skill is framed as data, which
  demotes promoted skills until they load; the gateway logs
  `prompt_skill_decisions_unavailable`. A proposal that cannot be filed does not
  fail the write: the answer says `not_filed` and `noo prompt-skills proposals`
  files it. A gateway or node that predates the field frames every runtime skill.
- **Effect.** A decision applies to the running gateway at once. Skill content in
  a running gateway is read at boot, so an edit takes effect after a restart; the
  text injected until then is still the text that was promoted.
