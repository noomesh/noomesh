# Memory & knowledge

Covers: memory and embedding management (`memory`), PageIndex RAG (`rag`), episodic recall — System 1 memory (`recall`), knowledge graph exploration and maintenance (`graph`), your saved graph threads (`walks`), asynchronous operations (`ops`), prompt skill templates (`prompt-skills`) and the self-improvement meta-cognitive loop (`loop`, pro).

Does not cover: the fleet or its models (`noo cluster`, `noo models`), or containerized skills (`noo skills`, under Fleet).

## Disambiguation

Four groups read four different stores, and two more are easy to confuse
with a Fleet group:

- `noo memory` — **conversation memory**: the raw chat entries and their pgvector embeddings in Postgres. Native gateway SQL; works without any add-on.
- `noo recall` — **episodic recall**: the System 1 layer of compressed conversation "recall memory" (Postgres + FAISS) that the trellion add-on maintains; `archive` feeds it, `lifecycle` prunes, elevates and compacts it.
- `noo rag` — the **PageIndex knowledge base**: ingested documents, pages and chunks; `query` answers questions with citations. Ingest and query run in trellion; `status`, `docs` and `scan` are native and keep answering during a trellion outage.
- `noo graph` — the **knowledge graph** of entities and edges extracted from those documents. Native SQL reads.
- `noo prompt-skills` — versioned **prompt templates** the gateway serves to agents (a filesystem registry, no container). `noo skills` (Fleet) runs **containerized code** in a sandbox via the node-agent; `noo plugins` (Stack & data) adds commands to your **shell**.
- `noo loop` and `noo ga` — the self-tuning loop and prompt evolution. They are **provided by the evolve add-on** (it describes its own commands; core ships none of them, see [CLI pieces](../development/addons.md#cli-pieces--bringing-your-own-noo-commands)), so they appear in `noo --help` only while evolve is enabled. When evolve is disabled or unlicensed they exit 5 with the gateway's explanation.

## Recipes

### Ingest documents and ask a question

```sh
noo rag status
noo rag ingest notes/architecture.md notes/runbook.md
noo rag docs
noo rag query "how does a node get its certificate?"
```

`status` exits 1 with `PageIndex RAG is not running` if the store is not
up; otherwise it prints `documents`, `pages N (X embedded, Y unembedded)`,
`chunks`, `entities`, `edges` and the `embedder` state. `ingest` reads
each file as UTF-8 text, posts it synchronously (chunk + embed complete
before it returns), prints `ingested <name>` and the bare `doc_id`
(the value `--quiet` captures). `-t <title>` names a single document;
with several files or a folder it is refused. A folder argument expands to
the text files one level deep (`-r` descends); `--audience <role>[,<role>]`
(`company`, `team:<name>`, `user:<name>`) sets who can read the result,
and without it the document is tagged to you. Binary formats (PDF, …) have no upload
route on this path — drop them in a watched folder instead (next
recipe). `query` prints a header (`rag query  strategy hybrid · intent … ·
N evidence pages`), the answer, a `verification` line with confidence and
supported/unsupported counts, optional `hypotheses`, and a `citations`
table (`# | title | page | conf | excerpt`). Strategies for `-s` are
`hybrid` (default), `lookup` and `graph_first`; `-p <persona-id>` biases
retrieval.

### Review who can read each document

```sh
noo rag docs --audience admin
noo rag doc <id>
noo rag retag --doc-id <id> --role user:alice --relabel --apply
```

`rag docs` pages through every document (or `--limit <n>`) with its real
audience, source, who ingested it and how many times the audience changed,
and ends with `269 documents · 0 untagged · admin 150 · user:* 80 · company
39`. `--untagged`, `--audience <role>` (`user:*` = any personal tier),
`--match <glob>` and `--title <text>` narrow the list and the summary
together. `rag doc` shows one document's provenance, audience history and a
text preview. `retag` refuses an empty audience; the full workflow is under
"Reviewing document audiences" in [config](../reference/config.md).

### Hold documents out of embedding and search

```sh
noo rag hold --title-prefix 'my-project / retrieval /' --reason retrieval-receipts          # dry run
noo rag hold --title-prefix 'my-project / retrieval /' --reason retrieval-receipts --apply
noo rag held --reason retrieval-receipts --export held-receipts.json
noo rag purge --reason retrieval-receipts                                                    # dry run
noo rag purge --reason retrieval-receipts --apply
```

A **hold** keeps a document (its row, pages, chunks and ids) but takes it
out of everything that reads the knowledge base: the embedder is not
offered its pages or chunks, search and retrieval never return it, the
graph reads and entity-to-page lookups skip it, and it is not counted in
the `unembedded_*` figures that drive the embedding backlog guard. It does
**not** delete anything, does not remove entities or edges already
extracted from it, and does not touch `noo rag docs` or `noo rag doc <id>`
(an operator can still inspect a held document by id). Selectors are
`--title-prefix <p>` (a literal prefix: `%` and `_` match themselves) or
`--doc <id>...`; exactly one. Every write is a **dry run unless
`--apply`** and says plainly that nothing changed. `--reason` defaults to
`operator-hold`. `noo rag unhold` mirrors it and makes the documents
eligible again.

Operator only. The order for retiring a body of documents is:

1. **Hold** them (dry run, then `--apply`). The embedding backlog stops
   growing at once; nothing is lost.
2. **Export and reconcile.** `noo rag held --reason <r> --export <file>`
   writes every held id and title to a JSON file
   (`{reason, total, count, docs: [{doc_id, title, reason, held_at}]}`) to
   check against whatever else holds those ids.
3. **Purge**, when the reconciliation is done. `noo rag purge --reason <r>`
   deletes only documents already held under exactly that reason, with
   their pages, chunks, embeddings and mentions, in batches. It is a dry
   run unless `--apply`; on a terminal `--apply` asks for the count typed
   back (`-y` skips it, and is required without a terminal). **Purge is
   irreversible.**

Holds need trellion's migration 105 (`docs.held_at`). A gateway running
beside an older trellion keeps working with the plain, unfiltered counts and
listings, and answers every hold command with "roll trellion first"; the
filters switch on within a minute of trellion migrating, with no gateway
restart.

### Pull in watched folders and Drive

```sh
noo rag scan -s folders      # or drives, or all
```

Runs one synchronous scan of the configured watched folders and/or
drives (up to 300 s) and prints, per source, `N seen, N new, N ingested`
with a `file | doc id` table and any errors. The same scan runs on its own
from the `watched_folders` autonomy location; this is the manual trigger.
All three dedup layers apply (source URI, archive directory, content
hash). `noo rag deduplicate` is the one-time cleanup of duplicate pages.

### Explore the knowledge graph

```sh
noo graph stats
noo graph search "gateway"
noo graph detail <entity-id>
noo graph neighbors <entity-id> -H 2
```

`search` is a case-insensitive name match (`id | name | type`); `neighbors`
walks edges up to `-H` hops (default 1, the gateway clamps to 1–5) and
prints `depth | src | rel | dst`. Entities appear as documents are
ingested and the `missing_graph_entities` autonomy location backfills
them; an empty graph right after ingest is normal.

### Navigate the graph and recall your saved threads

```sh
noo graph navigate "how do gateway and trellion relate?" -H 2
noo walks --q "gateway" --top-k 5
noo walks show <id>
noo walks settings --save off
```

`graph navigate` answers a question by walking the graph (Intelligent
tier) and saves the walk as a thread under your account; entity `search`
never saves one. `noo walks` recalls only your own threads (nearest `--q`,
else the latest `--top-k`, default 5), re-checked against the graph today,
so a thread through something you can no longer read is dropped.
`settings --save off` stops new saves and deletes nothing. `walks stats
[--user <account>]` (operator and above) returns counts only; `walks view
<account> [--limit <n>]` prints an account's threads verbatim, is
admin-only and every view is audited.

### Rebuild clusters and clean junk entities

```sh
noo graph recluster                  # follows the operation to the end
noo graph recluster --no-wait        # print the operation id and return
noo graph entity-cleanup             # dry run: counts + most-connected examples
noo graph entity-cleanup --apply     # preview, ask, stage and remove
noo graph prune restore --run <run-id>
```

`recluster` needs the Intelligent tier (Basic is refused with the add-on's
message). It is minutes of work (clustering plus labelling), so
the gateway runs it as an operation; the CLI follows it with a spinner for
up to 960 s (the run itself is allowed 900 s). `--no-wait` prints the
operation id and returns; `-m <min-size>` and `-r <resolution>` tune the
pass. A second run while one is in flight is not queued: yours is joined,
anyone else's is reported as already running. `entity-cleanup` (admin)
finds junk entities such as `a`, `x_t` or `0.003`. It is a dry run unless
`--apply`; `--apply` shows the same plan, asks for confirmation (`--yes`
skips it, `--json` never prompts), stages the entities and deletes at most
`--max-delete` (1 to 5000, default 5000) per run, so re-run to continue;
`--examples` is 0 to 200 (default 20). It prints a run id. `prune restore
--run <id>` (operator and above) brings that run's entities, edges and
mentions back within the 30-day staging window, in batches of 500.
Recluster afterwards to fold them into clusters.

### Follow long operations

```sh
noo ops
noo ops show <op-id> --wait
noo ops cancel <op-id>
noo ops types
```

A route that cannot finish in a few seconds (recluster, relation
extraction, consolidation, ingest, slow walks) answers `202` with an
operation handle instead of holding the request. `noo ops [list]` shows
your operations, newest first (`--status`, `--mine`, `--limit`; an admin
sees everyone's). `show --wait` blocks (default 900 s, `--timeout`
overrides) and exits 1 unless the operation succeeded. `cancel` stops only
the gateway-side wait; the output says whether the worker run was stopped,
and it may still complete. `types` lists each type with how long its route
waits and how long a run may take. Operations expire after a retention
window, after which `show` reports `expired`.

### Search conversation memory and keep it embedded

```sh
noo memory search "the vLLM VRAM decision" --user alice
noo memory health
noo memory embed-status
noo memory embed --watch
```

`search` embeds the query and ranks entries by cosine similarity
(`score | type | created | content`, top 5). `health` grades the store
(A–D) and warns when `Only X% of entries embedded — search misses recent
conversations`. `embed` flips the embedding worker's state flag to
`running` (the gateway ignores the batch-size and threshold flags; tuning
lives in `noomesh.yaml`) and returns immediately; `--watch` polls
`embed-status` every second until the state leaves `running` and prints
`embedding complete`. `embed-stop` flips it back. `stats`, `tool-stats`
and `conversations` are the read-only views over the same tables.

### Maintain episodic recall

```sh
noo recall status
noo recall archive                 # fold new conversations into recall memory
noo recall lifecycle --dry-run     # what prune / elevate / compact would do
noo recall refresh                 # archive, then run the lifecycle for real
noo recall search "the migration weekend" --top-k 5
```

`lifecycle --dry-run` lists `would prune`, `would elevate to System 2` and
`would compact` (or `nothing to do — all records are healthy`). `search`
ranks compressed records (`# | score | prom | hits | type | preview`);
`prominent` lists the most-accessed ones. When the trellion worker is
unreachable, `status` still answers (with an `error:` field, exit 0);
every other recall verb needs the add-on and exits 5 without it.
`recall test` is a local note about the current architecture, not a probe.

### Manage prompt skills

```sh
noo prompt-skills list
noo prompt-skills create summarise-incident -f skill.md -d "Incident summary" --tags ops -p 5
noo prompt-skills info summarise-incident
noo prompt-skills evolve -o "summaries miss the timeline"
noo prompt-skills evolve -o "summaries miss the timeline" --skill summarise-incident --apply
```

`create` takes the content from `-f` or stdin and prints `created skill
<name>`; a gateway reply without `ok: true` exits 1. `evolve` is served
by the evolve add-on (the gateway proxies the call; with the add-on off it
refuses with the add-on's 503). By default it prints a proposal (the action,
the skill name, the rationale and the moderation verdict) and writes
nothing; `--apply` creates or rewrites the evolved skill, `--skill <name>`
points the pass at one skill and `--role <role>` at one role.

### Review the self-improvement loop (provided by the evolve add-on)

```sh
noo loop status
noo loop cycles --limit 10
noo loop detail <cycle-id>
noo loop approve <cycle-id>          # or: noo loop reject <cycle-id> --reason "…"
```

`status` shows `running/stopped/unknown`, the cycle count and pending
approvals; `cycles` lists `time | score | delta | status | adapt |
rollback`; `approve` applies a cycle's config changes and actions with no
further confirmation. `loop run` starts a manual cycle with a full LLM
reflection (300 s timeout). Needs the evolve add-on enabled and licensed —
see [add-ons.md](../getting-started/add-ons.md).

## Related guides

- [../getting-started/add-ons.md](../getting-started/add-ons.md) — the trellion (knowledge) and evolve add-ons these groups need

## Command reference

<!-- BEGIN GENERATED: cli-reference section="Memory & knowledge" — do not edit; regenerate with scripts/gen-cli-docs.py -->
### `noo memory` — Memory & embedding management
| Command | Arguments | What it does |
|---|---|---|
| `noo memory search` | `<query> [--user <user>]` | Search memory by pgvector similarity, optionally scoped to one user |
| `noo memory stats` | — | Show memory storage, conversation and tool-usage statistics |
| `noo memory health` | — | Print the memory subsystem health report |
| `noo memory tool-stats` | `[--days <n>]` | Show tool call counts and success rates over the last N days |
| `noo memory embed` | `[--watch]` | Start the background embedding worker, optionally watching progress |
| `noo memory embed-status` | `[--watch]` | Show embedding worker state and record counts, optionally polling |
| `noo memory embed-stop` | — | Stop the background embedding worker |
| `noo memory conversations` | `[--user <user>] [--limit <n>]` | List recent conversations with message counts and previews |

### `noo rag` — PageIndex RAG commands
| Command | Arguments | What it does |
|---|---|---|
| `noo rag query` | `<question> [-s <strategy>] [-p <persona-id>]` | Ask the PageIndex RAG a question and print answer, verification and citations |
| `noo rag status` | — | Show PageIndex RAG table counts and embedder state |
| `noo rag docs` | `[--untagged] [--audience <role>] [--match <glob>] [--title <text>] [--limit <n>]` | List every document with audience, source and who ingested it; filterable |
| `noo rag doc` | `<id>` | Show one document: audience, provenance, audience history and a text preview |
| `noo rag ingest` | `<path>... [-t <title>] [-r] [--audience <role>[,<role>]]` | Ingest text files or a folder; audience defaults to you, share with team:<name> or company |
| `noo rag scan` | `[-s folders\|drives\|all]` | Run one synchronous ingest scan of watched folders and/or drives |
| `noo rag deduplicate` | `[--dry-run] [-y]` | Delete duplicate (doc_id, page_no) pages, keeping the newest; confirms first |
| `noo rag retag` | `(--match <glob> \| --doc-id <id>) --role <r>[,<r>] [--relabel] [--apply] [--limit <n>]` | Change which audience documents belong to; dry-run unless --apply |
| `noo rag hold` | `(--title-prefix <p> \| --doc <id>...) [--reason <r>] [--apply]` | Keep documents but take them out of embedding and search; dry-run unless --apply |
| `noo rag unhold` | `(--title-prefix <p> \| --doc <id>...) [--apply]` | Make held documents eligible for embedding and search again; dry-run unless --apply |
| `noo rag held` | `[--reason <r>] [--export <file>]` | List held documents; --export writes every held id and title to a file |
| `noo rag purge` | `--reason <r> [--apply] [-y]` | Delete the documents held under a reason (irreversible); dry-run unless --apply |

### `noo recall` — Episodic recall (System 1 memory)
| Command | Arguments | What it does |
|---|---|---|
| `noo recall status` | — | Show recall memory (System 1 recall) status |
| `noo recall videos` | — | List recall memory files with record counts and sizes |
| `noo recall search` | `<query> [--top-k <k>]` | Search compressed recall memory and rank results by score |
| `noo recall prominent` | `[--top-k <k>]` | List the most prominent recall records by access and relevance |
| `noo recall stats` | — | Show recall lifecycle statistics |
| `noo recall lifecycle-stats` | — | Hidden: alias of `recall stats` |
| `noo recall archive` | — | Archive new conversations into recall memory |
| `noo recall lifecycle` | `[--dry-run] [-y]` | Run the recall lifecycle (prune, elevate, compact) after confirming, or preview it |
| `noo recall refresh` | `[--dry-run] [-y]` | Archive new conversations then run the lifecycle (prunes); --dry-run previews |
| `noo recall test` | — | Hidden: retired; points at `recall status` and `recall lifecycle` |

### `noo graph` — Knowledge graph exploration
| Command | Arguments | What it does |
|---|---|---|
| `noo graph stats` | — | Show knowledge-graph entity/edge counts |
| `noo graph search` | `<query>` | Search knowledge-graph entities by name (ILIKE match) |
| `noo graph detail` | `<entity-id>` | Print one knowledge-graph entity as JSON |
| `noo graph neighbors` | `<entity-id> [-H <hops>]` | Walk edges from an entity up to N hops (default 1, gateway clamps 1-5) |
| `noo graph navigate` | `<question> [-H <hops>] [-s <entity-id>]...` | Navigate the graph for a question; saved as a walk (Intelligent tier) |
| `noo graph recluster` | `[-m <min-size>] [-r <resolution>] [--wait\|--no-wait]` | Rebuild entity clusters (Intelligent tier; minutes); --no-wait prints the operation id |
| `noo graph entity-cleanup` | `[--apply] [--examples <n>] [--max-delete <n>] [--yes]` | Find junk entities (a, x_t, 0.003); dry run unless --apply, which asks first (admin) |
| `noo graph prune restore` | `--run <id>` | Restore the entities one cleanup run staged (operator; within 30 days) |
| `noo graph clusters audit` | — | Audit how clusters mix audience tiers and what a non-admin sees (admin; read-only) |

### `noo walks` — Your saved graph threads: recall them, and control saving
| Command | Arguments | What it does |
|---|---|---|
| `noo walks` | `[--q <text>] [--top-k <n>]` | Recall your own saved graph threads (nearest --q, else the latest) |
| `noo walks show` | `<id>` | Show one of your saved threads: what you asked, the path, and why it ranked |
| `noo walks settings` | `[--save on\|off]` | Show or set whether your graph walks are saved as threads (default on) |
| `noo walks stats` | `[--user <account>]` | Count saved threads by kind, status and account (operator and above; counts only) |
| `noo walks view` | `<account> [--limit <n>]` | Print an account's saved threads verbatim (admin only; every view is audited) |

### `noo ops` — Asynchronous operations: long runs started as an op, polled for their result
| Command | Arguments | What it does |
|---|---|---|
| `noo ops` | `[--status <s>] [--mine] [--limit <n>]` | Hidden: same as ops list |
| `noo ops list` | `[--status <s>] [--mine] [--limit <n>]` | List your asynchronous operations, newest first (an admin sees everyone's) |
| `noo ops show` | `<id> [--wait]` | Show one operation: status, progress, result or error; --wait blocks until it finishes |
| `noo ops cancel` | `<id>` | Cancel an operation: stops the gateway-side wait (the worker run may continue) |
| `noo ops types` | — | List what can run as an operation, how long each waits and how long a run may take |

### `noo prompt-skills` — Prompt skill templates
| Command | Arguments | What it does |
|---|---|---|
| `noo prompt-skills list` | — | List prompt skill templates with priority and fitness |
| `noo prompt-skills info` | `<name>` | Show one prompt skill's metadata and content |
| `noo prompt-skills get` | `<name>` | Hidden: alias of `prompt-skills info` |
| `noo prompt-skills create` | `<name> [-f <file>] [-d <description>] [--tags <csv>] [-p <priority>]` | Create a prompt skill from a file or stdin content |
| `noo prompt-skills evolve` | `[-o <observation>] [--skill <name>] [--role <role>] [--apply]` | Propose (or with --apply, write) an LLM-evolved prompt skill |
<!-- END GENERATED -->
