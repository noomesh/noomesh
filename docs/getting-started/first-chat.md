# Your first chat

This page is for the first ten minutes after install: talk to the cluster
you just built, give it one document to know about, and find the dashboard.
The command that proves it works is `noo chat --message "hello"` printing an
answer.

You need a running stack: `noo stack start`, then `noo health` exiting 0
([install.md](install.md) §4-5).

## Say hello

```bash
noo chat
```

This opens a streaming conversation; every turn shares one conversation id.
`/exit` or `/quit` ends it. For a single turn that returns to the shell:

```bash
noo chat --message "in two lines, what can you do on this machine?"
```

`--model <m>` picks a model; without it the cluster chooses. The backend
that answered is shown on stderr. The full flag list is in
[agents-and-channels.md](../cli/agents-and-channels.md).

## A first good question: your own cluster

Ask about what you just built. These need no setup:

```bash
noo chat --message "which nodes and models do you have right now?"
noo cluster status
```

Compare the answer with `noo cluster status`; they should agree.

## A second good question: your own document

The knowledge base starts empty. Ingest one text or Markdown file, then ask
about it:

```bash
noo rag ingest ~/notes/anything.md
noo rag status
noo rag query "what does anything.md say about the deadline?"
noo chat --message "summarise what you know from anything.md"
```

`noo rag status` shows the document and page counts; `noo rag query` answers
with citations, so you can see which pages it used. More verbs (`docs`,
`scan`, watched folders) are in
[memory-and-knowledge.md](../cli/memory-and-knowledge.md).

## The dashboard

The web console is at `https://localhost:8080` (and on your tailnet name if
you joined one). A browser warns until it trusts the install's own CA:
[trust-the-cluster-ca.md](trust-the-cluster-ca.md). Sign in with the admin
account the wizard created. Grafana is at `https://localhost:3000`.

## The two things people hit first

- **The model is still loading.** Right after the first start, or after a
  restart, the model backend can take minutes to load into memory,
  longer on a CPU-only box. Chat reports that the backend is not ready
  rather than failing. Wait, then retry; `noo health` shows which
  dependency is still down and `noo stack logs <dep>` shows why.
- **The knowledge base is empty.** Until you ingest something, `noo rag
  query` has nothing to cite and a chat answer comes from the model alone.
  That is expected, not a fault: ingest a document as above.

## Next

- [add-ons.md](add-ons.md) — switch on knowledge, voice, the licensed tiers
