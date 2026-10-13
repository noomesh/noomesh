---
name: file-operations
version: "1.0"
description: "Local and remote file handling — browse, read, download, and route to other tools"
author: noo-builtin
tags: [files, filesystem, local, remote, download, url, browse, directory, path]
trigger_keywords: [file, files, folder, directory, path, browse, list files, read file, download, url, fetch, local files, papers, documents]
priority: 6
max_context_chars: 3000
composable: true
requires_tools: [local_files, web_search, noo_rag_ingest]
fitness: 0.0
generation: 0
parent_skill: null
---

# File Operations

You have direct filesystem access via `local_files`. Use it — do not tell the user to do it themselves.

## Local Files

- **List directory**: `local_files(action=list, path=<dir>)` — returns files with sizes and types
- **Read file**: `local_files(action=read, path=<file>)` — returns text content
- **Glob search**: `local_files(action=list, path=<dir>, pattern=*.pdf)` — filter by extension

Always use full absolute paths. Use the watched_folders config in noo-mesh.yaml to set document directories.

## Remote Files / URLs

- **Download and ingest**: `noo_rag_ingest(source=<https_url>, title=<name>)` — fetches the URL server-side and ingests into the knowledge base
- **Search the web**: `web_search(query=<topic>)` — find URLs for relevant content
- **Web → Knowledge base**: Find URLs via `web_search`, then ingest with `noo_rag_ingest(source=<url>)`

## Common Workflows

### "Show me what files are in X"
→ `local_files(action=list, path=X)`

### "Read/summarize this file"
→ `local_files(action=read, path=<file>)` → summarize the content

### "Load these files into memory / knowledge base"
→ `local_files(action=list)` → identify files → `noo_rag_ingest(source=<path>)` for each

### "Find and download a paper about X"
→ `web_search(query=X)` → find URL → `noo_rag_ingest(source=<url>, title=<name>)`

## Rules
- Complete the full workflow. Do not stop after listing to ask the user which files — make a reasonable selection and execute.
- When the user says "files about AI" or similar, filter by filename/topic and ingest the matching ones.
- Report what you ingested when done: file names, count, any errors.
