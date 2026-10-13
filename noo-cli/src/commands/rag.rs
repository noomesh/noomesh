// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo rag …` — PageIndex RAG (Rust gateway routes/knowledge.rs; query and
//! ingest are delegated to the Python worker over NATS).
//!
//! Ported: query, status, docs, ingest, scan, deduplicate.
//!
//! `ingest` deviates from Python deliberately: the Python CLI multiparts the
//! file to POST /api/v1/docs/ingest, but that route died with the archived
//! Python gateway — the Rust gateway's catch-all is JSON-only (multipart →
//! 415, and even JSON → 400 "Not Found" from the ASGI fallback; verified
//! live 2026-07-12). The working ingest surface is POST /api/v1/rag/ingest
//! (explicit Rust route → worker.rag.ingest), which takes
//! `{"text","title","source_uri"}` — so the Rust CLI reads the file locally
//! (UTF-8 text formats: md/txt/html/…) and sends its content as `text`.
//! Binary formats (PDF) have no working upload path on the current gateway;
//! use a watched folder for those.

use super::{truncate, urlencode};
use crate::http::{get_json, post_json};
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// `noo rag query QUESTION [--strategy/-s S] [--persona/-p ID]` —
/// POST /api/v1/rag/query {"question", "strategy", ["persona_id"]}.
pub fn rag_query(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut question: Option<String> = None;
    let mut strategy = "hybrid".to_string();
    let mut persona: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--strategy" | "-s" => strategy = iter.next().ok_or(Unhandled)?.clone(),
            "--persona" | "-p" => persona = Some(iter.next().ok_or(Unhandled)?.clone()),
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if question.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(q) = question else { return Err(Unhandled) };
    let mut body = serde_json::json!({ "question": q, "strategy": strategy });
    if let Some(p) = &persona {
        body["persona_id"] = p.as_str().into();
    }

    // Retrieval + verification is slow — Python parity: 60s.
    let resp = post_json(g, "/api/v1/rag/query", &body, true, 60);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }

    // The answer is the data (stdout, verbatim). Retrieval metadata,
    // verification, hypotheses and citations are the muted context around it.
    let mut meta = vec![
        format!("strategy {}", resp["strategy_used"].as_str().unwrap_or("?")),
        format!("intent {}", resp["intent"].as_str().unwrap_or("?")),
        format!("{} evidence pages", resp["evidence_count"].as_u64().unwrap_or(0)),
    ];
    if let Some(p) = resp["persona_id"].as_str() {
        meta.push(format!("persona {}", truncate(p, 12)));
    }
    println!("{}", ui::header("rag query", Some(&meta.join(" · "))));

    if let Some(answer) = resp["answer"].as_str().filter(|a| !a.is_empty()) {
        println!();
        println!("{answer}");
    }

    let verification = &resp["verification"];
    if verification.is_object() {
        let status = verification["status"].as_str().unwrap_or("?");
        let glyph = match status {
            "verified" | "supported" | "passed" => Glyph::Ok,
            "unsupported" | "failed" | "contradicted" => Glyph::Err,
            _ => Glyph::Warn,
        };
        println!();
        println!(
            "{}",
            ui::status_line(
                glyph,
                &format!(
                    "verification {status}  {}",
                    ui::muted(&format!(
                        "confidence {:.0}% · supported {} · unsupported {}",
                        verification["confidence"].as_f64().unwrap_or(0.0) * 100.0,
                        verification["supported_claims"].as_array().map(|a| a.len()).unwrap_or(0),
                        verification["unsupported_claims"].as_array().map(|a| a.len()).unwrap_or(0),
                    ))
                )
            )
        );
    }

    let empty = Vec::new();
    let hypotheses = resp["hypotheses"].as_array().unwrap_or(&empty);
    if !hypotheses.is_empty() {
        println!("{}", ui::section("hypotheses"));
        let rows: Vec<Vec<String>> = hypotheses
            .iter()
            .take(5)
            .map(|h| {
                let path: Vec<&str> = h["path"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|p| p.as_str()).take(4).collect())
                    .unwrap_or_default();
                vec![
                    ui::muted(&format!("{:.0}%", h["confidence"].as_f64().unwrap_or(0.0) * 100.0)),
                    path.join(" > "),
                    truncate(h["description"].as_str().unwrap_or(""), 80),
                ]
            })
            .collect();
        print!("{}", ui::table(&[Col::right("conf"), Col::left("path"), Col::left("description")], &rows));
    }

    let citations = resp["citations"].as_array().unwrap_or(&empty);
    if citations.is_empty() {
        println!();
        println!("{}", ui::muted("no citations"));
        return Ok(0);
    }
    println!("{}", ui::section("citations"));
    let rows: Vec<Vec<String>> = citations
        .iter()
        .enumerate()
        .map(|(i, c)| {
            vec![
                (i + 1).to_string(),
                c["title"].as_str().unwrap_or("").to_string(),
                ui::muted(&format!("p{}", c["page_no"])),
                ui::muted(&format!("{:.0}%", c["confidence"].as_f64().unwrap_or(0.0) * 100.0)),
                c["excerpt"].as_str().unwrap_or("").replace('\n', " "),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(&[Col::right("#"), Col::left("title"), Col::left("page"), Col::right("conf"), Col::left("excerpt")], &rows)
    );
    Ok(0)
}

/// `noo rag status` — GET /api/v1/rag/status (table counts).
pub fn rag_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/v1/rag/status", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    if !body["started"].as_bool().unwrap_or(false) {
        println!("{}", ui::header("rag", Some(&ui::state("stopped"))));
        println!("{}", ui::status_line(Glyph::Err, "PageIndex RAG is not running"));
        return Ok(1);
    }
    let n = |key: &str| body[key].as_u64().unwrap_or(0);
    println!("{}", ui::header("rag", Some(&ui::state("running"))));
    let mut rows = vec![
        ("documents", n("doc_count").to_string()),
        (
            "pages",
            format!(
                "{}  {}",
                n("page_count"),
                ui::muted(&format!("{} embedded, {} unembedded", n("embedded_pages"), n("unembedded_pages")))
            ),
        ),
        ("chunks", format!("{}  {}", n("chunk_count"), ui::muted(&format!("{} embedded", n("embedded_chunks"))))),
        ("entities", n("entity_count").to_string()),
        ("edges", n("edge_count").to_string()),
    ];
    if let Some(state) = body["embedder_state"]["state"].as_str() {
        rows.push(("embedder", ui::state(state)));
    }
    print!("{}", ui::kv(&rows));
    Ok(0)
}

/// What `noo rag docs` was asked for.
#[derive(Debug, Default, PartialEq, Eq)]
struct DocsArgs {
    untagged: bool,
    audience: Option<String>,
    source_glob: Option<String>,
    title: Option<String>,
    /// Stop after this many documents; None pages through ALL of them.
    limit: Option<usize>,
}

impl DocsArgs {
    fn parse(args: &[String]) -> Result<DocsArgs, Unhandled> {
        let mut out = DocsArgs::default();
        let mut iter = args.iter();
        while let Some(tok) = iter.next() {
            match tok.as_str() {
                "--untagged" => out.untagged = true,
                "--audience" => out.audience = Some(iter.next().ok_or(Unhandled)?.clone()),
                "--match" => out.source_glob = Some(iter.next().ok_or(Unhandled)?.clone()),
                "--title" => out.title = Some(iter.next().ok_or(Unhandled)?.clone()),
                "--limit" => {
                    out.limit = Some(iter.next().and_then(|v| v.parse().ok()).filter(|n| *n > 0).ok_or(Unhandled)?)
                }
                _ => return Err(Unhandled),
            }
        }
        Ok(out)
    }

    fn filtered(&self) -> bool {
        self.untagged || self.audience.is_some() || self.source_glob.is_some() || self.title.is_some()
    }

    /// The listing URL for one page. The summary rides on the first page
    /// only: it covers the whole filtered set, so asking again is waste.
    fn path(&self, limit: usize, offset: usize, summary: bool) -> String {
        let mut q = vec![format!("limit={limit}"), format!("offset={offset}")];
        if summary {
            q.push("summary=1".into());
        }
        if self.untagged {
            q.push("untagged=1".into());
        }
        if let Some(a) = &self.audience {
            q.push(format!("audience={}", urlencode(a)));
        }
        if let Some(m) = &self.source_glob {
            q.push(format!("match={}", urlencode(m)));
        }
        if let Some(t) = &self.title {
            q.push(format!("q={}", urlencode(t)));
        }
        format!("/api/v1/docs?{}", q.join("&"))
    }
}

/// Documents per request while paging. The gateway caps a page at 2000.
const DOCS_PAGE: usize = 500;

/// A page's documents and, on the first page, the summary.
fn split_page(body: &serde_json::Value) -> (Vec<serde_json::Value>, Option<serde_json::Value>) {
    match body.as_array() {
        Some(a) => (a.clone(), None),
        None => (
            body["docs"].as_array().cloned().unwrap_or_default(),
            body.get("summary").filter(|s| s.is_object()).cloned(),
        ),
    }
}

/// `admin 150 · user:* 80 · company 39`, biggest first.
fn audience_counts(summary: &serde_json::Value) -> String {
    let mut by: Vec<(String, u64)> = summary["by_audience"]
        .as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_u64().unwrap_or(0))).collect())
        .unwrap_or_default();
    by.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    by.iter().map(|(k, n)| format!("{k} {n}")).collect::<Vec<_>>().join(" · ")
}

/// `269 documents · 0 untagged · admin 150 · user:* 80 · company 39`.
fn summary_line(summary: &serde_json::Value, filtered: bool) -> String {
    let total = summary["total"].as_u64().unwrap_or(0);
    let mut parts = vec![
        format!("{total} {}", if filtered { "matching documents" } else { "documents" }),
        format!("{} untagged", summary["untagged"].as_u64().unwrap_or(0)),
    ];
    let counts = audience_counts(summary);
    if !counts.is_empty() {
        parts.push(counts);
    }
    parts.join(" · ")
}

/// Who and what ingested a document: `cli/alice`, `heartbeat`, or `unknown`
/// for one that predates provenance.
fn ingested_cell(d: &serde_json::Value) -> String {
    let p = &d["provenance"];
    let via = p["via"].as_str().unwrap_or("");
    let by = p["by"].as_str().unwrap_or("");
    match (via.is_empty(), by.is_empty()) {
        (true, true) => ui::muted("unknown"),
        (false, true) => via.to_string(),
        (true, false) => by.to_string(),
        (false, false) => format!("{via}/{by}"),
    }
}

/// An audience as the operator reads it: the real tags (`user:alice`, not
/// `user:*`; this is the operator's own view), or `untagged`.
fn audience_cell(d: &serde_json::Value) -> String {
    match d["roles"].as_array() {
        Some(r) if !r.is_empty() => {
            truncate(&r.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(","), 30)
        }
        _ if d.get("roles").is_some() => ui::warn("untagged"),
        // A restricted caller is not shown audiences at all.
        _ => String::new(),
    }
}

/// The listing table. Pure: the caller prints it.
fn docs_table(docs: &[serde_json::Value]) -> String {
    let rows: Vec<Vec<String>> = docs
        .iter()
        .map(|d| {
            let edits = d["audience_history_len"].as_u64().unwrap_or(0);
            vec![
                ui::muted(d["doc_id"].as_str().unwrap_or("")),
                audience_cell(d),
                truncate(d["title"].as_str().unwrap_or(""), 36),
                ingested_cell(d),
                ui::muted(&d["created_at"].as_str().unwrap_or("").chars().take(10).collect::<String>()),
                if edits > 0 { edits.to_string() } else { String::new() },
                d["source_uri"].as_str().unwrap_or("").to_string(),
            ]
        })
        .collect();
    ui::table(
        &[
            Col::left("doc id"),
            Col::left("audience"),
            Col::left("title"),
            Col::left("ingested"),
            Col::left("created"),
            Col::right("edits"),
            Col::left("source"),
        ],
        &rows,
    )
}

/// Page through the listing until it runs out (or `--limit`). `fetch` takes
/// a path and returns the gateway's JSON, so the loop is testable without one.
fn collect_docs(
    want: &DocsArgs,
    mut fetch: impl FnMut(&str) -> serde_json::Value,
) -> (Vec<serde_json::Value>, Option<serde_json::Value>) {
    let mut docs: Vec<serde_json::Value> = Vec::new();
    let mut summary: Option<serde_json::Value> = None;
    loop {
        let room = want.limit.map_or(DOCS_PAGE, |l| l - docs.len()).min(DOCS_PAGE);
        if room == 0 {
            break;
        }
        let (page, s) = split_page(&fetch(&want.path(room, docs.len(), summary.is_none() && docs.is_empty())));
        if s.is_some() {
            summary = s;
        }
        let got = page.len();
        docs.extend(page);
        if got < room {
            break;
        }
    }
    (docs, summary)
}

/// `noo rag docs [--untagged] [--audience R] [--match GLOB] [--title T] [--limit N]`
/// — GET /api/v1/docs, paged through every document, with the audience
/// summary at the end. The operator's review view.
pub fn rag_docs(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let want = DocsArgs::parse(args)?;
    let (docs, summary) = collect_docs(&want, |path| get_json(g, path, true, 30));
    if g.json {
        println!("{}", serde_json::json!({ "docs": docs, "summary": summary }));
        return Ok(0);
    }
    if docs.is_empty() {
        println!("{}", ui::muted(if want.filtered() { "no documents match" } else { "no documents" }));
        return Ok(0);
    }
    ui::auto_page();
    println!("{}", ui::header("documents", Some(&format!("{} shown", docs.len()))));
    println!();
    print!("{}", docs_table(&docs));
    println!();
    let untagged = match &summary {
        Some(s) => {
            println!("{}", summary_line(s, want.filtered()));
            s["untagged"].as_u64().unwrap_or(0)
        }
        None => 0,
    };
    let mut hints: Vec<(&str, &str)> = vec![
        ("noo rag doc <id>", "audience, provenance, history and a text preview"),
        ("noo rag retag --doc-id <id> --role <r> --relabel", "change one document's audience (dry-run)"),
    ];
    if untagged > 0 && !want.untagged {
        hints.insert(0, ("noo rag docs --untagged", "only the documents with no audience"));
    }
    ui::guide(&hints);
    Ok(0)
}

/// An ISO-8601 instant as `YYYY-MM-DD HH:MM`.
fn when(s: &str) -> String {
    s.chars().take(16).collect::<String>().replace('T', " ")
}

/// A role list as `a, b`, or `untagged` when empty.
fn roles_text(v: &serde_json::Value) -> String {
    match v.as_array() {
        Some(a) if !a.is_empty() => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "),
        _ => "untagged".to_string(),
    }
}

/// The detail view of one document. Pure: the caller prints it.
fn render_doc(d: &serde_json::Value) -> String {
    let mut out = String::new();
    out.push_str(&format!("{}\n\n", ui::header("document", Some(d["doc_id"].as_str().unwrap_or("")))));
    let prov = &d["provenance"];
    let ingested = if prov.is_object() {
        format!(
            "{} by {} · {}",
            prov["via"].as_str().unwrap_or("?"),
            prov["by"].as_str().unwrap_or("(internal)"),
            when(prov["at"].as_str().unwrap_or(""))
        )
    } else {
        ui::muted("unknown (ingested before provenance was recorded)")
    };
    let rows = vec![
        ("title", d["title"].as_str().unwrap_or("").to_string()),
        ("audience", if d.get("roles").is_some() { roles_text(&d["roles"]) } else { ui::muted("not shown") }),
        ("ingested", ingested),
        ("source", d["source_uri"].as_str().unwrap_or("").to_string()),
        ("created", when(d["created_at"].as_str().unwrap_or(""))),
        ("pages", d["page_count"].as_u64().unwrap_or(0).to_string()),
    ];
    out.push_str(&ui::kv(&rows));
    if let Some(h) = d["audience_history"].as_array().filter(|h| !h.is_empty()) {
        out.push_str(&ui::section("audience history"));
        out.push('\n');
        for e in h {
            out.push_str(&format!(
                "  {}  {}  {} → {}\n",
                ui::muted(&when(e["at"].as_str().unwrap_or(""))),
                e["by"].as_str().unwrap_or("?"),
                roles_text(&e["from"]),
                roles_text(&e["to"]),
            ));
        }
    } else if d.get("audience_history").is_some() {
        out.push_str(&format!("\n  {}\n", ui::muted("audience never changed since ingest")));
    }
    out.push_str(&ui::section("preview"));
    out.push('\n');
    match d["text_preview"].as_str().filter(|t| !t.trim().is_empty()) {
        Some(t) => {
            for line in t.lines() {
                out.push_str(&format!("  {line}\n"));
            }
        }
        None => out.push_str(&format!("  {}\n", ui::muted("no text stored for this document"))),
    }
    out
}

/// `noo rag doc ID` — GET /api/v1/docs/{id}: what a document is, where it
/// came from and who has changed its audience.
pub fn rag_doc(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let id = match args {
        [id] if !id.starts_with('-') => id.clone(),
        _ => return Err(Unhandled),
    };
    let body = get_json(g, &format!("/api/v1/docs/{}", urlencode(&id)), true, 15);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    print!("{}", render_doc(&body));
    ui::guide(&[
        ("noo rag retag --doc-id <id> --role <r> --relabel", "change this document's audience (dry-run)"),
        ("noo rag docs", "back to the full list"),
    ]);
    Ok(0)
}

/// Extensions a directory expansion will pick up. Deliberately a fixed list
/// and not "every file": the gateway ingests `text`, so a directory walk
/// that swept up a `.png` or a `.sqlite` would send its bytes as a document
/// and only fail once the whole read had already happened. Anything outside
/// the list is still ingestable by naming it explicitly.
const TEXT_EXTS: &[&str] = &[
    "md", "markdown", "txt", "text", "rst", "org", "adoc",
    "html", "htm", "json", "yaml", "yml", "toml", "csv", "tsv",
];

/// Expand one PATH into the files to ingest.
///
/// A file is itself, whatever its extension — naming it is the operator
/// saying they meant it. A directory becomes its `TEXT_EXTS` children,
/// sorted, so two runs over the same folder ingest in the same order and a
/// recording is reproducible. `recursive` walks subdirectories; without it
/// a directory is one level, which is what a folder of notes usually is and
/// is the one a demo can predict.
fn expand_path(path: &std::path::Path, recursive: bool, out: &mut Vec<std::path::PathBuf>) {
    if path.is_file() {
        out.push(path.to_path_buf());
        return;
    }
    let mut entries: Vec<std::path::PathBuf> = match std::fs::read_dir(path) {
        Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
        Err(_) => return,
    };
    entries.sort();
    for e in entries {
        if e.is_dir() {
            if recursive {
                expand_path(&e, recursive, out);
            }
            continue;
        }
        let keep = e
            .extension()
            .and_then(|x| x.to_str())
            .map(|x| TEXT_EXTS.contains(&x.to_ascii_lowercase().as_str()))
            .unwrap_or(false);
        if keep {
            out.push(e);
        }
    }
}

/// Split `--audience a,b` into role strings, dropping blanks.
fn parse_audience(v: &str) -> Vec<String> {
    v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

/// The ingest request body. `roles` is present ONLY when the operator asked
/// for an audience: an absent key lets the gateway apply its default
/// (the uploader's own tier), whereas `"roles": []` would be a claim.
fn ingest_body(text: &str, title: &str, abs_path: &str, audience: &[String]) -> serde_json::Value {
    let mut body = serde_json::json!({
        "text": text,
        "title": title,
        "source_uri": format!("file://{abs_path}"),
    });
    if !audience.is_empty() {
        body["roles"] = serde_json::json!(audience);
    }
    body
}

/// The one-line note for an ingest whose content was already stored. The
/// gateway sets `existing` only for operator/admin callers; an ingest never
/// changes an existing document's audience.
fn existing_note(name: &str, resp: &serde_json::Value) -> Option<String> {
    if resp["existing"].as_bool() != Some(true) {
        return None;
    }
    Some(format!(
        "{name} is already in the knowledge base; its audience is unchanged (change it with `noo rag retag --doc-id <id> --role <r> --relabel`)"
    ))
}

/// `noo rag ingest PATH… [--title/-t T] [--recursive/-r]` — POST
/// /api/v1/rag/ingest with `{"text": <file content>, "title", "source_uri"}`
/// per file (see module docs for why this differs from Python's dead
/// multipart endpoint).
///
/// A PATH may be a directory: it expands to its text files (`--recursive`
/// to descend). `--title` requires exactly one document, so it is rejected
/// alongside a directory as well as alongside several files — a title names
/// one document and a folder is not one.
///
/// Failure is per-origin, which matters for a long run. A file the operator
/// **named** and that fails is fatal, unchanged: you asked for it by name.
/// A file **discovered** by expanding a directory is counted, reported and
/// skipped, because one unreadable note in a folder of two hundred should
/// not end the run two thirds of the way through. Any skip makes the exit
/// code 1, so a script still knows.
///
/// `--audience <role>[,<role>…]` (also `--role`, matching `rag retag`) sends
/// `roles`: `company`, `team:<name>`, `user:<name>`. Omitted, nothing is sent
/// and the gateway tags the document to YOU (`user:<you>`) — an upload is
/// yours until you say otherwise.
///
/// `--json`: raw gateway JSON for one file, a JSON array of them for
/// several.
pub fn rag_ingest(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut paths: Vec<String> = Vec::new();
    let mut title: Option<String> = None;
    let mut recursive = false;
    let mut audience: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--title" | "-t" => title = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--recursive" | "-r" => recursive = true,
            "--audience" | "--role" => {
                audience.extend(parse_audience(iter.next().ok_or(Unhandled)?));
            }
            t if t.starts_with('-') => return Err(Unhandled),
            t => paths.push(t.to_string()),
        }
    }
    if paths.is_empty() {
        return Err(Unhandled);
    }

    // Expand, remembering which files the operator named and which we found,
    // because that is what decides whether a failure is fatal below.
    let mut files: Vec<(std::path::PathBuf, bool)> = Vec::new(); // (path, named)
    let mut any_dir = false;
    for raw in &paths {
        let path = std::path::Path::new(raw);
        if !path.exists() {
            // Python parity: "File not found: X", exit 1.
            fail(g.json, ExitCode::Generic, "file_not_found", &format!("File not found: {raw}"), None);
        }
        if path.is_dir() {
            any_dir = true;
            let mut found = Vec::new();
            expand_path(path, recursive, &mut found);
            if found.is_empty() {
                fail(
                    g.json,
                    ExitCode::Generic,
                    "no_text_files",
                    &format!("no text files in {raw}"),
                    Some(if recursive {
                        "looked for md/txt/html/json/yaml/csv and friends in the tree"
                    } else {
                        "looked one level deep — pass --recursive to descend"
                    }),
                );
            }
            files.extend(found.into_iter().map(|f| (f, false)));
        } else {
            files.push((path.to_path_buf(), true));
        }
    }
    if title.is_some() && (files.len() > 1 || any_dir) {
        fail(
            g.json,
            ExitCode::Generic,
            "title_with_multiple_files",
            "--title names a single document; pass one FILE with it",
            None,
        );
    }

    let total = files.len();
    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    for (i, (path, named)) in files.iter().enumerate() {
        let f = path.to_string_lossy().to_string();
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                let why = format!("cannot read {f} as UTF-8 text: {e}");
                if *named {
                    fail(
                        g.json,
                        ExitCode::Generic,
                        "file_unreadable",
                        &why,
                        Some("binary formats (PDF, …) have no working upload route on the current gateway — drop the file in a watched folder instead"),
                    );
                }
                if !g.json {
                    ui::warned(&format!("skipped {f} — not UTF-8 text"));
                }
                skipped.push((f, why));
                continue;
            }
        };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| f.clone());
        // Absolute-path provenance: docs.source_uri drives dedup, so
        // re-ingesting the same file updates instead of duplicating.
        let abs = std::fs::canonicalize(path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| f.clone());
        let body = ingest_body(
            &text,
            &title.clone().unwrap_or_else(|| name.clone()),
            &abs,
            &audience,
        );
        // Chunking + embedding is slow — Python parity: 120s.
        if !g.json {
            // The counter is the whole point of a bulk run: a folder of two
            // hundred notes is otherwise an unmoving cursor for ten minutes.
            if total > 1 {
                ui::step(&format!("[{}/{}] ingesting {name}", i + 1, total));
            } else {
                ui::step(&format!("ingesting {name}"));
            }
        }
        // Named files keep the exact old behaviour, gateway errors included:
        // continue-on-error is a property of a directory run, not of a long
        // one. That also keeps `--json`'s payload shape unchanged for every
        // invocation that was possible before this flag existed.
        let resp = if !any_dir {
            post_json(g, "/api/v1/rag/ingest", &body, true, 120)
        } else {
            match crate::http::post_json_try(g, "/api/v1/rag/ingest", &body, true, 120) {
                Ok(v) => v,
                Err(e) => {
                    if !g.json {
                        ui::warned(&format!("skipped {name} — {e}"));
                    }
                    skipped.push((f, e));
                    continue;
                }
            }
        };
        // A slow ingest is answered 202 with an operation handle (gateway
        // ops.rs): follow it, so "ingested" below means finished.
        let resp = match super::ops::settle(g, resp, &format!("ingesting {name}"), 150) {
            Ok(r) => r,
            Err(code) => {
                if !any_dir {
                    return Ok(code);
                }
                skipped.push((f, "the ingest operation did not finish".to_string()));
                continue;
            }
        };
        if !g.json {
            // The doc id is the captured value: plain, and all --quiet keeps.
            if let Some(note) = existing_note(&name, &resp) {
                ui::warned(&note);
            } else {
                ui::done(&format!("ingested {name}"));
            }
            ui::value(resp["doc_id"].as_str().unwrap_or("?"));
        }
        results.push(resp);
    }
    if !g.json {
        if total > 1 {
            println!();
            println!(
                "{}",
                ui::header(
                    "ingest",
                    Some(&format!("{} of {total} ingested{}", results.len(),
                        if skipped.is_empty() { String::new() }
                        else { format!(", {} skipped", skipped.len()) }))
                )
            );
        }
        ui::guide(&[
            ("noo rag docs", "lists every ingested document with its id"),
            ("noo rag query <question>", "asks the knowledge base, citing the new document when relevant"),
        ]);
    }
    if g.json {
        // Historical shapes, unchanged: one named file is its object, several
        // are an array. The `{ingested, skipped}` wrapper appears only for a
        // directory expansion — a mode that did not exist before, so no
        // existing caller's parse can break on it.
        if any_dir {
            println!(
                "{}",
                serde_json::json!({
                    "ingested": results,
                    "skipped": skipped.iter()
                        .map(|(f, e)| serde_json::json!({"path": f, "error": e}))
                        .collect::<Vec<_>>(),
                })
            );
        } else if results.len() == 1 {
            println!("{}", results[0]);
        } else {
            println!("{}", serde_json::Value::Array(results));
        }
    }
    // A partial run is not a success. The counts above say what landed.
    Ok(if skipped.is_empty() { 0 } else { 1 })
}

/// `noo rag scan [--source/-s folders|drives|all]` —
/// POST /api/v1/ingest/scan?source=… (native Rust route). Synchronous: each
/// scan cycle (download + ingest) completes before it returns, so a big
/// batch can take a while — Python parity 300s timeout. Idempotent
/// (source_uri dedup + content-hash backstop).
pub fn rag_scan(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut source = "all".to_string();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--source" | "-s" => source = iter.next().ok_or(Unhandled)?.clone(),
            _ => return Err(Unhandled),
        }
    }
    if !matches!(source.as_str(), "folders" | "drives" | "all") {
        // Python parity: validation error, exit 1.
        fail(
            g.json,
            ExitCode::Generic,
            "invalid_source",
            &format!("Invalid --source '{source}' — use folders, drives, or all"),
            None,
        );
    }
    let body = post_json(
        g,
        &format!("/api/v1/ingest/scan?source={}", urlencode(&source)),
        &serde_json::json!({}),
        true,
        300,
    );
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let results = body["results"].as_array().unwrap_or(&empty);
    if results.is_empty() {
        ui::failed("no results returned", None);
        return Ok(1);
    }
    println!("{}", ui::header("ingest scan", Some(&source)));
    for r in results {
        let src = r["source"].as_str().unwrap_or("?");
        println!("{}", ui::section(src));
        if let Some(skipped) = r["skipped_reason"].as_str() {
            println!("{}", ui::status_line(Glyph::Warn, &format!("{} — {skipped}", ui::state("skipped"))));
            continue;
        }
        let ingested = r["ingested"].as_array().unwrap_or(&empty);
        let backfilled = r["backfilled"].as_array().map(|a| a.len()).unwrap_or(0);
        let errors = r["errors"].as_array().unwrap_or(&empty);
        let mut summary = format!(
            "{} seen, {} new, {} ingested",
            r["seen"].as_u64().unwrap_or(0),
            r["new_count"].as_u64().unwrap_or(0),
            ingested.len(),
        );
        if backfilled > 0 {
            summary.push_str(&format!(", {backfilled} metadata-backfilled"));
        }
        if !errors.is_empty() {
            summary.push_str(&format!(", {} error(s)", errors.len()));
        }
        println!("{}", ui::status_line(if errors.is_empty() { Glyph::Ok } else { Glyph::Warn }, &summary));
        let rows: Vec<Vec<String>> = ingested
            .iter()
            .map(|entry| {
                // Entries are [file, doc_id] pairs (Python parity rendering).
                match entry.as_array() {
                    Some(pair) if pair.len() >= 2 => vec![
                        truncate(pair[0].as_str().unwrap_or("?"), 50),
                        ui::muted(&truncate(pair[1].as_str().unwrap_or(""), 16)),
                    ],
                    _ => vec![entry.to_string(), String::new()],
                }
            })
            .collect();
        if !rows.is_empty() {
            print!("{}", ui::table(&[Col::left("file"), Col::left("doc id")], &rows));
        }
        for err in errors {
            println!("{}", ui::status_line(Glyph::Err, err.as_str().unwrap_or(&err.to_string())));
        }
    }
    Ok(0)
}

/// Flags of `rag deduplicate`: `(dry_run, yes)`.
fn parse_dedup_flags(args: &[String]) -> Result<(bool, bool), Unhandled> {
    let (mut dry_run, mut yes) = (false, false);
    for tok in args {
        match tok.as_str() {
            "--dry-run" => dry_run = true,
            "--yes" | "-y" => yes = true,
            _ => return Err(Unhandled),
        }
    }
    Ok((dry_run, yes))
}

/// `noo rag deduplicate [--dry-run] [-y]` — POST /api/v1/rag/deduplicate.
/// Deletes duplicate (doc_id, page_no) pages, keeping the newest, so it asks
/// first (`-y` skips; no terminal and no `-y` refuses).
///
/// `--dry-run`: the worker's handler has no preview mode, so the CLI does not
/// pretend to count duplicates; it says what a run would do and sends nothing.
pub fn rag_deduplicate(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (dry_run, yes) = parse_dedup_flags(args)?;
    if dry_run {
        if g.json {
            println!(
                "{}",
                serde_json::json!({"dry_run": true, "would": "delete duplicate (doc_id, page_no) pages, keeping the newest", "sent": false})
            );
        } else {
            println!("{}", ui::header("rag deduplicate", Some(&ui::warn("dry-run"))));
            println!("{}", ui::muted("a run deletes duplicate (doc_id, page_no) pages and keeps the newest copy; nothing was sent"));
            ui::guide(&[("noo rag status", "page and document counts before you decide")]);
        }
        return Ok(0);
    }
    super::confirm_prompt(
        g,
        yes,
        "Delete duplicate (doc_id, page_no) pages from the RAG store, keeping the newest? This cannot be undone. Continue?",
    );
    let body = post_json(g, "/api/v1/rag/deduplicate", &serde_json::json!({}), true, 60);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let removed = body["removed"].as_u64().unwrap_or(0);
    if removed > 0 {
        ui::done(&format!("removed {removed} duplicate pages"));
    } else {
        ui::done("no duplicates found");
    }
    ui::guide(&[
        ("noo rag status", "page and document counts after the pass"),
        ("noo rag docs", "the documents that remain indexed"),
    ]);
    Ok(0)
}

/// Why an empty audience is refused (the gateway worker says the same).
const EMPTY_AUDIENCE: &str = "a document always has an audience; to make one admin-only use --role admin";

/// What a retag changes, one document per row: `from → to`.
fn retag_table(docs: &[serde_json::Value]) -> String {
    let rows: Vec<Vec<String>> = docs
        .iter()
        .map(|d| {
            vec![
                ui::muted(d["doc_id"].as_str().unwrap_or("")),
                truncate(d["title"].as_str().unwrap_or("(untitled)"), 40),
                roles_text(&d["from"]),
                format!("→ {}", roles_text(&d["to"])),
            ]
        })
        .collect();
    ui::table(&[Col::left("doc id"), Col::left("title"), Col::left("from"), Col::left("to")], &rows)
}

/// `noo rag retag` — change which audience a set of documents belongs to.
///
/// Exists because roles were written once, at ingest, and never again: an
/// empty `kb.default_roles` left every unmatched source untagged, and an
/// untagged document overlaps no audience, so only an unrestricted caller
/// could see it. Source rules change; "these went to the wrong team" has to
/// be fixable.
///
/// DRY RUN unless `--apply`. This moves documents between audiences, which
/// is an access-control change, and a mistyped glob should cost a printout
/// rather than a disclosure.
pub fn rag_retag(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut roles: Vec<String> = Vec::new();
    let mut doc_ids: Vec<String> = Vec::new();
    let mut matcher: Option<String> = None;
    let mut apply = false;
    let mut relabel = false;
    let mut limit: u64 = 1000;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--role" | "--roles" => {
                i += 1;
                let v = args.get(i).ok_or(Unhandled)?;
                roles.extend(v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
            }
            "--match" => {
                i += 1;
                matcher = Some(args.get(i).ok_or(Unhandled)?.clone());
            }
            "--doc-id" => {
                i += 1;
                doc_ids.push(args.get(i).ok_or(Unhandled)?.clone());
            }
            "--limit" => {
                i += 1;
                limit = args.get(i).ok_or(Unhandled)?.parse().map_err(|_| Unhandled)?;
            }
            // Opting IN to overwriting an audience somebody chose. Without
            // it only untagged documents are touched.
            "--relabel" => relabel = true,
            "--apply" => apply = true,
            // Clearing an audience is gone: it left the document untagged,
            // which a document never is. Kept as a flag only to say so.
            "--clear" => {
                ui::failed(EMPTY_AUDIENCE, Some("noo rag retag --doc-id <id> --role admin --relabel --apply"));
                return Ok(2);
            }
            _ => return Err(Unhandled),
        }
        i += 1;
    }

    if matcher.is_none() && doc_ids.is_empty() {
        ui::failed("give --match <glob> or --doc-id <id>; refusing to retag everything by omission", Some("noo rag retag --help"));
        return Ok(2);
    }

    if roles.is_empty() {
        ui::failed(EMPTY_AUDIENCE, Some("noo rag retag --doc-id <id> --role admin --relabel --apply"));
        return Ok(2);
    }

    let mut body = serde_json::json!({
        "roles": roles,
        "only_untagged": !relabel,
        "apply": apply,
        "limit": limit,
    });
    if let Some(m) = matcher {
        body["match"] = serde_json::json!(m);
    }
    if !doc_ids.is_empty() {
        body["doc_ids"] = serde_json::json!(doc_ids);
    }

    let out = post_json(g, "/api/v1/rag/retag", &body, true, 120);
    if g.json {
        println!("{out}");
        return Ok(0);
    }
    if let Some(err) = out["error"].as_str() {
        ui::failed(err, None);
        return Ok(1);
    }

    let matched = out["matched"].as_u64().unwrap_or(0);
    let applied = out["applied"].as_u64().unwrap_or(0);
    if let Some(docs) = out["documents"].as_array() {
        if !docs.is_empty() {
            print!("{}", retag_table(&docs[..docs.len().min(20)]));
            if docs.len() > 20 {
                println!("  … and {} more", docs.len() - 20);
            }
        }
    }
    if let Some(w) = out["warning"].as_str() {
        ui::warned(w);
    }
    if matched == 0 && !relabel {
        ui::warned("nothing matched; documents that already have an audience need --relabel");
    }
    if apply {
        ui::done(&format!("retagged {applied} of {matched} document(s)"));
    } else {
        ui::done(&format!(
            "{matched} document(s) would be retagged — re-run with --apply to write"
        ));
    }
    ui::guide(&[
        ("noo rag retag --match <glob> --role <r> --apply", "write the change"),
        ("noo security team list", "who can see a team: tier"),
    ]);
    Ok(0)
}

// ── document hold ────────────────────────────────────────────────────
//
// `hold` keeps a document and takes it out of embedding and search; `unhold`
// puts it back; `held` lists (and exports) what is held; `purge` DELETES the
// documents held under one reason. The order of use is hold, export and
// reconcile, then purge. Every write is a DRY RUN unless `--apply`.

/// The reason a hold carries when `--reason` is not given. `purge` needs the
/// same string back, so say it in the output rather than rely on memory.
const DEFAULT_HOLD_REASON: &str = "operator-hold";

/// How many IDs a dry run or an apply prints; the rest are in the export.
const SHOW_IDS: usize = 5;

/// Page size when `held --export` walks the whole list.
const EXPORT_PAGE: u64 = 5000;

#[derive(Debug, PartialEq, Eq, Default)]
struct HoldArgs {
    title_prefix: Option<String>,
    doc_ids: Vec<String>,
    reason: Option<String>,
    apply: bool,
}

/// Parse `--title-prefix <p> | --doc <id>... [--reason <r>] [--apply]`.
/// `Ok(Err(msg))` is a usage mistake worth a sentence; `Err(Unhandled)` is an
/// unknown flag (falls through to the usage text).
fn parse_hold_args(args: &[String], takes_reason: bool) -> Result<Result<HoldArgs, String>, Unhandled> {
    let mut a = HoldArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--title-prefix" => {
                i += 1;
                a.title_prefix = Some(args.get(i).ok_or(Unhandled)?.clone());
            }
            // `--doc a b c` and `--doc a --doc b` both work.
            "--doc" => {
                i += 1;
                let first = args.get(i).ok_or(Unhandled)?;
                a.doc_ids.push(first.clone());
                while args.get(i + 1).is_some_and(|n| !n.starts_with('-')) {
                    i += 1;
                    a.doc_ids.push(args[i].clone());
                }
            }
            "--reason" if takes_reason => {
                i += 1;
                a.reason = Some(args.get(i).ok_or(Unhandled)?.clone());
            }
            "--apply" => a.apply = true,
            _ => return Err(Unhandled),
        }
        i += 1;
    }
    Ok(match (&a.title_prefix, a.doc_ids.is_empty()) {
        (None, true) => Err("give --title-prefix <p> or --doc <id>; refusing to hold everything by omission".into()),
        (Some(_), false) => Err("give --title-prefix or --doc, not both".into()),
        (Some(p), _) if p.is_empty() => Err("--title-prefix must not be empty".into()),
        _ => Ok(a),
    })
}

fn hold_body(a: &HoldArgs, with_reason: bool) -> serde_json::Value {
    let mut body = serde_json::json!({ "apply": a.apply });
    if let Some(p) = &a.title_prefix {
        body["title_prefix"] = serde_json::json!(p);
    }
    if !a.doc_ids.is_empty() {
        body["doc_ids"] = serde_json::json!(a.doc_ids);
    }
    if with_reason {
        body["reason"] = serde_json::json!(a.reason.clone().unwrap_or_else(|| DEFAULT_HOLD_REASON.to_string()));
    }
    body
}

/// Print the count and the first few ids; say plainly when nothing changed.
fn print_hold_result(out: &serde_json::Value, verb_past: &str, verb_would: &str, apply: bool) {
    let count = out["count"].as_u64().unwrap_or(0);
    if let Some(ids) = out["doc_ids"].as_array() {
        for id in ids.iter().take(SHOW_IDS) {
            println!("  {}", ui::muted(id.as_str().unwrap_or("")));
        }
        if count as usize > ids.len().min(SHOW_IDS) {
            println!("  … and {} more", count as usize - ids.len().min(SHOW_IDS));
        }
    }
    if apply {
        ui::done(&format!("{verb_past} {count} document(s)"));
    } else {
        ui::warned(&format!(
            "dry run: nothing changed. {count} document(s) would be {verb_would}; re-run with --apply to write"
        ));
    }
}

fn hold_or_unhold(g: &Globals, args: &[String], hold: bool) -> Result<i32, Unhandled> {
    let a = match parse_hold_args(args, hold)? {
        Ok(a) => a,
        Err(msg) => {
            ui::failed(&msg, Some(if hold { "noo rag hold --help" } else { "noo rag unhold --help" }));
            return Ok(2);
        }
    };
    let path = if hold { "/api/v1/docs/hold" } else { "/api/v1/docs/unhold" };
    let out = post_json(g, path, &hold_body(&a, hold), true, 120);
    if g.json {
        println!("{out}");
        return Ok(0);
    }
    if let Some(err) = out["error"].as_str() {
        ui::failed(err, None);
        return Ok(1);
    }
    if hold {
        print_hold_result(&out, "held", "held", a.apply);
        let reason = a.reason.as_deref().unwrap_or(DEFAULT_HOLD_REASON);
        let next = hold_next_commands(&a, reason);
        if a.apply {
            ui::guide(&[
                (next.export.as_str(), "write every held id and title to a file to reconcile against"),
                (next.unhold.as_str(), "release them again"),
            ]);
            println!("  held under reason: {reason}");
        } else {
            ui::guide(&[(next.apply.as_str(), "write the hold")]);
        }
    } else {
        print_hold_result(&out, "released", "released", a.apply);
    }
    Ok(0)
}

/// The follow-up commands after a hold, spelled with the operator's own
/// selector and reason, quoted for the shell. The dry run's hint used to be
/// `noo rag hold --title-prefix <p> --apply`, with no reason: run as shown, it
/// filed the hold under the default reason, and a later
/// `noo rag purge --reason <the operator's reason>` matched nothing.
struct HoldNext {
    apply: String,
    export: String,
    unhold: String,
}

fn hold_next_commands(a: &HoldArgs, reason: &str) -> HoldNext {
    use super::enroll::sh_quote;
    let selector = match &a.title_prefix {
        Some(p) => format!("--title-prefix {}", sh_quote(p)),
        None => a.doc_ids.iter().map(|d| format!("--doc {}", sh_quote(d))).collect::<Vec<_>>().join(" "),
    };
    let r = sh_quote(reason);
    HoldNext {
        apply: format!("noo rag hold {selector} --reason {r} --apply"),
        export: format!("noo rag held --reason {r} --export held-{}.json", file_safe(reason)),
        unhold: format!("noo rag unhold {selector} --apply"),
    }
}

/// A reason as a file-name fragment: letters, digits and dashes.
fn file_safe(s: &str) -> String {
    let out: String = s.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).collect();
    let out = out.trim_matches('-').to_string();
    if out.is_empty() { "documents".into() } else { out }
}

/// `noo rag hold` — keep documents, out of embedding and search. Nothing is
/// deleted. Dry run unless `--apply`.
pub fn rag_hold(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    hold_or_unhold(g, args, true)
}

/// `noo rag unhold` — make held documents eligible for embedding and search
/// again. Dry run unless `--apply`.
pub fn rag_unhold(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    hold_or_unhold(g, args, false)
}

#[derive(Debug, PartialEq, Eq, Default)]
struct HeldArgs {
    reason: Option<String>,
    export: Option<String>,
}

fn parse_held_args(args: &[String]) -> Result<HeldArgs, Unhandled> {
    let mut a = HeldArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--reason" => {
                i += 1;
                a.reason = Some(args.get(i).ok_or(Unhandled)?.clone());
            }
            "--export" => {
                i += 1;
                a.export = Some(args.get(i).ok_or(Unhandled)?.clone());
            }
            _ => return Err(Unhandled),
        }
        i += 1;
    }
    Ok(a)
}

/// The export file: EVERY held id and title, for reconciliation.
fn export_document(reason: Option<&str>, total: u64, docs: &[serde_json::Value]) -> serde_json::Value {
    serde_json::json!({
        "reason": reason,
        "total": total,
        "count": docs.len(),
        "docs": docs.iter().map(|d| serde_json::json!({
            "doc_id": d["doc_id"],
            "title": d["title"],
            "reason": d["reason"],
            "held_at": d["held_at"],
        })).collect::<Vec<_>>(),
    })
}

fn held_path(reason: Option<&str>, limit: u64, offset: u64) -> String {
    let mut p = format!("/api/v1/docs/held?limit={limit}&offset={offset}");
    if let Some(r) = reason {
        p.push_str(&format!("&reason={}", urlencode(r)));
    }
    p
}

/// `noo rag held [--reason <r>] [--export <file.json>]` — list what is held;
/// `--export` writes ALL of it (ids and titles) to a file.
pub fn rag_held(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let a = parse_held_args(args)?;
    let reason = a.reason.as_deref();
    let limit = if a.export.is_some() { EXPORT_PAGE } else { 50 };
    let mut docs: Vec<serde_json::Value> = Vec::new();
    let mut total: u64;
    loop {
        let out = get_json(g, &held_path(reason, limit, docs.len() as u64), true, 60);
        if let Some(err) = out["error"].as_str() {
            ui::failed(err, None);
            return Ok(1);
        }
        total = out["total"].as_u64().unwrap_or(0);
        let page = out["docs"].as_array().cloned().unwrap_or_default();
        let got = page.len();
        docs.extend(page);
        // Only an export walks every page; a plain listing shows the first.
        if a.export.is_none() || got == 0 || docs.len() as u64 >= total {
            break;
        }
    }
    if let Some(file) = &a.export {
        let doc = export_document(reason, total, &docs);
        if let Err(e) = std::fs::write(file, serde_json::to_string_pretty(&doc).unwrap_or_default()) {
            ui::failed(&format!("cannot write {file}: {e}"), None);
            return Ok(1);
        }
        if docs.len() as u64 != total {
            ui::warned(&format!("exported {} of {total}: the list changed while it was read; re-run to be sure", docs.len()));
        }
        if g.json {
            println!("{}", serde_json::json!({"exported": docs.len(), "total": total, "file": file}));
        } else {
            ui::done(&format!("wrote {} held document(s) to {file}", docs.len()));
        }
        return Ok(0);
    }
    if g.json {
        println!("{}", serde_json::json!({"total": total, "docs": docs}));
        return Ok(0);
    }
    let rows: Vec<Vec<String>> = docs
        .iter()
        .map(|d| {
            vec![
                ui::muted(d["doc_id"].as_str().unwrap_or("")),
                truncate(d["title"].as_str().unwrap_or("(untitled)"), 50),
                d["reason"].as_str().unwrap_or("").to_string(),
                d["held_at"].as_str().unwrap_or("").chars().take(10).collect(),
            ]
        })
        .collect();
    print!("{}", ui::table(&[Col::left("doc id"), Col::left("title"), Col::left("reason"), Col::left("held")], &rows));
    ui::done(&format!("{total} held document(s)"));
    ui::guide(&[("noo rag held --reason <r> --export <file>", "write every held id and title to a file")]);
    Ok(0)
}

/// What a purge confirmation decided.
#[derive(Debug, PartialEq, Eq)]
enum PurgeConfirm {
    Proceed,
    /// `--json` without `-y`: never prompt.
    NeedsYesJson,
    /// Not a terminal and no `-y`: never block on a pipe.
    NeedsYesNoTty,
    /// A terminal, and the typed text is wanted; ask for it.
    Ask,
    Aborted,
}

/// The rule, pure so it can be pinned: `-y` skips the prompt; otherwise a
/// terminal is required and the operator must type the count back.
fn purge_confirmation(yes: bool, json: bool, tty: bool, typed: Option<&str>, count: u64) -> PurgeConfirm {
    if yes {
        return PurgeConfirm::Proceed;
    }
    if json {
        return PurgeConfirm::NeedsYesJson;
    }
    if !tty {
        return PurgeConfirm::NeedsYesNoTty;
    }
    match typed {
        None => PurgeConfirm::Ask,
        Some(t) if t.trim() == count.to_string() => PurgeConfirm::Proceed,
        Some(_) => PurgeConfirm::Aborted,
    }
}

#[derive(Debug, PartialEq, Eq, Default)]
struct PurgeArgs {
    reason: Option<String>,
    apply: bool,
    yes: bool,
}

fn parse_purge_args(args: &[String]) -> Result<PurgeArgs, Unhandled> {
    let mut a = PurgeArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--reason" => {
                i += 1;
                a.reason = Some(args.get(i).ok_or(Unhandled)?.clone());
            }
            "--apply" => a.apply = true,
            "-y" | "--yes" => a.yes = true,
            _ => return Err(Unhandled),
        }
        i += 1;
    }
    Ok(a)
}

/// `noo rag purge --reason <r> [--apply] [-y]` — DELETE the documents held
/// under exactly that reason, with their pages, chunks, embeddings and
/// mentions. IRREVERSIBLE. Dry run unless `--apply`; on a terminal `--apply`
/// asks for the count typed back unless `-y`. Hold first, export and
/// reconcile, then purge.
pub fn rag_purge(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    use std::io::{BufRead as _, IsTerminal as _, Write as _};
    let a = parse_purge_args(args)?;
    let reason = match a.reason.as_deref().map(str::trim) {
        Some(r) if !r.is_empty() => r.to_string(),
        _ => {
            ui::failed(
                "give --reason <r>, the reason the documents were held under; there is no purge-everything-held",
                Some("noo rag held --export <file>"),
            );
            return Ok(2);
        }
    };
    let call = |apply: bool| {
        post_json(g, "/api/v1/docs/purge", &serde_json::json!({"reason": reason, "apply": apply}), true, 900)
    };
    // Always look first: the count is what the operator confirms.
    let preview = call(false);
    if let Some(err) = preview["error"].as_str() {
        if g.json {
            println!("{preview}");
        } else {
            ui::failed(err, None);
        }
        return Ok(1);
    }
    let count = preview["count"].as_u64().unwrap_or(0);
    if !a.apply {
        if g.json {
            println!("{preview}");
            return Ok(0);
        }
        print_hold_result(&preview, "deleted", "deleted", false);
        ui::warned("purge is irreversible; the documents, pages, chunks and embeddings go");
        ui::guide(&[
            ("noo rag held --reason <r> --export <file>", "export the ids and titles to reconcile against first"),
            ("noo rag purge --reason <r> --apply", "delete them"),
        ]);
        return Ok(0);
    }
    if count == 0 {
        if g.json {
            println!("{preview}");
        } else {
            ui::done(&format!("nothing is held under reason {reason:?}; nothing to delete"));
        }
        return Ok(0);
    }
    if !g.json {
        ui::warned(&format!("about to DELETE {count} document(s) held under {reason:?}; this cannot be undone"));
        ui::guide(&[("noo rag held --reason <r> --export <file>", "export the ids and titles first, if you have not")]);
    }
    let tty = std::io::stdin().is_terminal();
    let mut decision = purge_confirmation(a.yes, g.json, tty, None, count);
    if decision == PurgeConfirm::Ask {
        eprint!("type {count} to delete {count} document(s): ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        decision = purge_confirmation(a.yes, g.json, tty, Some(&line), count);
    }
    match decision {
        PurgeConfirm::Proceed => {}
        PurgeConfirm::NeedsYesJson => fail(
            true,
            ExitCode::Generic,
            "confirmation_required",
            "confirmation required: pass --yes",
            Some("refusing to prompt in --json mode"),
        ),
        PurgeConfirm::NeedsYesNoTty => fail(
            false,
            ExitCode::Generic,
            "confirmation_required",
            "confirmation required: pass --yes (stdin is not a TTY; refusing to block on the count prompt)",
            Some("agents and pipes must confirm destructive commands explicitly with --yes/-y"),
        ),
        PurgeConfirm::Ask | PurgeConfirm::Aborted => {
            eprintln!("Aborted. Nothing was deleted.");
            return Ok(1);
        }
    }
    let out = call(true);
    if g.json {
        println!("{out}");
        return Ok(0);
    }
    if let Some(err) = out["error"].as_str() {
        ui::failed(err, None);
        return Ok(1);
    }
    ui::done(&format!("deleted {} of {count} document(s)", out["deleted"].as_u64().unwrap_or(0)));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_flags_parse_dry_run_and_yes() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(parse_dedup_flags(&a(&[])).unwrap(), (false, false));
        assert_eq!(parse_dedup_flags(&a(&["--dry-run"])).unwrap(), (true, false));
        assert_eq!(parse_dedup_flags(&a(&["-y"])).unwrap(), (false, true));
        assert!(parse_dedup_flags(&a(&["--apply"])).is_err());
    }

    fn touch(dir: &std::path::Path, name: &str) {
        std::fs::write(dir.join(name), "x").unwrap();
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("noo-rag-ingest-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn audience_is_sent_as_roles_and_absent_when_not_asked() {
        assert_eq!(parse_audience("company, team:eng,,"), vec!["company", "team:eng"]);
        let b = ingest_body("t", "T", "/a/b.md", &parse_audience("company,team:eng"));
        assert_eq!(b["roles"], serde_json::json!(["company", "team:eng"]));
        assert_eq!(b["source_uri"], "file:///a/b.md");
        // No flag: no key at all, so the gateway default (the uploader) applies.
        let b = ingest_body("t", "T", "/a/b.md", &[]);
        assert!(b.get("roles").is_none());
    }

    /// A directory expansion must take the text files and leave everything
    /// else. The gateway ingests `text`, so a walk that swept up a `.png`
    /// would read its bytes and only discover the problem afterwards.
    #[test]
    fn expansion_takes_text_and_leaves_the_rest() {
        let d = tmp("filter");
        for f in ["a.md", "b.txt", "c.html", "d.png", "e.sqlite", "noext"] {
            touch(&d, f);
        }
        let mut out = Vec::new();
        expand_path(&d, false, &mut out);
        let names: Vec<String> =
            out.iter().map(|p| p.file_name().unwrap().to_string_lossy().to_string()).collect();
        assert_eq!(names, vec!["a.md", "b.txt", "c.html"]);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Sorted, because a demo is a recording: two runs over the same folder
    /// must ingest in the same order or the second take does not match the
    /// first. `read_dir` order is the filesystem's, not the operator's.
    #[test]
    fn expansion_is_sorted() {
        let d = tmp("sorted");
        for f in ["z.md", "a.md", "m.md"] {
            touch(&d, f);
        }
        let mut out = Vec::new();
        expand_path(&d, false, &mut out);
        let names: Vec<String> =
            out.iter().map(|p| p.file_name().unwrap().to_string_lossy().to_string()).collect();
        assert_eq!(names, vec!["a.md", "m.md", "z.md"]);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Without `--recursive` a directory is one level. A notes folder with a
    /// `.git` or an `attachments/` in it should not silently become a
    /// different, much larger ingest than the operator watched themselves ask
    /// for.
    #[test]
    fn recursion_is_opt_in() {
        let d = tmp("recurse");
        touch(&d, "top.md");
        let sub = d.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        touch(&sub, "deep.md");

        let mut shallow = Vec::new();
        expand_path(&d, false, &mut shallow);
        assert_eq!(shallow.len(), 1, "one level by default");

        let mut deep = Vec::new();
        expand_path(&d, true, &mut deep);
        assert_eq!(deep.len(), 2, "--recursive descends");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// A named file is itself whatever its extension: naming it is the
    /// operator saying they meant it, and the filter exists only to make a
    /// directory walk safe.
    #[test]
    fn a_named_file_bypasses_the_extension_filter() {
        let d = tmp("named");
        touch(&d, "notes.weird");
        let mut out = Vec::new();
        expand_path(&d.join("notes.weird"), false, &mut out);
        assert_eq!(out.len(), 1);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn an_already_stored_ingest_says_so_and_a_new_one_does_not() {
        let dup = serde_json::json!({"doc_id": "d", "existing": true, "audience_unchanged": true});
        let note = existing_note("a.md", &dup).unwrap();
        assert!(note.contains("already in the knowledge base") && note.contains("audience is unchanged"));
        assert!(existing_note("a.md", &serde_json::json!({"doc_id": "d"})).is_none());
        // a restricted caller never receives the flag, so never sees the note
        assert!(existing_note("a.md", &serde_json::json!({"doc_id": "d", "existing": false})).is_none());
    }

    // ── the review view ───────────────────────────────

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn docs_flags_parse() {
        let a = DocsArgs::parse(&args(&["--untagged", "--audience", "user:*", "--match", "gdrive://*", "--title", "plan", "--limit", "5"])).unwrap();
        assert_eq!(
            a,
            DocsArgs {
                untagged: true,
                audience: Some("user:*".into()),
                source_glob: Some("gdrive://*".into()),
                title: Some("plan".into()),
                limit: Some(5),
            }
        );
        assert!(a.filtered());
        assert_eq!(DocsArgs::parse(&[]).unwrap(), DocsArgs::default());
        assert!(!DocsArgs::default().filtered());
        for bad in [&["--nope"][..], &["--audience"], &["--limit", "0"], &["--limit", "x"], &["stray"]] {
            assert!(DocsArgs::parse(&args(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn docs_path_encodes_filters_and_asks_for_the_summary_once() {
        let a = DocsArgs::parse(&args(&["--audience", "user:*", "--match", "gdrive://a b*", "--title", "100%", "--untagged"])).unwrap();
        let p = a.path(500, 0, true);
        assert_eq!(
            p,
            "/api/v1/docs?limit=500&offset=0&summary=1&untagged=1&audience=user%3A%2A&match=gdrive%3A%2F%2Fa%20b%2A&q=100%25"
        );
        assert!(!a.path(500, 500, false).contains("summary"));
    }

    fn fake_server(total: usize) -> impl FnMut(&str) -> serde_json::Value {
        move |path: &str| {
            let num = |k: &str| -> usize {
                path.split(['?', '&']).find_map(|kv| kv.strip_prefix(&format!("{k}="))).unwrap().parse().unwrap()
            };
            let (limit, offset) = (num("limit"), num("offset"));
            let docs: Vec<_> = (offset..total.min(offset + limit))
                .map(|i| serde_json::json!({"doc_id": format!("d{i}"), "title": format!("t{i}"), "roles": ["admin"]}))
                .collect();
            if path.contains("summary=1") {
                serde_json::json!({"docs": docs, "summary": {"total": total, "untagged": 0, "by_audience": {"admin": total}}})
            } else {
                serde_json::json!(docs)
            }
        }
    }

    #[test]
    fn docs_pages_through_all_of_them_and_keeps_the_first_summary() {
        let (docs, summary) = collect_docs(&DocsArgs::default(), fake_server(1203));
        assert_eq!(docs.len(), 1203, "every document, not just the first page");
        assert_eq!(docs[0]["doc_id"], "d0");
        assert_eq!(docs[1202]["doc_id"], "d1202");
        assert_eq!(summary.unwrap()["total"], 1203);
        // An exact multiple of the page size ends on an empty page, not a loop.
        assert_eq!(collect_docs(&DocsArgs::default(), fake_server(1000)).0.len(), 1000);
        assert_eq!(collect_docs(&DocsArgs::default(), fake_server(0)).0.len(), 0);
    }

    #[test]
    fn docs_limit_stops_early() {
        let want = DocsArgs { limit: Some(620), ..DocsArgs::default() };
        let mut seen = Vec::new();
        let mut inner = fake_server(5000);
        let (docs, _) = collect_docs(&want, |p| {
            seen.push(p.to_string());
            inner(p)
        });
        assert_eq!(docs.len(), 620);
        assert_eq!(seen.len(), 2, "500 then 120");
        assert!(seen[1].starts_with("/api/v1/docs?limit=120&offset=500"));
    }

    #[test]
    fn summary_line_reads_like_the_example() {
        let s = serde_json::json!({"total": 269, "untagged": 0,
            "by_audience": {"company": 39, "admin": 150, "user:*": 80}});
        assert_eq!(summary_line(&s, false), "269 documents · 0 untagged · admin 150 · user:* 80 · company 39");
        assert!(summary_line(&s, true).starts_with("269 matching documents"));
        let empty = serde_json::json!({"total": 0, "untagged": 0, "by_audience": {}});
        assert_eq!(summary_line(&empty, false), "0 documents · 0 untagged");
    }

    fn sample_docs() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({"doc_id": "11111111-1111-1111-1111-111111111111", "title": "Q3 budget",
                "source_uri": "file:///home/alice/q3.md", "created_at": "2026-10-01T12:00:00+00:00",
                "roles": ["user:alice", "team:ops"],
                "provenance": {"by": "alice", "via": "cli", "at": "2026-10-01T12:00:00+00:00"},
                "audience_history_len": 2}),
            serde_json::json!({"doc_id": "22222222-2222-2222-2222-222222222222", "title": "Daily report",
                "source_uri": "heartbeat://t1/r9", "created_at": "2026-09-30T06:00:00+00:00",
                "roles": ["admin"], "provenance": {"by": null, "via": "heartbeat", "at": "x"},
                "audience_history_len": 0}),
            serde_json::json!({"doc_id": "33333333-3333-3333-3333-333333333333", "title": "Old note",
                "source_uri": "gdrive://abc", "created_at": "2026-01-02T00:00:00+00:00",
                "roles": null, "provenance": null, "audience_history_len": 0}),
        ]
    }

    #[test]
    fn docs_table_shows_the_real_audience_ingest_path_and_unknowns() {
        let t = docs_table(&sample_docs());
        eprintln!("{t}");
        for want in [
            "AUDIENCE", "SOURCE", "INGESTED", "CREATED", "EDITS",
            "user:alice,team:ops", // the real value, never `user:*`
            "cli/alice", "heartbeat", "unknown", "untagged",
            "2026-10-01", "file:///", "11111111-1111-1111-1111-111111111111",
        ] {
            assert!(t.contains(want), "missing {want:?} in:\n{t}");
        }
        assert!(!t.contains("user:*"));
    }

    #[test]
    fn a_restricted_caller_gets_no_audience_column_values() {
        let d = serde_json::json!({"doc_id": "x", "title": "t", "source_uri": "u", "created_at": "2026-10-01T00:00:00+00:00"});
        assert_eq!(audience_cell(&d), "");
        assert_eq!(ingested_cell(&d), ui::muted("unknown"));
    }

    #[test]
    fn doc_detail_renders_audience_provenance_history_and_preview() {
        let d = serde_json::json!({"doc_id": "11111111-1111-1111-1111-111111111111", "title": "Q3 budget",
            "source_uri": "file:///q3.md", "created_at": "2026-10-01T12:00:00+00:00", "page_count": 3,
            "roles": ["user:alice"], "provenance": {"by": "alice", "via": "cli", "at": "2026-10-01T12:00:00+00:00"},
            "audience_history": [{"at": "2026-10-02T09:30:00+00:00", "by": "root", "from": ["admin"], "to": ["user:alice"]}],
            "text_preview": "line one\nline two"});
        let out = render_doc(&d);
        for want in ["Q3 budget", "user:alice", "cli by alice", "2026-10-01 12:00", "admin → user:alice", "root", "line one", "line two", "Audience History", "Preview"] {
            assert!(out.contains(want), "missing {want:?} in:\n{out}");
        }
        // A document from before provenance, never retagged.
        let old = serde_json::json!({"doc_id": "x", "title": "T", "roles": ["admin"], "provenance": null,
            "audience_history": [], "page_count": 0, "text_preview": null});
        let out = render_doc(&old);
        assert!(out.contains("unknown") && out.contains("never changed") && out.contains("no text stored"), "{out}");
    }

    #[test]
    fn retag_table_shows_from_and_to_per_document() {
        let t = retag_table(&[
            serde_json::json!({"doc_id": "d1", "title": "A", "from": [], "to": ["user:alice"]}),
            serde_json::json!({"doc_id": "d2", "title": "B", "from": ["admin"], "to": ["user:alice", "team:ops"]}),
        ]);
        assert!(t.contains("untagged") && t.contains("→ user:alice"), "{t}");
        assert!(t.contains("admin") && t.contains("→ user:alice, team:ops"), "{t}");
    }

    fn quiet_globals() -> Globals {
        Globals { json: false, verbose: false, gateway_override: None, timeout_secs: None, token: None, quiet: false }
    }

    /// An empty audience is refused BEFORE any request (these never reach a
    /// gateway: the test would hang or fail on connect if they did).
    #[test]
    fn retag_refuses_an_empty_audience_and_clear_without_a_request() {
        let g = quiet_globals();
        // no --role at all
        assert_eq!(rag_retag(&g, &args(&["--doc-id", "x"])).ok(), Some(2));
        // --role given only blanks
        assert_eq!(rag_retag(&g, &args(&["--doc-id", "x", "--role", " , "])).ok(), Some(2));
        // --clear is refused, wherever it sits
        assert_eq!(rag_retag(&g, &args(&["--doc-id", "x", "--role", "admin", "--clear"])).ok(), Some(2));
        assert_eq!(rag_retag(&g, &args(&["--clear", "--match", "*"])).ok(), Some(2));
        assert!(EMPTY_AUDIENCE.contains("use --role admin") && EMPTY_AUDIENCE.contains("always has an audience"));
    }

    // ── document hold ────────────────────────────────────────────────

    #[test]
    fn the_dry_run_hint_carries_the_operators_reason_and_selector() {
        // Run as shown, the old hint held under the DEFAULT reason, and a
        // purge by the operator's reason then matched nothing (live, 2026-10-09).
        let a = super::HoldArgs {
            title_prefix: Some("pai-trading / retrieval /".into()),
            reason: Some("retrieval-receipts".into()),
            ..Default::default()
        };
        let next = super::hold_next_commands(&a, "retrieval-receipts");
        assert_eq!(next.apply, "noo rag hold --title-prefix 'pai-trading / retrieval /' --reason 'retrieval-receipts' --apply");
        assert_eq!(next.export, "noo rag held --reason 'retrieval-receipts' --export held-retrieval-receipts.json");
        assert_eq!(next.unhold, "noo rag unhold --title-prefix 'pai-trading / retrieval /' --apply");
        let ids = super::HoldArgs { doc_ids: vec!["a1".into(), "b2".into()], ..Default::default() };
        let n = super::hold_next_commands(&ids, "operator-hold");
        assert_eq!(n.apply, "noo rag hold --doc 'a1' --doc 'b2' --reason 'operator-hold' --apply");
        assert_eq!(super::file_safe("x/y z!"), "x-y-z");
        assert_eq!(super::file_safe("//"), "documents");
    }

    #[test]
    fn hold_flags_parse_and_a_selector_is_required() {
        let a = parse_hold_args(&args(&["--title-prefix", "pai-trading / retrieval /", "--reason", "r1", "--apply"]), true)
            .ok()
            .unwrap()
            .unwrap();
        assert_eq!(a.title_prefix.as_deref(), Some("pai-trading / retrieval /"));
        assert_eq!(a.reason.as_deref(), Some("r1"));
        assert!(a.apply);
        // ids: repeated and trailing forms both work
        let a = parse_hold_args(&args(&["--doc", "a", "b", "--doc", "c"]), true).ok().unwrap().unwrap();
        assert_eq!(a.doc_ids, vec!["a", "b", "c"]);
        assert!(!a.apply, "dry run is the default");
        // no selector, or both: a sentence, not a request
        assert!(parse_hold_args(&args(&["--apply"]), true).ok().unwrap().is_err());
        assert!(parse_hold_args(&args(&["--doc", "a", "--title-prefix", "x"]), true).ok().unwrap().is_err());
        assert!(parse_hold_args(&args(&["--title-prefix", ""]), true).ok().unwrap().is_err());
        // unhold takes no --reason; unknown flags fall through
        assert!(parse_hold_args(&args(&["--doc", "a", "--reason", "r"]), false).is_err());
        assert!(parse_hold_args(&args(&["--bogus"]), true).is_err());
    }

    #[test]
    fn hold_body_is_a_dry_run_by_default_and_carries_a_reason() {
        let a = parse_hold_args(&args(&["--doc", "a"]), true).ok().unwrap().unwrap();
        let b = hold_body(&a, true);
        assert_eq!(b["apply"], false);
        assert_eq!(b["reason"], DEFAULT_HOLD_REASON);
        assert_eq!(b["doc_ids"], serde_json::json!(["a"]));
        assert!(b.get("title_prefix").is_none());
        let a = parse_hold_args(&args(&["--title-prefix", "p", "--apply"]), false).ok().unwrap().unwrap();
        let b = hold_body(&a, false);
        assert_eq!(b["apply"], true);
        assert!(b.get("reason").is_none());
    }

    #[test]
    fn hold_without_a_selector_is_refused_before_any_request() {
        let g = quiet_globals();
        assert_eq!(rag_hold(&g, &args(&["--apply"])).ok(), Some(2));
        assert_eq!(rag_unhold(&g, &args(&[])).ok(), Some(2));
        assert_eq!(rag_purge(&g, &args(&["--apply"])).ok(), Some(2));
        assert_eq!(rag_purge(&g, &args(&["--reason", "  ", "--apply"])).ok(), Some(2));
    }

    #[test]
    fn held_flags_and_the_export_file_shape() {
        let a = parse_held_args(&args(&["--reason", "r", "--export", "/tmp/x.json"])).ok().unwrap();
        assert_eq!((a.reason.as_deref(), a.export.as_deref()), (Some("r"), Some("/tmp/x.json")));
        assert!(parse_held_args(&args(&["--nope"])).is_err());
        assert_eq!(held_path(Some("a b"), 10, 20), "/api/v1/docs/held?limit=10&offset=20&reason=a%20b");
        let docs = vec![
            serde_json::json!({"doc_id": "d1", "title": "pai-trading / retrieval / u1", "reason": "r", "held_at": "2026-10-08T00:00:00+00:00", "extra": 1}),
            serde_json::json!({"doc_id": "d2", "title": "t2", "reason": "r", "held_at": null}),
        ];
        let e = export_document(Some("r"), 2, &docs);
        assert_eq!(e["total"], 2);
        assert_eq!(e["count"], 2);
        assert_eq!(e["reason"], "r");
        assert_eq!(e["docs"][0]["doc_id"], "d1");
        assert_eq!(e["docs"][0]["title"], "pai-trading / retrieval / u1");
        assert!(e["docs"][0].get("extra").is_none(), "only the reconciliation fields are exported");
        assert_eq!(e["docs"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn purge_flags_parse() {
        let a = parse_purge_args(&args(&["--reason", "r", "--apply", "-y"])).ok().unwrap();
        assert_eq!((a.reason.as_deref(), a.apply, a.yes), (Some("r"), true, true));
        let a = parse_purge_args(&args(&["--reason", "r"])).ok().unwrap();
        assert!(!a.apply && !a.yes, "dry run is the default");
        assert!(parse_purge_args(&args(&["--all"])).is_err());
    }

    #[test]
    fn purge_confirmation_cannot_be_skipped_without_yes_on_a_tty() {
        use PurgeConfirm::*;
        // -y is the only way past the prompt
        assert_eq!(purge_confirmation(true, false, true, None, 7), Proceed);
        assert_eq!(purge_confirmation(true, true, false, None, 7), Proceed);
        // a terminal without -y must ask, and only the count satisfies it
        assert_eq!(purge_confirmation(false, false, true, None, 7), Ask);
        assert_eq!(purge_confirmation(false, false, true, Some("7\n"), 7), Proceed);
        assert_eq!(purge_confirmation(false, false, true, Some("y"), 7), Aborted);
        assert_eq!(purge_confirmation(false, false, true, Some("yes"), 7), Aborted);
        assert_eq!(purge_confirmation(false, false, true, Some(""), 7), Aborted);
        assert_eq!(purge_confirmation(false, false, true, Some("8"), 7), Aborted);
        // a pipe or --json never blocks and never proceeds
        assert_eq!(purge_confirmation(false, false, false, None, 7), NeedsYesNoTty);
        assert_eq!(purge_confirmation(false, true, true, None, 7), NeedsYesJson);
    }
}
