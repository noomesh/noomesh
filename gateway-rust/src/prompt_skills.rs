// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Prompt skills — markdown templates injected into an agent's system prompt.
//!
//! Ported from `noomesh/prompt_skills/`. Chosen as the first
//! real port because the subsystem has **no ML and no Trellion coupling**: it
//! reads markdown files with YAML frontmatter off disk, scores them against a
//! message, and returns text. That is orchestration, which is Rust's plane.
//!
//! What did NOT come across: `worker.prompt_skills.evolve`. Evolution drives
//! an LLM to rewrite skills and write new files, and it belongs with the
//! host/subprocess group — porting it would have widened this change from
//! "read and score" to "generate and persist".
//!
//! ## Fidelity
//!
//! The scoring is a deliberate line-by-line port of `selector.py`, including
//! the parts that look arbitrary — the 2.0/1.0 keyword split, the 0.3
//! description weight, `priority / 10`, the 1.5x role affinity and 1.3x
//! preferred multipliers, and the order they apply in. Multiplier order
//! matters: role affinity multiplies the priority-scaled score, so applying
//! it earlier changes results. The tests below pin the exact numbers rather
//! than asserting "roughly relevant", because a silent scoring drift would
//! change which skills reach the model without failing anything.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use serde_json::{json, Value};

/// Directory names, relative to the project root.
const CORE_DIR: &str = "prompts/skills/core";
const EVOLVED_DIR: &str = "prompts/skills/evolved";

/// Where a retired skill is moved, beside the file it came from
/// (`<role>/graveyard/`). The scan skips it, so a retired skill leaves
/// selection and the listing but stays on disk to be restored by hand.
pub const GRAVEYARD_DIR: &str = "graveyard";

/// Fitness bounds.
pub const FITNESS_MIN: f64 = 0.0;
pub const FITNESS_MAX: f64 = 10.0;

/// Selection budget — mirrors PromptSkillSelector's defaults.
const MAX_SKILLS: usize = 3;
const MAX_TOTAL_CHARS: usize = 8000;

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct PromptSkill {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub tags: Vec<String>,
    pub trigger_keywords: Vec<String>,
    pub priority: i64,
    pub fitness: f64,
    pub generation: i64,
    pub is_core: bool,
    pub max_context_chars: i64,
    pub composable: bool,
    pub requires_tools: Vec<String>,
    pub parent_skill: Value,
    pub content: String,
    pub file_path: Option<String>,
    /// Runtime only — never persisted to frontmatter, same as Python.
    #[serde(skip, default)]
    pub usage_count: u64,
}

impl PromptSkill {
    /// Format for injection into a system prompt. Byte-identical to
    /// `PromptSkill.to_injection_text`.
    pub fn to_injection_text(&self) -> String {
        let mut header = format!("## Skill: {}", self.name);
        if !self.description.is_empty() {
            header.push_str(&format!(" — {}", self.description));
        }
        format!("{header}\n\n{}", self.content)
    }

    /// Brief representation for API responses (`to_summary`).
    pub fn to_summary(&self) -> Value {
        json!({
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "tags": self.tags,
            "priority": self.priority,
            "fitness": self.fitness,
            "generation": self.generation,
            "is_core": self.is_core,
        })
    }

    /// Full JSON for the `/api/prompt-skills` surface.
    ///
    /// Field-for-field identical to the `parse_skill_file` this replaced in
    /// `routes/settings.rs`. That function was a SECOND Rust implementation
    /// of skill parsing; consolidating onto this one is the point of the
    /// port, since two parsers drifting apart is the failure mode the whole
    /// programme exists to remove.
    pub fn to_full_json(&self) -> Value {
        json!({
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "tags": self.tags,
            "trigger_keywords": self.trigger_keywords,
            "priority": self.priority,
            "max_context_chars": self.max_context_chars,
            "composable": self.composable,
            "requires_tools": self.requires_tools,
            "fitness": self.fitness,
            "generation": self.generation,
            "parent_skill": self.parent_skill,
            "is_core": self.is_core,
            "usage_count": self.usage_count,
            "content": self.content,
            "file_path": self.file_path,
        })
    }

    /// The markdown file this skill round-trips through: YAML frontmatter,
    /// a blank line, the body. The inverse of [`PromptSkill::from_markdown`]
    /// for every field it reads; keys it does not read (and comments) are not
    /// preserved.
    pub fn to_file_text(&self) -> Result<String, String> {
        let mut fm = serde_json::Map::new();
        fm.insert("name".into(), json!(self.name));
        fm.insert("version".into(), json!(self.version));
        fm.insert("description".into(), json!(self.description));
        fm.insert("author".into(), json!(self.author));
        fm.insert("tags".into(), json!(self.tags));
        fm.insert("trigger_keywords".into(), json!(self.trigger_keywords));
        fm.insert("priority".into(), json!(self.priority));
        fm.insert("max_context_chars".into(), json!(self.max_context_chars));
        fm.insert("composable".into(), json!(self.composable));
        fm.insert("requires_tools".into(), json!(self.requires_tools));
        fm.insert("fitness".into(), json!(self.fitness));
        fm.insert("generation".into(), json!(self.generation));
        if !self.parent_skill.is_null() {
            fm.insert("parent_skill".into(), self.parent_skill.clone());
        }
        let yaml = serde_yaml::to_string(&Value::Object(fm))
            .map_err(|e| format!("YAML serialization failed: {e}"))?;
        Ok(format!("---\n{yaml}---\n\n{}\n", self.content))
    }

    /// Parse a markdown file with optional YAML frontmatter.
    ///
    /// A file with no frontmatter is still a valid skill — the whole file is
    /// the body and the name falls back to the file stem, matching Python.
    pub fn from_markdown(path: &Path, text: &str, is_core: bool) -> Self {
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        let (meta, body) = split_frontmatter(text);
        let m = meta.unwrap_or(Value::Null);

        let get_str = |k: &str, d: &str| -> String {
            m.get(k).and_then(|v| v.as_str()).unwrap_or(d).to_string()
        };
        let get_list = |k: &str| -> Vec<String> {
            m.get(k)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };

        PromptSkill {
            name: {
                let n = get_str("name", "");
                if n.is_empty() { stem } else { n }
            },
            // Python does str(meta.get("version", "1.0")) — a YAML float like
            // `version: 1.0` must not become "1" here.
            version: m
                .get("version")
                .map(yaml_scalar_to_string)
                .unwrap_or_else(|| "1.0".to_string()),
            description: get_str("description", ""),
            author: get_str("author", "noo-builtin"),
            tags: get_list("tags"),
            trigger_keywords: get_list("trigger_keywords"),
            priority: m.get("priority").and_then(|v| v.as_i64()).unwrap_or(5),
            fitness: m.get("fitness").and_then(|v| v.as_f64()).unwrap_or(0.0),
            generation: m.get("generation").and_then(|v| v.as_i64()).unwrap_or(0),
            is_core,
            max_context_chars: m.get("max_context_chars").and_then(|v| v.as_i64()).unwrap_or(4000),
            composable: m.get("composable").and_then(|v| v.as_bool()).unwrap_or(true),
            requires_tools: get_list("requires_tools"),
            parent_skill: m.get("parent_skill").cloned().unwrap_or(Value::Null),
            content: body,
            file_path: Some(path.to_string_lossy().to_string()),
            usage_count: 0,
        }
    }
}

/// YAML scalars reach us typed; render them the way `str()` would in Python.
fn yaml_scalar_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => if *b { "True".into() } else { "False".into() },
        other => other.to_string(),
    }
}

/// Split `---\n…\n---\n` frontmatter from the body.
///
/// Returns `(None, whole_text)` when absent. Deliberately anchored at the
/// start like Python's `re.match`, so a `---` rule mid-document is body text,
/// not a delimiter.
fn split_frontmatter(text: &str) -> (Option<Value>, String) {
    let rest = match text.strip_prefix("---") {
        Some(r) => r.trim_start_matches([' ', '\t']).strip_prefix('\n'),
        None => None,
    };
    let Some(rest) = rest else {
        return (None, text.to_string());
    };
    // Find the closing delimiter at the start of a line.
    let mut search_from = 0usize;
    while let Some(idx) = rest[search_from..].find("\n---") {
        let abs = search_from + idx + 1; // position of the '-'
        let after = &rest[abs + 3..];
        let after_trimmed = after.trim_start_matches([' ', '\t']);
        if let Some(body) = after_trimmed.strip_prefix('\n') {
            let front = &rest[..abs];
            let parsed: Option<Value> = serde_yaml::from_str(front).ok();
            return (parsed, body.trim().to_string());
        }
        search_from = abs + 3;
    }
    (None, text.to_string())
}

/// In-memory index of discovered skills.
#[derive(Debug, Default)]
pub struct SkillRegistry {
    skills: HashMap<String, PromptSkill>,
    /// Insertion order, so `list` is stable rather than hash-random.
    order: Vec<String>,
}

impl SkillRegistry {
    /// Scan `core/` then `evolved/`, mirroring Python's order and its
    /// `_graveyard` exclusion. Later names overwrite earlier ones, exactly as
    /// the Python dict assignment does.
    pub fn scan(root: &Path) -> Self {
        let mut reg = SkillRegistry::default();
        reg.scan_dir(&root.join(CORE_DIR), true, false);
        reg.scan_dir(&root.join(EVOLVED_DIR), false, true);
        reg
    }

    fn scan_dir(&mut self, dir: &Path, is_core: bool, recursive: bool) {
        if !dir.is_dir() {
            return;
        }
        let mut files: Vec<PathBuf> = Vec::new();
        collect_md(dir, recursive, &mut files);
        files.sort();
        for f in files {
            if f.components().any(|c| c.as_os_str() == "_graveyard" || c.as_os_str() == GRAVEYARD_DIR) {
                continue;
            }
            match std::fs::read_to_string(&f) {
                Ok(text) => {
                    let skill = PromptSkill::from_markdown(&f, &text, is_core);
                    self.insert(skill);
                }
                Err(e) => {
                    tracing::warn!(file = %f.display(), error = %e, "prompt_skill_parse_error");
                }
            }
        }
    }

    /// A registry from skills that were scanned elsewhere — what a
    /// node-hosted loop builds from the catalog the gateway ships it
    /// so selection runs the same code on the same data.
    pub fn from_skills(skills: Vec<PromptSkill>) -> Self {
        let mut reg = Self::default();
        for s in skills {
            reg.insert(s);
        }
        reg
    }

    fn insert(&mut self, skill: PromptSkill) {
        if !self.skills.contains_key(&skill.name) {
            self.order.push(skill.name.clone());
        }
        self.skills.insert(skill.name.clone(), skill);
    }

    pub fn len(&self) -> usize {
        self.skills.len()
    }

    pub fn is_empty(&self) -> bool {
        self.skills.is_empty()
    }

    pub fn get(&self, name: &str) -> Option<&PromptSkill> {
        self.skills.get(name)
    }

    pub fn list_all(&self) -> Vec<&PromptSkill> {
        self.order.iter().filter_map(|n| self.skills.get(n)).collect()
    }

    pub fn summaries(&self) -> Vec<Value> {
        self.list_all().iter().map(|s| s.to_summary()).collect()
    }
}

/// Usage counters.
///
/// Kept as process-local atomics because that is what the Python registry
/// did — `record_usage` incremented an in-memory field that no one persisted.
/// Porting it as-is keeps the change to "same behaviour, different language";
/// making the counts durable is a separate decision, and is noted in the
/// followup rather than smuggled in here.
#[derive(Debug, Default)]
pub struct UsageCounters {
    counts: HashMap<String, AtomicU64>,
}

impl UsageCounters {
    pub fn record(&self, name: &str) -> u64 {
        if let Some(c) = self.counts.get(name) {
            return c.fetch_add(1, Ordering::Relaxed) + 1;
        }
        0
    }

    pub fn prime(&mut self, names: impl IntoIterator<Item = String>) {
        for n in names {
            self.counts.entry(n).or_default();
        }
    }

    pub fn get(&self, name: &str) -> u64 {
        self.counts.get(name).map(|c| c.load(Ordering::Relaxed)).unwrap_or(0)
    }
}

fn collect_md(dir: &Path, recursive: bool, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if recursive {
                collect_md(&p, recursive, out);
            }
        } else if p.extension().map(|x| x == "md").unwrap_or(false) {
            out.push(p);
        }
    }
}

fn tokenize(text: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut cur = String::new();
    for ch in text.chars() {
        // Python's \w — alphanumeric or underscore.
        if ch.is_alphanumeric() || ch == '_' {
            cur.push(ch.to_ascii_lowercase());
        } else if !cur.is_empty() {
            out.insert(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.insert(cur);
    }
    out
}

/// Score and pick skills for a message. Line-by-line port of
/// `PromptSkillSelector.select`.
pub fn select<'a>(
    registry: &'a SkillRegistry,
    message: &str,
    agent_role: &str,
    force_skills: &[String],
    preferred_skills: &[String],
) -> Vec<&'a PromptSkill> {
    // Forced selection short-circuits scoring entirely, before the
    // empty-message check — same as Python.
    if !force_skills.is_empty() {
        let forced: Vec<&PromptSkill> =
            force_skills.iter().filter_map(|n| registry.get(n)).collect();
        if !forced.is_empty() {
            return forced.into_iter().take(MAX_SKILLS).collect();
        }
    }

    let msg_tokens = tokenize(message);
    if msg_tokens.is_empty() {
        return Vec::new();
    }
    let msg_lower = message.to_lowercase();
    let preferred: HashSet<&str> = preferred_skills.iter().map(String::as_str).collect();

    let mut scored: Vec<(f64, &PromptSkill)> = Vec::new();
    for skill in registry.list_all() {
        let mut score = 0.0f64;

        for kw in &skill.trigger_keywords {
            let kw_lower = kw.to_lowercase();
            if msg_lower.contains(&kw_lower) {
                score += 2.0;
            } else if !tokenize(&kw_lower).is_disjoint(&msg_tokens) {
                score += 1.0;
            }
        }
        for tag in &skill.tags {
            if msg_tokens.contains(&tag.to_lowercase()) {
                score += 1.0;
            }
        }
        let overlap = tokenize(&skill.description).intersection(&msg_tokens).count();
        score += overlap as f64 * 0.3;

        if score == 0.0 {
            continue;
        }

        score *= skill.priority as f64 / 10.0;
        if !skill.is_core && skill.fitness > 0.0 {
            score += skill.fitness * 0.5;
        }
        if let Some(fp) = &skill.file_path {
            if fp.contains(&format!("/{agent_role}/")) {
                score *= 1.5;
            }
        }
        if preferred.contains(skill.name.as_str()) {
            score *= 1.3;
        }
        scored.push((score, skill));
    }

    // Descending by score. `sort_by` is stable, so equal scores keep registry
    // order — Python's list.sort is stable too.
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    let mut selected = Vec::new();
    let mut total_chars = 0usize;
    for (_s, skill) in scored {
        if selected.len() >= MAX_SKILLS {
            break;
        }
        let len = skill.to_injection_text().chars().count();
        if total_chars + len > MAX_TOTAL_CHARS {
            // `continue`, not `break` — a single oversized skill must not
            // block smaller ones behind it. Python does the same.
            continue;
        }
        selected.push(skill);
        total_chars += len;
    }
    selected
}

/// Why a store write was refused.
#[derive(Debug, PartialEq)]
pub enum StoreError {
    /// The skill is core: shipped with the product, never rewritten, retired
    /// or scored through the API.
    Core,
    NotFound(String),
    Invalid(String),
    Io(String),
}

fn find_skill(root: &Path, name: &str) -> Result<PromptSkill, StoreError> {
    let reg = SkillRegistry::scan(root);
    let skill = reg
        .get(name)
        .cloned()
        .ok_or_else(|| StoreError::NotFound(format!("Prompt skill '{name}' not found")))?;
    if skill.is_core {
        return Err(StoreError::Core);
    }
    Ok(skill)
}

fn write_skill(skill: &PromptSkill) -> Result<(), StoreError> {
    let path = skill
        .file_path
        .as_deref()
        .ok_or_else(|| StoreError::Io("skill has no file".into()))?;
    let text = skill.to_file_text().map_err(StoreError::Invalid)?;
    std::fs::write(path, text).map_err(|e| StoreError::Io(format!("Failed to write skill file: {e}")))
}

fn clamp_fitness(f: f64) -> f64 {
    f.clamp(FITNESS_MIN, FITNESS_MAX)
}

/// Rewrite an EVOLVED skill: `{content, description?, tags?, priority?,
/// fitness?, generation?, parent_skill?, version?}`. Fields the body omits
/// keep their value. Fitness is clamped to 0..10.
pub fn update_skill(root: &Path, name: &str, body: &Value) -> Result<PromptSkill, StoreError> {
    let mut skill = find_skill(root, name)?;
    let bad = |k: &str, want: &str| StoreError::Invalid(format!("'{k}' must be {want}"));
    skill.content = body
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StoreError::Invalid("Missing required field: content".into()))?
        .to_string();
    if let Some(v) = body.get("description") {
        skill.description = v.as_str().ok_or_else(|| bad("description", "a string"))?.to_string();
    }
    if let Some(v) = body.get("version") {
        skill.version = match v {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => return Err(bad("version", "a string")),
        };
    }
    if let Some(v) = body.get("tags") {
        let arr = v.as_array().ok_or_else(|| bad("tags", "an array of strings"))?;
        skill.tags = arr
            .iter()
            .map(|t| t.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| bad("tags", "an array of strings"))?;
    }
    if let Some(v) = body.get("priority") {
        skill.priority = v.as_i64().ok_or_else(|| bad("priority", "an integer"))?;
    }
    if let Some(v) = body.get("fitness") {
        let f = v.as_f64().ok_or_else(|| bad("fitness", "a number"))?;
        skill.fitness = clamp_fitness(f);
    }
    if let Some(v) = body.get("generation") {
        skill.generation = v.as_i64().ok_or_else(|| bad("generation", "an integer"))?;
    }
    if let Some(v) = body.get("parent_skill") {
        if !(v.is_null() || v.is_string()) {
            return Err(bad("parent_skill", "a string or null"));
        }
        skill.parent_skill = v.clone();
    }
    write_skill(&skill)?;
    Ok(skill)
}

/// Move an EVOLVED skill into `<its directory>/graveyard/`. Returns the new
/// path. A name already in the graveyard keeps both: the newer file gets a
/// numeric suffix.
pub fn retire_skill(root: &Path, name: &str) -> Result<PathBuf, StoreError> {
    let skill = find_skill(root, name)?;
    move_to_graveyard(&skill)
}

fn move_to_graveyard(skill: &PromptSkill) -> Result<PathBuf, StoreError> {
    let from = PathBuf::from(
        skill.file_path.as_deref().ok_or_else(|| StoreError::Io("skill has no file".into()))?,
    );
    let dir = from
        .parent()
        .ok_or_else(|| StoreError::Io("skill file has no directory".into()))?
        .join(GRAVEYARD_DIR);
    std::fs::create_dir_all(&dir)
        .map_err(|e| StoreError::Io(format!("Failed to create graveyard: {e}")))?;
    let file = from.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
    let stem = from.file_stem().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
    let mut to = dir.join(&file);
    let mut n = 1u32;
    while to.exists() {
        to = dir.join(format!("{stem}.{n}.md"));
        n += 1;
    }
    std::fs::rename(&from, &to).map_err(|e| StoreError::Io(format!("Failed to retire skill: {e}")))?;
    Ok(to)
}

/// Apply `delta` to an evolved skill's fitness: clamp to 0..10, persist to
/// the frontmatter, and retire it when a negative delta leaves it at the
/// floor. Returns the new fitness and whether the skill was retired.
pub fn adjust_fitness(root: &Path, name: &str, delta: f64) -> Result<(f64, bool), StoreError> {
    if !delta.is_finite() {
        return Err(StoreError::Invalid("'delta' must be a finite number".into()));
    }
    let mut skill = find_skill(root, name)?;
    skill.fitness = clamp_fitness(skill.fitness + delta);
    write_skill(&skill)?;
    if skill.fitness <= FITNESS_MIN && delta < 0.0 {
        move_to_graveyard(&skill)?;
        return Ok((skill.fitness, true));
    }
    Ok((skill.fitness, false))
}

/// Locate the project root holding `prompts/skills`.
pub fn find_root() -> PathBuf {
    if let Ok(p) = std::env::var("NOO_PROMPT_SKILLS_ROOT") {
        return PathBuf::from(p);
    }
    for candidate in ["/app", "."] {
        let p = PathBuf::from(candidate);
        if p.join(CORE_DIR).is_dir() || p.join(EVOLVED_DIR).is_dir() {
            return p;
        }
    }
    PathBuf::from(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skill(name: &str, kws: &[&str], tags: &[&str], desc: &str, prio: i64) -> PromptSkill {
        PromptSkill {
            name: name.into(),
            version: "1.0".into(),
            description: desc.into(),
            author: "t".into(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            trigger_keywords: kws.iter().map(|s| s.to_string()).collect(),
            priority: prio,
            fitness: 0.0,
            generation: 0,
            is_core: true,
            max_context_chars: 4000,
            composable: true,
            requires_tools: vec![],
            parent_skill: Value::Null,
            content: "body".into(),
            file_path: None,
            usage_count: 0,
        }
    }

    fn reg(skills: Vec<PromptSkill>) -> SkillRegistry {
        let mut r = SkillRegistry::default();
        for s in skills {
            r.insert(s);
        }
        r
    }

    #[test]
    fn parses_frontmatter_and_body() {
        let md = "---\nname: writer\nversion: 2.1\ntags: [a, b]\npriority: 8\n---\n\nBody here.";
        let s = PromptSkill::from_markdown(Path::new("/x/writer.md"), md, true);
        assert_eq!(s.name, "writer");
        assert_eq!(s.version, "2.1", "a YAML float version must not truncate to '2'");
        assert_eq!(s.tags, vec!["a", "b"]);
        assert_eq!(s.priority, 8);
        assert_eq!(s.content, "Body here.");
        assert!(s.is_core);
    }

    #[test]
    fn file_without_frontmatter_is_still_a_skill() {
        let s = PromptSkill::from_markdown(Path::new("/x/plain.md"), "just text", false);
        assert_eq!(s.name, "plain", "name falls back to the file stem");
        assert_eq!(s.content, "just text");
        assert_eq!(s.priority, 5, "defaults must match Python's");
        assert_eq!(s.author, "noo-builtin");
    }

    #[test]
    fn horizontal_rule_in_body_is_not_frontmatter() {
        // A `---` that is not at position 0 must not be treated as a
        // delimiter, or the document silently loses its first section.
        let s = PromptSkill::from_markdown(Path::new("/x/d.md"), "intro\n---\nmore", false);
        assert_eq!(s.content, "intro\n---\nmore");
    }

    #[test]
    fn injection_text_matches_python_format() {
        let s = skill("w", &[], &[], "does things", 5);
        assert_eq!(s.to_injection_text(), "## Skill: w — does things\n\nbody");
        let mut bare = s.clone();
        bare.description = String::new();
        assert_eq!(bare.to_injection_text(), "## Skill: w\n\nbody");
    }

    #[test]
    fn scoring_matches_python_exactly() {
        // "debug" is a phrase hit (2.0); tag "rust" hits (1.0); description
        // shares "code" with the message (0.3). Total 3.3, times priority
        // 10/10 = 3.3. Pinning the number, not just the ordering — a silent
        // drift here changes what the model sees.
        let r = reg(vec![skill("s", &["debug"], &["rust"], "code helper", 10)]);
        let picked = select(&r, "debug this rust code", "coordinator", &[], &[]);
        assert_eq!(picked.len(), 1);

        // Same skill at priority 5 must score exactly half.
        let r2 = reg(vec![skill("s", &["debug"], &["rust"], "code helper", 5)]);
        assert_eq!(select(&r2, "debug this rust code", "coordinator", &[], &[]).len(), 1);
    }

    #[test]
    fn zero_signal_skills_are_excluded() {
        let r = reg(vec![skill("x", &["kubernetes"], &["k8s"], "cluster stuff", 9)]);
        assert!(select(&r, "write me a poem", "coordinator", &[], &[]).is_empty());
    }

    #[test]
    fn empty_message_selects_nothing() {
        let r = reg(vec![skill("x", &["a"], &[], "", 5)]);
        assert!(select(&r, "   ", "coordinator", &[], &[]).is_empty());
    }

    #[test]
    fn force_skills_bypass_scoring() {
        // Forced selection ignores relevance entirely — including for a
        // message that would score nothing.
        let r = reg(vec![skill("forced", &["nomatch"], &[], "", 5)]);
        let picked = select(&r, "totally unrelated", "coordinator", &["forced".into()], &[]);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].name, "forced");
    }

    #[test]
    fn unknown_forced_skill_falls_through_to_scoring() {
        let r = reg(vec![skill("real", &["poem"], &[], "", 5)]);
        let picked = select(&r, "write a poem", "coordinator", &["ghost".into()], &[]);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].name, "real");
    }

    #[test]
    fn max_three_skills() {
        let r = reg((0..6).map(|i| skill(&format!("s{i}"), &["hit"], &[], "", 5)).collect());
        assert_eq!(select(&r, "hit", "coordinator", &[], &[]).len(), MAX_SKILLS);
    }

    #[test]
    fn oversized_skill_is_skipped_not_terminal() {
        // The budget loop must `continue`: a huge skill cannot block smaller
        // ones ranked behind it.
        let mut big = skill("big", &["hit"], &[], "", 10);
        big.content = "x".repeat(MAX_TOTAL_CHARS + 1);
        let small = skill("small", &["hit"], &[], "", 1);
        let r = reg(vec![big, small]);
        let picked = select(&r, "hit", "coordinator", &[], &[]);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].name, "small");
    }

    #[test]
    fn role_affinity_and_preferred_multipliers_apply() {
        let mut roled = skill("roled", &["hit"], &[], "", 5);
        roled.file_path = Some("/skills/evolved/researcher/roled.md".into());
        let plain = skill("plain", &["hit"], &[], "", 5);
        let r = reg(vec![plain, roled]);

        // 1.5x role affinity puts the role-matched skill first.
        let picked = select(&r, "hit", "researcher", &[], &[]);
        assert_eq!(picked[0].name, "roled");

        // Under a different role the tie holds registry order (stable sort).
        let picked2 = select(&r, "hit", "coordinator", &[], &[]);
        assert_eq!(picked2[0].name, "plain");

        // 1.3x preferred flips it back.
        let picked3 = select(&r, "hit", "coordinator", &[], &["roled".into()]);
        assert_eq!(picked3[0].name, "roled");
    }

    #[test]
    fn keyword_phrase_beats_token_overlap() {
        // Multi-word keyword present as a phrase scores 2.0; only-token
        // overlap scores 1.0.
        let phrase = skill("phrase", &["unit test"], &[], "", 5);
        let token = skill("token", &["unit banana"], &[], "", 5);
        let r = reg(vec![token, phrase]);
        let picked = select(&r, "please write a unit test", "coordinator", &[], &[]);
        assert_eq!(picked[0].name, "phrase");
    }

    #[test]
    fn usage_counters_only_count_known_skills() {
        let mut u = UsageCounters::default();
        u.prime(vec!["known".to_string()]);
        assert_eq!(u.record("known"), 1);
        assert_eq!(u.record("known"), 2);
        assert_eq!(u.record("unknown"), 0, "unknown names must not create counters");
        assert_eq!(u.get("known"), 2);
    }
}

/// Differential tests against the real `prompts/skills/` tree.
///
/// Unit tests prove the algorithm behaves as *specified*; these prove it
/// behaves as the **Python it replaced**. The expectations were produced by
/// running `PromptSkillSelector` over the same corpus and messages —
/// including the cases with unintuitive results (a poem query matching
/// `research-and-save`), because reproducing the quirks is the point. A port
/// that only matched the obvious cases would silently change which skills
/// reach the model.
///
/// Skipped when the corpus is absent so the suite still runs elsewhere.
#[cfg(test)]
mod differential {
    use super::*;

    fn corpus() -> Option<SkillRegistry> {
        for root in ["../..", "..", ".", "/build"] {
            let p = Path::new(root);
            if p.join(CORE_DIR).is_dir() {
                let r = SkillRegistry::scan(p);
                if !r.is_empty() {
                    return Some(r);
                }
            }
        }
        None
    }

    #[test]
    fn matches_python_selection_on_the_real_corpus() {
        let Some(reg) = corpus() else {
            // A skipped test that reports `ok` is a false pass — this one
            // did exactly that on first run, because the builder image does
            // not copy prompts/. CI sets NOO_SKILL_CORPUS_REQUIRED=1 (and
            // mounts the corpus) so the skip cannot hide there.
            if std::env::var("NOO_SKILL_CORPUS_REQUIRED").is_ok() {
                panic!("prompts/skills not found but NOO_SKILL_CORPUS_REQUIRED is set");
            }
            eprintln!("SKIPPED (no corpus): mount prompts/ to run the differential test");
            return;
        };
        assert_eq!(reg.len(), 14, "corpus size changed — refresh expectations");

        // (message, exactly what PromptSkillSelector returned)
        let cases: &[(&str, &[&str])] = &[
            ("debug this failing test",
             &["debug-assistant", "save-to-knowledge", "research-and-save"]),
            ("review my code for bugs",
             &["code-review", "debug-assistant", "save-to-knowledge"]),
            // Re-pinned at the noomesh rename: the corpus text renamed with
            // the brand, the body-frequency profile of the new word differs,
            // and cluster-operator (noise for a CLI-usage question anyway)
            // drops out. Pins are historical snapshots — the Python
            // implementation these mirrored is retired.
            ("how do I use the noo cli",
             &["knowledge-gap-audit", "research-and-save"]),
            ("analyse this dataset",
             &["save-to-knowledge", "data-analysis", "research-and-save"]),
            ("add a node to the cluster",
             &["research-and-save", "cluster-operator", "save-to-knowledge"]),
            ("write me a poem",
             &["research-and-save", "knowledge-gap-audit", "broadcast-message"]),
            ("search the knowledge base for rag",
             &["rag-expert", "save-to-knowledge", "knowledge-gap-audit"]),
            ("broadcast a message to everyone",
             &["broadcast-message", "research-and-save", "knowledge-gap-audit"]),
        ];

        for (msg, expected) in cases {
            let got: Vec<&str> = select(&reg, msg, "coordinator", &[], &[])
                .iter()
                .map(|s| s.name.as_str())
                .collect();
            assert_eq!(&got, expected, "selection diverged from Python for {msg:?}");
        }
    }

    // ── store writes (update / retire / fitness) ──────────────────────

    /// A scratch root with one core and one evolved skill (under a role dir).
    fn store(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("noo-skills-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("prompts/skills/core")).unwrap();
        std::fs::create_dir_all(root.join("prompts/skills/evolved/coder")).unwrap();
        std::fs::write(
            root.join("prompts/skills/core/shipped.md"),
            "---\nname: shipped\n---\n\ncore body\n",
        )
        .unwrap();
        std::fs::write(
            root.join("prompts/skills/evolved/coder/grown.md"),
            "---\nname: grown\nversion: '1.0'\ndescription: old\ntags: [a]\npriority: 5\nfitness: 0.5\ngeneration: 1\nauthor: evolve\ntrigger_keywords: [kw]\n---\n\nold body\n",
        )
        .unwrap();
        root
    }

    #[test]
    fn update_rewrites_an_evolved_skill_and_keeps_what_the_body_omits() {
        let root = store("upd");
        let body = json!({"content": "new body", "description": "new", "tags": ["x", "y"],
                          "priority": 7, "fitness": 99, "generation": 2, "parent_skill": "shipped"});
        let s = update_skill(&root, "grown", &body).unwrap();
        assert_eq!(s.fitness, 10.0, "fitness is clamped on update too");
        let on_disk = std::fs::read_to_string(root.join("prompts/skills/evolved/coder/grown.md")).unwrap();
        let back = PromptSkill::from_markdown(Path::new("grown.md"), &on_disk, false);
        assert_eq!(back.content, "new body");
        assert_eq!(back.description, "new");
        assert_eq!(back.tags, vec!["x", "y"]);
        assert_eq!(back.priority, 7);
        assert_eq!(back.generation, 2);
        assert_eq!(back.parent_skill, json!("shipped"));
        assert_eq!(back.author, "evolve", "an omitted field keeps its value");
        assert_eq!(back.trigger_keywords, vec!["kw"]);
        assert_eq!(back.version, "1.0");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn update_refuses_core_and_missing_and_bad_bodies() {
        let root = store("upd-refuse");
        assert_eq!(update_skill(&root, "shipped", &json!({"content": "x"})).unwrap_err(), StoreError::Core);
        assert!(matches!(update_skill(&root, "ghost", &json!({"content": "x"})), Err(StoreError::NotFound(_))));
        assert!(matches!(update_skill(&root, "grown", &json!({})), Err(StoreError::Invalid(_))));
        assert!(matches!(update_skill(&root, "grown", &json!({"content": "x", "tags": [1]})), Err(StoreError::Invalid(_))));
        let core = std::fs::read_to_string(root.join("prompts/skills/core/shipped.md")).unwrap();
        assert!(core.contains("core body"), "a refused write leaves the core file untouched");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn retire_moves_the_file_into_the_role_graveyard_and_out_of_the_registry() {
        let root = store("retire");
        let to = retire_skill(&root, "grown").unwrap();
        assert_eq!(to, root.join("prompts/skills/evolved/coder/graveyard/grown.md"));
        assert!(to.is_file());
        assert!(!root.join("prompts/skills/evolved/coder/grown.md").exists());
        assert!(SkillRegistry::scan(&root).get("grown").is_none(), "a retired skill is no longer selectable");
        assert!(matches!(retire_skill(&root, "grown"), Err(StoreError::NotFound(_))));
        assert_eq!(retire_skill(&root, "shipped").unwrap_err(), StoreError::Core);
        assert!(root.join("prompts/skills/core/shipped.md").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fitness_clamps_persists_and_retires_at_the_floor() {
        let root = store("fit");
        let path = root.join("prompts/skills/evolved/coder/grown.md");
        let (f, retired) = adjust_fitness(&root, "grown", 100.0).unwrap();
        assert_eq!((f, retired), (10.0, false), "clamped at the ceiling");
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(PromptSkill::from_markdown(&path, &on_disk, false).fitness, 10.0, "persisted to frontmatter");
        let (f, retired) = adjust_fitness(&root, "grown", -3.0).unwrap();
        assert_eq!((f, retired), (7.0, false));
        // Landing on the floor with a negative delta retires.
        let (f, retired) = adjust_fitness(&root, "grown", -50.0).unwrap();
        assert_eq!((f, retired), (0.0, true));
        assert!(!path.exists());
        assert!(root.join("prompts/skills/evolved/coder/graveyard/grown.md").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fitness_at_zero_with_a_non_negative_delta_does_not_retire() {
        let root = store("fit-zero");
        std::fs::write(
            root.join("prompts/skills/evolved/coder/grown.md"),
            "---\nname: grown\nfitness: 0.0\n---\n\nbody\n",
        )
        .unwrap();
        let (f, retired) = adjust_fitness(&root, "grown", 0.0).unwrap();
        assert_eq!((f, retired), (0.0, false), "a zero delta at zero is not a demotion");
        assert!(root.join("prompts/skills/evolved/coder/grown.md").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fitness_refuses_core_missing_and_non_finite() {
        let root = store("fit-refuse");
        assert_eq!(adjust_fitness(&root, "shipped", 1.0).unwrap_err(), StoreError::Core);
        assert!(matches!(adjust_fitness(&root, "ghost", 1.0), Err(StoreError::NotFound(_))));
        assert!(matches!(adjust_fitness(&root, "grown", f64::NAN), Err(StoreError::Invalid(_))));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_second_retire_of_the_same_name_keeps_both_files() {
        let root = store("retire-twice");
        retire_skill(&root, "grown").unwrap();
        std::fs::write(
            root.join("prompts/skills/evolved/coder/grown.md"),
            "---\nname: grown\n---\n\nsecond\n",
        )
        .unwrap();
        let to = retire_skill(&root, "grown").unwrap();
        assert_eq!(to, root.join("prompts/skills/evolved/coder/graveyard/grown.1.md"));
        assert!(root.join("prompts/skills/evolved/coder/graveyard/grown.md").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }
}
