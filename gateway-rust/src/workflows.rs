// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Multi-step workflows — sequential agent runs with context threading.
//!
//! Ported from `noomesh/workflows/`. Backs
//! `POST /api/workflows/run`.
//!
//! ## This removes a duplicate declaration, not just a handler
//!
//! The three built-in workflows were declared TWICE: as Python objects in
//! `workflows/workflow.py`, and as hard-coded JSON in `routes/agents.rs`
//! serving `GET /api/workflows`. `workflows/registry.py`'s own docstring
//! admits the split — *"GET /api/workflows never noticed because the Rust
//! gateway serves the list natively from hard-coded templates that mirror
//! these three"*. Two declarations of the same fact, free to drift, with the
//! list endpoint and the run endpoint disagreeing silently.
//!
//! [`builtin_workflows`] is now the single definition; the list route reads
//! from it.
//!
//! ## Conditions
//!
//! Steps carry an optional condition like `len(summarize) > 100`. Python
//! evaluated these through an AST walker (`_safe_eval`) restricted to
//! comparisons, boolean logic, `len()` and arithmetic — deliberately not
//! `eval()`. [`eval_condition`] implements that same restricted grammar.
//! Anything outside it is an ERROR, not a default: silently treating an
//! unparseable condition as true would run a step the author gated.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};

use crate::state::AppState;

/// One step of a workflow.
#[derive(Debug, Clone)]
pub struct WorkflowStep {
    pub name: &'static str,
    pub agent_prompt: &'static str,
    pub tools_required: &'static [&'static str],
    pub condition: Option<&'static str>,
    /// "stop" | "continue" | "skip" — Python's `on_error`.
    pub on_error: &'static str,
}

#[derive(Debug, Clone)]
pub struct Workflow {
    pub name: &'static str,
    pub description: &'static str,
    pub steps: &'static [WorkflowStep],
}

const DEEP_RESEARCH: &[WorkflowStep] = &[
    WorkflowStep { name: "initial_search", agent_prompt: "Search for information about: {topic}", tools_required: &["web_search"], condition: None, on_error: "stop" },
    WorkflowStep { name: "summarize", agent_prompt: "Summarize these search results concisely:\n{initial_search}", tools_required: &[], condition: None, on_error: "stop" },
    WorkflowStep { name: "deep_dive", agent_prompt: "Research specific aspects of {topic} that need more detail based on:\n{summarize}", tools_required: &["web_search"], condition: Some("len(summarize) > 100"), on_error: "stop" },
    WorkflowStep { name: "final_report", agent_prompt: "Create a comprehensive report on {topic} using all findings", tools_required: &[], condition: None, on_error: "stop" },
];

const CODE_DEVELOPMENT: &[WorkflowStep] = &[
    WorkflowStep { name: "requirements", agent_prompt: "Analyze requirements for: {task}", tools_required: &[], condition: None, on_error: "stop" },
    WorkflowStep { name: "design", agent_prompt: "Design implementation approach for:\n{requirements}", tools_required: &[], condition: None, on_error: "stop" },
    WorkflowStep { name: "implement", agent_prompt: "Implement the following design:\n{design}", tools_required: &["python_exec", "local_files"], condition: None, on_error: "stop" },
    // `continue` on purpose: a failing test must not abort before review.
    WorkflowStep { name: "test", agent_prompt: "Test this implementation:\n{implement}", tools_required: &["python_exec"], condition: None, on_error: "continue" },
    WorkflowStep { name: "review", agent_prompt: "Review code quality and suggest improvements:\n{implement}", tools_required: &[], condition: None, on_error: "stop" },
];

const DATA_ANALYSIS: &[WorkflowStep] = &[
    WorkflowStep { name: "load_data", agent_prompt: "Load data from: {data_source}", tools_required: &["python_exec", "local_files"], condition: None, on_error: "stop" },
    WorkflowStep { name: "explore", agent_prompt: "Perform exploratory data analysis on:\n{load_data}", tools_required: &["python_exec"], condition: None, on_error: "stop" },
    WorkflowStep { name: "analyze", agent_prompt: "Analyze patterns and trends in the data:\n{explore}", tools_required: &["python_exec"], condition: None, on_error: "stop" },
    WorkflowStep { name: "visualize", agent_prompt: "Create visualizations for insights found:\n{analyze}", tools_required: &["python_exec"], condition: None, on_error: "stop" },
    WorkflowStep { name: "report", agent_prompt: "Generate analysis report with key findings", tools_required: &[], condition: None, on_error: "stop" },
];

pub fn builtin_workflows() -> Vec<Workflow> {
    vec![
        Workflow { name: "deep_research", description: "Research a topic thoroughly", steps: DEEP_RESEARCH },
        Workflow { name: "code_development", description: "Plan, implement, and test code", steps: CODE_DEVELOPMENT },
        Workflow { name: "data_analysis", description: "Load, analyze, and visualize data", steps: DATA_ANALYSIS },
    ]
}

/// JSON for `GET /api/workflows` — the shape the hard-coded templates served.
pub fn list_json() -> Value {
    let workflows: Vec<Value> = builtin_workflows()
        .iter()
        .map(|w| {
            let steps: Vec<Value> = w
                .steps
                .iter()
                .map(|s| {
                    json!({
                        "name": s.name,
                        "agent_prompt": s.agent_prompt,
                        "tools_required": s.tools_required,
                        "condition": s.condition,
                        "on_error": s.on_error,
                        "timeout": Value::Null,
                    })
                })
                .collect();
            json!({
                "name": w.name,
                "description": w.description,
                "steps": steps,
                "initial_context": {},
            })
        })
        .collect();
    json!({ "workflows": workflows })
}

// ── Condition evaluation ────────────────────────────────────────────────
//
// Restricted grammar, matching Python's `_safe_eval`: comparisons
// (> < >= <= == !=), boolean and/or/not, `len(var)`, arithmetic (+ - * /),
// numeric literals and context variables. No calls beyond `len`, no
// attribute access, no indexing — the point of the original was to avoid
// `eval()`, and a permissive port would reintroduce exactly that.

#[derive(Debug, PartialEq)]
enum Val {
    Num(f64),
    Bool(bool),
}

/// Evaluate a step condition against the accumulated context.
///
/// Returns `Err` for anything outside the grammar. Callers must FAIL the step
/// on error rather than defaulting to run — the condition exists to gate.
pub fn eval_condition(expr: &str, ctx: &HashMap<String, String>) -> Result<bool, String> {
    let tokens = tokenize(expr)?;
    let mut p = Parser { t: &tokens, i: 0, ctx };
    let v = p.parse_or()?;
    if p.i != p.t.len() {
        return Err(format!("unexpected trailing input in {expr:?}"));
    }
    match v {
        Val::Bool(b) => Ok(b),
        // Python's truthiness for a bare numeric condition.
        Val::Num(n) => Ok(n != 0.0),
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(f64),
    Ident(String),
    Op(String),
    LParen,
    RParen,
}

fn tokenize(s: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let cs: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        if c.is_whitespace() {
            i += 1;
        } else if c.is_ascii_digit() || (c == '.' && i + 1 < cs.len() && cs[i + 1].is_ascii_digit()) {
            let start = i;
            while i < cs.len() && (cs[i].is_ascii_digit() || cs[i] == '.') {
                i += 1;
            }
            let lit: String = cs[start..i].iter().collect();
            out.push(Tok::Num(lit.parse().map_err(|_| format!("bad number {lit:?}"))?));
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < cs.len() && (cs[i].is_alphanumeric() || cs[i] == '_') {
                i += 1;
            }
            out.push(Tok::Ident(cs[start..i].iter().collect()));
        } else if c == '(' {
            out.push(Tok::LParen);
            i += 1;
        } else if c == ')' {
            out.push(Tok::RParen);
            i += 1;
        } else {
            // Two-char operators first, so >= is not read as > then =.
            let two: String = cs[i..(i + 2).min(cs.len())].iter().collect();
            if ["==", "!=", ">=", "<="].contains(&two.as_str()) {
                out.push(Tok::Op(two));
                i += 2;
            } else if "><+-*/".contains(c) {
                out.push(Tok::Op(c.to_string()));
                i += 1;
            } else {
                return Err(format!("unsupported character {c:?}"));
            }
        }
    }
    Ok(out)
}

struct Parser<'a> {
    t: &'a [Tok],
    i: usize,
    ctx: &'a HashMap<String, String>,
}

impl<'a> Parser<'a> {
    fn peek_ident(&self, want: &str) -> bool {
        matches!(self.t.get(self.i), Some(Tok::Ident(s)) if s == want)
    }

    fn parse_or(&mut self) -> Result<Val, String> {
        let mut lhs = self.parse_and()?;
        while self.peek_ident("or") {
            self.i += 1;
            let rhs = self.parse_and()?;
            lhs = Val::Bool(truthy(&lhs) || truthy(&rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Val, String> {
        let mut lhs = self.parse_not()?;
        while self.peek_ident("and") {
            self.i += 1;
            let rhs = self.parse_not()?;
            lhs = Val::Bool(truthy(&lhs) && truthy(&rhs));
        }
        Ok(lhs)
    }

    fn parse_not(&mut self) -> Result<Val, String> {
        if self.peek_ident("not") {
            self.i += 1;
            let v = self.parse_not()?;
            return Ok(Val::Bool(!truthy(&v)));
        }
        self.parse_cmp()
    }

    fn parse_cmp(&mut self) -> Result<Val, String> {
        let lhs = self.parse_add()?;
        if let Some(Tok::Op(op)) = self.t.get(self.i) {
            if ["==", "!=", ">", "<", ">=", "<="].contains(&op.as_str()) {
                let op = op.clone();
                self.i += 1;
                let rhs = self.parse_add()?;
                let (a, b) = (num(&lhs)?, num(&rhs)?);
                let r = match op.as_str() {
                    ">" => a > b,
                    "<" => a < b,
                    ">=" => a >= b,
                    "<=" => a <= b,
                    "==" => (a - b).abs() < f64::EPSILON,
                    "!=" => (a - b).abs() >= f64::EPSILON,
                    _ => unreachable!(),
                };
                return Ok(Val::Bool(r));
            }
        }
        Ok(lhs)
    }

    fn parse_add(&mut self) -> Result<Val, String> {
        let mut lhs = self.parse_mul()?;
        while let Some(Tok::Op(op)) = self.t.get(self.i) {
            let op = op.clone();
            if op != "+" && op != "-" {
                break;
            }
            self.i += 1;
            let rhs = self.parse_mul()?;
            let v = if op == "+" { num(&lhs)? + num(&rhs)? } else { num(&lhs)? - num(&rhs)? };
            lhs = Val::Num(v);
        }
        Ok(lhs)
    }

    fn parse_mul(&mut self) -> Result<Val, String> {
        let mut lhs = self.parse_atom()?;
        while let Some(Tok::Op(op)) = self.t.get(self.i) {
            let op = op.clone();
            if op != "*" && op != "/" {
                break;
            }
            self.i += 1;
            let rhs = self.parse_atom()?;
            let (a, b) = (num(&lhs)?, num(&rhs)?);
            if op == "/" && b == 0.0 {
                return Err("division by zero".into());
            }
            lhs = Val::Num(if op == "*" { a * b } else { a / b });
        }
        Ok(lhs)
    }

    fn parse_atom(&mut self) -> Result<Val, String> {
        match self.t.get(self.i).cloned() {
            Some(Tok::Num(n)) => {
                self.i += 1;
                Ok(Val::Num(n))
            }
            Some(Tok::LParen) => {
                self.i += 1;
                let v = self.parse_or()?;
                match self.t.get(self.i) {
                    Some(Tok::RParen) => {
                        self.i += 1;
                        Ok(v)
                    }
                    _ => Err("unbalanced parentheses".into()),
                }
            }
            Some(Tok::Ident(name)) => {
                self.i += 1;
                match name.as_str() {
                    "True" | "true" => Ok(Val::Bool(true)),
                    "False" | "false" => Ok(Val::Bool(false)),
                    "len" => {
                        // len(<ident>) only — the sole call Python allowed.
                        if self.t.get(self.i) != Some(&Tok::LParen) {
                            return Err("len must be called".into());
                        }
                        self.i += 1;
                        let inner = match self.t.get(self.i).cloned() {
                            Some(Tok::Ident(v)) => v,
                            _ => return Err("len() takes a variable".into()),
                        };
                        self.i += 1;
                        if self.t.get(self.i) != Some(&Tok::RParen) {
                            return Err("unbalanced parentheses in len()".into());
                        }
                        self.i += 1;
                        let s = self.ctx.get(&inner).ok_or(format!("unknown variable {inner:?}"))?;
                        Ok(Val::Num(s.chars().count() as f64))
                    }
                    other => {
                        // A bare variable is its length-free value; conditions
                        // in practice compare len(x), so a non-numeric bare
                        // variable is an error rather than a silent 0.
                        let s = self.ctx.get(other).ok_or(format!("unknown variable {other:?}"))?;
                        s.trim()
                            .parse::<f64>()
                            .map(Val::Num)
                            .map_err(|_| format!("variable {other:?} is not numeric"))
                    }
                }
            }
            _ => Err("unexpected end of expression".into()),
        }
    }
}

fn truthy(v: &Val) -> bool {
    match v {
        Val::Bool(b) => *b,
        Val::Num(n) => *n != 0.0,
    }
}

fn num(v: &Val) -> Result<f64, String> {
    match v {
        Val::Num(n) => Ok(*n),
        Val::Bool(b) => Ok(if *b { 1.0 } else { 0.0 }),
    }
}

/// Substitute `{name}` placeholders from the context.
///
/// Python used `str.format(**context)` and FAILED the step on a missing key.
/// Same here: a silently-unsubstituted `{topic}` would be sent to the model
/// as literal text.
pub fn format_prompt(template: &str, ctx: &HashMap<String, String>) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let Some(close_rel) = rest[open..].find('}') else {
            return Err("unbalanced '{' in prompt".into());
        };
        let close = open + close_rel;
        out.push_str(&rest[..open]);
        let key = &rest[open + 1..close];
        let val = ctx.get(key).ok_or(format!("Missing variable '{key}'"))?;
        out.push_str(val);
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Execute a workflow. Mirrors `WorkflowExecutor.execute`.
pub async fn run_workflow(
    state: &Arc<AppState>,
    workflow_id: &str,
    params: &Value,
) -> Result<Value, Value> {
    let all = builtin_workflows();
    let Some(wf) = all.iter().find(|w| w.name == workflow_id) else {
        let mut known: Vec<&str> = all.iter().map(|w| w.name).collect();
        known.sort();
        return Err(json!({
            "error": format!("unknown workflow '{workflow_id}'"),
            "known_workflows": known,
        }));
    };

    // Seed context from the caller's params (string values only — prompts are
    // string templates).
    let mut ctx: HashMap<String, String> = HashMap::new();
    if let Some(obj) = params.as_object() {
        for (k, v) in obj {
            ctx.insert(
                k.clone(),
                v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()),
            );
        }
    }

    let started = Instant::now();
    let mut steps_out: Vec<Value> = Vec::new();
    let mut failed = false;

    for step in wf.steps {
        let step_start = Instant::now();

        if let Some(cond) = step.condition {
            match eval_condition(cond, &ctx) {
                Ok(true) => {}
                Ok(false) => {
                    steps_out.push(json!({
                        "name": step.name, "status": "skipped",
                        "output": Value::Null, "error": Value::Null,
                        "duration_ms": ms(step_start),
                    }));
                    continue;
                }
                Err(e) => {
                    steps_out.push(json!({
                        "name": step.name, "status": "failed",
                        "output": Value::Null,
                        "error": format!("Condition evaluation failed: {e}"),
                        "duration_ms": ms(step_start),
                    }));
                    if step.on_error == "stop" {
                        failed = true;
                        break;
                    }
                    continue;
                }
            }
        }

        let prompt = match format_prompt(step.agent_prompt, &ctx) {
            Ok(p) => p,
            Err(e) => {
                steps_out.push(json!({
                    "name": step.name, "status": "failed",
                    "output": Value::Null,
                    "error": format!("Prompt formatting failed: {e}"),
                    "duration_ms": ms(step_start),
                }));
                if step.on_error == "stop" {
                    failed = true;
                    break;
                }
                continue;
            }
        };

        let cid = format!("workflow-{}-{}", wf.name, step.name);
        let result = crate::coordinator::run(
            state, &prompt, &cid, "workflow",
            state.config.coordinator.max_iterations,
            None, None,
        )
        .await;

        match result {
            Ok(r) => {
                // Only a completed step with output feeds the context — the
                // next step's {placeholder} refers to it by step name.
                if !r.response.is_empty() {
                    ctx.insert(step.name.to_string(), r.response.clone());
                }
                steps_out.push(json!({
                    "name": step.name, "status": "completed",
                    "output": r.response, "error": Value::Null,
                    "duration_ms": ms(step_start),
                }));
            }
            Err(e) => {
                steps_out.push(json!({
                    "name": step.name, "status": "failed",
                    "output": Value::Null, "error": e.to_string(),
                    "duration_ms": ms(step_start),
                }));
                if step.on_error == "stop" {
                    failed = true;
                    break;
                }
            }
        }
    }

    Ok(json!({
        "workflow": wf.name,
        "status": if failed { "failed" } else { "completed" },
        "total_duration_ms": ms(started),
        "steps": steps_out,
    }))
}

fn ms(t: Instant) -> f64 {
    (t.elapsed().as_secs_f64() * 10_000.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn evaluates_the_only_condition_the_builtins_use() {
        let long = "x".repeat(150);
        let c = ctx(&[("summarize", &long)]);
        assert_eq!(eval_condition("len(summarize) > 100", &c), Ok(true));

        let c2 = ctx(&[("summarize", "short")]);
        assert_eq!(eval_condition("len(summarize) > 100", &c2), Ok(false));
    }

    #[test]
    fn supports_the_documented_grammar() {
        let c = ctx(&[("a", "abc"), ("n", "7")]);
        assert_eq!(eval_condition("len(a) == 3", &c), Ok(true));
        assert_eq!(eval_condition("len(a) >= 3 and n < 10", &c), Ok(true));
        assert_eq!(eval_condition("not (len(a) > 5)", &c), Ok(true));
        assert_eq!(eval_condition("len(a) * 2 == 6", &c), Ok(true));
        assert_eq!(eval_condition("(len(a) + 1) > 3", &c), Ok(true));
        assert_eq!(eval_condition("len(a) > 5 or n == 7", &c), Ok(true));
    }

    #[test]
    fn rejects_anything_outside_the_grammar() {
        // The Python original replaced eval() precisely to prevent this; a
        // permissive port would hand arbitrary execution back.
        let c = ctx(&[("a", "x")]);
        assert!(eval_condition("__import__('os').system('rm -rf /')", &c).is_err());
        assert!(eval_condition("a.upper()", &c).is_err());
        assert!(eval_condition("open('f')", &c).is_err());
        assert!(eval_condition("len(a) >", &c).is_err());
        assert!(eval_condition("len(missing) > 1", &c).is_err());
    }

    #[test]
    fn two_char_operators_are_not_split() {
        let c = ctx(&[("a", "abc")]);
        // `>=` must not lex as `>` then `=`.
        assert_eq!(eval_condition("len(a) >= 3", &c), Ok(true));
        assert_eq!(eval_condition("len(a) != 4", &c), Ok(true));
    }

    #[test]
    fn prompt_formatting_substitutes_and_fails_loudly() {
        let c = ctx(&[("topic", "rust")]);
        assert_eq!(
            format_prompt("Search for information about: {topic}", &c),
            Ok("Search for information about: rust".to_string())
        );
        // A missing key must FAIL, not pass "{topic}" through to the model.
        let err = format_prompt("about {nope}", &c).unwrap_err();
        assert!(err.contains("Missing variable 'nope'"), "{err}");
    }

    #[test]
    fn builtin_definitions_match_the_previously_served_list() {
        // These were declared twice — Python objects and hard-coded Rust JSON.
        // Pin the shape the list endpoint served so consolidating onto one
        // definition cannot silently change the API.
        let v = list_json();
        let ws = v["workflows"].as_array().unwrap();
        assert_eq!(ws.len(), 3);
        let names: Vec<&str> = ws.iter().map(|w| w["name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["deep_research", "code_development", "data_analysis"]);

        let research = &ws[0];
        assert_eq!(research["steps"].as_array().unwrap().len(), 4);
        assert_eq!(research["steps"][2]["condition"], "len(summarize) > 100");
        // The test step is the only "continue" — a failing test must not abort
        // before review runs.
        let code = &ws[1];
        assert_eq!(code["steps"][3]["name"], "test");
        assert_eq!(code["steps"][3]["on_error"], "continue");
    }
}
