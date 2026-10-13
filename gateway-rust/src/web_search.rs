// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Native `web_search` tool — DuckDuckGo HTML endpoint client.
//!
//! Port of `src/noomesh/tools/web_search.py` (the `worker.tool.web_search`
//! NATS subject). The Python implementation used the `ddgs` library; there is
//! no Rust equivalent in-tree, so this talks to the same public surface that
//! library scrapes — `https://html.duckduckgo.com/html/` — and parses the
//! `result__a` / `result__snippet` anchors out of the response.
//!
//! Output contract (the LLM sees the Ok string verbatim):
//! - results:      `- {title}\n  {url}\n  {snippet}` lines joined by `\n`
//! - empty:        `"No results found."`
//!
//! A search that could not RUN is an `Err`, not a string. It used to be
//! wrapped in `{"success": true, ...}` like the Python handler did, on the
//! reasoning that the LLM should read the error text. Live evidence on
//! 2026-09-20 showed what that costs: DuckDuckGo answered a research run with
//! challenge pages, the tool returned `"Search error: HTTP 403 Forbidden"` and
//! `"No results found."` as ordinary results, the gateway logged three
//! `tool_call_complete` in 46-76 ms, and the model wrote a report from nothing.
//! No counter, alert or run record showed a failure, because by the type there
//! wasn't one. See the design.
//!
//! Two rules follow, and they are the point of this module:
//!
//! 1. **A blocked search is not an empty one.** A challenge page parses to zero
//!    results, which is byte-identical to a genuine "nothing matched". Saying
//!    "No results found." there asserts a fact about the world on no evidence.
//!    We say we could not search instead — the safer direction to be wrong in.
//! 2. **The provider is config-driven.** Scraping a public HTML endpoint is
//!    best-effort by construction and WILL be blocked; the archived port audit
//!    said so in 2026 ("switching providers requires API keys"). `ddg` stays
//!    the default so nothing needs configuring to work as before, and an
//!    operator who needs search that actually runs points `search.provider` at
//!    SearXNG they host or an API they hold a key for.
//!
//! Moderation: the Python tool ran each title/snippet through the
//! ContentModerator provider. Here tags are stripped and entities decoded at
//! parse time, and the coordinator's `middleware::after_tool_call` applies
//! `security::sanitize_tool_output` (HTML escape + injection detection +
//! truncation) to the final output — the same entry-point moderation seam,
//! one layer up.

use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;

/// Where a search actually goes. Resolved per call so a config change takes
/// effect without a restart.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SearchProvider {
    /// Scrape the public DuckDuckGo HTML endpoint. Default, no credential,
    /// and best-effort by construction — see the module docs.
    Ddg,
    /// A SearXNG instance the operator runs. No third-party key, which is why
    /// it is the recommended one for a self-hosted cluster.
    Searxng { base: String },
    Brave { key: String },
    Tavily { key: String },
}

/// Why a search could not be performed. Distinct from "ran, found nothing".
#[derive(Debug, Clone, PartialEq)]
pub enum SearchError {
    /// No query to run.
    MissingQuery,
    /// Transport failure — provider unreachable, DNS, TLS, timeout.
    Unavailable(String),
    /// Provider answered, but not with results: a non-2xx, or a 2xx challenge
    /// page. Carries the status so the operator can tell 403 from 202.
    Blocked { status: u16, detail: String },
    /// Provider answered 2xx with a body this code could not read.
    Parse(String),
    /// The selected provider needs configuration that is absent.
    NotConfigured(String),
}

impl std::fmt::Display for SearchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SearchError::MissingQuery => write!(f, "'query' is required"),
            SearchError::Unavailable(e) => write!(f, "search provider unreachable: {e}"),
            SearchError::Blocked { status, detail } => write!(
                f,
                "search did not run — the provider answered HTTP {status} without results \
                 ({detail}). No sources were retrieved; do not treat this as an empty result set"
            ),
            SearchError::Parse(e) => write!(f, "search provider returned an unreadable body: {e}"),
            SearchError::NotConfigured(e) => write!(f, "search provider is not configured: {e}"),
        }
    }
}

/// Pick the provider from config. `search.provider` names it; the credential
/// or base URL comes from env (a key is a secret and lives in the secret
/// store, never in `noomesh.yaml`).
///
/// When nothing names one, a stored API key does: an operator who adds
/// TAVILY_API_KEY has said which search they want, and making them ALSO set
/// NOO_SEARCH_PROVIDER left the key unused behind the rate-limited scraper.
/// An explicit `ddg` still wins over a present key.
pub(crate) fn resolve_provider() -> Result<SearchProvider, SearchError> {
    let name = env_or_live_yaml("NOO_SEARCH_PROVIDER", "provider");
    let name = match name.trim() {
        "" => implied_provider(has_env("TAVILY_API_KEY"), has_env("BRAVE_SEARCH_API_KEY")).to_string(),
        n => n.to_string(),
    };
    match name.to_ascii_lowercase().as_str() {
        "ddg" | "duckduckgo" => Ok(SearchProvider::Ddg),
        "searxng" | "searx" => {
            let base = env_or_live_yaml("NOO_SEARCH_SEARXNG_URL", "searxng_url");
            if base.trim().is_empty() {
                return Err(SearchError::NotConfigured(
                    "search.provider is searxng but search.searxng_url / \
                     NOO_SEARCH_SEARXNG_URL is empty"
                        .into(),
                ));
            }
            Ok(SearchProvider::Searxng {
                base: base.trim_end_matches('/').to_string(),
            })
        }
        "brave" => env_key("BRAVE_SEARCH_API_KEY").map(|key| SearchProvider::Brave { key }),
        "tavily" => env_key("TAVILY_API_KEY").map(|key| SearchProvider::Tavily { key }),
        other => Err(SearchError::NotConfigured(format!(
            "unknown search provider {other:?} — expected ddg, searxng, brave or tavily"
        ))),
    }
}

/// The `search:` section of noomesh.yaml as the gateway last wrote or loaded
/// it. `None` until the first refresh, which startup does as soon as it caches
/// the config.
///
/// Reading `config::global()` here instead is what made `noo config set
/// search …` look live and change nothing: `global()` is a OnceLock filled at
/// boot, so a provider written to the file took effect only after a gateway
/// recreate (2026-09-28, Tavily on host8). Every config write goes through
/// `routes::settings::mutate_config`, which calls `refresh_live_config`.
static LIVE_SEARCH: std::sync::RwLock<Option<serde_json::Value>> = std::sync::RwLock::new(None);

/// Replace the live `search:` view from a whole config document.
pub(crate) fn refresh_live_config(doc: &serde_json::Value) {
    let section = doc.get("search").cloned().unwrap_or(serde_json::Value::Null);
    if let Ok(mut w) = LIVE_SEARCH.write() {
        *w = Some(section);
    }
}

/// One `search.<field>` string from the live view, or from the boot-time
/// config before the first refresh. A key removed from the live config
/// reads as absent — it does not fall back to the boot value.
fn live_yaml_field(field: &str) -> Option<String> {
    if let Some(section) = LIVE_SEARCH.read().ok().and_then(|g| g.clone()) {
        return section
            .get(field)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);
    }
    let boot = crate::config::global().search.as_ref();
    match field {
        "provider" => boot.and_then(|s| s.provider.clone()),
        "searxng_url" => boot.and_then(|s| s.searxng_url.clone()),
        _ => None,
    }
}

/// Env first (an explicit deployment override), then the live yaml.
fn env_or_live_yaml(env_key: &str, field: &str) -> String {
    if let Ok(v) = std::env::var(env_key) {
        if !v.trim().is_empty() {
            return v;
        }
    }
    live_yaml_field(field).unwrap_or_default()
}

/// The provider an unconfigured install uses: the one whose key is stored,
/// Tavily first (it returns page content, not just links), else the scraper.
fn implied_provider(tavily_key: bool, brave_key: bool) -> &'static str {
    if tavily_key {
        "tavily"
    } else if brave_key {
        "brave"
    } else {
        "ddg"
    }
}

/// Is the key configured? Read through `secret_env` (compose delivers the
/// search keys as `/run/secrets` files, `<NAME>_FILE` pointing at each).
fn has_env(name: &str) -> bool {
    crate::config::secret_env::secret_opt(name).is_some_and(|v| !v.trim().is_empty())
}

fn env_key(name: &str) -> Result<String, SearchError> {
    match crate::config::secret_env::secret(name) {
        Ok(Some(v)) if !v.trim().is_empty() => Ok(v),
        // A named file that cannot be read is a broken mount — say so,
        // naming the path, rather than "unset".
        Err(e) => Err(SearchError::NotConfigured(e.to_string())),
        _ => Err(SearchError::NotConfigured(format!(
            "{name} is unset — the key belongs in the secret store, not noomesh.yaml"
        ))),
    }
}

/// Run a search and format results for the LLM.
///
/// `Ok` means a search RAN: either formatted results, or the literal
/// `"No results found."` when the provider genuinely returned none.
pub async fn search(query: &str, max_results: usize) -> Result<String, SearchError> {
    let query = query.trim();
    if query.is_empty() {
        return Err(SearchError::MissingQuery);
    }
    let max_results = if max_results == 0 { 5 } else { max_results };
    let provider = resolve_provider()?;

    let results = match &provider {
        SearchProvider::Ddg => ddg_search(query, max_results).await?,
        SearchProvider::Searxng { base } => searxng_search(base, query, max_results).await?,
        SearchProvider::Brave { key } => brave_search(key, query, max_results).await?,
        SearchProvider::Tavily { key } => tavily_search(key, query, max_results).await?,
    };

    if results.is_empty() {
        return Ok("No results found.".to_string());
    }
    Ok(format_results(&results))
}

async fn ddg_search(query: &str, max_results: usize) -> Result<Vec<SearchResult>, SearchError> {
    let client = crate::tls::external_client();
    let resp = client
        .post("https://html.duckduckgo.com/html/")
        // The endpoint serves a JS challenge to clients with no UA;
        // ddgs sends a browser UA for the same reason.
        .header(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        )
        .form(&[("q", query)])
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| SearchError::Unavailable(e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(SearchError::Blocked {
            status: status.as_u16(),
            detail: "non-2xx from the DuckDuckGo HTML endpoint".into(),
        });
    }
    let body = resp
        .text()
        .await
        .map_err(|e| SearchError::Parse(e.to_string()))?;

    let results = parse_results(&body, max_results);
    if results.is_empty() {
        // Measured 2026-09-20: a soft block answers 200 or 202 with a ~14 KB
        // page carrying no result markup at all. A real zero-result page still
        // carries the results container, so "no markup whatsoever" is the
        // signal. Reporting this as an empty result set is the lie that let a
        // sourceless report ship.
        return Err(SearchError::Blocked {
            status: status.as_u16(),
            detail: "DuckDuckGo returned a page with no result markup — \
                     rate-limited or challenged"
                .into(),
        });
    }
    Ok(results)
}

/// SearXNG's JSON API: `GET {base}/search?q=…&format=json`, answering
/// `{"results":[{"url","title","content"}, …]}`. The instance must have
/// `json` in `search.formats`; it is not on by default.
async fn searxng_search(
    base: &str,
    query: &str,
    max_results: usize,
) -> Result<Vec<SearchResult>, SearchError> {
    let client = crate::tls::external_client();
    let resp = client
        .get(format!("{base}/search"))
        .query(&[("q", query), ("format", "json")])
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| SearchError::Unavailable(e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(SearchError::Blocked {
            status: status.as_u16(),
            detail: "non-2xx from SearXNG — is `json` enabled in its search.formats?".into(),
        });
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| SearchError::Parse(format!("{e} — is `json` enabled in search.formats?")))?;

    let results = parse_searxng(&body, max_results);
    // SearXNG answers 200 even when its upstream engines all failed, listing
    // them in `unresponsive_engines`. Verified against a live instance on
    // 2026-09-20, which returned `[["duckduckgo","CAPTCHA"],["wikidata",
    // "timeout"]]` alongside perfectly good results from the engines that did
    // answer — so unresponsive engines alone are NOT a failure. Zero results
    // WITH unresponsive engines is: the search did not run, and calling that
    // "No results found." is the same lie this module exists to stop, one
    // provider over.
    if results.is_empty() {
        if let Some(down) = unresponsive_engines(&body) {
            return Err(SearchError::Blocked {
                status: status.as_u16(),
                detail: format!("every SearXNG engine failed ({down})"),
            });
        }
    }
    Ok(results)
}

/// A human-readable list of engines SearXNG reported as unresponsive, or
/// `None` when it reported none.
pub(crate) fn unresponsive_engines(body: &serde_json::Value) -> Option<String> {
    let arr = body.get("unresponsive_engines")?.as_array()?;
    if arr.is_empty() {
        return None;
    }
    let names: Vec<String> = arr
        .iter()
        .map(|e| match e.as_array() {
            // The live shape is a positional pair: [engine, reason].
            Some(pair) if !pair.is_empty() => {
                let name = pair[0].as_str().unwrap_or("?");
                match pair.get(1).and_then(|r| r.as_str()) {
                    Some(reason) => format!("{name}: {reason}"),
                    None => name.to_string(),
                }
            }
            _ => e.as_str().unwrap_or("?").to_string(),
        })
        .collect();
    Some(names.join(", "))
}

pub(crate) fn parse_searxng(body: &serde_json::Value, max_results: usize) -> Vec<SearchResult> {
    body.get("results")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .take(max_results)
                .map(|r| SearchResult {
                    title: clean_text(r.get("title").and_then(|v| v.as_str()).unwrap_or("")),
                    url: r.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    snippet: clean_text(r.get("content").and_then(|v| v.as_str()).unwrap_or("")),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Brave Search API: `GET /res/v1/web/search`, key in `X-Subscription-Token`.
async fn brave_search(
    key: &str,
    query: &str,
    max_results: usize,
) -> Result<Vec<SearchResult>, SearchError> {
    let client = crate::tls::external_client();
    let resp = client
        .get("https://api.search.brave.com/res/v1/web/search")
        .header("X-Subscription-Token", key)
        .header("Accept", "application/json")
        .query(&[("q", query), ("count", &max_results.to_string())])
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| SearchError::Unavailable(e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(SearchError::Blocked {
            status: status.as_u16(),
            detail: "non-2xx from the Brave Search API".into(),
        });
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| SearchError::Parse(e.to_string()))?;
    Ok(parse_brave(&body, max_results))
}

pub(crate) fn parse_brave(body: &serde_json::Value, max_results: usize) -> Vec<SearchResult> {
    body.get("web")
        .and_then(|w| w.get("results"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .take(max_results)
                .map(|r| SearchResult {
                    title: clean_text(r.get("title").and_then(|v| v.as_str()).unwrap_or("")),
                    url: r.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    snippet: clean_text(
                        r.get("description").and_then(|v| v.as_str()).unwrap_or(""),
                    ),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Tavily: `POST /search` with the key in the body.
async fn tavily_search(
    key: &str,
    query: &str,
    max_results: usize,
) -> Result<Vec<SearchResult>, SearchError> {
    let client = crate::tls::external_client();
    let resp = client
        .post("https://api.tavily.com/search")
        .json(&serde_json::json!({
            "api_key": key,
            "query": query,
            "max_results": max_results,
        }))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| SearchError::Unavailable(e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(SearchError::Blocked {
            status: status.as_u16(),
            detail: "non-2xx from the Tavily API".into(),
        });
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| SearchError::Parse(e.to_string()))?;
    Ok(parse_tavily(&body, max_results))
}

pub(crate) fn parse_tavily(body: &serde_json::Value, max_results: usize) -> Vec<SearchResult> {
    body.get("results")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .take(max_results)
                .map(|r| SearchResult {
                    title: clean_text(r.get("title").and_then(|v| v.as_str()).unwrap_or("")),
                    url: r.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    snippet: clean_text(r.get("content").and_then(|v| v.as_str()).unwrap_or("")),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// One parsed search result.
#[derive(Debug, PartialEq)]
pub(crate) struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

static RESULT_LINK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>"#)
        .unwrap()
});

static RESULT_SNIPPET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)<a[^>]*class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>"#).unwrap()
});

static TAG_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<[^>]*>").unwrap());

/// Extract up to `max_results` results from the DuckDuckGo HTML page.
///
/// Links and snippets are matched independently and zipped by position —
/// the page emits exactly one `result__snippet` per `result__a`, in order.
/// A missing snippet degrades to an empty string rather than misaligning.
pub(crate) fn parse_results(html: &str, max_results: usize) -> Vec<SearchResult> {
    let snippets: Vec<String> = RESULT_SNIPPET_RE
        .captures_iter(html)
        .map(|c| clean_text(c.get(1).map(|m| m.as_str()).unwrap_or("")))
        .collect();

    RESULT_LINK_RE
        .captures_iter(html)
        .take(max_results)
        .enumerate()
        .map(|(i, c)| {
            let href = c.get(1).map(|m| m.as_str()).unwrap_or("");
            let title = clean_text(c.get(2).map(|m| m.as_str()).unwrap_or(""));
            SearchResult {
                title,
                url: resolve_redirect_url(href),
                snippet: snippets.get(i).cloned().unwrap_or_default(),
            }
        })
        .collect()
}

/// Format results exactly like the Python tool did.
pub(crate) fn format_results(results: &[SearchResult]) -> String {
    results
        .iter()
        .map(|r| {
            let snippet: String = r.snippet.chars().take(300).collect();
            format!("- {}\n  {}\n  {}", r.title, r.url, snippet)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// DuckDuckGo href values are redirect links of the form
/// `//duckduckgo.com/l/?uddg=<percent-encoded destination>&rut=...`.
/// Extract and decode the destination; pass through anything else.
pub(crate) fn resolve_redirect_url(href: &str) -> String {
    if let Some(pos) = href.find("uddg=") {
        let rest = &href[pos + 5..];
        let encoded = rest.split('&').next().unwrap_or(rest);
        return percent_decode(encoded);
    }
    // Protocol-relative hrefs are still real URLs.
    if let Some(stripped) = href.strip_prefix("//") {
        return format!("https://{stripped}");
    }
    href.to_string()
}

/// Minimal percent-decoder (UTF-8). Invalid sequences pass through verbatim.
pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            // Byte-level slice: `%` may be followed by non-ASCII in a
            // malformed input, and a str slice would panic mid-codepoint.
            if let Some(b) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(b);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Strip tags, decode the common HTML entities, collapse whitespace.
pub(crate) fn clean_text(html: &str) -> String {
    let no_tags = TAG_RE.replace_all(html, " ");
    let decoded = no_tags
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ");
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"
      <div class="result results_links results_links_deep web-result">
        <h2 class="result__title">
          <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fagentic%2Dai&amp;rut=abc123">Agentic <b>AI</b> in 2026</a>
        </h2>
        <a class="result__snippet" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fagentic%2Dai">The state of <b>agentic AI</b> &amp; tooling.</a>
      </div>
      <div class="result">
        <a rel="nofollow" class="result__a" href="https://plain.example.org/page">Plain link</a>
        <a class="result__snippet" href="https://plain.example.org/page">Second snippet</a>
      </div>
    "#;

    #[test]
    fn parses_links_titles_and_snippets_in_order() {
        let results = parse_results(PAGE, 5);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].title, "Agentic AI in 2026");
        assert_eq!(results[0].url, "https://example.com/agentic-ai");
        assert_eq!(results[0].snippet, "The state of agentic AI & tooling.");
        assert_eq!(results[1].title, "Plain link");
        assert_eq!(results[1].url, "https://plain.example.org/page");
        assert_eq!(results[1].snippet, "Second snippet");
    }

    #[test]
    fn respects_max_results() {
        let results = parse_results(PAGE, 1);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn formats_like_the_python_tool() {
        let results = parse_results(PAGE, 1);
        let out = format_results(&results);
        assert_eq!(
            out,
            "- Agentic AI in 2026\n  https://example.com/agentic-ai\n  The state of agentic AI & tooling."
        );
    }

    #[test]
    fn snippet_is_truncated_to_300_chars() {
        let results = vec![SearchResult {
            title: "t".into(),
            url: "u".into(),
            snippet: "x".repeat(400),
        }];
        let out = format_results(&results);
        let snippet_line = out.lines().nth(2).unwrap().trim();
        assert_eq!(snippet_line.chars().count(), 300);
    }

    #[test]
    fn percent_decode_handles_encoded_urls_and_plus() {
        assert_eq!(
            percent_decode("https%3A%2F%2Fexample.com%2Fa%2Db"),
            "https://example.com/a-b"
        );
        assert_eq!(percent_decode("a+b%20c"), "a b c");
        // Invalid escape passes through
        assert_eq!(percent_decode("100%zz"), "100%zz");
    }

    #[test]
    fn redirect_url_extraction() {
        assert_eq!(
            resolve_redirect_url("//duckduckgo.com/l/?uddg=https%3A%2F%2Fx.org%2Fy&rut=zz"),
            "https://x.org/y"
        );
        assert_eq!(
            resolve_redirect_url("//lite.example.com/direct"),
            "https://lite.example.com/direct"
        );
        assert_eq!(
            resolve_redirect_url("https://already.absolute/x"),
            "https://already.absolute/x"
        );
    }

    #[test]
    fn clean_text_strips_tags_and_decodes_entities() {
        assert_eq!(
            clean_text("The <b>state</b> of &amp; things &#x27;quoted&#x27;"),
            "The state of & things 'quoted'"
        );
    }

    #[test]
    fn empty_page_yields_no_results() {
        assert!(parse_results("<html><body>nothing here</body></html>", 5).is_empty());
    }
}

#[cfg(test)]
mod live_config_tests {
    use super::{live_yaml_field, refresh_live_config, LIVE_SEARCH};
    use serde_json::json;

    /// `noo config set search {...}` must change what the next search asks,
    /// without a gateway recreate — and a removed key must stay removed.
    #[test]
    fn a_config_write_changes_the_provider_and_a_removal_sticks() {
        refresh_live_config(&json!({"search": {"provider": "searxng", "searxng_url": "http://noo-searxng:8080"}}));
        assert_eq!(live_yaml_field("provider").as_deref(), Some("searxng"));
        assert_eq!(live_yaml_field("searxng_url").as_deref(), Some("http://noo-searxng:8080"));

        refresh_live_config(&json!({"search": {"provider": "tavily"}}));
        assert_eq!(live_yaml_field("provider").as_deref(), Some("tavily"));
        assert_eq!(live_yaml_field("searxng_url"), None, "a key dropped from the live config must not reappear");

        refresh_live_config(&json!({"other": 1}));
        assert_eq!(live_yaml_field("provider"), None, "removing the section clears the provider");

        *LIVE_SEARCH.write().unwrap() = None;
    }
}

#[cfg(test)]
mod provider_tests {
    use super::{implied_provider, parse_brave, parse_searxng, parse_tavily, unresponsive_engines, SearchError};
    use serde_json::json;

    /// The distinction the whole change exists for: a blocked search must not
    /// be phrased as a fact about the world. A model told "No results found."
    /// reasons onward from it; a model told the search did not run cannot.
    #[test]
    fn a_blocked_search_says_it_did_not_run() {
        let e = SearchError::Blocked {
            status: 202,
            detail: "no result markup".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("did not run"), "{msg}");
        assert!(msg.contains("202"), "status must be visible: {msg}");
        assert!(
            msg.contains("do not treat this as an empty result set"),
            "{msg}"
        );
        assert!(!msg.contains("No results found"), "{msg}");
    }

    #[test]
    fn a_stored_key_picks_the_provider_when_none_is_named() {
        assert_eq!(implied_provider(false, false), "ddg");
        assert_eq!(implied_provider(true, false), "tavily");
        assert_eq!(implied_provider(false, true), "brave");
        assert_eq!(implied_provider(true, true), "tavily");
    }

    #[test]
    fn a_missing_key_names_where_it_belongs() {
        let e = SearchError::NotConfigured("BRAVE_SEARCH_API_KEY is unset — the key belongs in the secret store, not noomesh.yaml".into());
        assert!(e.to_string().contains("secret store"));
    }

    #[test]
    fn searxng_results_are_read() {
        let body = json!({"results":[
            {"title":"A","url":"https://a.example/1","content":"first"},
            {"title":"B","url":"https://b.example/2","content":"second"}
        ]});
        let r = parse_searxng(&body, 5);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].url, "https://a.example/1");
        assert_eq!(r[1].snippet, "second");
    }

    #[test]
    fn brave_results_are_read_from_the_web_block() {
        let body = json!({"web":{"results":[
            {"title":"A","url":"https://a.example/1","description":"desc"}
        ]}});
        let r = parse_brave(&body, 5);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].snippet, "desc");
    }

    #[test]
    fn tavily_results_are_read() {
        let body = json!({"results":[{"title":"T","url":"https://t.example","content":"c"}]});
        let r = parse_tavily(&body, 5);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].title, "T");
    }

    /// A provider answering 2xx with a shape we do not recognise yields no
    /// results rather than panicking — the caller turns that into an error.
    #[test]
    fn an_unrecognised_body_yields_nothing() {
        assert!(parse_searxng(&json!({"oops": 1}), 5).is_empty());
        assert!(parse_brave(&json!({"web": {}}), 5).is_empty());
        assert!(parse_tavily(&json!([]), 5).is_empty());
    }

    #[test]
    fn max_results_is_honoured_per_provider() {
        let body = json!({"results":[
            {"title":"1","url":"u1","content":"c"},
            {"title":"2","url":"u2","content":"c"},
            {"title":"3","url":"u3","content":"c"}
        ]});
        assert_eq!(parse_searxng(&body, 2).len(), 2);
        assert_eq!(parse_tavily(&body, 1).len(), 1);
    }


    /// The exact payload a live SearXNG instance returned on 2026-09-20:
    /// results from the engines that answered, and a positional
    /// `[engine, reason]` list for the ones that did not. Engines being down
    /// is normal and must NOT be treated as a failure when results came back.
    #[test]
    fn unresponsive_engines_are_named_but_do_not_hide_results() {
        let body = json!({
            "results": [{"title": "A", "url": "https://a.example", "content": "c"}],
            "unresponsive_engines": [["duckduckgo", "CAPTCHA"], ["wikidata", "timeout"]]
        });
        assert_eq!(parse_searxng(&body, 5).len(), 1, "good results still parse");
        let down = unresponsive_engines(&body).expect("engines listed");
        assert!(down.contains("duckduckgo: CAPTCHA"), "{down}");
        assert!(down.contains("wikidata: timeout"), "{down}");
    }

    #[test]
    fn no_unresponsive_engines_reads_as_none() {
        assert!(unresponsive_engines(&json!({"results": []})).is_none());
        assert!(unresponsive_engines(&json!({"unresponsive_engines": []})).is_none());
    }
}

/// The real reader path against a real `/run/secrets` file — how the tier-2
/// file flip was proved on a throwaway compose project:
/// the gateway's test binary, run as uid 65532 inside a container whose
/// compose `secrets:` / `<NAME>_FILE` wiring is copied from the shipped
/// gateway service. `<test binary> --ignored --exact
/// web_search::live_file_proof::tavily_key_from_the_secret_file --nocapture`.
#[cfg(test)]
mod live_file_proof {
    use super::{resolve_provider, SearchProvider};

    #[test]
    #[ignore = "needs TAVILY_API_KEY_FILE pointing at a mounted secret file"]
    fn tavily_key_from_the_secret_file() {
        let path = std::env::var("TAVILY_API_KEY_FILE").expect("TAVILY_API_KEY_FILE is not set here");
        assert!(std::env::var("TAVILY_API_KEY").is_err(), "a plain TAVILY_API_KEY is in this environment");
        match resolve_provider() {
            Ok(SearchProvider::Tavily { key }) => {
                println!("PROOF web_search::resolve_provider -> tavily, key {} chars, read from {path}", key.len())
            }
            Ok(_) => panic!("resolved a provider other than tavily"),
            Err(e) => panic!("no provider: {e:?}"),
        }
        let conflicts = crate::config::secret_env::both_set_conflicts();
        println!("PROOF secret_env::both_set_conflicts -> {conflicts:?}");
        for n in ["TELEGRAM_BOT_TOKEN", "GOOGLE_CHAT_CREDENTIALS_JSON", "ANTHROPIC_API_KEY"] {
            match crate::config::secret_env::secret(n) {
                Ok(Some(v)) => println!("PROOF secret_env::secret({n}) -> {} chars", v.len()),
                Ok(None) => println!("PROOF secret_env::secret({n}) -> <unset>"),
                Err(e) => println!("PROOF secret_env::secret({n}) -> ERROR {e}"),
            }
        }
    }
}
