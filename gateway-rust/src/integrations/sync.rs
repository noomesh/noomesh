// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Bounded, resumable provider reads. No shared worker, temporary file, URL
//! supplied by a provider, or system/user impersonation enters this pipeline.
use super::{
    content::{self, Document},
    crypto::Vault,
    oauth, provider, Error,
};
use crate::connections::{DriveExposure, GmailExposure, SourcePolicy};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

#[derive(Clone)]
pub struct Page {
    pub docs: Vec<Document>,
    pub cursor: Option<Value>,
    pub skipped: usize,
    /// Hashed IDs observed in this scan, including unchanged documents. Kept
    /// in the encrypted cursor instead of rewriting every document's generation.
    pub retained: BTreeSet<String>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Cursor {
    page: Option<String>,
    folders: VecDeque<String>,
    active: Option<String>,
    visited: BTreeSet<String>,
    label: usize,
    before: i64,
    known: BTreeMap<String, String>,
    retained: BTreeSet<String>,
    candidates: BTreeMap<String, MailRef>,
    fetching: bool,
    offset: usize,
}

#[derive(Serialize, Deserialize)]
struct MailRef {
    date: i64,
    version: String,
}

// Explicit transport boundary lets tests run the real traversal/parser without
// real account data. Production endpoints cannot be reconfigured by users.
pub(crate) trait Api {
    async fn get(
        &self,
        gmail: bool,
        path: &[&str],
        query: &[(String, String)],
        raw: bool,
    ) -> Result<Option<Vec<u8>>, Error>;
}
struct Google<'a> {
    token: &'a str,
}

fn url(gmail: bool, path: &[&str], query: &[(String, String)]) -> Result<reqwest::Url, Error> {
    let mut url = reqwest::Url::parse(if gmail {
        "https://gmail.googleapis.com/gmail/v1/users/me/"
    } else {
        "https://www.googleapis.com/drive/v3/"
    })
    .expect("fixed provider URL");
    {
        let mut segments = url.path_segments_mut().expect("HTTP URL");
        segments.pop_if_empty();
        for part in path {
            if part.is_empty() || part.len() > 1024
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err(Error::Invalid("Invalid provider resource ID".into()));
            }
            segments.push(part);
        }
    }
    url.query_pairs_mut()
        .extend_pairs(query.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    Ok(url)
}

impl Api for Google<'_> {
    async fn get(
        &self,
        gmail: bool,
        path: &[&str],
        query: &[(String, String)],
        _raw: bool,
    ) -> Result<Option<Vec<u8>>, Error> {
        let mut response = provider::http_client()
            .get(url(gmail, path, query)?)
            .bearer_auth(self.token)
            .send()
            .await
            .map_err(|_| Error::Unavailable("Cannot reach Google for private sync".into()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::Reauth);
        }
        if !response.status().is_success() {
            return Err(Error::Unavailable(
                "Google private sync is unavailable; retry or check access".into(),
            ));
        }
        let mut data = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Error::Unavailable("Google private sync was interrupted".into()))?
        {
            if data.len() + chunk.len() > 1024 * 1024 {
                return Ok(None);
            }
            data.extend_from_slice(&chunk);
        }
        Ok(Some(data))
    }
}

async fn get_json(
    api: &impl Api,
    gmail: bool,
    path: &[&str],
    query: Vec<(String, String)>,
) -> Result<Option<Value>, Error> {
    let bytes = api
        .get(gmail, path, &query, false)
        .await?
        .map(zeroize::Zeroizing::new);
    bytes
        .map(|data| {
            serde_json::from_slice(&data)
                .map_err(|_| Error::Unavailable("Invalid Google sync response".into()))
        })
        .transpose()
}

fn truncate(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn revision(value: &Value) -> Result<String, Error> {
    let value = value.as_str().unwrap_or("");
    if value.len() > 256 {
        return Err(Error::Unavailable("Invalid Google resource revision".into()));
    }
    Ok(value.to_string())
}

/// Plain text only. Attachments and HTML never enter a browser renderer or a
/// file parser; multipart messages select text/plain rather than duplicating
/// the HTML alternative. Header values are bounded plain text too.
fn mail_text(part: &Value, depth: usize, output: &mut String) {
    if depth > 20 || output.len() >= content::MAX_TEXT {
        return;
    }
    if part["mimeType"] == "text/plain" && part["filename"].as_str().unwrap_or("").is_empty() {
        if let Some(data) = part["body"]["data"].as_str() {
            if let Ok(decoded) = URL_SAFE_NO_PAD.decode(data.trim_end_matches('=')) {
                let decoded = zeroize::Zeroizing::new(decoded);
                output.push_str(&truncate(
                    &String::from_utf8_lossy(&decoded),
                    content::MAX_TEXT - output.len(),
                ));
            }
        }
    }
    if let Some(parts) = part["parts"].as_array() {
        for child in parts {
            mail_text(child, depth + 1, output);
        }
    }
}

fn message(id: &str, value: &Value) -> Option<Document> {
    let mut text = String::new();
    let headers = value["payload"]["headers"].as_array();
    let header = |name: &str| {
        headers
            .and_then(|hs| {
                hs.iter().find(|h| {
                    h["name"]
                        .as_str()
                        .is_some_and(|s| s.eq_ignore_ascii_case(name))
                })
            })
            .and_then(|h| h["value"].as_str())
            .unwrap_or("")
    };
    for name in ["From", "To", "Date"] {
        text.push_str(&format!("{name}: {}\n", truncate(header(name), 1024)));
    }
    text.push('\n');
    let before = text.len();
    mail_text(&value["payload"], 0, &mut text);
    if text.len() == before {
        return None;
    }
    Some(Document {
        external_id: id.into(),
        title: truncate(header("Subject"), 1024),
        text,
        url: format!("https://mail.google.com/mail/u/0/#all/{id}"),
        version: String::new(),
    })
}

pub(crate) async fn page(
    api: &impl Api,
    policy: &SourcePolicy,
    previous: Option<Value>,
    known: BTreeMap<String, String>,
) -> Result<Page, Error> {
    policy.validate_for_sync().map_err(Error::Invalid)?;
    let initial = previous.is_none();
    let mut c: Cursor = previous
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| Error::Invalid("Invalid sync cursor".into()))?
        .unwrap_or_default();
    if initial { c.known = known; }
    if c.retained.len() > content::MAX_DOCUMENTS as usize
        || c.candidates.len() > content::MAX_DOCUMENTS as usize
        || c.known.len() > 2 * content::MAX_DOCUMENTS as usize
        || c.offset > content::MAX_DOCUMENTS as usize
    {
        return Err(Error::Invalid("Invalid sync inventory".into()));
    }
    let mut docs = Vec::new();
    let mut skipped = 0;
    match policy {
        SourcePolicy::Gmail {
            exposure,
            label_ids,
            lookback_days,
        } => {
            if initial {
                c.before = chrono::Utc::now().timestamp() + 1;
            }
            let after = c.before - i64::from(*lookback_days) * 86400;
            if !c.fetching {
                let mut query = vec![
                    ("maxResults".into(), "20".into()),
                    ("q".into(), format!("after:{after} before:{}", c.before)),
                ];
                if *exposure == GmailExposure::SelectedLabels {
                    let label = label_ids
                        .get(c.label)
                        .ok_or_else(|| Error::Invalid("Invalid label cursor".into()))?;
                    query.push(("labelIds".into(), label.clone()));
                }
                if let Some(token) = &c.page {
                    query.push(("pageToken".into(), token.clone()));
                }
                let list = get_json(api, true, &["messages"], query)
                    .await?
                    .ok_or_else(|| Error::Unavailable("Google mailbox is unavailable".into()))?;
                let rows = list["messages"].as_array();
                if rows.is_some_and(|rows| rows.len() > 20) {
                    return Err(Error::Unavailable(
                        "Google exceeded the sync page limit".into(),
                    ));
                }
                for row in rows.into_iter().flatten() {
                    let id = row["id"]
                        .as_str()
                        .ok_or_else(|| Error::Unavailable("Invalid Gmail item".into()))?;
                    if let Some(value) = get_json(
                        api,
                        true,
                        &["messages", id],
                        vec![("format".into(), "metadata".into()),
                             ("fields".into(), "internalDate,historyId".into())],
                    )
                    .await?
                    {
                        let date = value["internalDate"].as_str().and_then(|s| s.parse().ok())
                            .ok_or_else(|| Error::Unavailable("Invalid Gmail date".into()))?;
                        let version = revision(&value["historyId"])?;
                        c.candidates.insert(id.to_string(), MailRef { date, version });
                    } else {
                        skipped += 1;
                    }
                }
                c.page = list["nextPageToken"].as_str().map(str::to_string);
                if c.page.is_none() {
                    c.label += 1;
                }
                let more = c.page.is_some()
                    || (*exposure == GmailExposure::SelectedLabels && c.label < label_ids.len());
                // Gmail list has no contractual sort option. Select the newest
                // bounded set from metadata across every page and selected label,
                // then fetch bodies. No body for an out-of-window item is imported.
                let mut newest: Vec<_> = c.candidates.iter().map(|(id, m)| (m.date, id.clone())).collect();
                newest.sort_by(|a,b| b.cmp(a));
                for (_, id) in newest.into_iter().skip(content::MAX_DOCUMENTS as usize) {
                    c.candidates.remove(&id);
                }
                if more {
                    return Ok(Page { docs, skipped, retained: c.retained.clone(), cursor: Some(json!(c)) });
                }
                c.fetching = true;
            }
            let mut newest: Vec<_> = c.candidates.iter().collect();
            newest.sort_by(|(a_id,a),(b_id,b)| (b.date,b_id).cmp(&(a.date,a_id)));
            for (id, metadata) in newest.iter().skip(c.offset).take(20) {
                let key = super::crypto::hash(id);
                if !metadata.version.is_empty() && c.known.get(&key) == Some(&metadata.version) {
                    c.retained.insert(key);
                    continue;
                }
                if let Some(value) = get_json(api, true, &["messages", id], vec![("format".into(), "full".into())]).await? {
                    if let Some(mut doc) = message(id, &value) {
                        doc.version = metadata.version.clone();
                        c.retained.insert(key);
                        docs.push(doc);
                    } else { skipped += 1; }
                } else { skipped += 1; }
            }
            c.offset += 20;
            let more = c.offset < newest.len();
            Ok(Page {
                docs,
                skipped,
                retained: c.retained.clone(),
                cursor: if more { Some(json!(c)) } else { None },
            })
        }
        SourcePolicy::GoogleDrive {
            exposure,
            folder_ids,
            drive_id,
        } => {
            let folders = *exposure == DriveExposure::SelectedFolders;
            if folders && initial {
                c.folders = folder_ids.iter().cloned().collect();
            }
            if folders && c.active.is_none() {
                while let Some(folder) = c.folders.pop_front() {
                    if c.visited.insert(folder.clone()) {
                        c.active = Some(folder);
                        break;
                    }
                }
                if c.active.is_none() {
                    return Ok(Page {
                        docs,
                        skipped,
                        retained: c.retained.clone(),
                        cursor: None,
                    });
                }
            }
            if c.visited.len() > 5000 {
                return Err(Error::Invalid(
                    "Folder traversal limit reached; choose fewer folders".into(),
                ));
            }
            let q = match &c.active {
                Some(id) => format!(
                    "'{}' in parents and trashed=false",
                    id.replace('\\', "\\\\").replace('\'', "\\'")
                ),
                None => "trashed=false".into(),
            };
            let mut query = vec![
                ("q".into(), q),
                ("pageSize".into(), "20".into()),
                (
                    "fields".into(),
                    "nextPageToken,incompleteSearch,files(id,name,mimeType,version)".into(),
                ),
                ("orderBy".into(), "modifiedTime desc".into()),
                ("supportsAllDrives".into(), "true".into()),
                ("includeItemsFromAllDrives".into(), "true".into()),
            ];
            if *exposure == DriveExposure::SelectedDrive {
                query.push(("corpora".into(), "drive".into()));
                query.push(("driveId".into(), drive_id.clone().unwrap_or_default()));
            }
            if let Some(token) = &c.page {
                query.push(("pageToken".into(), token.clone()));
            }
            let list = get_json(api, false, &["files"], query)
                .await?
                .ok_or_else(|| Error::Unavailable("Google Drive is unavailable".into()))?;
            if list["incompleteSearch"].as_bool() == Some(true) {
                return Err(Error::Unavailable(
                    "Drive search was incomplete; select one drive or folders".into(),
                ));
            }
            let rows = list["files"].as_array();
            if rows.is_some_and(|rows| rows.len() > 20) {
                return Err(Error::Unavailable(
                    "Google exceeded the sync page limit".into(),
                ));
            }
            for row in rows.into_iter().flatten() {
                if c.retained.len() >= content::MAX_DOCUMENTS as usize { break; }
                let id = row["id"]
                    .as_str()
                    .ok_or_else(|| Error::Unavailable("Invalid Drive item".into()))?;
                let mime = row["mimeType"].as_str().unwrap_or("");
                if mime == "application/vnd.google-apps.folder" {
                    if folders && !c.visited.contains(id) {
                        c.folders.push_back(id.to_string());
                        if c.folders.len() + c.visited.len() > 5000 {
                            return Err(Error::Invalid(
                                "Folder traversal limit reached; choose fewer folders".into(),
                            ));
                        }
                    }
                    continue;
                }
                let key = super::crypto::hash(id);
                let version = revision(&row["version"])?;
                if !version.is_empty() && c.known.get(&key) == Some(&version) {
                    c.retained.insert(key);
                    continue;
                }
                let bytes = if mime == "application/vnd.google-apps.document" {
                    api.get(
                        false,
                        &["files", id, "export"],
                        &[("mimeType".into(), "text/plain".into())],
                        true,
                    )
                    .await?
                } else if matches!(mime, "text/plain" | "text/markdown" | "text/csv") {
                    api.get(
                        false,
                        &["files", id],
                        &[("alt".into(), "media".into())],
                        true,
                    )
                    .await?
                } else {
                    skipped += 1;
                    continue;
                };
                if let Some(bytes) = bytes {
                    let bytes = zeroize::Zeroizing::new(bytes);
                    let Ok(text) = std::str::from_utf8(&bytes) else {
                        skipped += 1;
                        continue;
                    };
                    docs.push(Document {
                        external_id: id.into(),
                        title: truncate(row["name"].as_str().unwrap_or("Untitled"), 1024),
                        text: truncate(text, content::MAX_TEXT),
                        url: format!("https://drive.google.com/file/d/{id}/view"),
                        version,
                    });
                    c.retained.insert(key);
                } else {
                    skipped += 1;
                }
            }
            c.page = list["nextPageToken"].as_str().map(str::to_string);
            if c.page.is_none() {
                c.active = None;
            }
            let more = c.retained.len() < content::MAX_DOCUMENTS as usize
                && (c.page.is_some() || (folders && !c.folders.is_empty()));
            Ok(Page {
                docs,
                skipped,
                retained: c.retained.clone(),
                cursor: if more { Some(json!(c)) } else { None },
            })
        }
    }
}

pub fn spawn(state: Arc<crate::state::AppState>) {
    tokio::spawn(async move {
        loop {
            if let Ok(vault) = Vault::configured() {
                match content::claim(&state.db, &vault).await {
                    Ok(Some(job)) => {
                        let result = async {
                            let credentials = oauth::credential(
                                &state.db,
                                &state.config.integrations,
                                job.owner,
                                job.account,
                            )
                            .await?;
                            if !provider::GOOGLE
                                .granted_services(&credentials.scopes)
                                .iter()
                                .any(|s| s == job.policy.kind())
                            {
                                return Err(Error::Reauth);
                            }
                            let api = Google {
                                token: &credentials.access_token,
                            };
                            let known = if job.cursor.is_none() {
                                content::versions(&state.db, &vault, &job).await?
                            } else { BTreeMap::new() };
                            let page = tokio::time::timeout(
                                std::time::Duration::from_secs(240),
                                page(&api, &job.policy, job.cursor.clone(), known),
                            )
                            .await
                            .map_err(|_| {
                                Error::Unavailable("Google sync page timed out".into())
                            })??;
                            content::commit(
                                &state.db,
                                &vault,
                                &job,
                                &page,
                            )
                            .await?;
                            Ok::<(), Error>(())
                        }
                        .await;
                        if let Err(error) = result {
                            // No provider response, title, content or source policy in logs.
                            if content::fail(&state.db, &job, &error).await.is_err() {
                                tracing::warn!("cannot record private sync retry");
                            }
                        }
                        continue;
                    }
                    Err(_) => tracing::warn!("private sync queue unavailable"),
                    Ok(None) => {}
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fixture {
        calls: Mutex<Vec<(bool, Vec<String>, Vec<(String, String)>)>>,
    }
    impl Api for Fixture {
        async fn get(
            &self,
            gmail: bool,
            path: &[&str],
            query: &[(String, String)],
            raw: bool,
        ) -> Result<Option<Vec<u8>>, Error> {
            self.calls.lock().unwrap().push((
                gmail,
                path.iter().map(|s| s.to_string()).collect(),
                query.to_vec(),
            ));
            if raw {
                return Ok(Some(b"nested private content".to_vec()));
            }
            let v = if gmail {
                json!({"messages":[]})
            } else if query.iter().any(|(k, v)| k == "q" && v.contains("'root'")) {
                json!({"files":[{"id":"child","mimeType":"application/vnd.google-apps.folder"},{"id":"shortcut","mimeType":"application/vnd.google-apps.shortcut","webContentLink":"https://evil.invalid/leak"}]})
            } else {
                json!({"files":[{"id":"leaf","name":"Private file","mimeType":"text/plain"}]})
            };
            Ok(Some(serde_json::to_vec(&v).unwrap()))
        }
    }
    fn fixture() -> Fixture {
        Fixture {
            calls: Mutex::new(Vec::new()),
        }
    }

    #[test]
    fn resource_paths_cannot_change_provider_origin_or_escape_endpoint() {
        for id in [
            "..",
            ".",
            "a/b",
            "x?alt=media",
            "https://evil.invalid",
            "a%2fb",
            "a\\b",
        ] {
            assert!(url(false, &["files", id], &[]).is_err());
        }
        let u = url(
            true,
            &["messages", "abc_123"],
            &[("q".into(), "after:1 & external=secret".into())],
        )
        .unwrap();
        assert_eq!(u.host_str(), Some("gmail.googleapis.com"));
        assert_eq!(u.path(), "/gmail/v1/users/me/messages/abc_123");
    }

    #[test]
    fn multipart_mail_ignores_html_attachments_and_remote_links() {
        let value = json!({"payload":{"mimeType":"multipart/alternative","headers":[{"name":"Subject","value":"Private message"}],"parts":[
            {"mimeType":"text/html","body":{"data":URL_SAFE_NO_PAD.encode("<img src='https://evil.invalid'>HTML canary")}},
            {"mimeType":"text/plain","filename":"attachment.txt","body":{"data":URL_SAFE_NO_PAD.encode("attachment canary")}},
            {"mimeType":"text/plain","body":{"data":URL_SAFE_NO_PAD.encode("plain body canary")}}
        ]}});
        let doc = message("msg1", &value).unwrap();
        assert!(doc.text.contains("plain body canary"));
        assert!(!doc.text.contains("attachment canary"));
        assert!(!doc.text.contains("HTML canary"));
        let mut no_plain = value.clone();
        no_plain["payload"]["parts"].as_array_mut().unwrap().pop();
        assert!(message("msg1", &no_plain).is_none());
        assert!(
            truncate(&"é".repeat(content::MAX_TEXT), content::MAX_TEXT).len() <= content::MAX_TEXT
        );
    }

    #[tokio::test]
    async fn selected_folders_walk_only_descendants_and_never_follow_shortcuts() {
        let api = fixture();
        let policy = serde_json::from_value(
            json!({"kind":"google_drive","exposure":"selected_folders","folder_ids":["root"]}),
        )
        .unwrap();
        let first = page(&api, &policy, None, BTreeMap::new()).await.unwrap();
        assert!(first.docs.is_empty());
        assert_eq!(first.skipped, 1);
        let next = page(&api, &policy, first.cursor, BTreeMap::new()).await.unwrap();
        assert_eq!(next.docs.len(), 1);
        assert!(next.cursor.is_none());
        let calls = api.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert!(calls[1]
            .2
            .iter()
            .any(|(k, v)| k == "q" && v == "'child' in parents and trashed=false"));
        assert_eq!(calls[2].1, vec!["files", "leaf"]);
    }

    #[tokio::test]
    async fn label_selection_is_a_union_with_stable_lookback_across_pages() {
        let api = fixture();
        let policy=serde_json::from_value(json!({"kind":"gmail","exposure":"selected_labels","label_ids":["INBOX","LabelWork"],"lookback_days":7})).unwrap();
        let first = page(&api, &policy, None, BTreeMap::new()).await.unwrap();
        assert!(first.cursor.is_some());
        let second = page(&api, &policy, first.cursor, BTreeMap::new()).await.unwrap();
        assert!(second.cursor.is_none());
        let calls = api.calls.lock().unwrap();
        assert!(calls[0].2.contains(&("labelIds".into(), "INBOX".into())));
        assert!(calls[1]
            .2
            .contains(&("labelIds".into(), "LabelWork".into())));
        assert_eq!(
            calls[0].2.iter().find(|(k, _)| k == "q"),
            calls[1].2.iter().find(|(k, _)| k == "q")
        );
    }

    #[tokio::test]
    async fn empty_picker_drafts_cannot_expand_to_all_content_during_sync() {
        for value in [
            json!({"kind":"gmail","exposure":"selected_labels"}),
            json!({"kind":"google_drive","exposure":"selected_folders"}),
            json!({"kind":"google_drive","exposure":"selected_drive"}),
        ] {
            let policy = serde_json::from_value(value).unwrap();
            assert!(page(&fixture(), &policy, None, BTreeMap::new()).await.is_err());
        }
    }
}
