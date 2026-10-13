// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Google Drive uploads for heartbeat reports.
//!
//! The bot SA is a member of a Shared Drive (no DWD impersonation needed).
//! Reports get uploaded with `drive.file` scope and a viewable link is
//! returned for chat dispatch.
//!
//! Why not the chat-attachment path: Google's media:upload requires
//! user-context auth (DWD impersonation), but the resulting attachment
//! ref can't be referenced by a bot-context messages.create call —
//! cross-identity attachment refs are forbidden. Drive sidesteps the
//! whole identity-coupling problem.

use serde_json::{json, Value};

const DRIVE_API: &str = "https://www.googleapis.com";

/// Upload a local file to a Drive folder (typically inside a Shared Drive
/// the SA is a member of). Returns the Drive file ID and a webViewLink.
///
/// `folder_id`: Drive folder ID — the part after `/folders/` in the
///   browser URL. For Shared-Drive folders this works the same as for
///   My-Drive folders, plus the call sets `supportsAllDrives=true`.
/// `mime_type`: source content mime type (e.g. `text/markdown`).
/// `convert_to_gdoc`: if true, Drive converts the upload to a native
///   Google Doc (renders markdown headings/lists/bold properly in the
///   browser viewer, which can't render raw `.md` nicely). Set false for
///   non-prose artifacts (CSV, JSON, code) or when raw fidelity matters.
pub async fn upload_to_folder(
    folder_id: &str,
    file_path: &str,
    filename: &str,
    mime_type: &str,
    convert_to_gdoc: bool,
) -> Result<DriveUpload, String> {
    let token = crate::google_auth::drive_file_token().await?;
    let bytes = tokio::fs::read(file_path)
        .await
        .map_err(|e| format!("read {file_path}: {e}"))?;

    // When converting, the metadata mimeType is the *destination* type
    // (Google Docs); the source bytes' mime is set on the file_header
    // part below. Drive uses the metadata mime to decide what to convert
    // INTO. For raw uploads, both are the same.
    let metadata_mime = if convert_to_gdoc {
        "application/vnd.google-apps.document"
    } else {
        mime_type
    };
    let metadata = json!({
        "name": filename,
        "parents": [folder_id],
        "mimeType": metadata_mime,
    });

    let boundary = "mesh_drive_upload_boundary";
    let crlf = "\r\n";
    let meta_part = format!(
        "--{boundary}{crlf}\
         Content-Type: application/json; charset=UTF-8{crlf}{crlf}\
         {metadata}{crlf}",
        metadata = metadata,
    );
    let file_header = format!(
        "--{boundary}{crlf}\
         Content-Type: {mime_type}{crlf}{crlf}"
    );
    let trailer = format!("{crlf}--{boundary}--{crlf}");

    let mut body: Vec<u8> =
        Vec::with_capacity(meta_part.len() + file_header.len() + bytes.len() + trailer.len());
    body.extend_from_slice(meta_part.as_bytes());
    body.extend_from_slice(file_header.as_bytes());
    body.extend_from_slice(&bytes);
    body.extend_from_slice(trailer.as_bytes());

    // supportsAllDrives=true is required when the parent is a Shared Drive
    // folder. fields= asks the response to include id + webViewLink so the
    // caller can paste the link directly into chat.
    let url = format!(
        "{DRIVE_API}/upload/drive/v3/files\
         ?uploadType=multipart\
         &supportsAllDrives=true\
         &fields=id,webViewLink,name"
    );

    let client = crate::tls::external_client();
    let resp = client
        .post(&url)
        .bearer_auth(&token)
        .header(
            "Content-Type",
            format!("multipart/related; boundary={boundary}"),
        )
        .body(body)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
        .map_err(|e| format!("drive upload request: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        // Char-boundary-safe truncation: &txt[..500] could split a UTF-8 char
        // (the error body may be non-ASCII) and panic.
        let end = txt
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= 500)
            .last()
            .unwrap_or(0);
        return Err(format!("drive upload {status}: {}", &txt[..end]));
    }

    let v: Value = resp
        .json()
        .await
        .map_err(|e| format!("drive upload response parse: {e}"))?;
    let id = v
        .get("id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("drive upload response missing id: {v}"))?
        .to_string();
    let link = v
        .get("webViewLink")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("https://drive.google.com/file/d/{id}/view"));
    let name = v
        .get("name")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| filename.to_string());

    Ok(DriveUpload { id, name, link })
}

#[derive(Debug, Clone)]
pub struct DriveUpload {
    pub id: String,
    pub name: String,
    pub link: String,
}
