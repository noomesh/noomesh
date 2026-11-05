// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Provider-independent handoff. A code locates a request only within the
//! signed-in owner's account; it never authenticates a phone or an OAuth grant.
use crate::integrations::{crypto::hash, oauth, provider, ClientKind, Error, IntegrationConfig};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    pub provider: String,
    pub services: Vec<String>,
    pub device_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Code {
    pub code: String,
}

fn new_code() -> String {
    let bytes = rand::random::<[u8; 10]>();
    let chars: String = bytes
        .iter()
        .map(|b| ALPHABET[(b & 31) as usize] as char)
        .collect();
    format!("{}-{}", &chars[..5], &chars[5..])
}

fn normalize(raw: &str) -> Result<String, Error> {
    if raw.len() > 32 {
        return Err(Error::Invalid(
            "Enter the pairing code shown in your terminal".into(),
        ));
    }
    let code: String = raw
        .chars()
        .filter(|c| *c != '-' && !c.is_ascii_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if code.len() != 10 || !code.bytes().all(|b| ALPHABET.contains(&b)) {
        return Err(Error::Invalid(
            "Enter the pairing code shown in your terminal".into(),
        ));
    }
    Ok(code)
}

pub async fn start(
    db: &PgPool,
    config: &IntegrationConfig,
    owner: Uuid,
    request: Start,
) -> Result<Value, Error> {
    provider::get(&request.provider)?.scopes(&request.services)?;
    if !oauth::ready(config, &request.provider, ClientKind::Web) {
        return Err(Error::Unavailable("Phone approval needs a configured Web OAuth client and a registered HTTPS callback reachable from your phone. The local browser flow is still available".into()));
    }
    let device = request.device_name.trim();
    if device.is_empty() || device.len() > 100 || device.chars().any(char::is_control) {
        return Err(Error::Invalid(
            "Use a device name between 1 and 100 characters".into(),
        ));
    }
    let callback = provider::redirect(&config.app(&request.provider), ClientKind::Web, None)?;
    let origin = reqwest::Url::parse(&callback)
        .expect("validated callback")
        .origin()
        .ascii_serialization();
    let id = Uuid::new_v4();
    let code = new_code();
    let mut tx = db.begin().await?;
    // Serializes the per-owner cap with erasure and other starts.
    sqlx::query("SELECT user_uuid FROM noo_users WHERE user_uuid=$1 FOR UPDATE")
        .bind(owner)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM noo_integration_oauth_sessions WHERE owner_uuid=$1 AND id IN (SELECT session_id FROM noo_integration_pairings WHERE owner_uuid=$1 AND expires_at<=now())")
        .bind(owner).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM noo_integration_pairings WHERE owner_uuid=$1 AND expires_at<=now()")
        .bind(owner)
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM noo_integration_pairings WHERE owner_uuid=$1 AND status IN ('pending','authorizing')")
        .bind(owner).fetch_one(&mut *tx).await?;
    if count >= 5 {
        return Err(Error::Invalid(
            "Finish or cancel an existing pairing before starting another".into(),
        ));
    }
    sqlx::query("INSERT INTO noo_integration_pairings (id,owner_uuid,code_hash,provider,services,device_name,expires_at) VALUES ($1,$2,$3,$4,$5,$6,now()+interval '10 minutes')")
        .bind(id).bind(owner).bind(hash(&normalize(&code)?)).bind(&request.provider).bind(&request.services).bind(device).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(
        json!({"id":id,"code":code,"verification_uri":format!("{origin}/#/connect"),"expires_in":600,"interval":5}),
    )
}

pub async fn lookup(db: &PgPool, owner: Uuid, code: &str) -> Result<Value, Error> {
    let row: Option<(Uuid,String,Vec<String>,String,i64)> = sqlx::query_as("SELECT id,provider,services,device_name,GREATEST(0,extract(epoch FROM expires_at-now())::bigint) FROM noo_integration_pairings WHERE owner_uuid=$1 AND code_hash=$2 AND expires_at>now() AND status='pending'")
        .bind(owner).bind(hash(&normalize(code)?)).fetch_optional(db).await?;
    let (id, provider, services, device_name, expires_in) = row.ok_or_else(invalid_code)?;
    Ok(
        json!({"id":id,"provider":provider,"services":services,"device_name":device_name,"expires_in":expires_in}),
    )
}

fn invalid_code() -> Error {
    Error::Invalid("Code not found, expired, or already used. Sign in to the same Noomesh account as the terminal and try again".into())
}

pub async fn approve(
    db: &PgPool,
    config: &IntegrationConfig,
    owner: Uuid,
    code: &str,
    origin: Option<&str>,
) -> Result<Value, Error> {
    // Preview grants nothing. The explicit Continue action consumes the code
    // atomically, before creating exactly one ordinary Web OAuth session.
    let preview = lookup(db, owner, code).await?;
    let provider_id = preview["provider"].as_str().expect("provider");
    let callback = provider::redirect(&config.app(provider_id), ClientKind::Web, None)?;
    if origin
        != Some(
            reqwest::Url::parse(&callback)
                .expect("callback")
                .origin()
                .ascii_serialization()
                .as_str(),
        )
    {
        return Err(Error::Invalid(
            "Open the pairing link shown in your terminal".into(),
        ));
    }
    let id = Uuid::parse_str(preview["id"].as_str().expect("id")).expect("uuid");
    let claimed = sqlx::query("UPDATE noo_integration_pairings SET status='authorizing' WHERE id=$1 AND owner_uuid=$2 AND status='pending' AND expires_at>now()")
        .bind(id).bind(owner).execute(db).await?.rows_affected();
    if claimed != 1 {
        return Err(invalid_code());
    }
    let result = oauth::start(
        db,
        config,
        owner,
        oauth::Start {
            provider: provider_id.to_string(),
            services: serde_json::from_value(preview["services"].clone()).expect("services"),
            client_kind: ClientKind::Web,
            redirect_uri: None,
            account_id: None,
        },
        origin,
    )
    .await;
    let session = match result {
        Ok(session) => session,
        Err(error) => {
            cancel(db, owner, id).await?;
            return Err(error);
        }
    };
    let session_id =
        Uuid::parse_str(session["session_id"].as_str().expect("session")).expect("uuid");
    let linked = sqlx::query("UPDATE noo_integration_pairings SET session_id=$3 WHERE id=$1 AND owner_uuid=$2 AND status='authorizing' AND expires_at>now()")
        .bind(id).bind(owner).bind(session_id).execute(db).await?.rows_affected();
    if linked != 1 {
        crate::repo::integrations::cancel(db, owner, session_id).await?;
        return Err(invalid_code());
    }
    let mut session = session;
    // OAuth never outlives its parent handoff from the phone's perspective.
    session["expires_in"] = preview["expires_in"].clone();
    Ok(session)
}

pub async fn status(db: &PgPool, owner: Uuid, id: Uuid) -> Result<Value, Error> {
    let row: Option<(String,bool,Option<Uuid>)> = sqlx::query_as("SELECT status,expires_at>now(),account_id FROM noo_integration_pairings WHERE id=$1 AND owner_uuid=$2")
        .bind(id).bind(owner).fetch_optional(db).await?;
    let (status, valid, account_id) = row.ok_or(Error::NotFound)?;
    Ok(
        json!({"status":if !valid && status!="connected" && status!="cancelled" {"expired"} else {&status},"account_id":account_id}),
    )
}

pub async fn cancel(db: &PgPool, owner: Uuid, id: Uuid) -> Result<bool, Error> {
    let mut tx = db.begin().await?;
    sqlx::query("SELECT user_uuid FROM noo_users WHERE user_uuid=$1 FOR UPDATE")
        .bind(owner)
        .execute(&mut *tx)
        .await?;
    let row: Option<Option<Uuid>> = sqlx::query_scalar("UPDATE noo_integration_pairings SET status='cancelled' WHERE id=$1 AND owner_uuid=$2 AND status IN ('pending','authorizing') RETURNING session_id")
        .bind(id).bind(owner).fetch_optional(&mut *tx).await?;
    if let Some(Some(session_id)) = row {
        sqlx::query("DELETE FROM noo_integration_oauth_sessions WHERE id=$1 AND owner_uuid=$2")
            .bind(session_id)
            .bind(owner)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(row.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codes_accept_display_format_without_ambiguous_characters() {
        let code = new_code();
        assert_eq!(code.len(), 11);
        assert_eq!(normalize(&code).unwrap().len(), 10);
        assert_eq!(normalize(" abcdE-fghjk ").unwrap(), "ABCDEFGHJK");
        for bad in [
            "",
            "ABCDE-FGHIJ",
            "ABCDE-FGH0K",
            "ABCDE-FGHJK-extra",
            "../../../../../",
        ] {
            assert!(normalize(bad).is_err());
        }
    }
}
