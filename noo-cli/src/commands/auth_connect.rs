// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Browser-computer helper. Codes return over an ephemeral IPv4 loopback
//! listener; provider credentials are exchanged and encrypted by the gateway.
use crate::{Globals, Unhandled};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::TcpListener,
    time::{Duration, Instant},
};

fn decode(raw: &str) -> Option<String> {
    let mut bytes = Vec::new();
    let mut chars = raw.bytes();
    while let Some(c) = chars.next() {
        match c {
            b'%' => {
                let hi = (chars.next()? as char).to_digit(16)?;
                let lo = (chars.next()? as char).to_digit(16)?;
                bytes.push((hi * 16 + lo) as u8);
            }
            b'+' => bytes.push(b' '),
            _ => bytes.push(c),
        }
    }
    String::from_utf8(bytes).ok()
}

fn callback(target: &str, expected_state: &str) -> Option<Result<String, String>> {
    let (path, query) = target.split_once('?')?;
    if path != "/noomesh/oauth/callback" {
        return None;
    }
    let mut pairs = std::collections::HashMap::new();
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        if pairs.insert(decode(k)?, decode(v)?).is_some() {
            return None;
        }
    }
    if pairs.get("state").map(String::as_str) != Some(expected_state) {
        return None;
    }
    if pairs.contains_key("error") {
        return Some(Err(
            "Google sign-in was declined. Connect again when ready".into()
        ));
    }
    pairs
        .remove("code")
        .filter(|s| !s.is_empty() && s.len() <= 8192)
        .map(Ok)
}

fn run(g: &Globals, provider: &str, services: Vec<&str>) -> Result<Value, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|_| "Cannot open the local Google callback listener")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "Cannot configure the local callback")?;
    let redirect = format!(
        "http://127.0.0.1:{}/noomesh/oauth/callback",
        listener
            .local_addr()
            .map_err(|_| "Cannot read callback address")?
            .port()
    );
    let start = crate::http::post_json_try(
        g,
        "/api/connections/oauth/start",
        &json!({"provider":provider,"services":services,"client_kind":"desktop","redirect_uri":redirect}),
        true,
        30,
    )?;
    let field = |name| {
        start
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| "Invalid connection setup response".to_string())
    };
    let id = field("session_id")?;
    let ticket = field("completion_token")?;
    let state = field("state")?;
    let url = field("authorization_url")?;
    if !url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?") {
        return Err("Unexpected provider authorization URL".into());
    }
    let browser = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let opened = std::process::Command::new(browser)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok();
    if opened {
        eprintln!("Approve Google access in your browser. Waiting up to 10 minutes…");
    } else {
        eprintln!("Open this URL in a browser ON THIS COMPUTER:\n{url}");
    }
    let result = (|| {
        let deadline = Instant::now() + Duration::from_secs(600);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, peer)) => {
                    if !peer.ip().is_loopback() {
                        continue;
                    }
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                    let mut request = Vec::new();
                    let mut buf = [0; 1024];
                    while request.len() < 16384 && !request.windows(4).any(|s| s == b"\r\n\r\n") {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    let target = std::str::from_utf8(&request)
                        .ok()
                        .and_then(|s| s.lines().next())
                        .and_then(|s| s.strip_prefix("GET "))
                        .and_then(|s| s.strip_suffix(" HTTP/1.1"));
                    let response = target.and_then(|target| callback(target, state));
                    let message = if response.is_some() {
                        "Google response received. Return to your Noomesh terminal to finish connecting."
                    } else {
                        "Invalid callback. Return to Noomesh and try again."
                    };
                    let status = if response.is_some() {
                        "200 OK"
                    } else {
                        "400 Bad Request"
                    };
                    let _ = write!(stream, "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{message}", message.len());
                    if let Some(code) = response {
                        return crate::http::post_json_try(
                            g,
                            "/api/connections/oauth/complete",
                            &json!({"session_id":id,"completion_token":ticket,"state":state,"code":code?}),
                            true,
                            60,
                        );
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100))
                }
                Err(_) => return Err("Local callback listener failed".into()),
            }
        }
        Err("Google sign-in expired. Connect again".into())
    })();
    if result.is_err() {
        let _ = crate::http::post_json_try(
            g,
            "/api/connections/oauth/cancel",
            &json!({"session_id":id}),
            true,
            15,
        );
    }
    result
}

fn run_pairing(g: &Globals, provider: &str, services: Vec<&str>) -> Result<Value, String> {
    let device = std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .unwrap_or_else(|| "execution computer".into());
    let start = crate::http::post_json_try(
        g,
        "/api/connections/pairing/start",
        &json!({"provider":provider,"services":services,"device_name":device.trim()}),
        true,
        30,
    )?;
    let id = start["id"].as_str().ok_or("Invalid pairing response")?;
    let code = start["code"].as_str().ok_or("Invalid pairing response")?;
    let uri = start["verification_uri"]
        .as_str()
        .filter(|u| u.starts_with("https://"))
        .ok_or("Pairing needs an HTTPS phone link")?;
    let expires = start["expires_in"].as_u64().unwrap_or(600).clamp(1, 600);
    let interval = start["interval"].as_u64().unwrap_or(5).clamp(5, 30);
    eprintln!("On your phone, open:\n{uri}\n\nPairing code: {code}\n\nSign in to the same Noomesh account as this CLI, enter the code, and approve access.\nWaiting up to {} minutes…", expires.div_ceil(60));
    let path = format!("/api/connections/pairing/{id}");
    let result = (|| {
        let deadline = Instant::now() + Duration::from_secs(expires);
        loop {
            let response = crate::http::get_json_try(g, &path, true, 20)?;
            match response["status"].as_str() {
                Some("connected") => {
                    let id = response["account_id"]
                        .as_str()
                        .ok_or("Invalid connection result")?;
                    return Ok(json!({"id":id,"status":"connected"}));
                }
                Some("pending" | "authorizing") => {}
                Some("cancelled") => return Err("Pairing cancelled. Start again when ready".into()),
                Some("expired") => break,
                _ => return Err("Unexpected pairing status".into()),
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(
                Duration::from_secs(interval)
                    .min(deadline.saturating_duration_since(Instant::now())),
            );
        }
        Err("Pairing expired. Run the connect command again for a new code".into())
    })();
    if result.is_err() {
        let _ = crate::http::delete_json_try(g, &path, true, 15);
    }
    result
}

pub fn auth_connect(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if args.first().map(String::as_str) != Some("google") {
        return Err(Unhandled);
    }
    let mut services = Vec::new();
    let mut pairing = false;
    for flag in &args[1..] {
        if flag == "--pair" {
            if pairing {
                return Err(Unhandled);
            }
            pairing = true;
            continue;
        }
        let service = match flag.as_str() {
            "--drive" => "google_drive",
            "--gmail" => "gmail",
            _ => return Err(Unhandled),
        };
        if services.contains(&service) {
            return Err(Unhandled);
        }
        services.push(service);
    }
    if services.is_empty() {
        services.extend(["google_drive", "gmail"]);
    }
    match if pairing {
        run_pairing(g, "google", services)
    } else {
        run(g, "google", services)
    } {
        Ok(value) => {
            if g.json {
                println!("{value}");
            } else {
                println!("Google account connected. Open Connections to choose folders, drives or labels.");
            }
            Ok(0)
        }
        Err(detail) => {
            eprintln!("{detail}");
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn callback_requires_exact_path_state_and_unique_parameters() {
        assert_eq!(
            callback("/noomesh/oauth/callback?state=s&code=a%2Bb", "s")
                .unwrap()
                .unwrap(),
            "a+b"
        );
        for path in [
            "/other?state=s&code=x",
            "/noomesh/oauth/callback?state=wrong&code=x",
            "/noomesh/oauth/callback?state=s&state=s&code=x",
            "/noomesh/oauth/callback?state=s&code=%xx",
        ] {
            assert!(callback(path, "s").is_none());
        }
        assert!(
            callback("/noomesh/oauth/callback?state=s&error=access_denied", "s")
                .unwrap()
                .is_err()
        );
    }
}
