// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Secret generation + host probing helpers for the wizard.

use std::io::Read as _;
use std::net::{IpAddr, UdpSocket};
use std::process::Command;

/// `secrets.token_urlsafe(nbytes)` parity: base64url(nbytes of urandom) with
/// `=` padding stripped. 32 bytes → 43 chars, matching the on-disk secret
/// files. Same primitive the Rust gateway's auth secret generator uses.
pub fn token_urlsafe(nbytes: usize) -> String {
    let mut buf = vec![0u8; nbytes];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("read /dev/urandom");
    b64url_nopad(&buf)
}

/// A secret that survives the NATS config parser: strictly alphanumeric
/// with a guaranteed LEADING LETTER. nats-server interpolates `$VAR`
/// references untyped — a value starting with a digit is parsed as a
/// number and the trailing characters become "Parse error on line 1"
/// (found by the sandbox --dist rehearsal; older installs survived on
/// password luck). ~190 bits of entropy at n=32.
pub fn token_alnum(len: usize) -> String {
    const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut buf = vec![0u8; len];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("read /dev/urandom");
    buf.iter()
        .enumerate()
        .map(|(i, b)| {
            let set = if i == 0 { ALPHA } else { ALNUM };
            set[(*b as usize) % set.len()] as char
        })
        .collect()
}

/// URL-safe base64 (RFC 4648 §5) with no padding — the alphabet + trimming
/// that `base64.urlsafe_b64encode(...).rstrip(b"=")` produces.
fn b64url_nopad(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 63) as usize] as char);
        }
    }
    out
}

/// Best-effort LAN IP via the UDP-connect trick, then hostname resolution,
/// then `127.0.0.1` — parity with `step_environment._detect_ip` (minus the
/// NOO_CONTROLLER_IP env override, which the caller handles).
pub fn detect_ip() -> String {
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                let ip = addr.ip().to_string();
                if ip != "0.0.0.0" {
                    return ip;
                }
            }
        }
    }
    // hostname -I first token (avoids 127.0.0.1 when a real IP exists)
    if let Ok(out) = Command::new("hostname").arg("-I").output() {
        if let Some(first) = String::from_utf8_lossy(&out.stdout).split_whitespace().next() {
            if let Ok(IpAddr::V4(_)) = first.parse::<IpAddr>() {
                if first != "127.0.0.1" {
                    return first.to_string();
                }
            }
        }
    }
    "127.0.0.1".to_string()
}

/// GPU model + VRAM (GB) via `nvidia-smi`, mirroring `_detect_gpu`.
pub fn detect_gpu() -> Option<(String, f64)> {
    let out = Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,memory.total",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout);
    let line = line.lines().next()?;
    let mut parts = line.split(',');
    let model = parts.next()?.trim().to_string();
    let vram_mb: f64 = parts.next()?.trim().parse().ok()?;
    Some((model, vram_mb / 1024.0))
}

/// Tier from VRAM, matching `step_prerequisites`: ≥10 GB → 1, ≥4 → 2, else 3.
pub fn tier_for_vram(vram_gb: f64) -> u8 {
    if vram_gb >= 10.0 {
        1
    } else if vram_gb >= 4.0 {
        2
    } else {
        3
    }
}

/// Current local time as `%Y-%m-%d %H:%M:%S` for the .env header stamp.
/// Uses `date` so the value matches the operator's wall clock like Python's
/// `time.strftime`.
pub fn local_timestamp() -> String {
    Command::new("date")
        .arg("+%Y-%m-%d %H:%M:%S")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_urlsafe_shape() {
        let t = token_urlsafe(32);
        assert_eq!(t.len(), 43, "token_urlsafe(32) is 43 chars like Python");
        assert!(!t.contains('='), "padding stripped");
        assert!(
            t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "url-safe alphabet only"
        );
        // Uniqueness across calls (not a fixed value).
        assert_ne!(token_urlsafe(32), token_urlsafe(32));
    }

    #[test]
    fn b64url_known_vectors() {
        assert_eq!(b64url_nopad(b""), "");
        assert_eq!(b64url_nopad(b"f"), "Zg");
        assert_eq!(b64url_nopad(b"fo"), "Zm8");
        assert_eq!(b64url_nopad(b"foo"), "Zm9v");
        assert_eq!(b64url_nopad(b"foob"), "Zm9vYg");
        // byte that exercises the url-safe '-'/'_' substitutions
        assert_eq!(b64url_nopad(&[0xff, 0xff, 0xff]), "____");
        assert_eq!(b64url_nopad(&[0xfb, 0xff, 0xbf]), "-_-_");
    }

    #[test]
    fn tier_boundaries() {
        assert_eq!(tier_for_vram(24.0), 1);
        assert_eq!(tier_for_vram(10.0), 1);
        assert_eq!(tier_for_vram(9.9), 2);
        assert_eq!(tier_for_vram(4.0), 2);
        assert_eq!(tier_for_vram(3.9), 3);
        assert_eq!(tier_for_vram(0.0), 3);
    }
}
