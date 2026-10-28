// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo voice …` — thin HTTP to the gateway's voice routes (WP-V).
//!
//! The Python CLI runs faster-whisper / Piper IN-PROCESS (voice_cli.py),
//! which is why `voice` once sat in the old Python-only list. The Rust gateway now proxies those
//! services natively (gateway-rust routes/communication.rs):
//!   POST /api/voice/transcribe           — multipart audio → whisper service
//!   POST /api/voice/transcribe/detailed  — same, + segment timestamps
//!   POST /api/voice/synthesize           — JSON {text,…} → audio bytes
//!   GET  /api/voice/voices               — installed piper voices + edge-tts
//!   GET  /api/voice/status               — STT/TTS service reachability
//! so the CLI is a thin client of those routes; no ML libraries here.
//!
//! Behaviour deltas vs Python (documented in the WP-V PR):
//!   - `status`/`voices` report what the GATEWAY sees (service reachability /
//!     server-side voice inventory), not which pip packages are installed on
//!     the local host — the local in-process backends died with the port.
//!   - `transcribe --device` has no gateway equivalent → Err(Unhandled)
//!     (a usage error, exit 2; the Python CLI is gone).
//!   - `synthesize -o` is optional here (defaults to `speech` + the
//!     content-type-derived extension); Python required it.
//!   - `speak` plays via the first system player found on PATH
//!     (paplay/aplay/ffplay/afplay) instead of an in-process audio lib.

use crate::http::{get_json, post_bytes, post_json_binary};
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};
use std::path::{Path, PathBuf};

/// Guess the audio MIME type from a file extension (multipart part header;
/// the whisper service sniffs the container anyway, this is advisory).
fn audio_mime(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "wav" => "audio/wav",
        "mp3" => "audio/mpeg",
        "webm" => "audio/webm",
        "ogg" => "audio/ogg",
        "m4a" | "mp4" => "audio/mp4",
        "flac" => "audio/flac",
        _ => "application/octet-stream",
    }
}

/// Build a multipart/form-data body: one binary `file` part plus text fields.
/// Returns (body, content_type). Hand-rolled because ureq has no multipart
/// support and one static upload doesn't justify a dependency.
fn multipart_body(
    file_name: &str,
    file_mime: &str,
    file_bytes: &[u8],
    fields: &[(&str, &str)],
) -> (Vec<u8>, String) {
    // Boundary uniqueness: pid + monotonic-ish nanos is plenty for a body we
    // fully control (no attacker-supplied parts).
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let boundary = format!("paicli{:x}{:x}", std::process::id(), nanos);

    let mut body: Vec<u8> = Vec::with_capacity(file_bytes.len() + 512);
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"file\"; filename=\"{file_name}\"\r\n\
             Content-Type: {file_mime}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(file_bytes);
    body.extend_from_slice(b"\r\n");
    for (name, value) in fields {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
                .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let content_type = format!("multipart/form-data; boundary={boundary}");
    (body, content_type)
}

/// `noo voice transcribe FILE [--model M] [--language L] [--output/-o F]
/// [--timestamps]` — multipart upload to /api/voice/transcribe (or
/// …/detailed when segments are requested). `--device` never leaves the
/// local host in Python and has no gateway field → Unhandled (usage
/// error, exit 2).
pub fn voice_transcribe(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut file: Option<PathBuf> = None;
    let mut model = "base".to_string();
    let mut language: Option<String> = None;
    let mut output: Option<PathBuf> = None;
    let mut timestamps = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--model" => model = iter.next().ok_or(Unhandled)?.clone(),
            "--language" => language = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--output" | "-o" => output = Some(PathBuf::from(iter.next().ok_or(Unhandled)?)),
            "--timestamps" => timestamps = true,
            t if t.starts_with('-') => return Err(Unhandled), // incl. --device
            t => {
                if file.replace(PathBuf::from(t)).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(file) = file else { return Err(Unhandled) };

    let bytes = match std::fs::read(&file) {
        Ok(b) => b,
        Err(e) => fail(
            g.json,
            ExitCode::Generic,
            "file_not_found",
            &format!("cannot read {}: {e}", file.display()),
            None,
        ),
    };

    let mut fields: Vec<(&str, &str)> = vec![("model", model.as_str())];
    if let Some(l) = &language {
        fields.push(("language", l.as_str()));
    }
    let file_name = file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("audio.wav")
        .to_string();
    let (body, content_type) = multipart_body(&file_name, audio_mime(&file), &bytes, &fields);

    let path = if timestamps {
        "/api/voice/transcribe/detailed"
    } else {
        "/api/voice/transcribe"
    };
    // Whisper on CPU is slow — match the gateway's own 120s proxy timeout.
    let resp = post_bytes(g, path, &content_type, &body, true, 120);

    let full_text = resp["text"].as_str().unwrap_or("").to_string();
    let empty = Vec::new();
    let segments = resp["segments"].as_array().unwrap_or(&empty);
    let rendered = if timestamps {
        segments
            .iter()
            .map(|s| {
                format!(
                    "[{:.2}s - {:.2}s] {}",
                    s["start"].as_f64().unwrap_or(0.0),
                    s["end"].as_f64().unwrap_or(0.0),
                    s["text"].as_str().unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        full_text.clone()
    };

    if let Some(out) = &output {
        if let Err(e) = std::fs::write(out, &rendered) {
            fail(
                g.json,
                ExitCode::Generic,
                "write_failed",
                &format!("cannot write {}: {e}", out.display()),
                None,
            );
        }
    }

    if g.json {
        // Python-parity envelope (voice_cli.py): text/language/confidence/
        // duration, + segments when --timestamps, + saved_to when --output.
        let mut payload = serde_json::json!({
            "text": full_text,
            "language": resp["language"],
            "confidence": resp["confidence"],
            "duration": resp["duration"],
        });
        if timestamps {
            payload["segments"] = resp["segments"].clone();
        }
        if let Some(out) = &output {
            payload["saved_to"] = out.display().to_string().into();
        }
        println!("{payload}");
        return Ok(0);
    }

    // The transcript (or the saved path) is the captured value; the
    // language/confidence line is narration.
    if !ui::quiet() {
        println!(
            "{}",
            ui::muted(&format!(
                "language {} · confidence {:.2}% · duration {:.1}s",
                resp["language"].as_str().unwrap_or("?"),
                resp["confidence"].as_f64().unwrap_or(0.0) * 100.0,
                resp["duration"].as_f64().unwrap_or(0.0),
            ))
        );
    }
    if let Some(out) = &output {
        ui::done(&format!("saved transcript to {}", out.display()));
        ui::value(&out.display().to_string());
        let ingest = format!("noo rag ingest {}", out.display());
        ui::guide(&[(ingest.as_str(), "indexes the transcript so it is searchable")]);
    } else {
        ui::value(&rendered);
    }
    Ok(0)
}

/// Shared synthesize call: POST /api/voice/synthesize, return
/// (audio_bytes, extension, backend). Exits on transport/auth/status errors.
fn synthesize_bytes(
    g: &Globals,
    text: &str,
    backend: &Option<String>,
    voice: &Option<String>,
    speed: f64,
) -> (Vec<u8>, &'static str, String) {
    let mut body = serde_json::json!({ "text": text, "speed": speed });
    if let Some(b) = backend {
        body["backend"] = b.as_str().into();
    }
    if let Some(v) = voice {
        body["voice"] = v.as_str().into();
    }
    let resp = post_json_binary(g, "/api/voice/synthesize", &body, true, 60);
    // Python parity: wav unless the service says mpeg/mp3.
    let ext = if resp.content_type.contains("wav") { "wav" } else { "mp3" };
    (resp.bytes, ext, resp.tts_backend)
}

/// `noo voice synthesize TEXT [-o FILE] [--backend B] [--voice V] [--speed S]`
/// — POST /api/voice/synthesize, write the audio bytes to FILE. Python's
/// suffix behavior is kept: a FILE without an extension gets `.wav`/`.mp3`
/// from the response content-type. FILE defaults to `speech` (Python made
/// -o mandatory; the gateway names the download `speech.<ext>` too).
pub fn voice_synthesize(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut text: Option<String> = None;
    let mut output: Option<PathBuf> = None;
    let mut backend: Option<String> = None;
    let mut voice: Option<String> = None;
    let mut speed = 1.0f64;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--output" | "-o" => output = Some(PathBuf::from(iter.next().ok_or(Unhandled)?)),
            "--backend" => backend = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--voice" => voice = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--speed" => {
                speed = iter.next().ok_or(Unhandled)?.parse().map_err(|_| Unhandled)?
            }
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if text.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(text) = text else { return Err(Unhandled) };

    let (audio, ext, tts_backend) = synthesize_bytes(g, &text, &backend, &voice, speed);

    let requested = output.unwrap_or_else(|| PathBuf::from("speech"));
    let out = if requested.extension().is_some() {
        requested
    } else {
        requested.with_extension(ext)
    };
    if let Err(e) = std::fs::write(&out, &audio) {
        fail(
            g.json,
            ExitCode::Generic,
            "write_failed",
            &format!("cannot write {}: {e}", out.display()),
            None,
        );
    }

    if g.json {
        // Python-parity envelope (voice_cli.py synthesize).
        println!(
            "{}",
            serde_json::json!({
                "status": "ok",
                "output": out.display().to_string(),
                "bytes": audio.len(),
                "backend": tts_backend,
                "content_type": if ext == "wav" { "audio/wav" } else { "audio/mpeg" },
            })
        );
    } else {
        // The output path is the captured value; the summary is narration.
        ui::done(&format!("saved {} bytes to {} (backend {tts_backend})", audio.len(), out.display()));
        ui::value(&out.display().to_string());
        ui::guide(&[
            ("noo voice voices", "the voices available for --voice"),
            ("noo voice status", "which TTS backend answered"),
        ]);
    }
    Ok(0)
}

/// System audio players tried in order — first one found on PATH wins.
/// No audio libraries are bundled; playback is delegated to the OS.
const PLAYERS: &[&str] = &["paplay", "aplay", "ffplay", "afplay"];

/// Return the first candidate that exists as an executable file in `path_var`
/// (a PATH-style dir list). Pure on its inputs → unit-testable.
fn first_player_on_path(candidates: &[&str], path_var: &str) -> Option<String> {
    for cand in candidates {
        for dir in std::env::split_paths(path_var) {
            let p = dir.join(cand);
            if !p.is_file() {
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let executable = std::fs::metadata(&p)
                    .map(|m| m.permissions().mode() & 0o111 != 0)
                    .unwrap_or(false);
                if !executable {
                    continue;
                }
            }
            return Some(cand.to_string());
        }
    }
    None
}

/// Build the player argv for an audio file. ffplay needs flags to behave as
/// a headless one-shot player; the others take the file directly. Pure →
/// unit-testable without playing audio.
fn player_invocation(player: &str, file: &str) -> Vec<String> {
    match player {
        "ffplay" => vec![
            "ffplay".into(),
            "-nodisp".into(),
            "-autoexit".into(),
            "-loglevel".into(),
            "error".into(),
            file.into(),
        ],
        "aplay" => vec!["aplay".into(), "-q".into(), file.into()],
        p => vec![p.into(), file.into()],
    }
}

/// `noo voice speak TEXT [--backend B] [--voice V] [--speed S]` — synthesize
/// via the gateway, then play through the first system player found
/// (paplay → aplay → ffplay → afplay), inherited stdio.
pub fn voice_speak(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut text: Option<String> = None;
    let mut backend: Option<String> = None;
    let mut voice: Option<String> = None;
    let mut speed = 1.0f64;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--backend" => backend = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--voice" => voice = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--speed" => {
                speed = iter.next().ok_or(Unhandled)?.parse().map_err(|_| Unhandled)?
            }
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if text.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(text) = text else { return Err(Unhandled) };

    // Resolve the player BEFORE the (slow) synthesis round-trip so a host
    // with no player fails fast and clearly.
    let path_var = std::env::var("PATH").unwrap_or_default();
    let Some(player) = first_player_on_path(PLAYERS, &path_var) else {
        fail(
            g.json,
            ExitCode::Generic,
            "no_audio_player",
            &format!(
                "no system audio player found on PATH (tried: {})",
                PLAYERS.join(", ")
            ),
            Some("install one, e.g. `apt install pulseaudio-utils` (paplay) or `alsa-utils` (aplay)"),
        );
    };

    let (audio, ext, _tts_backend) = synthesize_bytes(g, &text, &backend, &voice, speed);

    let tmp = std::env::temp_dir().join(format!("noo-speak-{}.{ext}", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, &audio) {
        fail(
            g.json,
            ExitCode::Generic,
            "write_failed",
            &format!("cannot write temp audio {}: {e}", tmp.display()),
            None,
        );
    }

    let argv = player_invocation(&player, &tmp.display().to_string());
    let status = std::process::Command::new(&argv[0]).args(&argv[1..]).status();
    let _ = std::fs::remove_file(&tmp);
    match status {
        Ok(s) if s.success() => {
            if g.json {
                // Python-parity envelope (voice_cli.py speak).
                println!(
                    "{}",
                    serde_json::json!({"status": "ok", "action": "speak", "player": player})
                );
            }
            Ok(0)
        }
        Ok(s) => fail(
            g.json,
            ExitCode::Generic,
            "player_failed",
            &format!("{player} exited with {}", s.code().unwrap_or(-1)),
            None,
        ),
        Err(e) => fail(
            g.json,
            ExitCode::Generic,
            "player_failed",
            &format!("failed to run {player}: {e}"),
            None,
        ),
    }
}

/// `noo voice status` — GET /api/voice/status. Reports what the GATEWAY
/// probes: whisper-service reachability + piper/edge-tts availability
/// (Python reported which pip packages were importable locally — that
/// surface has no meaning for the standalone binary).
pub fn voice_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let resp = get_json(g, "/api/voice/status", true, 10);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    // An absent `stt_backend` used to render as the literal "faster-whisper"
    // — naming a backend the gateway never claimed (it sends "none" when STT
    // is unavailable). And the two TTS rows were hardcoded "piper"/"edge-tts"
    // regardless of what the gateway serves; it reports the real set in
    // `tts_backends`.
    println!("{}", ui::header("voice", None));
    println!();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let stt_up = resp["stt_available"].as_bool().unwrap_or(false);
    rows.push(vec![
        ui::glyph_cell(if stt_up { Glyph::Ok } else { Glyph::Err }),
        "stt".into(),
        resp["stt_backend"].as_str().unwrap_or("unknown").to_string(),
        if stt_up { ui::ok("available") } else { ui::err("unavailable") },
    ]);
    match resp["tts_backends"].as_array() {
        Some(backends) if !backends.is_empty() => {
            for b in backends {
                rows.push(vec![
                    ui::glyph_cell(Glyph::Ok),
                    "tts".into(),
                    b.as_str().unwrap_or("?").to_string(),
                    ui::ok("available"),
                ]);
            }
        }
        Some(_) => rows.push(vec![ui::glyph_cell(Glyph::Err), "tts".into(), "none".into(), ui::err("unavailable")]),
        None => rows.push(vec![ui::glyph_cell(Glyph::Warn), "tts".into(), "unknown".into(), ui::state("not reported")]),
    }
    print!("{}", ui::table(&[Col::left(""), Col::left("kind"), Col::left("backend"), Col::left("state")], &rows));
    if !resp["tts_available"].as_bool().unwrap_or(false) {
        println!();
        println!("{}", ui::status_line(Glyph::Warn, "no TTS backend available on the gateway"));
    }
    Ok(0)
}

/// `noo voice voices [--backend B]` — GET /api/voice/voices; the backend
/// filter is applied client-side exactly like the Python CLI.
pub fn voice_voices(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut backend: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--backend" => backend = Some(iter.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }

    let resp = get_json(g, "/api/voice/voices", true, 10);
    let empty = Vec::new();
    let voices: Vec<&serde_json::Value> = resp["voices"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter(|v| match &backend {
            Some(b) => v["backend"].as_str() == Some(b.as_str()),
            None => true,
        })
        .collect();

    if g.json {
        // Python-parity envelope: filtered list + count.
        let list: Vec<serde_json::Value> = voices.iter().map(|v| (*v).clone()).collect();
        println!(
            "{}",
            serde_json::json!({"voices": list, "count": list.len()})
        );
        return Ok(0);
    }

    if voices.is_empty() {
        println!("{}", ui::muted("no voices"));
        return Ok(0);
    }
    println!("{}", ui::header("voices", Some(&format!("{} available", voices.len()))));
    println!();
    let rows: Vec<Vec<String>> = voices
        .iter()
        .take(50)
        .map(|v| {
            vec![
                v["backend"].as_str().unwrap_or("?").to_string(),
                v["name"].as_str().unwrap_or("?").to_string(),
                v["language"].as_str().unwrap_or("?").to_string(),
                ui::muted(v["gender"].as_str().unwrap_or("")),
            ]
        })
        .collect();
    print!("{}", ui::table(&[Col::left("backend"), Col::left("name"), Col::left("lang"), Col::left("gender")], &rows));
    if voices.len() > 50 {
        println!("{}", ui::muted(&format!("  … and {} more", voices.len() - 50)));
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Player selection: command construction only — never plays audio ──

    #[test]
    fn player_invocation_shapes() {
        assert_eq!(player_invocation("paplay", "/t/a.wav"), vec!["paplay", "/t/a.wav"]);
        assert_eq!(player_invocation("aplay", "/t/a.wav"), vec!["aplay", "-q", "/t/a.wav"]);
        assert_eq!(player_invocation("afplay", "/t/a.mp3"), vec!["afplay", "/t/a.mp3"]);
        assert_eq!(
            player_invocation("ffplay", "/t/a.mp3"),
            vec!["ffplay", "-nodisp", "-autoexit", "-loglevel", "error", "/t/a.mp3"]
        );
    }

    /// Drop-cleaned temp dir holding fake player executables.
    struct FakeBin(PathBuf);
    impl FakeBin {
        fn new(names: &[&str]) -> FakeBin {
            let dir = std::env::temp_dir().join(format!(
                "noo-voice-test-{}-{:x}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            for n in names {
                let p = dir.join(n);
                crate::test_exec::write_exec(&p, "#!/bin/sh\n", 0o755);
            }
            FakeBin(dir)
        }
    }
    impl Drop for FakeBin {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn first_player_respects_preference_order() {
        let bins = FakeBin::new(&["aplay", "ffplay"]);
        let path = bins.0.display().to_string();
        // paplay missing → aplay (earlier in PLAYERS than ffplay) wins.
        assert_eq!(first_player_on_path(PLAYERS, &path), Some("aplay".into()));
    }

    #[test]
    fn no_player_found_returns_none() {
        let bins = FakeBin::new(&[]);
        let path = bins.0.display().to_string();
        assert_eq!(first_player_on_path(PLAYERS, &path), None);
    }

    #[cfg(unix)]
    #[test]
    fn non_executable_candidate_is_skipped() {
        use std::os::unix::fs::PermissionsExt;
        let bins = FakeBin::new(&["paplay", "aplay"]);
        // Strip the exec bits from paplay — aplay must win.
        let paplay = bins.0.join("paplay");
        std::fs::set_permissions(&paplay, std::fs::Permissions::from_mode(0o644)).unwrap();
        let path = bins.0.display().to_string();
        assert_eq!(first_player_on_path(PLAYERS, &path), Some("aplay".into()));
    }

    // ── Multipart body construction ──

    #[test]
    fn multipart_body_carries_file_and_fields() {
        let (body, ctype) =
            multipart_body("a.wav", "audio/wav", b"RIFFxxxx", &[("model", "base"), ("language", "en")]);
        let s = String::from_utf8_lossy(&body);
        assert!(ctype.starts_with("multipart/form-data; boundary="));
        let boundary = ctype.split('=').nth(1).unwrap();
        assert!(s.contains(&format!("--{boundary}\r\n")));
        assert!(s.contains("name=\"file\"; filename=\"a.wav\""));
        assert!(s.contains("Content-Type: audio/wav"));
        assert!(s.contains("RIFFxxxx"));
        assert!(s.contains("name=\"model\"\r\n\r\nbase"));
        assert!(s.contains("name=\"language\"\r\n\r\nen"));
        assert!(s.ends_with(&format!("--{boundary}--\r\n")));
    }

    #[test]
    fn audio_mime_by_extension() {
        assert_eq!(audio_mime(Path::new("x.wav")), "audio/wav");
        assert_eq!(audio_mime(Path::new("x.MP3")), "audio/mpeg");
        assert_eq!(audio_mime(Path::new("x.bin")), "application/octet-stream");
        assert_eq!(audio_mime(Path::new("noext")), "application/octet-stream");
    }
}
