// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// The gateway's voice surface, as the chat composer uses it. Every call goes
// through the app's one typed client (the same auth-refreshing fetch as the
// rest of the console) — never a token path of its own.
//
// Contract (gateway-rust/src/routes/communication.rs):
//   GET  /api/voice/status      → { stt_available, tts_available, … } (always 200;
//                                  reachability is probed, not configured)
//   GET  /api/voice/voices      → { voices: [{name, language, description, backend, …}], [error] }
//   POST /api/voice/transcribe  → multipart, field "file" (+ optional "language")
//                                  → { text, language, confidence, duration }
//   POST /api/voice/synthesize  → JSON { text, voice?, speed? } → audio bytes
//                                  (audio/wav or audio/mpeg)
// Errors on transcribe/synthesize are JSON `{ error }` with the provider's
// status (502 unreachable, 503 refused, 400 bad input).
//
// Size: neither route raises axum's default 2 MiB body limit, so a recording
// is capped well below it (MAX_RECORDING_BYTES) and long replies are read
// aloud in sentence-sized chunks.

import type { MetisClient } from '@metis/api';

export interface VoiceStatus {
  stt_available: boolean;
  tts_available: boolean;
  stt_provider?: string;
  tts_provider?: string;
  tts_voice?: string | null;
  tts_voice_count?: number;
}

export interface VoiceOption {
  name: string;
  language?: string;
  description?: string;
  backend?: string;
}

/** Below axum's 2 MiB default body limit, with room for the multipart framing. */
export const MAX_RECORDING_BYTES = 1_900_000;

/** One synthesize request's worth of text: a few sentences, quick to first sound. */
export const TTS_CHUNK_CHARS = 600;

/** Pull a readable message out of an openapi-fetch error body. */
export function errorMessage(error: unknown, status: number, what: string): string {
  if (error && typeof error === 'object' && 'error' in error) {
    const e = (error as { error: unknown }).error;
    if (typeof e === 'string' && e) return `${what} failed: ${e}`;
  }
  if (typeof error === 'string' && error.trim()) return `${what} failed: ${error.trim().slice(0, 200)}`;
  if (status === 401 || status === 403) return `${what} is not allowed for this account (HTTP ${status}).`;
  if (status === 502 || status === 503) return `${what} failed: the voice provider is unreachable.`;
  return `${what} failed (HTTP ${status}).`;
}

/** Voice status, or null when the route is missing / refused / unreachable. */
export async function fetchVoiceStatus(client: MetisClient): Promise<VoiceStatus | null> {
  try {
    const { data, response } = await client.GET('/api/voice/status', {
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok || !data || typeof data !== 'object') return null;
    const d = data as Record<string, unknown>;
    return {
      stt_available: d.stt_available === true,
      tts_available: d.tts_available === true,
      stt_provider: typeof d.stt_provider === 'string' ? d.stt_provider : undefined,
      tts_provider: typeof d.tts_provider === 'string' ? d.tts_provider : undefined,
      tts_voice: typeof d.tts_voice === 'string' ? d.tts_voice : null,
      tts_voice_count: typeof d.tts_voice_count === 'number' ? d.tts_voice_count : undefined,
    };
  } catch {
    return null;
  }
}

/** The voice add-on's state from /health, or undefined when /health does not name it. */
export async function fetchVoiceAddonState(client: MetisClient): Promise<string | undefined> {
  try {
    const { data } = await client.GET('/health', { signal: AbortSignal.timeout(5000) });
    const addons = (data as { addons?: Record<string, unknown> } | undefined)?.addons;
    const v = addons?.voice;
    return typeof v === 'string' ? v : undefined;
  } catch {
    return undefined;
  }
}

export async function fetchVoices(client: MetisClient): Promise<{ voices: VoiceOption[]; error?: string }> {
  const { data, error, response } = await client.GET('/api/voice/voices');
  if (!response.ok) throw new Error(errorMessage(error, response.status, 'Listing voices'));
  const d = (data ?? {}) as { voices?: unknown; error?: unknown };
  const voices = Array.isArray(d.voices)
    ? d.voices
        .filter((v): v is Record<string, unknown> => !!v && typeof v === 'object' && typeof (v as { name?: unknown }).name === 'string')
        .map((v) => ({
          name: v.name as string,
          language: typeof v.language === 'string' ? v.language : undefined,
          description: typeof v.description === 'string' ? v.description : undefined,
          backend: typeof v.backend === 'string' ? v.backend : undefined,
        }))
    : [];
  return { voices, error: typeof d.error === 'string' ? d.error : undefined };
}

/** File extension the STT provider can sniff the container from. */
export function extensionFor(mime: string): string {
  if (mime.includes('webm')) return 'webm';
  if (mime.includes('ogg')) return 'ogg';
  if (mime.includes('mp4') || mime.includes('aac') || mime.includes('m4a')) return 'm4a';
  if (mime.includes('wav')) return 'wav';
  return 'webm';
}

export async function transcribe(client: MetisClient, audio: Blob, signal?: AbortSignal): Promise<string> {
  if (audio.size > MAX_RECORDING_BYTES) {
    throw new Error('Recording is too long to upload — keep it under two minutes.');
  }
  const mime = (audio.type || 'audio/webm').split(';')[0];
  const form = new FormData();
  form.append('file', audio, `recording.${extensionFor(mime)}`);
  const { data, error, response } = await client.POST('/api/voice/transcribe', {
    body: form as never,
    signal,
  });
  if (!response.ok) throw new Error(errorMessage(error, response.status, 'Transcription'));
  const text = (data as { text?: unknown } | undefined)?.text;
  return typeof text === 'string' ? text.trim() : '';
}

export async function synthesize(
  client: MetisClient,
  text: string,
  voice: string | undefined,
  signal?: AbortSignal,
): Promise<Blob> {
  const { data, error, response } = await client.POST('/api/voice/synthesize', {
    body: voice ? { text, voice } : { text },
    parseAs: 'blob',
    signal,
  });
  if (!response.ok || !(data instanceof Blob)) {
    throw new Error(errorMessage(error, response.status, 'Read-aloud'));
  }
  return data;
}

/**
 * Speakable text: code blocks are announced rather than spelled out, and the
 * markdown punctuation a TTS engine would read literally is dropped.
 */
export function speakable(text: string): string {
  return text
    .replace(/```[\s\S]*?(```|$)/g, ' (code block) ')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/!\[[^\]]*\]\([^)]*\)/g, '')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/^\s{0,3}#{1,6}\s+/gm, '')
    .replace(/^\s*[-*+]\s+/gm, '')
    .replace(/[*_~]{1,3}([^*_~\n]+)[*_~]{1,3}/g, '$1')
    .replace(/[ \t]+/g, ' ')
    .replace(/^ +| +$/gm, '')
    .replace(/\n{2,}/g, '\n')
    .trim();
}

/**
 * Split text into chunks of at most `max` characters, breaking at sentence
 * ends where it can, then at spaces, and hard-cutting only a single
 * unbroken run longer than `max`.
 */
export function chunkText(text: string, max = TTS_CHUNK_CHARS): string[] {
  const sentences = text.match(/[^.!?\n]+[.!?]*[\s]*|[\n]+/g) ?? [text];
  const out: string[] = [];
  let cur = '';
  const push = () => {
    const t = cur.trim();
    if (t) out.push(t);
    cur = '';
  };
  for (const s of sentences) {
    if ((cur + s).length <= max) {
      cur += s;
      continue;
    }
    push();
    if (s.length <= max) {
      cur = s;
      continue;
    }
    // One sentence longer than a chunk: split on spaces.
    for (const w of s.split(/(\s+)/)) {
      if ((cur + w).length <= max) {
        cur += w;
      } else {
        push();
        let rest = w;
        while (rest.length > max) {
          out.push(rest.slice(0, max));
          rest = rest.slice(max);
        }
        cur = rest;
      }
    }
  }
  push();
  return out;
}
