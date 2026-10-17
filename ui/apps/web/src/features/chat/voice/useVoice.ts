// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useCallback, useEffect, useState } from 'react';
import { useAuth, useMetisClient, useQuery } from '@metis/core';
import { fetchVoiceAddonState, fetchVoiceStatus, type VoiceStatus } from './voiceApi';

/** `hidden` = voice is off (or unknown); `ready` = usable; `down` = on, but the provider is not answering. */
export type ControlState = 'hidden' | 'ready' | 'down';

export interface VoiceControls {
  mic: ControlState;
  speaker: ControlState;
  /** Tooltip for a `down` control. */
  micReason?: string;
  speakerReason?: string;
}

const HIDDEN: VoiceControls = { mic: 'hidden', speaker: 'hidden' };

/**
 * Decide what the chat shows from the two signals the gateway gives.
 *
 * `/health` names add-ons it knows; when it reports `voice` as anything but
 * `enabled` the controls are hidden. When it is `enabled`, a provider that
 * does not answer shows its control disabled with a tooltip.
 *
 * Today `voice` is not in the gateway's add-on table, so `/health` does not
 * name it (addonState undefined). Then "off" and "both providers down" look
 * the same on the wire, and both hide: a control shows only when at least one
 * half of voice answers, and the half that does not is shown disabled.
 */
export function voiceControls(status: VoiceStatus | null, addonState: string | undefined): VoiceControls {
  if (addonState !== undefined && addonState !== 'enabled') return HIDDEN;
  if (!status) return HIDDEN;
  const on = addonState === 'enabled' || status.stt_available || status.tts_available;
  if (!on) return HIDDEN;
  return {
    mic: status.stt_available ? 'ready' : 'down',
    speaker: status.tts_available ? 'ready' : 'down',
    micReason: status.stt_available ? undefined : 'Voice input unavailable: the speech-to-text provider is not responding.',
    speakerReason: status.tts_available ? undefined : 'Read-aloud unavailable: the text-to-speech provider is not responding.',
  };
}

export const VOICE_STATUS_KEY = ['voice', 'status'] as const;

/**
 * Voice availability for the chat. Polled on mount, every minute after, and
 * again whenever `active` turns true (the chat opening from its rail).
 */
export function useVoiceControls(active = true): VoiceControls & { status: VoiceStatus | null } {
  const client = useMetisClient();
  const q = useQuery({
    queryKey: VOICE_STATUS_KEY,
    refetchInterval: 60_000,
    staleTime: 10_000,
    queryFn: async () => {
      const [status, addon] = await Promise.all([fetchVoiceStatus(client), fetchVoiceAddonState(client)]);
      return { status, addon };
    },
  });
  const { refetch } = q;
  useEffect(() => {
    if (active) void refetch();
  }, [active, refetch]);
  const status = q.data?.status ?? null;
  return { ...voiceControls(status, q.data?.addon), status };
}

// ── Per-user voice preference ─────────────────────────────────────────────
// The gateway has no per-user settings store the console can write, so the
// choice lives in this browser, keyed by username. Storage can be absent or
// throw (private windows, blocked site data): every access is guarded and the
// fallback is the provider's default voice.

const PREF_EVENT = 'noo:voice-pref';
export const prefKey = (user: string) => `noo_voice:${user}`;

export function readVoicePref(user: string): string | undefined {
  try {
    return localStorage.getItem(prefKey(user)) || undefined;
  } catch {
    return undefined;
  }
}

export function writeVoicePref(user: string, voice: string | undefined): void {
  try {
    if (voice) localStorage.setItem(prefKey(user), voice);
    else localStorage.removeItem(prefKey(user));
  } catch {
    /* not persisted; the in-memory choice below still applies this session */
  }
  window.dispatchEvent(new CustomEvent(PREF_EVENT, { detail: { user, voice } }));
}

/** The signed-in user's read-aloud voice (undefined = provider default). */
export function useVoicePref(): [string | undefined, (v: string | undefined) => void] {
  const { user } = useAuth();
  const name = user?.username ?? 'guest';
  const [voice, setVoice] = useState<string | undefined>(() => readVoicePref(name));
  useEffect(() => {
    setVoice(readVoicePref(name));
    const on = (e: Event) => {
      const d = (e as CustomEvent<{ user: string; voice?: string }>).detail;
      if (d?.user === name) setVoice(d.voice);
    };
    window.addEventListener(PREF_EVENT, on);
    return () => window.removeEventListener(PREF_EVENT, on);
  }, [name]);
  const set = useCallback((v: string | undefined) => writeVoicePref(name, v), [name]);
  return [voice, set];
}
