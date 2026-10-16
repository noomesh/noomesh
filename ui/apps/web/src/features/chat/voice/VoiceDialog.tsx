// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import * as AlertDialog from '@radix-ui/react-alert-dialog';
import { useMetisClient, useQuery } from '@metis/core';
import { Button } from '@/components/ui/button';
import { fetchVoices } from './voiceApi';
import { useVoicePref } from './useVoice';

/**
 * Pick the voice replies are read aloud in. The list is whatever the
 * configured TTS provider serves (`GET /api/voice/voices`); the choice is
 * kept per user in this browser.
 */
export function VoiceDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const client = useMetisClient();
  const [voice, setVoice] = useVoicePref();
  const q = useQuery({
    queryKey: ['voice', 'voices'],
    enabled: open,
    staleTime: 5 * 60_000,
    queryFn: () => fetchVoices(client),
  });
  const voices = q.data?.voices ?? [];
  const known = !voice || voices.some((v) => v.name === voice);

  return (
    <AlertDialog.Root open={open} onOpenChange={onOpenChange}>
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="confirm-overlay" />
        <AlertDialog.Content className="confirm-content voice-dialog" onEscapeKeyDown={() => onOpenChange(false)}>
          <AlertDialog.Title className="confirm-title">Read-aloud voice</AlertDialog.Title>
          <AlertDialog.Description className="confirm-desc">
            The voice the speaker button on each reply uses. Saved for your account in this browser.
          </AlertDialog.Description>
          {q.isLoading ? (
            <p className="voice-note">Loading voices…</p>
          ) : q.isError ? (
            <p className="voice-note err" role="alert">
              {(q.error as Error).message}
            </p>
          ) : (
            <>
              <label className="voice-field">
                <span>Voice</span>
                <select
                  value={voice ?? ''}
                  onChange={(e) => setVoice(e.target.value || undefined)}
                  aria-label="Read-aloud voice"
                >
                  <option value="">Provider default</option>
                  {!known && <option value={voice}>{voice} (not offered now)</option>}
                  {voices.map((v) => (
                    <option key={v.name} value={v.name}>
                      {v.name}
                      {v.language ? ` · ${v.language}` : ''}
                    </option>
                  ))}
                </select>
              </label>
              {!voices.length && (
                <p className="voice-note">
                  {q.data?.error
                    ? `The voice provider did not list its voices: ${q.data.error}`
                    : 'The voice provider offers no voice choice; its default is used.'}
                </p>
              )}
            </>
          )}
          <div className="confirm-actions">
            <AlertDialog.Cancel asChild>
              <Button size="sm">Done</Button>
            </AlertDialog.Cancel>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}
