// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi, afterEach } from 'vitest';
import { chunkText, extensionFor, speakable } from './voiceApi';
import { readVoicePref, voiceControls, writeVoicePref } from './useVoice';

describe('voiceControls', () => {
  const up = { stt_available: true, tts_available: true };
  const down = { stt_available: false, tts_available: false };

  it('hides everything with no status', () => {
    expect(voiceControls(null, undefined)).toMatchObject({ mic: 'hidden', speaker: 'hidden' });
  });
  it('hides when the add-on is not enabled, whatever the probes say', () => {
    expect(voiceControls(up, 'disabled').mic).toBe('hidden');
    expect(voiceControls(up, 'unlicensed').speaker).toBe('hidden');
  });
  it('without an add-on state, both down reads as off', () => {
    expect(voiceControls(down, undefined)).toMatchObject({ mic: 'hidden', speaker: 'hidden' });
  });
  it('without an add-on state, one half up shows the other as down', () => {
    const c = voiceControls({ stt_available: true, tts_available: false }, undefined);
    expect(c.mic).toBe('ready');
    expect(c.speaker).toBe('down');
    expect(c.speakerReason).toMatch(/text-to-speech/);
  });
  it('an enabled add-on with both providers down shows both disabled', () => {
    expect(voiceControls(down, 'enabled')).toMatchObject({ mic: 'down', speaker: 'down' });
  });
});

describe('chunkText', () => {
  it('keeps short text whole', () => {
    expect(chunkText('One. Two.', 100)).toEqual(['One. Two.']);
  });
  it('breaks at sentence ends and respects the limit', () => {
    const text = Array.from({ length: 20 }, (_, i) => `Sentence number ${i}.`).join(' ');
    const chunks = chunkText(text, 60);
    expect(chunks.length).toBeGreaterThan(1);
    for (const c of chunks) expect(c.length).toBeLessThanOrEqual(60);
    for (const c of chunks) expect(c.endsWith('.')).toBe(true);
    expect(chunks.join(' ')).toBe(text);
  });
  it('hard-splits one unbroken run', () => {
    const chunks = chunkText('x'.repeat(250), 100);
    expect(chunks.map((c) => c.length)).toEqual([100, 100, 50]);
  });
});

describe('speakable', () => {
  it('drops markdown punctuation and announces code', () => {
    expect(speakable('## Title\n**bold** and `x`\n```js\nlet a=1\n```\n- [link](http://x)')).toBe(
      'Title\nbold and x\n(code block)\nlink',
    );
  });
});

describe('extensionFor', () => {
  it('maps recorder containers', () => {
    expect(extensionFor('audio/webm')).toBe('webm');
    expect(extensionFor('audio/mp4')).toBe('m4a');
    expect(extensionFor('audio/ogg')).toBe('ogg');
  });
});

describe('voice preference storage', () => {
  afterEach(() => vi.restoreAllMocks());

  it('round-trips per user', () => {
    writeVoicePref('ann', 'amy');
    expect(readVoicePref('ann')).toBe('amy');
    expect(readVoicePref('bob')).toBeUndefined();
    writeVoicePref('ann', undefined);
    expect(readVoicePref('ann')).toBeUndefined();
  });

  it('survives storage that throws', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    expect(() => writeVoicePref('ann', 'amy')).not.toThrow();
    expect(readVoicePref('ann')).toBeUndefined();
  });
});
