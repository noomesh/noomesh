// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup, waitFor, act } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';

const H = vi.hoisted(() => ({
  send: vi.fn(),
  status: {} as Record<string, unknown> | null,
  health: {} as Record<string, unknown>,
  transcribe: null as null | (() => { data?: unknown; error?: unknown; response: { ok: boolean; status: number } }),
  synthesize: null as null | (() => { data?: unknown; error?: unknown; response: { ok: boolean; status: number } }),
  posts: [] as { path: string; init: Record<string, unknown> }[],
}));

vi.mock('./useCoordinator', () => ({
  useCoordinator: () => ({
    messages: [{ role: 'metis', text: 'Hello there. How can I help?' }],
    status: 'live',
    send: H.send,
    canSend: true,
    busy: false,
    serving: null,
  }),
}));
vi.mock('./useBackendHealth', () => ({
  useBackendHealth: () => ({ state: 'ready', ready: true, models: [] }),
}));
vi.mock('@metis/core', async (orig) => ({
  ...(await orig<typeof import('@metis/core')>()),
  useAuth: () => ({ user: { username: 'ann' } }),
}));

import { MetisClientContext } from '@metis/core';
import { ChatPane } from './ChatPane';
import { stopPlayback } from './voice/player';

const ok = (data: unknown) => ({ data, response: { ok: true, status: 200 } });

const fakeClient = {
  GET: vi.fn(async (path: string) => {
    if (path === '/api/voice/status') {
      return H.status ? ok(H.status) : { error: 'nope', response: { ok: false, status: 404 } };
    }
    if (path === '/health') return ok(H.health);
    return { error: 'unexpected', response: { ok: false, status: 404 } };
  }),
  POST: vi.fn(async (path: string, init: Record<string, unknown>) => {
    H.posts.push({ path, init });
    if (path === '/api/voice/transcribe') return H.transcribe!();
    if (path === '/api/voice/synthesize') return H.synthesize!();
    return { error: 'unexpected', response: { ok: false, status: 404 } };
  }),
};

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MetisClientContext.Provider value={fakeClient as never}>{ui}</MetisClientContext.Provider>
    </QueryClientProvider>
  );
}

const STATUS_UP = { stt_available: true, tts_available: true };

// ── browser media fakes ────────────────────────────────────────────────────
const tracks = [{ stop: vi.fn() }];
class FakeRecorder {
  static isTypeSupported = (m: string) => m === 'audio/webm;codecs=opus';
  static last: FakeRecorder | null = null;
  state = 'inactive';
  mimeType: string;
  ondataavailable: ((e: { data: Blob }) => void) | null = null;
  onstop: (() => void) | null = null;
  constructor(_s: unknown, o?: { mimeType?: string }) {
    this.mimeType = o?.mimeType ?? '';
    FakeRecorder.last = this;
  }
  start() {
    this.state = 'recording';
  }
  stop() {
    this.state = 'inactive';
    this.ondataavailable?.({ data: new Blob(['opus-bytes'], { type: 'audio/webm' }) });
    this.onstop?.();
  }
}
class FakeAudio {
  static all: FakeAudio[] = [];
  src = '';
  onended: (() => void) | null = null;
  onerror: (() => void) | null = null;
  play = vi.fn(() => Promise.resolve());
  pause = vi.fn();
  constructor() {
    FakeAudio.all.push(this);
  }
}
const getUserMedia = vi.fn();

// jsdom has no layout: the transcript's follow-the-tail scroll is a no-op here.
Element.prototype.scrollTo = function () {} as never;

beforeEach(() => {
  H.send.mockReset();
  H.status = STATUS_UP;
  H.health = { status: 'ok' };
  H.posts = [];
  H.transcribe = () => ok({ text: 'turn on the lights' });
  H.synthesize = () => ok(new Blob(['RIFF'], { type: 'audio/wav' }));
  FakeAudio.all = [];
  FakeRecorder.last = null;
  getUserMedia.mockReset().mockResolvedValue({ getTracks: () => tracks });
  vi.stubGlobal('MediaRecorder', FakeRecorder);
  vi.stubGlobal('Audio', FakeAudio);
  Object.defineProperty(navigator, 'mediaDevices', { value: { getUserMedia }, configurable: true });
  URL.createObjectURL = vi.fn(() => 'blob:x');
  URL.revokeObjectURL = vi.fn();
  try {
    localStorage.clear();
  } catch {
    /* ignore */
  }
});
afterEach(() => {
  stopPlayback();
  cleanup();
  vi.unstubAllGlobals();
});

const mic = () => screen.queryByRole('button', { name: /record a voice message/i });
const speaker = () => screen.queryByRole('button', { name: /read aloud/i });
const box = () => screen.getByLabelText('Message Noomesh') as HTMLInputElement;

describe('voice controls visibility', () => {
  it('hides both controls when neither provider answers', async () => {
    H.status = { stt_available: false, tts_available: false };
    render(wrap(<ChatPane panelHidden />));
    await waitFor(() => expect(fakeClient.GET).toHaveBeenCalledWith('/api/voice/status', expect.anything()));
    // let the query settle
    await act(async () => {});
    expect(mic()).toBeNull();
    expect(speaker()).toBeNull();
  });

  it('hides both controls when the status route is refused or missing', async () => {
    H.status = null;
    render(wrap(<ChatPane panelHidden />));
    await act(async () => {});
    await act(async () => {});
    expect(mic()).toBeNull();
    expect(speaker()).toBeNull();
  });

  it('hides when /health reports the voice add-on disabled', async () => {
    H.health = { addons: { voice: 'disabled' } };
    render(wrap(<ChatPane panelHidden />));
    await act(async () => {});
    await act(async () => {});
    expect(mic()).toBeNull();
    expect(speaker()).toBeNull();
  });

  it('shows both when available', async () => {
    render(wrap(<ChatPane panelHidden />));
    await waitFor(() => expect(mic()).not.toBeNull());
    expect(speaker()).not.toBeNull();
    expect(mic()!.getAttribute('aria-keyshortcuts')).toBe('Alt+M');
  });

  it('shows a down provider disabled with a tooltip when the add-on is on', async () => {
    H.health = { addons: { voice: 'enabled' } };
    H.status = { stt_available: false, tts_available: true };
    render(wrap(<ChatPane panelHidden />));
    await waitFor(() => expect(mic()).not.toBeNull());
    expect((mic() as HTMLButtonElement).disabled).toBe(true);
    expect(mic()!.getAttribute('title')).toMatch(/speech-to-text provider is not responding/);
    expect((speaker() as HTMLButtonElement).disabled).toBe(false);
  });
});

describe('voice input', () => {
  it('records, transcribes and inserts the text without sending', async () => {
    render(wrap(<ChatPane panelHidden />));
    await waitFor(() => expect(mic()).not.toBeNull());
    fireEvent.change(box(), { target: { value: 'please' } });

    await act(async () => fireEvent.click(mic()!));
    expect(getUserMedia).toHaveBeenCalledWith({ audio: true });
    expect(FakeRecorder.last?.mimeType).toBe('audio/webm;codecs=opus');
    expect(screen.getByRole('button', { name: /cancel recording/i })).toBeTruthy();
    const stopBtn = screen.getByRole('button', { name: /stop recording/i });
    expect(stopBtn.getAttribute('aria-pressed')).toBe('true');

    await act(async () => fireEvent.click(stopBtn));
    await waitFor(() => expect(box().value).toBe('please turn on the lights'));

    const call = H.posts.find((p) => p.path === '/api/voice/transcribe')!;
    const form = call.init.body as FormData;
    const file = form.get('file') as File;
    expect(file).toBeInstanceOf(Blob);
    expect(file.name).toBe('recording.webm');
    expect(H.send).not.toHaveBeenCalled();
    expect(tracks[0].stop).toHaveBeenCalled();
  });

  it('Alt+M toggles recording and Esc cancels without uploading', async () => {
    render(wrap(<ChatPane panelHidden />));
    await waitFor(() => expect(mic()).not.toBeNull());
    await act(async () => fireEvent.keyDown(window, { code: 'KeyM', key: 'm', altKey: true }));
    expect(FakeRecorder.last?.state).toBe('recording');
    await act(async () => fireEvent.keyDown(window, { key: 'Escape' }));
    expect(FakeRecorder.last?.state).toBe('inactive');
    await act(async () => {});
    expect(H.posts.some((p) => p.path === '/api/voice/transcribe')).toBe(false);
    expect(box().value).toBe('');
  });

  it('explains a denied microphone', async () => {
    getUserMedia.mockRejectedValue(new DOMException('denied', 'NotAllowedError'));
    render(wrap(<ChatPane panelHidden />));
    await waitFor(() => expect(mic()).not.toBeNull());
    await act(async () => fireEvent.click(mic()!));
    expect((await screen.findByRole('alert')).textContent).toMatch(/Microphone access was denied/);
  });

  it('shows the provider error when transcription fails', async () => {
    H.transcribe = () => ({ error: { error: 'STT provider unreachable' }, response: { ok: false, status: 502 } });
    render(wrap(<ChatPane panelHidden />));
    await waitFor(() => expect(mic()).not.toBeNull());
    await act(async () => fireEvent.click(mic()!));
    await act(async () => fireEvent.click(screen.getByRole('button', { name: /stop recording/i })));
    expect((await screen.findByRole('alert')).textContent).toMatch(/Transcription failed: STT provider unreachable/);
    expect(box().value).toBe('');
  });
});

describe('read-aloud', () => {
  it('plays the reply and toggles to stop', async () => {
    render(wrap(<ChatPane panelHidden />));
    await waitFor(() => expect(speaker()).not.toBeNull());
    await act(async () => fireEvent.click(speaker()!));

    const call = H.posts.find((p) => p.path === '/api/voice/synthesize')!;
    expect(call.init.body).toEqual({ text: 'Hello there. How can I help?' });
    expect(call.init.parseAs).toBe('blob');
    const stop = await screen.findByRole('button', { name: /stop reading aloud/i });
    expect(stop.getAttribute('aria-pressed')).toBe('true');
    expect(FakeAudio.all[0].play).toHaveBeenCalled();

    await act(async () => fireEvent.click(stop));
    expect(FakeAudio.all[0].pause).toHaveBeenCalled();
    expect(screen.getByRole('button', { name: /^read aloud$/i }).getAttribute('aria-pressed')).toBe('false');
  });

  it('returns to idle when the audio ends', async () => {
    render(wrap(<ChatPane panelHidden />));
    await waitFor(() => expect(speaker()).not.toBeNull());
    await act(async () => fireEvent.click(speaker()!));
    await screen.findByRole('button', { name: /stop reading aloud/i });
    await act(async () => FakeAudio.all[0].onended?.());
    expect(screen.getByRole('button', { name: /^read aloud$/i })).toBeTruthy();
  });

  it('uses the voice the user picked', async () => {
    localStorage.setItem('noo_voice:ann', 'en_US-amy-low');
    render(wrap(<ChatPane panelHidden />));
    await waitFor(() => expect(speaker()).not.toBeNull());
    await act(async () => fireEvent.click(speaker()!));
    const call = H.posts.find((p) => p.path === '/api/voice/synthesize')!;
    expect(call.init.body).toEqual({ text: 'Hello there. How can I help?', voice: 'en_US-amy-low' });
  });

  it('shows a synthesis error inline', async () => {
    H.synthesize = () => ({ error: { error: 'TTS provider refused' }, response: { ok: false, status: 503 } });
    render(wrap(<ChatPane panelHidden />));
    await waitFor(() => expect(speaker()).not.toBeNull());
    await act(async () => fireEvent.click(speaker()!));
    expect((await screen.findByRole('alert')).textContent).toMatch(/Read-aloud failed: TTS provider refused/);
  });
});
