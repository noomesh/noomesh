// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC
// @vitest-environment jsdom
import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const H = vi.hoisted(() => ({ post: vi.fn(), invalidate: vi.fn() }));
vi.mock('@metis/core', () => ({
  useAuth: () => ({ user: { username: 'alice' } }),
  useMetisClient: () => ({ POST: H.post }),
  useQueryClient: () => ({ invalidateQueries: H.invalidate }),
}));
import { useGoogleConnect } from './useConnections';

class Channel {
  static current: Channel;
  onmessage?: (event: MessageEvent) => void;
  close = vi.fn();
  constructor(public name: string) {
    Channel.current = this;
  }
  receive(data: unknown) {
    this.onmessage?.({ data } as MessageEvent);
  }
}
const session = {
  session_id: 'session-a',
  completion_token: 'private-ticket',
  state: 'random-state',
  authorization_url:
    'https://accounts.google.com/o/oauth2/v2/auth?state=random-state',
  expires_in: 600,
};
const popup = { location: { href: '' }, close: vi.fn() };
beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal('BroadcastChannel', Channel);
  vi.spyOn(window, 'open').mockReturnValue(popup as unknown as Window);
  H.post.mockImplementation(async (path: string) =>
    path.endsWith('/start')
      ? { data: session }
      : { data: { id: 'account-a', status: 'connected' } },
  );
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('Google browser authorization', () => {
  it('keeps the completion ticket out of the URL and ignores unrelated and duplicate responses', async () => {
    const { result } = renderHook(useGoogleConnect);
    let promise!: Promise<void>;
    await act(async () => {
      promise = result.current.connect(['gmail']);
    });
    expect(Channel.current.name).toBe('noomesh:oauth:random-state');
    expect(popup.location.href).toBe(session.authorization_url);
    expect(popup.location.href).not.toContain('private-ticket');
    Channel.current.receive({
      type: 'noomesh:oauth-result',
      state: 'another-state',
      code: 'foreign-code',
    });
    expect(H.post).toHaveBeenCalledTimes(1);
    await act(async () => {
      Channel.current.receive({
        type: 'noomesh:oauth-result',
        state: session.state,
        code: 'single-code',
      });
      Channel.current.receive({
        type: 'noomesh:oauth-result',
        state: session.state,
        code: 'single-code',
      });
      await promise;
    });
    expect(
      H.post.mock.calls.filter(([path]) => path.endsWith('/complete')),
    ).toHaveLength(1);
    expect(H.post).toHaveBeenCalledWith('/api/connections/oauth/complete', {
      body: {
        session_id: 'session-a',
        completion_token: 'private-ticket',
        state: 'random-state',
        code: 'single-code',
      },
    });
    expect(H.invalidate).toHaveBeenCalledWith({
      queryKey: ['connections', 'alice'],
    });
    expect(result.current.pending).toBe(false);
    expect(Channel.current.close).toHaveBeenCalled();
  });

  it('cancels declined consent without attempting code exchange', async () => {
    const { result } = renderHook(useGoogleConnect);
    let promise!: Promise<void>;
    await act(async () => {
      promise = result.current.connect(['google_drive'], 'draft-a');
    });
    const rejection = expect(promise).rejects.toThrow('declined');
    await act(async () => {
      Channel.current.receive({
        type: 'noomesh:oauth-result',
        state: session.state,
        error: 'access_denied',
      });
      await rejection;
    });
    expect(H.post.mock.calls.some(([path]) => path.endsWith('/complete'))).toBe(
      false,
    );
    expect(H.post).toHaveBeenCalledWith('/api/connections/oauth/cancel', {
      body: { session_id: session.session_id },
    });
    expect(H.post.mock.calls[0][1].body.account_id).toBe('draft-a');
  });

  it('does not create sessions when pop-ups are blocked', async () => {
    vi.mocked(window.open).mockReturnValue(null);
    const { result } = renderHook(useGoogleConnect);
    await expect(result.current.connect(['gmail'])).rejects.toThrow(
      'Allow pop-ups',
    );
    expect(H.post).not.toHaveBeenCalled();
  });
});
