// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC
// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, waitFor, cleanup } from '@testing-library/react';
const state = vi.hoisted(() => ({
  auth: { ready: true, isLoggedIn: true, user: { username: 'alice' } },
  open: vi.fn(),
}));
vi.mock('@metis/core', () => ({ useAuth: () => state.auth }));
vi.mock('@/components/LoginOverlay', () => ({ LoginOverlay: () => null }));
vi.mock('./useAddonUis', () => ({ useOpenAddonUi: () => ({ mutateAsync: state.open, isPending: false }) }));
import { VoiceSpace, voiceFrameUrl } from './VoiceSpace';

describe('Voice Space', () => {
  beforeEach(() => {
    cleanup(); state.open.mockReset();
    document.head.innerHTML = '<meta name="noo-voice-space-addon" content="rhaddon">';
    state.auth = { ready: true, isLoggedIn: true, user: { username: 'alice' } };
  });
  it('requires an operator-configured workspace', () => {
    document.head.innerHTML = '';
    render(<VoiceSpace />);
    expect(screen.getByRole('status').textContent).toBe('No voice workspace is configured.');
    expect(state.open).not.toHaveBeenCalled();
  });
  it('embeds only an isolated same-host HTTPS handoff', () => {
    const here = { hostname: 'mesh.test', origin: 'https://mesh.test' } as Location;
    expect(voiceFrameUrl('https://mesh.test:8458/__noo/session?code=once', here).origin).toBe('https://mesh.test:8458');
    for (const url of ['https://mesh.test/__noo/session?code=x', 'https://evil.test:8458/__noo/session?code=x',
      'http://mesh.test:8458/__noo/session?code=x', 'https://user:pass@mesh.test:8458/__noo/session?code=x',
      'https://mesh.test:8458/other?code=x', 'https://mesh.test:8458/__noo/session',
      'https://mesh.test:8458/__noo/session?code=x&token=y']) {
      expect(() => voiceFrameUrl(url, here)).toThrow('invalid address');
    }
  });
  it('mints on click, limits device permissions, and discards the frame on logout', async () => {
    state.open.mockResolvedValue(`https://${window.location.hostname}:8458/__noo/session?code=once`);
    const view = render(<VoiceSpace />);
    expect(state.open).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Open voice' }));
    const frame = await screen.findByTitle('Voice workspace');
    expect(state.open).toHaveBeenCalledWith('rhaddon');
    expect(frame.getAttribute('allow')).toBe(`microphone https://${window.location.hostname}:8458; autoplay https://${window.location.hostname}:8458`);
    expect(frame.getAttribute('sandbox')).not.toContain('allow-top-navigation');
    expect(frame.getAttribute('referrerpolicy')).toBe('no-referrer');
    state.auth = { ...state.auth, isLoggedIn: false };
    view.rerender(<VoiceSpace />);
    expect(screen.queryByTitle('Voice workspace')).toBeNull();
    state.auth = { ...state.auth, isLoggedIn: true };
    view.rerender(<VoiceSpace />);
    expect(screen.queryByTitle('Voice workspace')).toBeNull();
    expect(screen.getByRole('button', { name: 'Open voice' })).toBeTruthy();
  });
  it('shows the gateway refusal without creating a frame', async () => {
    state.open.mockRejectedValue(new Error('Voice is disabled'));
    render(<VoiceSpace />);
    fireEvent.click(screen.getByRole('button', { name: 'Open voice' }));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toBe('Voice is disabled'));
    expect(screen.queryByTitle('Voice workspace')).toBeNull();
  });
});
