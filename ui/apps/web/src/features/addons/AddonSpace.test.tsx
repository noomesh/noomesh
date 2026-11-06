// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC
// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, waitFor, cleanup } from '@testing-library/react';
const state = vi.hoisted(() => ({
  auth: { ready: true, isLoggedIn: true, user: { username: 'alice' } },
  open: vi.fn(),
  ui: { addon: 'rhaddon', title: 'Example workspace', canOpen: true, consolePath: '/', framePermissions: ['microphone', 'autoplay'] },
}));
vi.mock('@metis/core', () => ({ useAuth: () => state.auth }));
vi.mock('@/components/LoginOverlay', () => ({ LoginOverlay: () => null }));
vi.mock('./useAddonUis', () => ({ useAddonUis: () => ({ data: [state.ui], isLoading: false }), useOpenAddonUi: () => ({ mutateAsync: state.open, isPending: false }) }));
import { AddonSpace, addonFrameUrl } from './AddonSpace';

describe('Voice Space', () => {
  beforeEach(() => {
    cleanup(); state.open.mockReset(); state.ui.canOpen = true;
    document.head.innerHTML = '<meta name="noo-addon-space" content="rhaddon">';
    state.auth = { ready: true, isLoggedIn: true, user: { username: 'alice' } };
  });
  it('requires an manifest-declared workspace', () => {
    document.head.innerHTML = '';
    render(<AddonSpace />);
    expect(screen.getByRole('status').textContent).toBe('No add-on workspace is configured.');
    expect(state.open).not.toHaveBeenCalled();
  });
  it('embeds only an isolated same-host HTTPS handoff', () => {
    const here = { hostname: 'mesh.test', origin: 'https://mesh.test' } as Location;
    expect(addonFrameUrl('https://mesh.test:8458/__noo/session?code=once', here).origin).toBe('https://mesh.test:8458');
    for (const url of ['https://mesh.test/__noo/session?code=x', 'https://evil.test:8458/__noo/session?code=x',
      'http://mesh.test:8458/__noo/session?code=x', 'https://user:pass@mesh.test:8458/__noo/session?code=x',
      'https://mesh.test:8458/other?code=x', 'https://mesh.test:8458/__noo/session',
      'https://mesh.test:8458/__noo/session?code=x&token=y', 'https://mesh.test:8458/__noo/session?code=x&code=y']) {
      expect(() => addonFrameUrl(url, here)).toThrow('invalid address');
    }
  });
  it('mints on click, limits device permissions, and discards the frame on logout', async () => {
    state.open.mockResolvedValue(`https://${window.location.hostname}:8458/__noo/session?code=once`);
    const view = render(<AddonSpace />);
    expect(state.open).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Open' }));
    const frame = await screen.findByTitle('Example workspace');
    expect(state.open).toHaveBeenCalledWith('rhaddon');
    expect(frame.getAttribute('allow')).toBe(`microphone https://${window.location.hostname}:8458; autoplay https://${window.location.hostname}:8458`);
    expect(frame.getAttribute('sandbox')).not.toContain('allow-top-navigation');
    expect(frame.getAttribute('referrerpolicy')).toBe('no-referrer');
    state.auth = { ...state.auth, isLoggedIn: false };
    view.rerender(<AddonSpace />);
    expect(screen.queryByTitle('Example workspace')).toBeNull();
    state.auth = { ...state.auth, isLoggedIn: true };
    view.rerender(<AddonSpace />);
    expect(screen.queryByTitle('Example workspace')).toBeNull();
    expect(screen.getByRole('button', { name: 'Open' })).toBeTruthy();
  });
  it('does not mint a handoff when can_open is false', () => {
    state.ui.canOpen = false;
    render(<AddonSpace />);
    fireEvent.click(screen.getByRole('button', { name: 'Open' }));
    expect(state.open).not.toHaveBeenCalled();
    expect(screen.queryByTitle('Example workspace')).toBeNull();
  });
  it('explains a blocked frame and clears it when the console CSP refuses it', async () => {
    state.open.mockResolvedValue(`https://${window.location.hostname}:8458/__noo/session?code=once`);
    render(<AddonSpace />);
    fireEvent.click(screen.getByRole('button', { name: 'Open' }));
    await screen.findByTitle('Example workspace');
    const event = new Event('securitypolicyviolation');
    Object.defineProperty(event, 'effectiveDirective', { value: 'frame-src' });
    fireEvent(document, event);
    expect(screen.getByRole('alert').textContent).toContain('Content Security Policy');
    expect(screen.queryByTitle('Example workspace')).toBeNull();
  });
  it('shows the gateway refusal without creating a frame', async () => {
    state.open.mockRejectedValue(new Error('Voice is disabled'));
    render(<AddonSpace />);
    fireEvent.click(screen.getByRole('button', { name: 'Open' }));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toBe('Voice is disabled'));
    expect(screen.queryByTitle('Example workspace')).toBeNull();
  });
});
