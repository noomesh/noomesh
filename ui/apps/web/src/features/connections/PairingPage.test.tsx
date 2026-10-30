// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC
// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const H = vi.hoisted(() => ({ post: vi.fn(), remove: vi.fn(), user: { username: 'alice' }, remember: vi.fn() }));
vi.mock('@metis/core', () => ({
  useAuth: () => ({ user: H.user, isLoggedIn: true }),
  useMetisClient: () => ({ POST: H.post, DELETE: H.remove }),
}));
vi.mock('@/components/LoginOverlay', () => ({ LoginOverlay: () => null }));
vi.mock('./pairingReturn', () => ({ takePairingReturn: () => null, rememberPairing: H.remember }));
import { PairingPage } from './PairingPage';
const preview = { id: 'owned-pair', provider: 'google', services: ['gmail'], device_name: 'My execution computer', expires_in: 600 };
beforeEach(() => {
  vi.clearAllMocks(); H.user = { username: 'alice' };
  H.post.mockResolvedValue({ data: preview }); H.remove.mockResolvedValue({ data: { cancelled: true } });
});
afterEach(cleanup);
async function review() {
  fireEvent.change(screen.getByLabelText('Pairing code from your terminal'), { target: { value: 'ABCDE-FGHJK' } });
  fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
  await screen.findByText('My execution computer');
}
describe('phone pairing approval', () => {
  it('shows the requesting device and services before starting provider consent', async () => {
    render(<PairingPage />); await review();
    expect(screen.getByText(/Gmail \(read only\)/)).toBeTruthy();
    expect(H.post).toHaveBeenCalledTimes(1);
    expect(H.post).toHaveBeenCalledWith('/api/connections/pairing/lookup', { body: { code: 'ABCDE-FGHJK' } });
    expect(screen.getByRole('button', { name: 'Continue to Google' })).toBeTruthy();
  });
  it('lets the phone cancel the owned request and notify the CLI', async () => {
    render(<PairingPage />); await review();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel request' }));
    await screen.findByText('Pairing cancelled. Your terminal has been notified.');
    expect(H.remove).toHaveBeenCalledWith('/api/connections/pairing/{id}', { params: { path: { id: 'owned-pair' } } });
  });
  it('does not start authorization for missing or wrong-owner codes', async () => {
    H.post.mockResolvedValue({ error: {} }); render(<PairingPage />);
    fireEvent.change(screen.getByLabelText('Pairing code from your terminal'), { target: { value: 'ABCDE-FGHJK' } });
    fireEvent.click(screen.getByRole('button', { name: 'Review request' }));
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('same Noomesh account'));
    expect(H.post).toHaveBeenCalledTimes(1);
  });
  it('cancels the OAuth session if the phone cannot retain its short-lived return ticket', async () => {
    render(<PairingPage />); await review();
    const session = { session_id: 'owned-oauth' };
    H.post.mockResolvedValue({ data: session }); H.remember.mockImplementation(() => { throw new Error('Storage unavailable'); });
    fireEvent.click(screen.getByRole('button', { name: 'Continue to Google' }));
    await screen.findByText('Storage unavailable');
    await waitFor(() => expect(H.post).toHaveBeenCalledWith('/api/connections/oauth/cancel', { body: { session_id: 'owned-oauth' } }));
  });
});
