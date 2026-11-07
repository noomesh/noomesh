// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi } from 'vitest';

// i515c: the console's access token is never in script-readable storage.
describe('the web token store', () => {
  it('purges the old localStorage copy and never writes the token there', async () => {
    localStorage.setItem('pai_token', 'old-jwt');
    vi.resetModules();
    const { tokenStore } = await import('./client');
    expect(localStorage.getItem('pai_token')).toBeNull();

    await tokenStore.set('new-jwt');
    expect(await tokenStore.get()).toBe('new-jwt');
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i)!;
      expect(localStorage.getItem(k)).not.toContain('new-jwt');
    }
    expect(sessionStorage.length).toBe(0);
  });
});
