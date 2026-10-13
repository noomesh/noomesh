// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi, beforeEach } from 'vitest';

const H = vi.hoisted(() => ({
  post: vi.fn(),
  // Capture the options useMutation was built with so mutationFn can be driven
  // directly — no React, no query client.
  lastMutation: { current: null as null | Record<string, unknown> },
}));

vi.mock('@metis/core', () => ({
  useMetisClient: () => ({ POST: H.post }),
  useMutation: (opts: Record<string, unknown>) => {
    H.lastMutation.current = opts;
    return {};
  },
}));

import { useMintBootstrapToken, mintBody, type MintRequest } from './useMintBootstrapToken';

const run = async (req: MintRequest) => {
  useMintBootstrapToken();
  const fn = H.lastMutation.current?.mutationFn as (r: MintRequest) => Promise<unknown>;
  return fn(req);
};

const OK = {
  status: 'ok',
  id: 'tok-1',
  token: 'RAW',
  expires_at: '2026-09-28T00:00:00Z',
  node_name: 'n1',
  install_command: 'command -v noo >/dev/null || curl -fsSL https://x/install.sh | sh',
  enroll_command: 'noo enroll noo1.BLOB',
  provision_command: 'noo cluster provision n1 --wait',
  joins_tailnet: true,
  tailnet_skipped: null,
  ca_sha256: 'ab',
  controller_url: 'https://ctl:8080',
};

describe('useMintBootstrapToken', () => {
  beforeEach(() => H.post.mockReset());

  it('mints on the bootstrap-token route — never the retired join-key lane', async () => {
    H.post.mockResolvedValue({ data: OK });
    await run({ nodeName: ' n1 ', withTailscale: true, ttlSeconds: 7200 });
    expect(H.post).toHaveBeenCalledWith('/api/security/bootstrap-tokens', {
      body: { node_name: 'n1', with_tailscale: true, ttl_seconds: 7200 },
    });
    expect(H.post.mock.calls.flat()).not.toContain('/api/cluster/mint-join-key');
  });

  it("returns the gateway's own paste, not one composed here", async () => {
    H.post.mockResolvedValue({ data: OK });
    await expect(run({ nodeName: 'n1', withTailscale: true })).resolves.toEqual({
      id: 'tok-1',
      nodeName: 'n1',
      expiresAt: '2026-09-28T00:00:00Z',
      installCommand: OK.install_command,
      enrollCommand: 'noo enroll noo1.BLOB',
      provisionCommand: 'noo cluster provision n1 --wait',
      joinsTailnet: true,
      tailnetSkipped: undefined,
      tailnetCleared: [],
      tailnetClearError: undefined,
    });
  });

  it('passes through what the gateway cleared from the tailnet, and why it could not', async () => {
    H.post.mockResolvedValue({ data: { ...OK, tailnet_cleared: ['n1.tail.ts.net'] } });
    await expect(run({ nodeName: 'n1', withTailscale: true })).resolves.toMatchObject({
      tailnetCleared: ['n1.tail.ts.net'],
    });
    H.post.mockResolvedValue({ data: { ...OK, tailnet_clear_error: 'no Tailscale credential' } });
    await expect(run({ nodeName: 'n1', withTailscale: true })).resolves.toMatchObject({
      tailnetCleared: [],
      tailnetClearError: 'no Tailscale credential',
    });
  });

  it("surfaces the gateway's reason on failure (it says what to fix)", async () => {
    H.post.mockResolvedValue({ error: { error: 'no cluster CA certificate is readable here' } });
    await expect(run({ nodeName: 'n1', withTailscale: false })).rejects.toThrow(
      'no cluster CA certificate is readable here',
    );
    H.post.mockResolvedValue({ error: {} });
    await expect(run({ nodeName: 'n1', withTailscale: false })).rejects.toThrow(
      'Could not mint a bootstrap token',
    );
  });

  it('leaves the TTL to the gateway default when none is chosen', () => {
    expect(mintBody({ nodeName: 'n1', withTailscale: false })).toEqual({
      node_name: 'n1',
      with_tailscale: false,
    });
  });
});
