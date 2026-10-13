// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useMutation, useMetisClient } from '@metis/core';

export interface MintRequest {
  nodeName: string;
  withTailscale: boolean;
  /** Token lifetime in seconds; the gateway defaults to an hour. */
  ttlSeconds?: number;
}

/** The ONE enrollment paste, as the gateway composed it. */
export interface EnrollPaste {
  id: string;
  nodeName: string;
  expiresAt: string;
  /** Step 1, on the new machine: install the noo CLI. */
  installCommand: string;
  /** Step 2, on the new machine as its user: `noo enroll noo1.<blob>`. */
  enrollCommand: string;
  /** Step 3, on the controller. */
  provisionCommand: string;
  joinsTailnet: boolean;
  /** Why a requested tailnet key was not minted (the node is the controller). */
  tailnetSkipped?: string;
  /** Stale tailnet records under this name the gateway removed (so the node keeps its name). */
  tailnetCleared: string[];
  /** Set when the stale-record check could not run; the paste is still valid. */
  tailnetClearError?: string;
}

/** The gateway's own words on failure: `{"error": "…"}`. Its messages say what
 * to fix (no cluster CA, a localhost controller URL, a Tailscale credential),
 * which a generic "could not mint" throws away. */
function gatewayMessage(error: unknown): string | undefined {
  if (error && typeof error === 'object') {
    const e = error as { error?: unknown; detail?: unknown };
    if (typeof e.error === 'string' && e.error) return e.error;
    if (typeof e.detail === 'string' && e.detail) return e.detail;
  }
  return undefined;
}

export function mintBody(req: MintRequest) {
  return {
    node_name: req.nodeName.trim(),
    with_tailscale: req.withTailscale,
    ...(req.ttlSeconds ? { ttl_seconds: req.ttlSeconds } : {}),
  };
}

/**
 * Mint a single-use bootstrap token bound to one node name. The gateway
 * composes the paste server-side — the same one `noo cluster bootstrap-token
 * create` prints — so the console never assembles an enrollment command of
 * its own.
 */
export function useMintBootstrapToken() {
  const client = useMetisClient();
  return useMutation<EnrollPaste, Error, MintRequest>({
    mutationFn: async (req) => {
      const { data, error } = await client.POST('/api/security/bootstrap-tokens', {
        body: mintBody(req),
      });
      if (error || !data) {
        throw new Error(gatewayMessage(error) ?? 'Could not mint a bootstrap token');
      }
      return {
        id: data.id,
        nodeName: data.node_name ?? req.nodeName.trim(),
        expiresAt: data.expires_at,
        installCommand: data.install_command,
        enrollCommand: data.enroll_command,
        provisionCommand: data.provision_command,
        joinsTailnet: data.joins_tailnet,
        tailnetSkipped: data.tailnet_skipped ?? undefined,
        tailnetCleared: data.tailnet_cleared ?? [],
        tailnetClearError: data.tailnet_clear_error ?? undefined,
      };
    },
  });
}
