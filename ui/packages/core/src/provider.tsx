// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { MetisClient } from '@metis/api';
import { MetisClientContext } from './context.tsx';

/**
 * Wraps the app in a TanStack Query client and exposes the noomesh gateway client
 * via context. Web and mobile both mount this at the root, passing a client
 * built from their own token store.
 */
export function MetisProvider({ client, children }: { client: MetisClient; children: ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: { staleTime: 5_000, retry: 1, refetchOnWindowFocus: false },
        },
      }),
  );
  return (
    <QueryClientProvider client={queryClient}>
      <MetisClientContext.Provider value={client}>{children}</MetisClientContext.Provider>
    </QueryClientProvider>
  );
}
