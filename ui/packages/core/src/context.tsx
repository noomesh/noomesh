// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { createContext, useContext } from 'react';
import type { MetisClient } from '@metis/api';

const MetisClientContext = createContext<MetisClient | null>(null);
export { MetisClientContext };

/** The gateway client provided by <MetisProvider>. Throws if used outside it. */
export function useMetisClient(): MetisClient {
  const client = useContext(MetisClientContext);
  if (!client) throw new Error('useMetisClient must be used within <MetisProvider>');
  return client;
}
