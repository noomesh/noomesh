// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @metis/core — shared React data layer.
export { MetisProvider } from './provider.tsx';
export { useMetisClient, MetisClientContext } from './context.tsx';
export { AuthProvider, useAuth } from './auth.tsx';

// Re-export the TanStack Query surface features build on, so apps depend on one place.
export {
  useQuery,
  useMutation,
  useQueryClient,
  QueryClient,
  QueryClientProvider,
} from '@tanstack/react-query';
