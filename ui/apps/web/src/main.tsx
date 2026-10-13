// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { MetisProvider, AuthProvider } from '@metis/core';
import '@metis/tokens/tokens.css';
import './app.css';
import { App } from './App';
import { ConfirmProvider } from '@/components/ConfirmDialog';
import { Toaster } from '@/components/ui/sonner';
import { client, authApi } from './lib/client';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <MetisProvider client={client}>
      <AuthProvider authApi={authApi}>
        <ConfirmProvider>
          <App />
        </ConfirmProvider>
        <Toaster />
      </AuthProvider>
    </MetisProvider>
  </StrictMode>,
);
