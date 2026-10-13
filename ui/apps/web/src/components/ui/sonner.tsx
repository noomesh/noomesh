// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { Toaster as Sonner } from 'sonner';

/** App toaster — themed to the Slate tokens (flips with .dark automatically). */
export function Toaster() {
  return (
    <Sonner
      position="bottom-right"
      toastOptions={{
        style: {
          background: 'var(--surface)',
          color: 'var(--ink)',
          border: '1px solid var(--line-2)',
        },
      }}
    />
  );
}
