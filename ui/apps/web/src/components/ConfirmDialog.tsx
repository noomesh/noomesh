// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';
import * as AlertDialog from '@radix-ui/react-alert-dialog';
import { Button } from '@/components/ui/button';

export interface ConfirmOptions {
  title: string;
  description?: string;
  confirmText?: string;
  cancelText?: string;
  destructive?: boolean;
}

type ConfirmFn = (opts: ConfirmOptions) => Promise<boolean>;

const ConfirmContext = createContext<ConfirmFn | null>(null);

/** Imperative confirm dialog (shadcn AlertDialog). `const confirm = useConfirm();
 *  if (await confirm({...})) { ... }`. One host mounted at the root. */
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [opts, setOpts] = useState<ConfirmOptions>({ title: '' });
  const resolver = useRef<((v: boolean) => void) | undefined>(undefined);

  const confirm = useCallback<ConfirmFn>((o) => {
    setOpts(o);
    setOpen(true);
    return new Promise<boolean>((resolve) => {
      resolver.current = resolve;
    });
  }, []);

  const settle = (v: boolean) => {
    setOpen(false);
    resolver.current?.(v);
    resolver.current = undefined;
  };

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      <AlertDialog.Root
        open={open}
        onOpenChange={(o) => {
          if (!o) settle(false); // Esc / overlay / Cancel
        }}
      >
        <AlertDialog.Portal>
          <AlertDialog.Overlay className="confirm-overlay" />
          <AlertDialog.Content className="confirm-content">
            <AlertDialog.Title className="confirm-title">{opts.title}</AlertDialog.Title>
            {opts.description && (
              <AlertDialog.Description className="confirm-desc">{opts.description}</AlertDialog.Description>
            )}
            <div className="confirm-actions">
              <AlertDialog.Cancel asChild>
                <Button variant="outline" size="sm">
                  {opts.cancelText ?? 'Cancel'}
                </Button>
              </AlertDialog.Cancel>
              <AlertDialog.Action asChild>
                <Button
                  size="sm"
                  variant={opts.destructive ? 'destructive' : 'default'}
                  onClick={() => settle(true)}
                >
                  {opts.confirmText ?? 'Confirm'}
                </Button>
              </AlertDialog.Action>
            </div>
          </AlertDialog.Content>
        </AlertDialog.Portal>
      </AlertDialog.Root>
    </ConfirmContext.Provider>
  );
}

export function useConfirm(): ConfirmFn {
  const c = useContext(ConfirmContext);
  if (!c) throw new Error('useConfirm must be used within <ConfirmProvider>');
  return c;
}
