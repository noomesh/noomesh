// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useAuth } from '@metis/core';
import { AddonUisPanel } from './AddonUisPanel';
import { AddonAccessPanel } from './AddonAccessPanel';

/**
 * The Add-ons tab: the add-on web UIs for everyone, and who may use each
 * add-on feature for operators and above (the access routes refuse anyone
 * below; hiding the section only spares them a 403).
 */
export function AddonsPanel() {
  const { isOperator } = useAuth();
  return (
    <>
      <AddonUisPanel />
      {isOperator && <AddonAccessPanel />}
    </>
  );
}
