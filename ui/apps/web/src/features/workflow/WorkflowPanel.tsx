// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { DiagramView } from '@/features/_diagram/DiagramView';
import { useMemo } from 'react';
import { slotNodeInfo, addonStateMap } from '@/features/addons/slots';
import { useConsolePieces } from '@/features/addons/useConsolePieces';
import { useObservability } from '@/features/observability/useObservability';
import { WORKFLOW_SVG, WORKFLOW_INFO, WORKFLOW_LEGEND, WORKFLOW_SLOT_NODES } from './svg';

/**
 * The static architecture diagram — how a request becomes an answer.
 *
 * Ships in `core` because it is the cheapest way to orient someone who has
 * just installed a four-lane distributed system and has no idea which part
 * does what. The trade is that a hand-maintained diagram drifts: its node
 * file-paths all still pointed at the retired Python gateway until 2026-08-27.
 * They are directory-level now, which survives refactors that file names do not.
 */
export function WorkflowPanel() {
  const obs = useObservability();
  const pieces = useConsolePieces();
  const info = useMemo(
    () => ({ ...WORKFLOW_INFO, ...slotNodeInfo(WORKFLOW_SLOT_NODES, addonStateMap(obs.data?.addons), pieces) }),
    [obs.data?.addons, pieces],
  );
  return (
    <section className="panel diagram-panel">
      <div className="panel-head">
        <h2>Architecture</h2>
        <span className="meta">data flow · click a node</span>
      </div>
      <DiagramView svg={WORKFLOW_SVG} info={info} legend={WORKFLOW_LEGEND} />
    </section>
  );
}
