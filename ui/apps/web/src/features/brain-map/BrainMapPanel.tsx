// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { DiagramView } from '@/features/_diagram/DiagramView';
import { useMemo } from 'react';
import { slotNodeInfo, addonStateMap } from '@/features/addons/slots';
import { useConsolePieces } from '@/features/addons/useConsolePieces';
import { useObservability } from '@/features/observability/useObservability';
import { BRAIN_SVG, BRAIN_INFO, BRAIN_LEGEND, BRAIN_SLOT_NODES } from './svg';
import { useBrainStatus } from './useBrainStatus';

export function BrainMapPanel() {
  const { data } = useBrainStatus();
  const obs = useObservability();
  const pieces = useConsolePieces();
  const info = useMemo(
    () => ({ ...BRAIN_INFO, ...slotNodeInfo(BRAIN_SLOT_NODES, addonStateMap(obs.data?.addons), pieces) }),
    [obs.data?.addons, pieces],
  );

  return (
    <section className="panel diagram-panel">
      <div className="panel-head">
        <h2>Brain Map</h2>
        <span className="meta">architecture · click a node</span>
      </div>
      <DiagramView
        svg={BRAIN_SVG}
        info={info}
        legend={BRAIN_LEGEND}
        dots={data?.dots}
        texts={data ? { 'brain-score-val': data.score != null ? data.score.toFixed(2) : '—' } : undefined}
      />
    </section>
  );
}
