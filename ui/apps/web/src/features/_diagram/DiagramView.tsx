// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useEffect, useRef, useState } from 'react';
import { reskin, reskinColor } from './reskin';

/** One node/loop's inspect-modal payload. Short keys mirror the legacy dicts so
 *  the (large) info tables port over near-verbatim. */
export interface NodeInfo {
  t: string; // title
  l: string; // layer
  c: string; // color (legacy hue; reskinned at render)
  d: string; // description
  f?: string; // key files (comma-separated)
  k?: string; // connects-to / data types
  w?: string; // flow (mono block)
  x?: string; // extra note
  steps?: string[]; // ordered steps (licensed slots)
  badge?: string; // state badge (licensed slots)
}

export interface LegendItem {
  label: string;
  color: string;
}

function DiagramModal({ info, onClose }: { info: NodeInfo; onClose: () => void }) {
  return (
    <div className="diag-modal-overlay" onClick={onClose}>
      <div className="diag-modal" onClick={(e) => e.stopPropagation()}>
        <button className="diag-modal-close" onClick={onClose} aria-label="Close">
          ×
        </button>
        <h3 className="diag-modal-title">
          <span className="diag-modal-dot" style={{ background: reskinColor(info.c) }} />
          {info.t}
        </h3>
        <div className="diag-modal-layer">{info.l}</div>
        {info.badge && <div className="diag-modal-badge">{info.badge}</div>}
        <div className="diag-modal-desc">
          {info.d.split('\n').map((line, i) => (
            <p key={i}>{line}</p>
          ))}
        </div>
        {info.steps && (
          <ol className="diag-modal-steps">
            {info.steps.map((st, i) => (
              <li key={i}>{st}</li>
            ))}
          </ol>
        )}
        {info.w && <pre className="diag-modal-flow">{info.w}</pre>}
        {info.f && (
          <div className="diag-modal-sec">
            <strong>Key files</strong>
            <span className="diag-modal-files">
              {info.f.split(', ').map((f) => (
                <code key={f}>{f}</code>
              ))}
            </span>
          </div>
        )}
        {info.k && (
          <div className="diag-modal-sec">
            <strong>Connects to</strong>
            <span>{info.k}</span>
          </div>
        )}
        {info.x && <div className="diag-modal-note">{info.x}</div>}
      </div>
    </div>
  );
}

/**
 * Renders a reskinned architecture diagram: the raw SVG is injected verbatim
 * (recolored to Slate) and clicks are delegated to any element carrying a
 * `data-id` that matches the info table, opening an inspect modal.
 *
 * `dots` (optional) maps an SVG element id → fill color for live status dots.
 */
export function DiagramView({
  svg,
  info,
  legend,
  dots,
  texts,
}: {
  svg: string;
  info: Record<string, NodeInfo>;
  legend: LegendItem[];
  dots?: Record<string, string>;
  texts?: Record<string, string>;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [sel, setSel] = useState<NodeInfo | null>(null);
  const [html] = useState(() => reskin(svg));

  useEffect(() => {
    const root = ref.current;
    if (!root) return;
    if (dots) {
      for (const [id, color] of Object.entries(dots)) {
        const el = root.querySelector(`#${CSS.escape(id)}`);
        if (el) el.setAttribute('fill', color);
      }
    }
    if (texts) {
      for (const [id, value] of Object.entries(texts)) {
        const el = root.querySelector(`#${CSS.escape(id)}`);
        if (el) el.textContent = value;
      }
    }
  }, [dots, texts]);

  const onClick = (e: React.MouseEvent) => {
    const g = (e.target as HTMLElement).closest<HTMLElement>('[data-id]');
    const id = g?.dataset.id;
    if (id && info[id]) setSel(info[id]);
  };

  return (
    <>
      <div className="diagram-scroll">
        <div className="diagram" ref={ref} onClick={onClick} dangerouslySetInnerHTML={{ __html: html }} />
      </div>
      <div className="diagram-legend">
        {legend.map((l) => (
          <span key={l.label}>
            <span className="ldot" style={{ background: l.color }} />
            {l.label}
          </span>
        ))}
      </div>
      {sel && <DiagramModal info={sel} onClose={() => setSel(null)} />}
    </>
  );
}
