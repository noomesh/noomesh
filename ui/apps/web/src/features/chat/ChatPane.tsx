// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useCallback, useEffect, useRef, useState } from 'react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { ChatRail } from '@/components/ChatRail';
import { ApprovalCard } from './ApprovalCard';
import { useCoordinator, type TurnStats, type ToolRun } from './useCoordinator';
import { useBackendHealth } from './useBackendHealth';
import { atTail } from './followTail';
import { formatElapsed } from './toolElapsed';
import { useVoiceControls } from './voice/useVoice';
import { MicControl } from './voice/MicControl';
import { SpeakButton } from './voice/SpeakButton';

export interface ChatPaneProps {
  /** Whether the side panel is currently collapsed. */
  panelHidden: boolean;
  /** Toggle the side panel. Absent when the active tab has no panel (Chat). */
  onTogglePanel?: () => void;
  /** Minimise the chat to a rail / restore it. Absent when there is no panel
   *  to give the width to — collapsing then would leave an empty screen. */
  onToggleChat?: () => void;
  /** Render as the rail rather than the full pane. */
  collapsed?: boolean;
}

/** Short model label — `org/Model-Name` renders as `Model-Name`. */
const shortModel = (m: string) => m.split('/').pop() ?? m;

/**
 * Reasoning disclosure: live and open while the model thinks, then collapses
 * itself to a one-line "Thought for Ns" summary once content starts. Expanding
 * it by hand pins it — the auto-collapse won't yank it shut again.
 */
function ThinkingBlock({
  text,
  streaming,
  thinkMs,
}: {
  text: string;
  streaming?: boolean;
  thinkMs?: number;
}) {
  const live = streaming && thinkMs === undefined;
  const [open, setOpen] = useState(!!live);
  const pinned = useRef(false);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!pinned.current) setOpen(!!live);
  }, [live]);

  // Follow the reasoning as it streams.
  useEffect(() => {
    if (open && live) bodyRef.current?.scrollTo({ top: bodyRef.current.scrollHeight });
  }, [text, open, live]);

  const label = live
    ? 'Thinking…'
    : thinkMs
      ? `Thought for ${(thinkMs / 1000).toFixed(1)}s`
      : 'Reasoning';

  return (
    <div className={cn('reason', live && 'live', open && 'open')}>
      <button
        type="button"
        className="reason-head"
        aria-expanded={open}
        onClick={() => {
          pinned.current = true;
          setOpen((v) => !v);
        }}
      >
        <svg className="chev" viewBox="0 0 20 20" aria-hidden="true">
          <path d="M7.5 5l5 5-5 5" />
        </svg>
        <span className="reason-label">{label}</span>
      </button>
      {open && (
        <div className="reason-body" ref={bodyRef}>
          {text}
        </div>
      )}
    </div>
  );
}

/** Tool runs as status chips; click to see the server's output. */
function ToolChips({ tools }: { tools: ToolRun[] }) {
  const [shown, setShown] = useState<number | null>(null);

  return (
    <div className="tools">
      {tools.map((t, i) => (
        <div className="tool" key={`${t.name}-${i}`}>
          <button
            type="button"
            className={cn('tool-chip', t.status)}
            onClick={() => setShown((s) => (s === i ? null : i))}
            aria-expanded={shown === i}
            disabled={!t.detail}
          >
            <span className="tool-mark" aria-hidden="true">
              {t.status === 'running' ? '◌' : t.status === 'ok' ? '✓' : '✕'}
            </span>
            <span className="tool-name">{t.name}</span>
            {t.elapsedMs !== undefined && (
              <span className="tool-ms">{formatElapsed(t.elapsedMs)}</span>
            )}
          </button>
          {shown === i && t.detail && <pre className="tool-detail">{t.detail}</pre>}
        </div>
      ))}
    </div>
  );
}

function StatsFooter({ stats }: { stats: TurnStats }) {
  const parts: string[] = [];
  if (stats.cached) parts.push('cached');
  if (stats.elapsedSeconds) parts.push(`${stats.elapsedSeconds}s`);
  if (stats.tokensOut) parts.push(`${stats.tokensOut.toLocaleString()} tokens`);
  if (stats.tokensIn) parts.push(`${stats.tokensIn.toLocaleString()} prompt`);
  if (stats.tokensPerSec) parts.push(`${stats.tokensPerSec} tok/s`);
  if (stats.iterations && stats.iterations > 1) parts.push(`${stats.iterations} iterations`);
  if (stats.toolCalls) parts.push(`${stats.toolCalls} tool call${stats.toolCalls === 1 ? '' : 's'}`);
  if (!parts.length) return null;

  return (
    <div className="turn-stats">
      {parts.map((p) => (
        <span key={p}>{p}</span>
      ))}
    </div>
  );
}

export function ChatPane({ panelHidden, onTogglePanel, onToggleChat, collapsed }: ChatPaneProps) {
  const { messages, status, send, canSend, busy, serving } = useCoordinator();
  const health = useBackendHealth();
  const [draft, setDraft] = useState('');
  const [model, setModel] = useState('');
  // Voice: hidden unless the gateway's voice providers answer; re-polled
  // whenever the chat opens from its rail.
  const voice = useVoiceControls(!collapsed);
  const [voiceError, setVoiceError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  // A transcript lands in the box for the user to edit and send — never sent.
  const onTranscript = useCallback((text: string) => {
    setDraft((d) => (d.trim() ? `${d.replace(/\s+$/, '')} ${text}` : text));
    inputRef.current?.focus();
  }, []);
  const listRef = useRef<HTMLDivElement>(null);
  // Whether the reader is following the tail. Starts true — a fresh pane is
  // at the bottom because it is also at the top.
  const followRef = useRef(true);

  const onTranscriptScroll = () => {
    const el = listRef.current;
    if (el) followRef.current = atTail(el);
  };

  const turnsRef = useRef(messages.length);

  useEffect(() => {
    const el = listRef.current;
    if (!el) return;
    // Sending is the reader asking for the tail again, wherever they were.
    // The count only grows on send (the user turn plus its placeholder);
    // streamed tokens patch the last entry in place and leave it alone.
    if (messages.length !== turnsRef.current) {
      turnsRef.current = messages.length;
      followRef.current = true;
    }
    // Otherwise follow only if the reader has not deliberately scrolled away.
    // Without that test the transcript yanks back to the end on EVERY streamed
    // token, so scrolling up to re-read is undone before the thumb leaves the
    // glass — which is indistinguishable from not being able to scroll at all.
    if (followRef.current) el.scrollTo({ top: el.scrollHeight });
  }, [messages]);

  // A model that stops being served shouldn't stay selected — fall back to auto.
  useEffect(() => {
    if (model && health.models.length && !health.models.some((m) => m.model === model)) {
      setModel('');
    }
  }, [health.models, model]);

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSend || !health.ready) return;
    send(draft, model);
    setDraft('');
  };

  // The composer is gated on a backend that can actually answer, not just on
  // the socket being open — sending into the loading gap returns a 502.
  const sendable = canSend && health.ready;

  const activity = busy
    ? 'Generating…'
    : health.state === 'loading'
      ? 'Backend loading model — please wait…'
      : health.state === 'down'
        ? 'No inference backend available'
        : '';

  // Collapsed renders the rail instead of the pane — but every hook above has
  // already run, so the socket stays open and the transcript survives. Any
  // in-flight turn keeps streaming into state while minimised.
  if (collapsed && onToggleChat) {
    return <ChatRail status={status} onExpand={onToggleChat} />;
  }

  return (
    <section className="chat">
      <div className="bar">
        <span className="t">Coordinator</span>
        <div className="bar-right">
          {serving?.model && (
            <span className="serving" title={serving.backend ? `via ${serving.backend}` : undefined}>
              {shortModel(serving.model)}
              {serving.backend && <span className="serving-via">via {serving.backend}</span>}
            </span>
          )}
          <span className="model-pick">
            <span className={cn('serve-dot', health.state)} aria-hidden="true" />
            <select
              value={model}
              onChange={(e) => setModel(e.target.value)}
              aria-label="Model"
              title={
                health.state === 'ready'
                  ? 'Model for the next turn'
                  : health.state === 'loading'
                    ? 'Backend loading model — please wait…'
                    : 'No inference backend available'
              }
              disabled={!health.models.length}
            >
              <option value="">{health.models.length ? '(auto)' : 'no backend'}</option>
              {health.models.map((m) => (
                <option key={m.model} value={m.model}>
                  {shortModel(m.model)}
                  {m.node ? ` (${m.node})` : ''}
                </option>
              ))}
            </select>
          </span>
          <span className={cn('live', status !== 'live' && 'off')}>{status}</span>
          {/* Ordered to match the layout: the chat's own control on the left,
              the panel's on the right. In both icons the bar is the edge the
              column lives at and the chevron is the way it is about to move. */}
          {/* Panel-rectangle glyphs: the shaded region is the column the button
              toggles, left for the chat and right for the panel. An earlier
              bar-and-chevron pair read as "skip to start / skip to end" media
              controls at 16px. State is carried by the tooltip and
              aria-pressed rather than by flipping the icon. */}
          {onToggleChat && (
            <button
              type="button"
              className="panel-toggle"
              onClick={onToggleChat}
              title="Minimise the chat — give the panel the width"
              aria-label="Minimise chat"
            >
              <svg viewBox="0 0 20 20" aria-hidden="true">
                <rect x="2.5" y="4" width="15" height="12" rx="1.5" />
                <rect x="2.5" y="4" width="5.5" height="12" fill="currentColor" stroke="none" opacity="0.4" />
                <path d="M8 4v12" />
              </svg>
            </button>
          )}
          {onTogglePanel && (
            <button
              type="button"
              className="panel-toggle"
              onClick={onTogglePanel}
              aria-pressed={panelHidden}
              title={panelHidden ? 'Show the side panel' : 'Hide the side panel — widen the chat'}
              aria-label={panelHidden ? 'Show side panel' : 'Hide side panel'}
            >
              <svg viewBox="0 0 20 20" aria-hidden="true">
                <rect x="2.5" y="4" width="15" height="12" rx="1.5" />
                <rect x="12" y="4" width="5.5" height="12" fill="currentColor" stroke="none" opacity="0.4" />
                <path d="M12 4v12" />
              </svg>
            </button>
          )}
        </div>
      </div>

      <div className="transcript" ref={listRef} onScroll={onTranscriptScroll}>
        {messages.map((m, i) =>
          m.role === 'you' ? (
            <div key={i} className="turn you">
              <div className="who">You</div>
              <div className="u">{m.text}</div>
            </div>
          ) : (
            <div key={i} className="turn metis">
              <div className="who">Noomesh</div>
              {m.thinking && (
                <ThinkingBlock text={m.thinking} streaming={m.streaming} thinkMs={m.thinkMs} />
              )}
              {!!m.tools?.length && <ToolChips tools={m.tools} />}
              {m.approvals?.map((a) => <ApprovalCard key={a.id} approval={a} />)}
              <div className={cn('m', m.error && 'err')}>
                {m.text}
                {m.streaming && <span className="cursor">▍</span>}
              </div>
              {m.stats && <StatsFooter stats={m.stats} />}
              {voice.speaker !== 'hidden' && !m.streaming && !m.error && !!m.text.trim() && (
                <div className="turn-actions">
                  <SpeakButton id={`turn-${i}`} text={m.text} state={voice.speaker} reason={voice.speakerReason} />
                </div>
              )}
            </div>
          ),
        )}
      </div>

      <form className="composer" onSubmit={onSubmit}>
        <div className="composer-row">
          <input
            ref={inputRef}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="Message Noomesh…"
            aria-label="Message Noomesh"
          />
          {voice.mic !== 'hidden' && (
            <MicControl
              state={voice.mic}
              reason={voice.micReason}
              onTranscript={onTranscript}
              onError={setVoiceError}
            />
          )}
          <Button type="submit" size="icon" aria-label="Send" disabled={!sendable}>
            <svg viewBox="0 0 20 20" fill="currentColor">
              <path d="M3 10l14-6-6 14-2-6z" />
            </svg>
          </Button>
        </div>

        {voiceError && voice.mic !== 'hidden' && (
          <div className="composer-status err voice-err" role="alert">
            {voiceError}
            <button type="button" className="voice-err-x" onClick={() => setVoiceError(null)} aria-label="Dismiss">
              ×
            </button>
          </div>
        )}

        {activity && (
          <div
            className={cn('composer-status', health.state === 'down' && !busy && 'err')}
            role="status"
          >
            {activity}
          </div>
        )}
      </form>
    </section>
  );
}
