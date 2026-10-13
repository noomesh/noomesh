// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useMintBootstrapToken } from './useMintBootstrapToken';

/** Hostname charset the gateway accepts for a bound node name. */
const NODE_NAME = /^[a-zA-Z0-9._-]{1,64}$/;

const TTL_CHOICES: { label: string; seconds: number }[] = [
  { label: '1 hour', seconds: 3600 },
  { label: '4 hours', seconds: 4 * 3600 },
  { label: '24 hours', seconds: 86400 },
];

function CopyLine({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard is blocked outside a secure context — the command is on
      // screen and selectable, so say nothing rather than claim a copy.
      setCopied(false);
    }
  }
  return (
    <>
      <pre className="onboard-cmd">{text}</pre>
      <Button size="sm" variant="outline" onClick={copy} aria-label={`Copy ${label}`}>
        {copied ? 'Copied ✓' : 'Copy'}
      </Button>
    </>
  );
}

/**
 * Add a machine to the mesh — the pull-rail lane, the only one there is.
 *
 * Mints a single-use bootstrap token bound to the node's name and shows the
 * paste the gateway composed for it: install the noo CLI, `noo enroll
 * noo1.<blob>` on the machine, then `noo cluster provision <name> --wait` on
 * the controller. Identical to `noo cluster bootstrap-token create --node`.
 * The join-key + SSH-user form this replaced handed out the retired
 * bootstrap-node.sh one-liner.
 */
export function AddNode() {
  const [open, setOpen] = useState(false);
  const [nodeName, setNodeName] = useState('');
  const [withTailscale, setWithTailscale] = useState(true);
  const [ttlSeconds, setTtlSeconds] = useState(3600);
  const mint = useMintBootstrapToken();

  const name = nodeName.trim();
  const nameOk = NODE_NAME.test(name);

  if (!open) {
    return (
      <Button size="sm" onClick={() => setOpen(true)} title="Get the enrollment commands for a new machine">
        + Add node
      </Button>
    );
  }

  function close() {
    setOpen(false);
    mint.reset();
  }

  return (
    <div className="addnode">
      <div className="addnode-head">
        <span className="addnode-title">Add a node</span>
        <button type="button" className="addnode-close" onClick={close} aria-label="Close">
          ✕
        </button>
      </div>

      {!mint.data && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (nameOk) mint.mutate({ nodeName: name, withTailscale, ttlSeconds });
          }}
        >
          <p className="addnode-lead">
            Mints a single-use enrollment token for one machine, then gives you the commands to
            run on it.
          </p>
          <div className="addnode-row">
            <Input
              placeholder="node name (its hostname)"
              value={nodeName}
              onChange={(e) => setNodeName(e.target.value)}
              aria-label="Node name"
              aria-invalid={name !== '' && !nameOk}
              title="The machine's hostname. Enrollment from any other hostname is refused."
              required
            />
            <select
              className="addnode-select"
              value={ttlSeconds}
              onChange={(e) => setTtlSeconds(Number(e.target.value))}
              aria-label="Token lifetime"
            >
              {TTL_CHOICES.map((c) => (
                <option key={c.seconds} value={c.seconds}>
                  valid {c.label}
                </option>
              ))}
            </select>
            <Button size="sm" type="submit" disabled={!nameOk || mint.isPending}>
              {mint.isPending ? 'Minting…' : 'Get commands'}
            </Button>
          </div>
          <label className="addnode-check">
            <input
              type="checkbox"
              checked={withTailscale}
              onChange={(e) => setWithTailscale(e.target.checked)}
            />
            Join the tailnet (adds a single-use Tailscale key; leave off if the machine already
            reaches this controller)
          </label>
          {name !== '' && !nameOk && (
            <p className="addnode-hint">Letters, digits, dot, dash and underscore; up to 64.</p>
          )}
        </form>
      )}

      {mint.isError && (
        <div className="addnode-err">
          <p>{mint.error.message}</p>
          {withTailscale && (
            <p className="addnode-hint">
              If the Tailscale key could not be minted, store an OAuth client via{' '}
              <code>noo onboard --reconfigure --only enrollment</code> and restart the gateway —
              or untick <em>Join the tailnet</em> when the machine can already reach this
              controller.
            </p>
          )}
        </div>
      )}

      {mint.data && (
        <>
          <p className="addnode-lead">
            On <strong>{mint.data.nodeName}</strong>, as your user (one sudo prompt):
          </p>
          <p className="addnode-step">
            1 · Install the noo CLI (skip if <code>noo --version</code> works)
          </p>
          <CopyLine text={mint.data.installCommand} label="install command" />
          <p className="addnode-step">
            2 · Enroll —{' '}
            {mint.data.joinsTailnet
              ? 'joins the tailnet, runs host prep, installs the agent'
              : 'runs host prep, installs the agent'}
          </p>
          <CopyLine text={mint.data.enrollCommand} label="enroll command" />
          <p className="addnode-step">3 · Then, on the controller</p>
          <CopyLine text={mint.data.provisionCommand} label="provision command" />
          {mint.data.tailnetSkipped && <p className="addnode-hint">{mint.data.tailnetSkipped}</p>}
          {mint.data.tailnetCleared.length > 0 && (
            <p className="addnode-hint">
              Cleared stale tailnet record{mint.data.tailnetCleared.length > 1 ? 's' : ''} under this name
              ({mint.data.tailnetCleared.join(', ')}) so the node joins as itself, not as a “-1”.
            </p>
          )}
          {mint.data.tailnetClearError && (
            <p className="addnode-hint">
              Could not check the tailnet for a stale record ({mint.data.tailnetClearError}). If a device
              with this name is still listed there, remove it before enrolling or the node joins as “-1”.
            </p>
          )}
          <p className="addnode-hint">
            The token is <strong>single-use</strong>, bound to <code>{mint.data.nodeName}</code>,
            and expires {new Date(mint.data.expiresAt).toLocaleString()}. It is shown once — if
            it leaks, revoke it with{' '}
            <code>noo cluster bootstrap-token revoke {mint.data.id}</code>.
          </p>
          <div className="addnode-row">
            <Button size="sm" variant="outline" onClick={() => mint.reset()}>
              Add another
            </Button>
          </div>
        </>
      )}
    </div>
  );
}
