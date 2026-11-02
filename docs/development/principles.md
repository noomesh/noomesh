# Engineering principles

These are the questions a review asks of every change: least privilege,
secure by default, fast, and clean and clear, plus the working rules that keep
those true. A reviewer cites them by number ("P3", "P8"), and so can you in a
PR body or an issue.

## P1. Least privilege

Containers run non-root, on read-only roots, with capabilities dropped. Nodes
hold no credentials. A change that widens access is made by a person, never by
an agent's credential. A helper runs as root only for a documented hard
blocker.

Example: the hardened Ollama image runs as a fixed non-root uid. The node agent
re-owns an existing root-owned model store once, in a throwaway helper that
only runs `chown`, and refuses the start with the manual command if that fails
(#558).

## P2. Secure by default

TLS everywhere, mutual TLS between parts, signed releases and bundles, verified
callers. Switches ship on. Nothing is "enable it later".

Example: the vLLM engine used to serve TLS itself and admit any certificate
signed by the cluster CA. It now sits behind its own TLS door that admits only
named callers, and the engine listens on loopback inside the door's network
namespace. No setting turns this on; it is how vLLM runs (#522).

## P3. Fail loud

Refuse and name the fix. Never fall back quietly to something less safe.

Example: when a node needs the hardened llama.cpp or Ollama image and the
controller has not staged it for the node's architecture, the start is
refused. The message says it will not fall back to an upstream image and names
the command that stages it (`noo cluster sync-images <node> -i <ref>`). A root
upstream container is never started silently (#558).

## P4. One behaviour, no throwaway switches

When a new default is decided, the old path goes. An old value is tolerated
only while a release rolls out.

Example: nodes now take images only from the controller. The variable that
chose an image source and the old modes behind it were removed rather than left
as a switch. During the roll, a node that still sets the variable ignores it
and logs once, and `noo cluster verify` accepts an older agent and says it
changes on this roll (#557).

## P5. Fast

Speed that costs none of the above.

Example: the first chat after a vLLM restart used to wait while the engine
compiled. The compile caches now live on a named volume, and the agent sends
one small warm request before it reports the backend ready. The engine flags
are unchanged, no root-owned files land in the data root, and the warm request
is bounded and never blocks readiness: a failure only logs a warning (#546).

## P6. Clean and clear

One summary line. Every error carries its remedy. Records say what is true.
Help text matches the code.

Example: `noo upgrade` used to print hundreds of image-layer progress lines.
It now prints one line (`images pulled: 31 layers (12 already present)`), and
error lines still pass through verbatim (#537).

## P7. The team runs changes

The team is the operator and their own agents. Decisions are the operator's;
carrying them out is the team's. An agent runs a change that follows a decision
already made, and reports what it did with evidence. Anything irreversible,
outside a prior decision, or that widens access is asked first.

Example: the operator decides to ship a release. An agent then runs the fleet
roll (`noo upgrade --all`) against that decision and reports the
`noo cluster verify` output.

## P8. Prove it, don't assert it

A test fails without the fix. A rehearsal runs the real path. A live check
follows a roll. A verdict needs evidence, and a PR says what only a live system
can prove.

Example: a release-candidate rehearsal on a fresh dist install found three
TLS doors that still built from a Dockerfile the dist install does not ship,
so vLLM did not start. The fix added two tests that fail without it (2 failed)
and pass with it (#533). See also "Proving a guard works" in the
[developer guide](developer-guide.md).

## Using them

- Cite a principle by number in a review or PR: "P3: this falls back to the
  upstream image without saying so", "P8: no test fails without this change".
- A change that trades one principle for another says so in its PR body: which
  two, what is given up, and why.
