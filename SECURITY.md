# Security Policy

## Reporting a vulnerability

Please report security issues privately:

1. **Do not open a public GitHub issue.**
2. Email **contact@noomesh.ai** with a description, steps to
   reproduce, the impact you see, and any suggested fix.
3. You will get an acknowledgement within 48 hours.
4. We work with you to understand and fix the issue before any public
   disclosure, under a 90-day coordinated-disclosure window; if a fix
   cannot ship within 90 days we agree a timeline with you.

Security fixes are released as patch versions of the `noo-cli-v*` and
`stack-v*` releases and called out in the release notes. Only the current
release line is supported.

## How noomesh is secured

Every layer — per-user JWT credentials and scopes, cluster HMAC between
nodes, the EC P-384 PKI and mTLS, input sanitisation, the risk-based
exec-approval gate, per-IP rate limiting, secrets management, audit
logging and network isolation — is on by default (see the
[security CLI reference](docs/cli/security.md)); the
setup wizard (`noo onboard`) enables all of it, and
`noo security scan` checks the posture of an existing install.

### What the model reads as instructions

Only text the operator controls is in the system message: the persona
prompt, the shipped runbooks and the shipped (core) prompt skills.
Everything a third party could have written travels instead as one fenced
data block at the head of the user's own message, marked as data, with the
begin and end markers made unforgeable and likely injection lines flagged:
retrieved documents, graph facts, memory, other-channel messages, video
recall, conversation summaries and recall (they are built from past
messages), skills written at runtime (evolved, through the API, the
`noo_prompt_skills_create` tool or the evolve add-on) and companion-device
reports. The block is removed again before the session is cached.
