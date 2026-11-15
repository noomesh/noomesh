# Contract changes

## 2026-11-15

Added `POST /api/security/service-keys/{consumer}/context-overflow`
(operator or admin, a person only: any key, exchanged token, harness door or
delegated credential gets 403): body `{"mode": "flag" | "refuse"}`, answers
`{status, consumer, context_overflow, updated_keys}`; 400 for another word,
404 with no active key. `GET /api/security/service-keys` rows carry
`context_overflow` (`flag` on every existing key). With `refuse`, that
consumer's `/v1/chat/completions` and `/api/external/chat/completions` answer
413 `context_too_small` instead of sending a prompt no candidate's context
holds. Additive.

## 2026-11-14

Added `GET /api/monitoring/status` (every signed-in tier):
`{monitoring, grafana, log_search, traces, message?}`, which optional
monitoring parts run. With `cluster.monitoring: lean` and no Grafana,
`POST /api/monitoring/grafana-session` answers 409 (was 503) naming
`noo stack monitoring on`; with no Loki, `POST /api/logs/search` answers 200
`{"lines": [], "backend": "off", "message": …}` (was 503). Unset or `full`
is unchanged. Additive.

Added `POST /api/inference/chat` (a signed-in person): one coordinator turn
as Server-Sent Events (`data: {"type": …}` events, the console socket's
shape) with the caller's retrieval, memory and tools; what `noo chat` uses.
`POST /api/inference/stream` is unchanged (a plain model call). Additive.

Added `POST /api/autonomy/locations/{name}/dry-run` (operator or admin):
`{"dry_run": false}` takes a rule with a dry-run gate (`disk_watermark`,
`cert_auto_rotate`) live, `{"dry_run": true}` puts it back into preview;
400 for any other rule. Answers `{name, dry_run, config, live_means}`.
`POST /api/autonomy/locations/{name}/toggle` now MERGES a sent `config`
into the stored one (as its description already said) instead of replacing
it, so arming or disarming keeps `dry_run` and tunables. Additive.

`POST /api/autonomy/locations/{name}/dry-run`, later the same day: going
live (`{"dry_run": false}`) now also arms the rule (`enabled_action: true`)
in the same update, and a switched-off rule answers 409. The answer adds
`enabled` and `armed`, read back after the write. Additive for clients.

## 2026-11-09

Added `POST /api/cluster/nodes/{node_id}/model-set-retry` (operator): ends a
refused model-set backoff on one node. Body `{"set": "<id>@<rev>"}` or `{}`.
No placement changes. Additive.

## 2026-11-05

Added `GET /voice-space`, a public HTML shell. The voice session handoff and all
add-on data remain authenticated. The shell embeds the isolated voice origin;
it does not expose add-on scripts or console tokens across origins.
