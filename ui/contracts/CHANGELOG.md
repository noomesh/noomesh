# Contract changes

## 2026-11-09

Added `POST /api/cluster/nodes/{node_id}/model-set-retry` (operator): ends a
refused model-set backoff on one node. Body `{"set": "<id>@<rev>"}` or `{}`.
No placement changes. Additive.

## 2026-11-05

Added `GET /voice-space`, a public HTML shell. The voice session handoff and all
add-on data remain authenticated. The shell embeds the isolated voice origin;
it does not expose add-on scripts or console tokens across origins.
