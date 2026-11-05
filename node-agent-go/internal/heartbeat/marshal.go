// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"encoding/json"
	"log/slog"
	"sort"
)

// marshalPayload marshals a heartbeat body. If marshalling fails (a NaN or
// Inf float is the usual cause: encoding/json refuses them), it finds which
// top-level key holds the bad value, logs that key, and marshals the body
// without it: one bad metric must not drop the whole beat.
func marshalPayload(payload map[string]any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err == nil {
		return body, nil
	}
	keys := make([]string, 0, len(payload))
	for k := range payload {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	clean := make(map[string]any, len(payload))
	for _, k := range keys {
		if _, kerr := json.Marshal(payload[k]); kerr != nil {
			slog.Error("heartbeat key cannot be marshalled; sending the beat without it", "key", k, "error", kerr)
			continue
		}
		clean[k] = payload[k]
	}
	return json.Marshal(clean)
}
