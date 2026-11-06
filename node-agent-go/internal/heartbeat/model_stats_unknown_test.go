// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/lanes"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelpresence"
)

// i495 item 4: the dockerised ollama's /api/ps fails while /api/tags
// answers. `model_stats` lists the model with loaded, resident_bytes and
// vram_bytes OMITTED (unknown), never loaded:false with 0 bytes.
func TestOllamaModelStatsFailedPsIsLoadedUnknown(t *testing.T) {
	tags := `{"models":[{"name":"gemma4:12b","size":7000000000,"digest":"d1"}]}`
	cases := map[string]func(w http.ResponseWriter, r *http.Request){
		"500": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) },
		"closed connection": func(w http.ResponseWriter, r *http.Request) {
			c, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = c.Close()
			}
		},
	}
	for name, psHandler := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/tags":
					_, _ = w.Write([]byte(tags))
				case "/api/ps":
					psHandler(w, r)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			r := &Reporter{}
			r.SetOllamaDoor(func() string { return srv.URL })
			stats := r.ollamaModelStats()
			if len(stats) != 1 || stats[0].Name != "gemma4:12b" || stats[0].SizeBytes != 7000000000 {
				t.Fatalf("stats = %+v, want the one model on disk", stats)
			}
			if !stats[0].LoadedUnknown || stats[0].Loaded {
				t.Errorf("failed /api/ps must give loaded unknown, got %+v", stats[0])
			}
			b, _ := json.Marshal(stats)
			var wire []map[string]any
			_ = json.Unmarshal(b, &wire)
			for _, k := range []string{"loaded", "resident_bytes", "vram_bytes"} {
				if _, ok := wire[0][k]; ok {
					t.Errorf("wire shape carries %q while unknown: %s", k, b)
				}
			}

			// Lanes: on disk, loaded unknown -> on_demand (routable), never
			// serving on a guess and never missing.
			modelpresence.Reset()
			t.Cleanup(func() { modelpresence.Reset(); lanes.SetPlaced(nil) })
			lanes.SetPlaced([]lanes.Placed{{Backend: "ollama", Model: "gemma4:12b", Role: "chat"}})
			got := r.lanesReport(map[string]any{
				"running_backends": map[string]string{"ollama": "gemma4:12b"},
				"model_stats":      stats,
			})
			want := []lanes.Lane{{Backend: "ollama", Model: "gemma4:12b", Role: "chat", State: "on_demand", Reason: "not loaded"}}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("lanes = %#v\nwant %#v", got, want)
			}
		})
	}
}

// /api/tags failing too: no model_stats at all (nothing is known on disk).
func TestOllamaModelStatsFailedTagsIsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	r := &Reporter{}
	r.SetOllamaDoor(func() string { return srv.URL })
	if got := r.ollamaModelStats(); got != nil {
		t.Errorf("stats = %+v, want nil", got)
	}
}
