// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// createDaemon is the slice of the Docker Engine API `ollama create` in the
// container touches: inspect (is noo-ollama running), the archive copy, and
// exec create. It records each exec-create body as sent on the wire, then
// refuses the exec start, so nothing past the create runs.
type createDaemon struct {
	mu    sync.Mutex
	execs []map[string]any
}

func newCreateDaemon(t *testing.T, d *createDaemon) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/_ping"):
			w.Header().Set("API-Version", "1.45")
			_, _ = w.Write([]byte("OK"))
		case r.Method == http.MethodGet && strings.HasSuffix(p, "/containers/"+OllamaContainer+"/json"):
			_, _ = w.Write([]byte(`{"Id":"c1","Name":"/` + OllamaContainer + `","State":{"Status":"running","Running":true}}`))
		case r.Method == http.MethodPut && strings.HasSuffix(p, "/containers/"+OllamaContainer+"/archive"):
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/containers/"+OllamaContainer+"/exec"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			d.mu.Lock()
			d.execs = append(d.execs, body)
			d.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"e1"}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"not faked: ` + r.Method + " " + p + `"}`))
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(srv.URL, "http://"))
	c, err := NewClient(http.DefaultClient, "http", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Finding 125 (outside tester, 0.6.21 retest): run with a TTY, `ollama
// create` wrote terminal queries (OSC 11, CSI 6n) and spinner frames into its
// output, and they reached the journal. The cause fix is the exec itself: no
// TTY, in the directory the Modelfile's `FROM ./<file>` resolves against.
// The cleaner (terminal_clean.go) is only the backstop.
func TestOllamaCreateExecsWithoutATTYInTheConvertDir(t *testing.T) {
	work := t.TempDir()
	for _, f := range []string{"Modelfile", "qwen3-4b-Q4_K_M.gguf"} {
		if err := os.WriteFile(filepath.Join(work, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d := &createDaemon{}
	c := newCreateDaemon(t, d)
	// The exec start is refused by the fake, so this errors after the create.
	_, _ = c.ollamaCreateInContainer(context.Background(), work, "qwen3:4b", "Modelfile", "qwen3-4b-Q4_K_M.gguf")

	d.mu.Lock()
	defer d.mu.Unlock()
	var create map[string]any
	for _, e := range d.execs {
		if cmd, _ := e["Cmd"].([]any); len(cmd) > 1 && cmd[0] == "ollama" && cmd[1] == "create" {
			create = e
		}
	}
	if create == nil {
		t.Fatalf("no `ollama create` exec was sent; execs: %v", d.execs)
	}
	if tty, _ := create["Tty"].(bool); tty {
		t.Errorf("ollama create exec has Tty=true: the CLI writes terminal queries and spinner frames into the log")
	}
	if wd, _ := create["WorkingDir"].(string); wd != convertDir {
		t.Errorf("WorkingDir = %q, want %q (FROM ./<file> resolves there)", wd, convertDir)
	}
	want := []any{"ollama", "create", "qwen3:4b", "-f", "Modelfile"}
	if got, _ := create["Cmd"].([]any); !reflect.DeepEqual(got, want) {
		t.Errorf("Cmd = %v, want %v", got, want)
	}
}
