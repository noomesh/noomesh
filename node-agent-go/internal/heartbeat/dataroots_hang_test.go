// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/dataroots"
)

// A data root on a hung mount (a hard NFS mount, a dead USB disk) blocks a
// stat in the kernel. The heartbeat still goes out, within the probe bound,
// with the root reported "not answering" (i1160): before, the beat's first
// stat of the root held it, and the controller saw a silent node.
func TestAHungDataRootStillSendsTheHeartbeat(t *testing.T) {
	prev := dataroots.ProbeTimeout
	dataroots.ProbeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { dataroots.ProbeTimeout = prev })
	release := make(chan struct{})
	restore := dataroots.SetFSIdentityForTest(func(string) (dataroots.FSID, string, error) {
		<-release
		return dataroots.FSID{Target: "/", Dev: "8:1"}, "8:1", nil
	})
	root := t.TempDir()
	t.Cleanup(func() {
		close(release)
		// The stuck probe still reads the seam once it answers.
		dataroots.WaitProbeForTest(root, 3*time.Second)
		restore()
	})
	t.Setenv("NOO_DATA_ROOT", root)
	t.Setenv("NOO_AGENT_STATE", t.TempDir())
	t.Setenv("MODELS_DIR", "")
	t.Setenv("NOO_PKI_DIR", t.TempDir())

	beats := make(chan map[string]any, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got map[string]any
		_ = json.NewDecoder(r.Body).Decode(&got)
		beats <- got
		w.WriteHeader(200)
	}))
	defer server.Close()
	r := newTestReporter(t, server.URL, &config.Config{NodeID: "test-node", Tier: 3, NodeIP: "192.0.2.10"})

	sent := make(chan struct{})
	go func() { r.SendHeartbeat(); close(sent) }()
	select {
	case <-sent:
	case <-time.After(15 * time.Second):
		t.Fatal("the heartbeat waited on a hung data root")
	}
	var beat map[string]any
	select {
	case beat = <-beats:
	default:
		t.Fatal("no heartbeat reached the controller")
	}
	dr, _ := beat["data_roots"].(map[string]any)
	pol, _ := dr["policy"].(map[string]any)
	probs, _ := pol["problems"].([]any)
	if len(probs) != 1 {
		t.Fatalf("data_roots.policy: %v", pol)
	}
	p, _ := probs[0].(map[string]any)
	if p["code"] != "not_answering" || !strings.Contains(p["detail"].(string), "data root "+root+" not answering") {
		t.Fatalf("problem: %v", p)
	}
	if dr["noo_data_root"] != root {
		t.Fatalf("the resolved paths still go out: %v", dr)
	}
}
