package reconcile

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/addonwl"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// A lookup straight after registration, before the first 30 s tick, must
// resolve: Run loads addon_workloads from the first desired-config fetch.
func TestAddonWorkloadsDeclaredBeforeFirstTick(t *testing.T) {
	addonwl.SetDeclared(nil)
	t.Cleanup(func() { addonwl.SetDeclared(nil) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"addon_workloads":[{"addon":"rhaddon","name":"rhworker","container":"rhaddon-rhworker","gpu":true}]}`))
	}))
	defer srv.Close()
	r := &Reconciler{cfg: &config.Config{ControllerURL: srv.URL, NodeID: "awolf"}, client: srv.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if d, ok := addonwl.Lookup("rhaddon", "rhworker"); ok {
			if d.Container != "rhaddon-rhworker" {
				t.Fatalf("container = %q", d.Container)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("addon workload not declared within 5 s of Run (waited for the 30 s tick)")
}
