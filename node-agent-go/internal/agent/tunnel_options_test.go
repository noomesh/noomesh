package agent

import (
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/heartbeat"
)

// The tunnel's OnChange is a heartbeat kick: the controller's record of the
// tunnel follows a connect or a loss within about a second.
func TestTunnelOptionsOnChangeKicksAHeartbeat(t *testing.T) {
	a := &Agent{cfg: &config.Config{NodeID: "n1"}, hb: &heartbeat.Reporter{}}
	o := a.tunnelOptions(nil, nil, nil)
	if o.OnChange == nil {
		t.Fatal("tunnel options carry no OnChange")
	}
	o.OnChange(true)
	if got := a.hb.KickPending(); got != 1 {
		t.Fatalf("pending kicks after a connect = %d, want 1", got)
	}
}
