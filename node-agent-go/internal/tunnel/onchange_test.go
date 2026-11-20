package tunnel

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

type changes struct {
	mu  sync.Mutex
	log []bool
}

func (c *changes) add(v bool) { c.mu.Lock(); c.log = append(c.log, v); c.mu.Unlock() }
func (c *changes) snapshot() []bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]bool(nil), c.log...)
}

// A connect and a loss each tell OnChange (the agent turns each into a
// heartbeat kick), and the flag is already right when the hook runs.
func TestOnChangeFiresOnConnectAndOnLoss(t *testing.T) {
	var ch changes
	var rg *rig
	seen := make(chan bool, 8)
	rg = newRig(t, http.NotFoundHandler(), func(o *Options) {
		o.OnChange = func(v bool) {
			seen <- rg.client.Connected() == v
			ch.add(v)
		}
	})
	gc, _ := rg.run(t)
	waitFor(t, "the connect to reach OnChange", func() bool { return len(ch.snapshot()) >= 1 })
	if got := ch.snapshot(); got[0] != true {
		t.Fatalf("first change = %v, want connect (true)", got)
	}
	_ = gc.c.Close()
	waitFor(t, "the loss to reach OnChange", func() bool {
		g := ch.snapshot()
		return len(g) >= 2 && g[1] == false
	})
	deadline := time.After(time.Second)
	for i := 0; i < 2; i++ {
		select {
		case ok := <-seen:
			if !ok {
				t.Fatal("OnChange ran before Connected() held the new state")
			}
		case <-deadline:
			t.Fatal("missing OnChange observation")
		}
	}
}

// Only a CHANGE tells OnChange: two connects in a row are one kick.
func TestOnChangeIgnoresARepeatedState(t *testing.T) {
	var ch changes
	c := &Client{opt: Options{OnChange: ch.add}}
	c.setConnected(true)
	c.setConnected(true)
	c.setConnected(false)
	c.setConnected(false)
	got := ch.snapshot()
	if len(got) != 2 || got[0] != true || got[1] != false {
		t.Fatalf("changes = %v, want [true false]", got)
	}
}
