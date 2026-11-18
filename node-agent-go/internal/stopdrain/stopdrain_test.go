package stopdrain

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// A handler that holds its stream open until released or cut, and says which.
type held struct {
	release chan struct{}
	cut     chan struct{}
	header  chan string
}

func newHeld() *held {
	return &held{release: make(chan struct{}), cut: make(chan struct{}, 1), header: make(chan string, 1)}
}

func (h *held) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.header <- r.Header.Get(ResendHeader)
	select {
	case <-h.release:
		w.WriteHeader(http.StatusOK)
	case <-r.Context().Done():
		h.cut <- struct{}{}
	}
}

const controller = "x-test-controller"

func gate() *Gate {
	return New(func(r *http.Request) bool { return r.Header.Get(controller) == "yes" })
}

// start sends one request through the gate in the background and waits until
// the handler holds it.
func start(t *testing.T, g *Gate, h *held, marked, fromController bool) *sync.WaitGroup {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	if marked {
		req.Header.Set(ResendHeader, ResendWhole)
	}
	if fromController {
		req.Header.Set(controller, "yes")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.Wrap(h).ServeHTTP(httptest.NewRecorder(), req)
	}()
	if got := <-h.header; got != "" {
		t.Fatalf("the marker reached the backend: %q", got)
	}
	return &wg
}

func cutSoon(h *held) bool {
	select {
	case <-h.cut:
		return true
	case <-time.After(150 * time.Millisecond):
		return false
	}
}

// The controller's marked stream is cut at once; the same marker from anyone
// else is ignored and that stream is drained like any other.
func TestOnlyTheControllersMarkerCutsAtOnce(t *testing.T) {
	g := gate()
	ctrl, other, plain := newHeld(), newHeld(), newHeld()
	w1 := start(t, g, ctrl, true, true)
	w2 := start(t, g, other, true, false)
	w3 := start(t, g, plain, false, true)
	done := make(chan Result)
	go func() { done <- g.Drain(2*time.Second, 5*time.Millisecond) }()
	if !cutSoon(ctrl) {
		t.Fatal("the controller's marked stream was not cut at once")
	}
	if cutSoon(other) || cutSoon(plain) {
		t.Fatal("a stream a caller is reading was cut")
	}
	close(other.release)
	close(plain.release)
	r := <-done
	w1.Wait()
	w2.Wait()
	w3.Wait()
	if r.CutMarked != 1 || r.Drained != 2 || r.BoundHit || r.CutAtBound != 0 {
		t.Fatalf("result %+v", r)
	}
}

// Past the bound what is still open is cut, and the result says so.
func TestTheBoundCutsWhatIsLeftAndSaysSo(t *testing.T) {
	g := gate()
	slow := newHeld()
	w := start(t, g, slow, false, true)
	r := g.Drain(120*time.Millisecond, 5*time.Millisecond)
	if !cutSoon(slow) {
		t.Fatal("the stream outlived the bound")
	}
	w.Wait()
	if !r.BoundHit || r.CutAtBound != 1 || r.Drained != 0 {
		t.Fatalf("result %+v", r)
	}
}

// An idle node stops at once.
func TestAnIdleNodeStopsAtOnce(t *testing.T) {
	t0 := time.Now()
	r := gate().Drain(Bound, 5*time.Millisecond)
	if time.Since(t0) > 100*time.Millisecond || r.Drained != 0 || r.BoundHit {
		t.Fatalf("result %+v after %v", r, time.Since(t0))
	}
}

// A new call during the drain: refused with node_restarting and a Retry-After
// covering the rest of the drain and the restart, ONLY when the controller
// advertised it; otherwise served as before.
func TestANewCallDuringTheDrainIsRefusedOnlyWhenTheControllerCanReadIt(t *testing.T) {
	g := gate()
	hold := newHeld()
	w := start(t, g, hold, false, true)
	go g.Drain(10*time.Second, 5*time.Millisecond)
	time.Sleep(30 * time.Millisecond)

	served := 0
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served++; w.WriteHeader(http.StatusOK) })
	rec := httptest.NewRecorder()
	g.Wrap(ok).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if rec.Code != http.StatusOK || served != 1 {
		t.Fatalf("without the feature a new call must be served: %d", rec.Code)
	}

	g.SetFeatures([]string{"something", Feature})
	rec = httptest.NewRecorder()
	g.Wrap(ok).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if rec.Code != http.StatusServiceUnavailable || served != 1 {
		t.Fatalf("with the feature a new call is refused: %d", rec.Code)
	}
	var body struct {
		Error struct{ Code string } `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Error.Code != Code {
		t.Fatalf("code %q", body.Error.Code)
	}
	secs, _ := strconv.Atoi(rec.Header().Get("Retry-After"))
	if secs < 10 || secs > 14 {
		t.Fatalf("Retry-After %q must cover the drain left (~10 s) and the restart (3 s)", rec.Header().Get("Retry-After"))
	}
	g.SetFeatures(nil)
	if g.feature.Load() {
		t.Fatal("an absent feature list allows nothing")
	}
	close(hold.release)
	w.Wait()
}

func TestTheBoundIsAConstantNearTheFleetsP99(t *testing.T) {
	if Bound != 30*time.Second || RestartAllowance != 3*time.Second {
		t.Fatalf("bound %v allowance %v", Bound, RestartAllowance)
	}
	_ = context.Background()
}
