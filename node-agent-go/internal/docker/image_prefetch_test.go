// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed/preseedtest"
)

// prefetchRig fakes the daemon-facing seams: nothing is local, every
// EnsureImage blocks on release until the test lets it go, and in-flight
// calls and the maximum seen at once are recorded.
type prefetchRig struct {
	mu       sync.Mutex
	calls    []string
	inflight int32
	maxSeen  int32
	started  chan string
	release  chan struct{}
	failRef  string
}

func newPrefetchRig(t *testing.T) *prefetchRig {
	t.Helper()
	g := &prefetchRig{started: make(chan string, 16), release: make(chan struct{}, 16)}
	pl, pe := imageLocalID, ensureImageFn
	imageLocalID = func(context.Context, *Client, string) (string, bool) { return "", false }
	ensureImageFn = func(_ context.Context, _ *Client, ref string) error {
		n := atomic.AddInt32(&g.inflight, 1)
		for {
			m := atomic.LoadInt32(&g.maxSeen)
			if n <= m || atomic.CompareAndSwapInt32(&g.maxSeen, m, n) {
				break
			}
		}
		g.mu.Lock()
		g.calls = append(g.calls, ref)
		g.mu.Unlock()
		g.started <- ref
		<-g.release
		atomic.AddInt32(&g.inflight, -1)
		if ref == g.failRef {
			return errors.New("rail down")
		}
		return nil
	}
	t.Cleanup(func() { imageLocalID, ensureImageFn = pl, pe })
	return g
}

// run starts PrefetchImages and returns a channel carrying its result.
func (g *prefetchRig) run(refs []string, placements int) <-chan PrefetchResult {
	out := make(chan PrefetchResult, 1)
	go func() { out <- (&Client{}).PrefetchImages(context.Background(), refs, placements) }()
	return out
}

func (g *prefetchRig) waitStarted(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-g.started:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d pulls started", i, n)
		}
	}
}

func (g *prefetchRig) noMoreStarts(t *testing.T) {
	t.Helper()
	select {
	case ref := <-g.started:
		t.Fatalf("%s started beyond the parallelism bound", ref)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestPrefetchPullsDistinctImagesUpToTheBound(t *testing.T) {
	t.Setenv(ImagePullParallelismEnv, "")
	g := newPrefetchRig(t)
	done := g.run([]string{"a:1", "b:1", "c:1"}, 3)

	g.waitStarted(t, imagePullParallelism)
	g.noMoreStarts(t) // the third waits for a free worker
	select {
	case <-done:
		t.Fatal("PrefetchImages returned before its pulls finished")
	default:
	}
	for i := 0; i < 3; i++ {
		g.release <- struct{}{}
		if i == 0 {
			g.waitStarted(t, 1) // a worker freed: the third begins
		}
	}
	res := <-done
	if res.Pulled != 3 || res.Failed != 0 || res.Wanted != 3 {
		t.Fatalf("result %+v", res)
	}
	if got := atomic.LoadInt32(&g.maxSeen); got != imagePullParallelism {
		t.Fatalf("max in flight %d, want %d", got, imagePullParallelism)
	}
	if len(g.calls) != 3 {
		t.Fatalf("calls %v", g.calls)
	}
}

func TestPrefetchOnePullPerImage(t *testing.T) {
	t.Setenv(ImagePullParallelismEnv, "")
	g := newPrefetchRig(t)
	g.release <- struct{}{}
	res := <-g.run([]string{"same:1", "same:1", " same:1 "}, 3)
	if len(g.calls) != 1 || res.Wanted != 1 || res.Pulled != 1 {
		t.Fatalf("calls %v result %+v", g.calls, res)
	}
}

func TestPrefetchParallelismOneIsSerial(t *testing.T) {
	t.Setenv(ImagePullParallelismEnv, "1")
	g := newPrefetchRig(t)
	done := g.run([]string{"a:1", "b:1", "c:1"}, 3)
	for i := 0; i < 3; i++ {
		g.waitStarted(t, 1)
		g.noMoreStarts(t)
		g.release <- struct{}{}
	}
	<-done
	if got := atomic.LoadInt32(&g.maxSeen); got != 1 {
		t.Fatalf("max in flight %d, want 1", got)
	}
	if got := []string{"a:1", "b:1", "c:1"}; len(g.calls) != 3 || g.calls[0] != got[0] || g.calls[2] != got[2] {
		t.Fatalf("not in order: %v", g.calls)
	}
}

func TestPrefetchBadParallelismFallsBackToTheDefault(t *testing.T) {
	for _, v := range []string{"0", "-3", "many"} {
		t.Setenv(ImagePullParallelismEnv, v)
		if got := imagePullParallelismNow(); got != imagePullParallelism {
			t.Fatalf("%q -> %d", v, got)
		}
	}
	t.Setenv(ImagePullParallelismEnv, "4")
	if got := imagePullParallelismNow(); got != 4 {
		t.Fatalf("4 -> %d", got)
	}
}

func TestPrefetchOneFailureDoesNotStopTheOthers(t *testing.T) {
	t.Setenv(ImagePullParallelismEnv, "")
	g := newPrefetchRig(t)
	g.failRef = "b:1"
	for i := 0; i < 3; i++ {
		g.release <- struct{}{}
	}
	res := <-g.run([]string{"a:1", "b:1", "c:1"}, 3)
	if res.Pulled != 2 || res.Failed != 1 || len(g.calls) != 3 {
		t.Fatalf("result %+v calls %v", res, g.calls)
	}
}

func TestPrefetchLeavesLocalImagesAlone(t *testing.T) {
	g := newPrefetchRig(t)
	imageLocalID = func(_ context.Context, _ *Client, ref string) (string, bool) { return "sha256:x", ref == "have:1" }
	g.release <- struct{}{}
	res := <-g.run([]string{"have:1", "need:1"}, 2)
	if len(g.calls) != 1 || g.calls[0] != "need:1" || res.Skipped != 1 {
		t.Fatalf("calls %v result %+v", g.calls, res)
	}
}

func TestPrefetchWithNothingMissingPullsNothing(t *testing.T) {
	g := newPrefetchRig(t)
	imageLocalID = func(context.Context, *Client, string) (string, bool) { return "sha256:x", true }
	res := (&Client{}).PrefetchImages(context.Background(), []string{"a:1"}, 1)
	if len(g.calls) != 0 || res.Skipped != 1 {
		t.Fatalf("calls %v result %+v", g.calls, res)
	}
}

// Concurrent PullImageArtifact calls for one ref run one at a time (they
// would otherwise share a staged .partial); another ref is not held up.
func TestPullImageArtifactSerialisesPerRef(t *testing.T) {
	pki := preseedtest.New(t)
	pki.SetNodeEnv(t)
	srv := pki.Store(t, http.NotFoundHandler())
	t.Setenv("NOO_MODEL_CACHE_URL", srv.URL)
	var inflight, maxSeen int32
	release := make(chan struct{})
	entered := make(chan string, 8)
	prev := imageManifestFetch
	imageManifestFetch = func(_ context.Context, tar string) (*artifactManifest, error) {
		n := atomic.AddInt32(&inflight, 1)
		for {
			m := atomic.LoadInt32(&maxSeen)
			if n <= m || atomic.CompareAndSwapInt32(&maxSeen, m, n) {
				break
			}
		}
		entered <- tar
		<-release
		atomic.AddInt32(&inflight, -1)
		return nil, ErrArtifactAbsent
	}
	t.Cleanup(func() { imageManifestFetch = prev })

	var wg sync.WaitGroup
	pull := func(ref string) {
		defer wg.Done()
		if _, err := (&Client{}).PullImageArtifact(context.Background(), ref, "", ""); !IsImageNotStaged(err) {
			t.Errorf("%s: err %v", ref, err)
		}
	}
	wg.Add(2)
	go pull("same:1")
	go pull("same:1")
	<-entered
	select {
	case tar := <-entered:
		t.Fatalf("second pull of the same ref entered (%s) while the first held the lock", tar)
	case <-time.After(150 * time.Millisecond):
	}
	wg.Add(1)
	go pull("other:1")
	select {
	case <-entered: // a different ref is not blocked
	case <-time.After(5 * time.Second):
		t.Fatal("a pull of another ref was blocked by the per-ref lock")
	}
	close(release)
	wg.Wait()
	if got := atomic.LoadInt32(&maxSeen); got != 2 {
		t.Fatalf("max in flight %d, want 2 (one per distinct ref)", got)
	}
}

// A pull that waited on the per-ref lock finds the image local once the
// first one lands and makes no manifest or fetch call of its own.
func TestPullImageArtifactSecondCallerFindsItLocal(t *testing.T) {
	pki := preseedtest.New(t)
	pki.SetNodeEnv(t)
	t.Setenv("NOO_MODEL_CACHE_URL", pki.Store(t, http.NotFoundHandler()).URL)
	var landed atomic.Bool
	var manifestCalls int32
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	pl, pm := imageLocalID, imageManifestFetch
	imageLocalID = func(context.Context, *Client, string) (string, bool) { return "sha256:new", landed.Load() }
	imageManifestFetch = func(context.Context, string) (*artifactManifest, error) {
		atomic.AddInt32(&manifestCalls, 1)
		entered <- struct{}{}
		<-release
		landed.Store(true) // the first pull "loads" the image
		return nil, ErrArtifactAbsent
	}
	var removed []string
	var rmu sync.Mutex
	pr := removeContainerFn
	removeContainerFn = func(_ context.Context, _ *Client, name string) error {
		rmu.Lock()
		removed = append(removed, name)
		rmu.Unlock()
		return nil
	}
	t.Cleanup(func() { imageLocalID, imageManifestFetch, removeContainerFn = pl, pm, pr })

	type out struct {
		res *PullImageArtifactResult
		err error
	}
	results := make(chan out, 2)
	pull := func() {
		r, err := (&Client{}).PullImageArtifact(context.Background(), "race:1", "", "noo-old")
		results <- out{r, err}
	}
	go pull()
	<-entered
	go pull()
	time.Sleep(150 * time.Millisecond) // let the second reach the lock
	close(release)
	var upToDate, refused int
	for i := 0; i < 2; i++ {
		o := <-results
		switch {
		case o.err == nil && o.res.Status == "up_to_date":
			upToDate++
			if o.res.Removed != "noo-old" {
				t.Fatalf("the waiter must still remove the old container, Removed=%q", o.res.Removed)
			}
		case IsImageNotStaged(o.err):
			refused++
		default:
			t.Fatalf("unexpected result %+v %v", o.res, o.err)
		}
	}
	if len(removed) != 1 || removed[0] != "noo-old" {
		t.Fatalf("daemon removals %v, want [noo-old]", removed)
	}
	if upToDate != 1 || refused != 1 || atomic.LoadInt32(&manifestCalls) != 2 {
		t.Fatalf("upToDate=%d refused=%d manifestCalls=%d, want 1 1 2 (one pull asks for the .tar.gz then the .tar name)", upToDate, refused, manifestCalls)
	}
}
