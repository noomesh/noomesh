// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// The F5b additions to dockerProvAPI, over a daemon on a loopback port: the
// label-based listing that finds the workloads this agent created, the extra
// inspect fields, start and stop, and the nvidia-runtime fact. A fake of the
// function would prove nothing about what is asked of the daemon.

type engineCtr struct {
	ID     string
	Name   string
	Labels map[string]string
	State  string
	Status string // inspect: State.Status
	Run    bool
	Start  string // inspect: State.StartedAt
}

type lifeDaemon struct {
	mu   sync.Mutex
	ctrs []engineCtr
	// honorFilter: apply the label filter the way dockerd does. False: answer
	// every container whatever the filter says.
	honorFilter bool
	listStatus  int
	infoStatus  int
	runtimes    map[string]any

	listQueries []string
	calls       []string // "POST /containers/<name>/start", ".../stop?t=30"
}

func newLifeDaemon(t *testing.T, d *lifeDaemon) dockerProvAPI {
	t.Helper()
	if d.listStatus == 0 {
		d.listStatus = http.StatusOK
	}
	if d.infoStatus == 0 {
		d.infoStatus = http.StatusOK
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		if strings.HasSuffix(p, "/_ping") {
			w.Header().Set("API-Version", "1.45")
			_, _ = w.Write([]byte("OK"))
			return
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(p, "/containers/json"):
			d.listQueries = append(d.listQueries, r.URL.RawQuery)
			if d.listStatus != http.StatusOK {
				w.WriteHeader(d.listStatus)
				_, _ = w.Write([]byte(`{"message":"daemon unhappy"}`))
				return
			}
			all := r.URL.Query().Get("all") == "1" || r.URL.Query().Get("all") == "true"
			var want map[string]map[string]bool
			_ = json.Unmarshal([]byte(r.URL.Query().Get("filters")), &want)
			out := []map[string]any{}
			for _, c := range d.ctrs {
				if !all && c.State != "running" {
					continue
				}
				if d.honorFilter {
					ok := true
					for kv := range want["label"] {
						k, v, hasV := strings.Cut(kv, "=")
						got, has := c.Labels[k]
						if !has || (hasV && got != v) {
							ok = false
						}
					}
					if !ok {
						continue
					}
				}
				out = append(out, map[string]any{"Id": c.ID, "Names": []string{"/" + c.Name}, "Labels": c.Labels, "State": c.State})
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodGet && strings.Contains(p, "/containers/") && strings.HasSuffix(p, "/json"):
			name := strings.TrimSuffix(p[strings.Index(p, "/containers/")+len("/containers/"):], "/json")
			for _, c := range d.ctrs {
				if c.Name == name {
					_ = json.NewEncoder(w).Encode(map[string]any{
						"Id": c.ID, "Name": "/" + c.Name,
						"State":  map[string]any{"Status": c.Status, "Running": c.Run, "StartedAt": c.Start},
						"Config": map[string]any{"Labels": c.Labels},
					})
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"No such container: ` + name + `"}`))
		case r.Method == http.MethodPost && strings.Contains(p, "/containers/") && (strings.HasSuffix(p, "/start") || strings.HasSuffix(p, "/stop")):
			rest := p[strings.Index(p, "/containers/")+len("/containers/"):]
			call := "POST /containers/" + rest
			if t := r.URL.Query().Get("t"); t != "" {
				call += "?t=" + t
			}
			d.calls = append(d.calls, call)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasSuffix(p, "/info"):
			if d.infoStatus != http.StatusOK {
				w.WriteHeader(d.infoStatus)
				_, _ = w.Write([]byte(`{"message":"info failed"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Runtimes": d.runtimes})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"unexpected ` + r.Method + " " + p + `"}`))
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(srv.URL, "http://"))
	c, err := NewClient(http.DefaultClient, "http", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	return dockerProvAPI{c}
}

func agentLabels(addon, wl, role string, extra map[string]string) map[string]string {
	l := map[string]string{LabelManagedBy: ManagedByAgent, LabelAddon: addon, LabelWorkload: wl, LabelRole: role}
	for k, v := range extra {
		l[k] = v
	}
	return l
}

func TestListManagedAsksForTheAgentsLabelInEveryState(t *testing.T) {
	drain := map[string]string{LabelDrainPath: "/d", LabelDrainDone: "/d/done", LabelDrainTimeout: "90"}
	d := &lifeDaemon{honorFilter: true, ctrs: []engineCtr{
		{ID: "1", Name: "noo-stunnel-a-w", State: "running", Labels: agentLabels("a", "w", RoleDoor, nil)},
		{ID: "2", Name: "noo-wl-a-w", State: "exited", Labels: agentLabels("a", "w", RoleWorker, drain)},
		{ID: "3", Name: "noo-wl-b-x", State: "created", Labels: agentLabels("b", "x", RoleWorker, nil)},
		// Someone else's container, even one that reuses our other labels.
		{ID: "4", Name: "db", State: "running", Labels: map[string]string{"com.example": "1"}},
		{ID: "5", Name: "lookalike", State: "running", Labels: map[string]string{LabelAddon: "c", LabelWorkload: "y", LabelRole: RoleWorker}},
		{ID: "6", Name: "noo-managed-no-names", State: "running", Labels: map[string]string{LabelManagedBy: ManagedByAgent}},
		{ID: "7", Name: "noo-managed-no-workload", State: "running", Labels: map[string]string{LabelManagedBy: ManagedByAgent, LabelAddon: "d"}},
		{ID: "8", Name: "noo-managed-no-addon", State: "running", Labels: map[string]string{LabelManagedBy: ManagedByAgent, LabelWorkload: "z"}},
	}}
	api := newLifeDaemon(t, d)
	refs, err := api.ListManaged(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]string{}
	for _, r := range refs {
		got[r.Addon+"/"+r.Name] = r.Labels
	}
	if len(refs) != 2 || got["a/w"] == nil || !reflect.DeepEqual(got["a/w"], agentLabels("a", "w", RoleWorker, drain)) {
		t.Fatalf("refs = %+v; want a/w (with the WORKER's labels, not the door's) and b/x only", refs)
	}
	if _, ok := got["b/x"]; !ok {
		t.Fatalf("a created-but-never-started workload is missing: %+v", refs)
	}
	// What was asked of the daemon: every state, and the agent's label.
	if len(d.listQueries) != 1 {
		t.Fatalf("list queries = %v", d.listQueries)
	}
	q := d.listQueries[0]
	if !strings.Contains(q, "all=1") && !strings.Contains(q, "all=true") {
		t.Errorf("the listing does not ask for stopped containers: %q", q)
	}
	if !strings.Contains(q, "filters=") || !strings.Contains(q, "noo.managed-by") || !strings.Contains(q, "agent") {
		t.Errorf("the listing does not filter on noo.managed-by=agent: %q", q)
	}
}

// A daemon (or a proxy in front of it) that ignored the filter must not turn a
// foreign container into one of ours: the orphan sweep drains and DELETES what
// it finds.
func TestListManagedChecksTheAgentLabelItself(t *testing.T) {
	d := &lifeDaemon{honorFilter: false, ctrs: []engineCtr{
		{ID: "1", Name: "noo-wl-a-w", State: "running", Labels: agentLabels("a", "w", RoleWorker, nil)},
		{ID: "2", Name: "lookalike", State: "running", Labels: map[string]string{LabelAddon: "c", LabelWorkload: "y", LabelRole: RoleWorker}},
		{ID: "3", Name: "other-manager", State: "running", Labels: map[string]string{LabelManagedBy: "someone-else", LabelAddon: "e", LabelWorkload: "q", LabelRole: RoleWorker}},
	}}
	refs, err := newLifeDaemon(t, d).ListManaged(context.Background())
	if err != nil || len(refs) != 1 || refs[0].Addon != "a" {
		t.Fatalf("refs = %+v, %v; want only a/w", refs, err)
	}
}

func TestListManagedErrorIsAnErrorNotAnEmptyList(t *testing.T) {
	d := &lifeDaemon{listStatus: http.StatusInternalServerError, ctrs: []engineCtr{
		{ID: "1", Name: "noo-wl-a-w", State: "running", Labels: agentLabels("a", "w", RoleWorker, nil)},
	}}
	if refs, err := newLifeDaemon(t, d).ListManaged(context.Background()); err == nil {
		t.Fatalf("a failed listing = %+v, nil; want an error (the sweep would read it as 'none left')", refs)
	}
}

func TestInspectReportsStatusAndStartTime(t *testing.T) {
	d := &lifeDaemon{ctrs: []engineCtr{
		{ID: "1", Name: "ran", Status: "exited", Run: false, Start: "2026-11-05T12:00:00.123456789Z", Labels: agentLabels("a", "w", RoleWorker, nil)},
		{ID: "2", Name: "never", Status: "created", Run: false, Start: "0001-01-01T00:00:00Z", Labels: agentLabels("a", "w", RoleWorker, nil)},
		{ID: "3", Name: "offset-zero", Status: "created", Run: false, Start: "0001-01-01T00:00:00+01:00", Labels: agentLabels("a", "w", RoleWorker, nil)},
		{ID: "4", Name: "garbage", Status: "running", Run: true, Start: "yesterday", Labels: agentLabels("a", "w", RoleWorker, nil)},
		{ID: "5", Name: "dead", Status: "dead", Run: false, Start: "2026-11-05T12:00:00Z", Labels: agentLabels("a", "w", RoleWorker, nil)},
	}}
	api := newLifeDaemon(t, d)
	for name, want := range map[string]struct {
		status  string
		running bool
		started time.Time
	}{
		"ran":         {"exited", false, time.Date(2026, 11, 5, 12, 0, 0, 123456789, time.UTC)},
		"never":       {"created", false, time.Time{}},
		"offset-zero": {"created", false, time.Time{}},
		"garbage":     {"running", true, time.Time{}},
		"dead":        {"dead", false, time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)},
	} {
		c, err := api.InspectContainer(context.Background(), name)
		if err != nil || c == nil {
			t.Fatalf("%s: %v, %v", name, c, err)
		}
		if c.Status != want.status || c.Running != want.running || !c.StartedAt.Equal(want.started) {
			t.Errorf("%s: status %q running %v started %v; want %q %v %v", name, c.Status, c.Running, c.StartedAt, want.status, want.running, want.started)
		}
	}
	if c, err := api.InspectContainer(context.Background(), "absent"); err != nil || c != nil {
		t.Errorf("an absent container = %v, %v; want nil, nil", c, err)
	}
}

func TestStartAndStopGoToTheDaemonByName(t *testing.T) {
	d := &lifeDaemon{}
	api := newLifeDaemon(t, d)
	if err := api.StartContainer(context.Background(), "noo-wl-a-w"); err != nil {
		t.Fatal(err)
	}
	if err := api.StopContainer(context.Background(), "noo-wl-a-w", 30); err != nil {
		t.Fatal(err)
	}
	want := []string{"POST /containers/noo-wl-a-w/start", "POST /containers/noo-wl-a-w/stop?t=30"}
	if !reflect.DeepEqual(d.calls, want) {
		t.Fatalf("daemon calls = %v, want %v", d.calls, want)
	}
}

// The heartbeat's nvidia_runtime fact: a failed `docker info` is unknown (an
// error), never "registered" and never "missing". The existing helper that
// fails open is not the one used.
func TestNvidiaRuntimeKnownIsAnErrorWhenDockerCannotSay(t *testing.T) {
	for name, tc := range map[string]struct {
		d    *lifeDaemon
		want bool
		err  bool
	}{
		"registered": {&lifeDaemon{runtimes: map[string]any{"runc": map[string]any{}, "nvidia": map[string]any{}}}, true, false},
		"missing":    {&lifeDaemon{runtimes: map[string]any{"runc": map[string]any{}}}, false, false},
		"info fails": {&lifeDaemon{infoStatus: http.StatusInternalServerError}, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			api := newLifeDaemon(t, tc.d)
			got, err := api.c.NvidiaRuntimeKnown(context.Background())
			if (err != nil) != tc.err || got != tc.want {
				t.Fatalf("NvidiaRuntimeKnown = %v, %v; want %v, error=%v", got, err, tc.want, tc.err)
			}
		})
	}
}
