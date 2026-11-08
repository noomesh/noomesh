// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// i300 F5c: NodeWorkloadOf decides which containers get the door relay. It is
// driven against the Docker Engine API on a loopback port, so the real client,
// its inspect call and its error mapping are what answer. (listFakeDaemon
// cannot be reused as is: its failing inspect always says "inspect broke",
// and "no such container" is the wording the not-found path keys on.)

func wlInspectJSON(name, labels string) string {
	return fmt.Sprintf(`{"Id":"id-%s","Name":"/%s","Config":{"Labels":%s}}`, name, name, labels)
}

// inspectDaemon answers GET /containers/<name>/json with status/body from
// answers; a name not in the map is a 404 "No such container".
type inspectAnswer struct {
	status int
	body   string
}

func newInspectDaemon(t *testing.T, answers map[string]inspectAnswer) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			w.Header().Set("API-Version", "1.45")
			_, _ = w.Write([]byte("OK"))
			return
		}
		if m := listInspectPath.FindStringSubmatch(r.URL.Path); m != nil {
			if a, ok := answers[m[1]]; ok {
				w.WriteHeader(a.status)
				_, _ = w.Write([]byte(a.body))
				return
			}
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"message":"No such container: ` + m[1] + `"}`))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"message":"unexpected path"}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(srv.URL, "http://"))
	c, err := NewClient(http.DefaultClient, "http", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNodeWorkloadOf(t *testing.T) {
	const (
		worker = "noo-wl-ao-wk"
		door   = "noo-stunnel-ao-wk"
	)
	managedLabels := `{"noo.managed-by":"agent","noo.addon":"ao","noo.workload":"wk"}`
	type tc struct {
		name         string
		ask          string
		answer       *inspectAnswer // nil: the daemon does not know the container
		wantManaged  bool
		wantAddon    string
		wantWorkload string
		wantErr      bool
	}
	cases := []tc{
		{name: "the worker", ask: worker, answer: &inspectAnswer{200, wlInspectJSON(worker, managedLabels)}, wantManaged: true, wantAddon: "ao", wantWorkload: "wk"},
		{name: "container gone", ask: worker},
		{name: "no Config at all", ask: worker, answer: &inspectAnswer{200, fmt.Sprintf(`{"Id":"id","Name":"/%s"}`, worker)}},
		{name: "no labels", ask: worker, answer: &inspectAnswer{200, wlInspectJSON(worker, `{}`)}},
		{name: "managed-by missing", ask: worker, answer: &inspectAnswer{200, wlInspectJSON(worker, `{"noo.addon":"ao","noo.workload":"wk"}`)}},
		{name: "managed-by another value", ask: worker, answer: &inspectAnswer{200, wlInspectJSON(worker, `{"noo.managed-by":"someone","noo.addon":"ao","noo.workload":"wk"}`)}},
		{name: "addon label empty", ask: worker, answer: &inspectAnswer{200, wlInspectJSON(worker, `{"noo.managed-by":"agent","noo.addon":"","noo.workload":"wk"}`)}},
		{name: "workload label missing", ask: worker, answer: &inspectAnswer{200, wlInspectJSON(worker, `{"noo.managed-by":"agent","noo.addon":"ao"}`)}},
		// The name check cannot catch these: the name IS what the labels imply.
		{name: "addon label empty, name agrees", ask: "noo-wl--wk", answer: &inspectAnswer{200, wlInspectJSON("noo-wl--wk", `{"noo.managed-by":"agent","noo.addon":"","noo.workload":"wk"}`)}},
		{name: "workload label empty, name agrees", ask: "noo-wl-ao-", answer: &inspectAnswer{200, wlInspectJSON("noo-wl-ao-", `{"noo.managed-by":"agent","noo.addon":"ao","noo.workload":""}`)}},
		{name: "the door sidecar carrying the worker's labels", ask: door, answer: &inspectAnswer{200, wlInspectJSON(door, managedLabels)}},
		{name: "a foreign container carrying the labels", ask: "noo-browser-ab12", answer: &inspectAnswer{200, wlInspectJSON("noo-browser-ab12", managedLabels)}},
		{name: "another workload's worker name with these labels", ask: "noo-wl-ao-other", answer: &inspectAnswer{200, wlInspectJSON("noo-wl-ao-other", managedLabels)}},
		{name: "daemon error is an error", ask: worker, answer: &inspectAnswer{500, `{"message":"daemon exploded"}`}, wantErr: true},
	}
	for _, c := range cases {
		answers := map[string]inspectAnswer{}
		if c.answer != nil {
			answers[c.ask] = *c.answer
		}
		cl := newInspectDaemon(t, answers)
		addon, workload, managed, err := cl.NodeWorkloadOf(context.Background(), c.ask)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, want error: %v", c.name, err, c.wantErr)
		}
		if managed != c.wantManaged || addon != c.wantAddon || workload != c.wantWorkload {
			t.Errorf("%s: got (%q, %q, managed=%v), want (%q, %q, managed=%v)", c.name, addon, workload, managed, c.wantAddon, c.wantWorkload, c.wantManaged)
		}
	}
}
