// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/moby/moby/client"
)

// fakeDaemon answers the few Docker API calls the door code makes:
// inspect by name or ID from containers, and create/start, recording each
// create body.
type fakeDaemon struct {
	containers map[string]map[string]any
	created    []map[string]any
}

func (f *fakeDaemon) client(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/containers/create"):
			body, _ := io.ReadAll(r.Body)
			var req map[string]any
			_ = json.Unmarshal(body, &req)
			req["Name"] = r.URL.Query().Get("name")
			f.created = append(f.created, req)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Id":"created","Warnings":[]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/start"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasSuffix(path, "/json") && strings.Contains(path, "/containers/"):
			name := strings.TrimSuffix(path[strings.LastIndex(path, "/containers/")+len("/containers/"):], "/json")
			ctr, ok := f.containers[name]
			if !ok {
				http.Error(w, `{"message":"No such container: `+name+`"}`, http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ctr)
		default:
			http.Error(w, `{"message":"unexpected `+r.Method+` `+path+`"}`, http.StatusNotImplemented)
		}
	}))
	t.Cleanup(srv.Close)
	dc, err := client.NewClientWithOpts(client.WithHost("tcp://"+strings.TrimPrefix(srv.URL, "http://")), client.WithVersion("1.47"))
	if err != nil {
		t.Fatal(err)
	}
	return &Client{docker: dc}
}

func inspectJSON(id, name, netMode string, networks map[string]string) map[string]any {
	nets := map[string]any{}
	for n, ip := range networks {
		nets[n] = map[string]any{"IPAddress": ip}
	}
	return map[string]any{
		"Id": id, "Name": "/" + name,
		"HostConfig":      map[string]any{"NetworkMode": netMode},
		"NetworkSettings": map[string]any{"Networks": nets},
	}
}

// The engine keeps the name callers dial (noo-vllm) but has no address of
// its own inside its door's namespace: a host-mode agent's dial of
// noo-vllm:8000 must land on the door's bridge address, the same place
// docker DNS sends a containerised caller (the door's alias). One hop only.
func TestContainerDialAddrFollowsTheDoorNamespace(t *testing.T) {
	if LoopbackDoorPublish() {
		t.Skip("macOS dials the door's loopback publish")
	}
	door := inspectJSON("d00r", "noo-stunnel-vllm", "noo-cluster", map[string]string{"noo-cluster": "172.19.0.7"})
	engine := inspectJSON("e9g1ne", "noo-vllm", "container:d00r", nil)
	f := &fakeDaemon{containers: map[string]map[string]any{
		"noo-vllm": engine, "e9g1ne": engine, "d00r": door, "noo-stunnel-vllm": door,
	}}
	c := f.client(t)
	got, err := c.ContainerDialAddr(context.Background(), "noo-vllm", "8000")
	if err != nil || got != "172.19.0.7:8000" {
		t.Fatalf("ContainerDialAddr(noo-vllm) = %q, %v; want the door's 172.19.0.7:8000", got, err)
	}
	// A container on the bridge itself resolves as before.
	if got, err := c.ContainerDialAddr(context.Background(), "noo-stunnel-vllm", "8000"); err != nil || got != "172.19.0.7:8000" {
		t.Fatalf("ContainerDialAddr(noo-stunnel-vllm) = %q, %v", got, err)
	}
	// An owner that itself shares another's namespace is not followed.
	f.containers["d00r"] = inspectJSON("d00r", "noo-stunnel-vllm", "container:elsewhere", nil)
	if _, err := c.ContainerDialAddr(context.Background(), "noo-vllm", "8000"); err == nil || !strings.Contains(err.Error(), "not followed") {
		t.Fatalf("a two-hop namespace must be refused: %v", err)
	}
	// An owner that is gone is named.
	delete(f.containers, "d00r")
	if _, err := c.ContainerDialAddr(context.Background(), "noo-vllm", "8000"); err == nil || !strings.Contains(err.Error(), "shares the network of d00r") {
		t.Fatalf("a missing owner must be named: %v", err)
	}
}

// vLLM's door joins the bridge under noo-vllm, so every caller's URL
// (https://noo-vllm:8000) and the vllm leaf's SAN stay what they were; a
// door with no alias joins under its own name only.
func TestTheVLLMDoorTakesTheEngineName(t *testing.T) {
	prev := doorSelfName
	doorSelfName = func() (string, error) { return "awolf", nil }
	t.Cleanup(func() { doorSelfName = prev })
	t.Setenv("NOO_PKI_DIR", t.TempDir())

	f := &fakeDaemon{containers: map[string]map[string]any{}}
	c := f.client(t)
	if err := c.startSidecar(context.Background(), "vllm", "noomesh/stunnel:latest", "noo-cluster", 8000); err != nil {
		t.Fatal(err)
	}
	if err := c.startSidecar(context.Background(), "llamacpp", "noomesh/stunnel:latest", "noo-cluster", 8085); err != nil {
		t.Fatal(err)
	}
	if len(f.created) != 2 {
		t.Fatalf("created %d containers, want 2", len(f.created))
	}
	aliases := func(req map[string]any) []string {
		var out []string
		nc, _ := req["NetworkingConfig"].(map[string]any)
		eps, _ := nc["EndpointsConfig"].(map[string]any)
		ep, _ := eps["noo-cluster"].(map[string]any)
		list, _ := ep["Aliases"].([]any)
		for _, a := range list {
			out = append(out, a.(string))
		}
		return out
	}
	vllm, llama := f.created[0], f.created[1]
	if vllm["Name"] != "noo-stunnel-vllm" || strings.Join(aliases(vllm), ",") != "noo-vllm" {
		t.Errorf("vllm door %v joins with aliases %v, want noo-stunnel-vllm with noo-vllm", vllm["Name"], aliases(vllm))
	}
	if llama["Name"] != "noo-stunnel-llamacpp" || len(aliases(llama)) != 0 {
		t.Errorf("llamacpp door %v joins with aliases %v, want none", llama["Name"], aliases(llama))
	}
	// The vLLM door serves the vllm leaf and connects to the engine on loopback.
	env, _ := vllm["Env"].([]any)
	conf := ""
	for _, e := range env {
		if s, _ := e.(string); strings.HasPrefix(s, "STUNNEL_CONF=") {
			conf = s
		}
	}
	for _, needle := range []string{"accept = noo-stunnel-vllm:8000", "connect = 127.0.0.1:8000", "cert = /tls/services/vllm/service.crt", "verify = 2", "checkHost = awolf"} {
		if !strings.Contains(conf, needle) {
			t.Errorf("vllm door conf lacks %q:\n%s", needle, conf)
		}
	}
}
