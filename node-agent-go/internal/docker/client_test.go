// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"errors"
	"strings"
	"testing"

	"github.com/moby/moby/client"
)

// the design removed docker.sock from the node-agent compose service.
// The service is opt-in (`--profile node-agent-compose`; there is no `worker`
// compose profile any more), so a deployment that selects it CAN still start
// this agent in a container with no socket. These pin what happens then.
func TestContainerisedAgentWithoutDockerRefusesToStart(t *testing.T) {
	origPing, origIn := pingDocker, inContainer
	defer func() { pingDocker, inContainer = origPing, origIn }()

	pingDocker = func(*client.Client) error { return errors.New("dial unix /var/run/docker.sock: no such file") }
	inContainer = func() bool { return true }

	_, err := NewClient(nil, "https", "noo", false)
	if err == nil {
		t.Fatal("a containerised agent with no Docker API must refuse to start — " +
			"otherwise it serves :8081, answers health, and fails every backend op")
	}
	// The message has to carry the fix, not just the fact — and the fix has
	// to be a command that WORKS. It named `noo cluster agent-host`, which
	// shells out to the ansible tree deleted in 3695e129, so an operator
	// following the advice hit a second dead end. It now names the pull
	// rail, which is how every agent in the fleet is actually installed.
	for _, want := range []string{"IN A CONTAINER", "cluster provision"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

// On a HOST the same condition is only a warning: the agent runs natively on
// macOS to drive a native Metal Ollama with no Docker at all, and on Linux it
// may simply start before dockerd. Refusing there breaks supported setups.
func TestHostAgentWithoutDockerStillStarts(t *testing.T) {
	origPing, origIn := pingDocker, inContainer
	defer func() { pingDocker, inContainer = origPing, origIn }()

	pingDocker = func(*client.Client) error { return errors.New("connection refused") }
	inContainer = func() bool { return false }

	if _, err := NewClient(nil, "https", "noo", false); err != nil {
		t.Fatalf("a host agent must tolerate Docker being absent or not yet up, got: %v", err)
	}
}

// A tier-5 SENSOR PROXY container has no docker.sock BY DESIGN (least
// privilege — its job never involves backend management), so for it the
// in-container condition is expected state, not misconfiguration: warn and
// start. Pinned live 2026-08-28: the host9-sensors recreate crash-looped
// on the fatal above until this exemption existed.
func TestSensorProxyContainerWithoutDockerStillStarts(t *testing.T) {
	origPing, origIn := pingDocker, inContainer
	defer func() { pingDocker, inContainer = origPing, origIn }()

	pingDocker = func(*client.Client) error { return errors.New("dial unix /var/run/docker.sock: no such file") }
	inContainer = func() bool { return true }

	if _, err := NewClient(nil, "https", "noo", true); err != nil {
		t.Fatalf("a sensor-proxy container must tolerate a missing docker.sock, got: %v", err)
	}
}

// And a reachable daemon must not be disturbed by any of this.
func TestReachableDockerStartsCleanly(t *testing.T) {
	origPing := pingDocker
	defer func() { pingDocker = origPing }()
	pingDocker = func(*client.Client) error { return nil }

	if _, err := NewClient(nil, "https", "noo", false); err != nil {
		t.Fatalf("healthy Docker must start cleanly, got: %v", err)
	}
}

// A rename-orphan is a container docker left behind on a deferred removal:
// a 12-hex prefix and an underscore before the original name. It still
// CONTAINS the backend's name, so the substring match counted it as the live
// backend — and because the caller builds a map, whichever appeared last in
// the listing won.
//
// The symptom is a reconciler that never converges: it recreates the backend
// every tick, logs "backend started via SDK", then reads the ORPHAN back and
// decides the model still does not match. Observed on host9 2026-09-04,
// where a placement change never took effect while every tick reported
// success — the shape this repo keeps meeting, an operation reporting what
// it did rather than what is true.
func TestRenameOrphansAreNotTheLiveBackend(t *testing.T) {
	for _, name := range []string{
		"a1b2c3d4e5f6_noo-llamacpp",
		"000000000000_noo-vllm",
		"deadbeefcafe_noo-reranker",
	} {
		if got := backendKeyFromName(name); got != "" {
			t.Errorf("%q is an orphan and must not claim a backend, got %q", name, got)
		}
	}
}

// The real containers must still map, including the name whose mapping was
// itself a past bug (noo-reranker matched nothing and the reconciler
// recreated it every tick — host8 2026-08-07).
func TestLiveBackendNamesStillMap(t *testing.T) {
	cases := map[string]string{
		"noo-llamacpp":       "llamacpp",
		"noo-vllm":           "vllm",
		"noo-vllm-secondary": "vllm-secondary",
		"noo-reranker":       "reranker",
		"noo-airllm":         "airllm",
		"noo-ollama":         "ollama",
		// A 12-hex-looking string that is not a PREFIX must not be filtered.
		"noo-llamacpp-a1b2c3d4e5f6": "llamacpp",
	}
	for name, want := range cases {
		if got := backendKeyFromName(name); got != want {
			t.Errorf("%q → %q, want %q", name, got, want)
		}
	}
}

// A host agent on a standalone controller reaches the embed container on
// loopback via OLLAMA_URL; a containerised worker keeps the compose alias.
func TestBackendURLHonoursOllamaURL(t *testing.T) {
	t.Setenv("OLLAMA_URL", "http://127.0.0.1:11434/")
	if got := BackendURL("ollama", ""); got != "http://127.0.0.1:11434" {
		t.Fatalf("override: got %q", got)
	}
	t.Setenv("OLLAMA_URL", "")
	if got := BackendURL("ollama", ""); got != "https://stunnel-ollama:11434" {
		t.Fatalf("default: got %q", got)
	}
}

// Every fronted backend's door is https, whatever the retired NOO_*_TLS
// flags say (a false value refuses the agent's START in config; here it
// is simply not read). airllm is the one named plaintext exception.
func TestSchemeFor_HTTPSByDefault(t *testing.T) {
	for _, env := range []string{"NOO_VLLM_TLS", "NOO_LLAMACPP_TLS", "NOO_OLLAMA_TLS", "NOO_TEI_TLS", "NOO_RERANKER_TLS"} {
		t.Setenv(env, "")
	}
	for _, b := range []string{"vllm", "llamacpp", "ollama", "embedding", "reranker"} {
		if got := SchemeFor(b); got != "https" {
			t.Errorf("SchemeFor(%s) = %q with no flag set; the door is TLS by default", b, got)
		}
	}
	t.Setenv("NOO_LLAMACPP_TLS", "false")
	if got := SchemeFor("llamacpp"); got != "https" {
		t.Errorf("NOO_LLAMACPP_TLS=false must not switch the scheme (it refuses the start instead): %q", got)
	}
	if got := SchemeFor("airllm"); got != "http" {
		t.Errorf("airllm is plain by named exception: %q", got)
	}
	// The flag table is config's — one declaration.
	if len(backendTLSEnvVars) != 5 || backendTLSEnvVars["embedding"] != "NOO_TEI_TLS" {
		t.Errorf("backendTLSEnvVars must be config.BackendTLSFlags: %v", backendTLSEnvVars)
	}
}

// The running containers' declaration decides the dial: a vLLM whose
// command says `--ssl-cert-reqs 2` over https, a backend whose
// noo-stunnel-<x> runs AT the sidecar, a pre-door container (no flag, no
// sidecar — created by an older agent) plain, and with no declaration
// readable the TLS door every agent-started backend is created with.
func TestBackendDialURL_FollowsTheContainersDeclaration(t *testing.T) {
	t.Setenv("OLLAMA_URL", "")
	decl := func(tls, sidecar, known []string) *declaredTLS {
		d := &declaredTLS{tls: map[string]bool{}, sidecars: map[string]bool{}, known: map[string]bool{}}
		for _, b := range tls {
			d.tls[b] = true
			d.known[b] = true
		}
		for _, b := range sidecar {
			d.sidecars[b] = true
			d.known[b] = true
		}
		for _, b := range known {
			d.known[b] = true
		}
		return d
	}
	cases := []struct {
		name, backend string
		d             *declaredTLS
		want          string
	}{
		{"no declaration: vllm's TLS door", "vllm", nil, "https://noo-vllm:8000"},
		{"no declaration: llama.cpp's sidecar door", "llamacpp", nil, "https://noo-stunnel-llamacpp:8085"},
		{"no declaration: reranker's sidecar door", "reranker", nil, "https://noo-stunnel-reranker:443"},
		{"no declaration: embedding's sidecar door", "embedding", nil, "https://noo-stunnel-tei:443"},
		{"no declaration: ollama's sidecar door", "ollama", nil, "https://noo-stunnel-ollama:11434"},
		{"no declaration: airllm plain by exception", "airllm", nil, "http://noo-airllm:8000"},
		{"vllm declares the flag", "vllm", decl([]string{"vllm"}, nil, nil), "https://noo-vllm:8000"},
		{"secondary declares the flag", "vllm-secondary", decl([]string{"vllm-secondary"}, nil, nil), "https://noo-vllm-secondary:8000"},
		{"sidecar running: dial it", "llamacpp", decl(nil, []string{"llamacpp"}, nil), "https://noo-stunnel-llamacpp:8085"},
		{"tei sidecar running (compose or agent)", "embedding", decl(nil, []string{"embedding"}, nil), "https://noo-stunnel-tei:443"},
		{"ollama sidecar running", "ollama", decl(nil, []string{"ollama"}, nil), "https://noo-stunnel-ollama:11434"},
		{"pre-door vllm: plain, what runs", "vllm", decl(nil, nil, []string{"vllm"}), "http://noo-vllm:8000"},
		{"pre-door secondary: plain", "vllm-secondary", decl(nil, nil, []string{"vllm-secondary"}), "http://noo-vllm-secondary:8000"},
		{"pre-door llama.cpp: plain", "llamacpp", decl(nil, nil, []string{"llamacpp"}), "http://noo-llamacpp:8085"},
		{"pre-door tei: plain on 80", "embedding", decl(nil, nil, []string{"embedding"}), "http://noo-tei:80"},
		{"declaration read, backend not running: the door", "llamacpp", decl(nil, nil, nil), "https://noo-stunnel-llamacpp:8085"},
	}
	for _, tc := range cases {
		if got := backendDialURL(tc.backend, tc.d); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	// OLLAMA_URL (the standalone controller's loopback embed container) wins.
	t.Setenv("OLLAMA_URL", "http://127.0.0.1:11434/")
	if got := backendDialURL("ollama", decl(nil, []string{"ollama"}, nil)); got != "http://127.0.0.1:11434" {
		t.Errorf("OLLAMA_URL: %q", got)
	}
	t.Setenv("OLLAMA_URL", "")
	// A nil client (tests, tier-5 sensors) answers the door.
	var c *Client
	if got := c.BackendDialURL("llamacpp"); got != "https://noo-stunnel-llamacpp:8085" {
		t.Fatalf("nil client: %q", got)
	}
	// The compose-alias form for a containerised agent stays.
	if got := BackendURL("embedding", ""); got != "https://stunnel-tei:443" {
		t.Fatalf("BackendURL(embedding): %q", got)
	}
	if got := BackendURL("llamacpp", ""); got != "https://noo-stunnel-llamacpp:8085" {
		t.Fatalf("BackendURL(llamacpp): %q", got)
	}
}

// The compose vLLM's command is one `sh -c` script; the flag sits inside a
// single argument. The agent-started vLLM's script names the flag nowhere.
func TestCommandDeclaresClientCert(t *testing.T) {
	compose := []string{"\nARGS=\"--model x --host 0.0.0.0 --port 8000\"\nARGS=\"$ARGS --ssl-certfile /app/pki/services/vllm/service.crt --ssl-cert-reqs 2\"\npython3 -m vllm.entrypoints.openai.api_server $ARGS\n"}
	if !commandDeclaresClientCert([]string{"sh", "-c"}, compose) {
		t.Fatal("the compose vLLM command declares a client-cert listener")
	}
	if !commandDeclaresClientCert([]string{"sh", "-c"}, []string{vllmEntrypointScript}) {
		t.Fatal("the agent-started vLLM script must declare the client-cert listener (it passes --ssl-cert-reqs 2)")
	}
	if commandDeclaresClientCert(nil, nil) {
		t.Fatal("empty command")
	}
}

// A stunnel sidecar carries the backend's name and none of its env. Counted
// as the backend it fronts, it set the model to "" and could make a running
// llama.cpp vanish from RunningBackends (whichever came last won).
func TestBackendKeyFromName_IgnoresStunnelSidecars(t *testing.T) {
	for _, name := range []string{"noo-stunnel-llamacpp", "noo-stunnel-ollama", "noo-stunnel-tei", "noo-stunnel-reranker"} {
		if got := backendKeyFromName(name); got != "" {
			t.Fatalf("%s classified as backend %q", name, got)
		}
	}
	if got := backendKeyFromName("noo-llamacpp"); got != "llamacpp" {
		t.Fatalf("the backend itself: %q", got)
	}
}
